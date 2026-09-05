"""Single-use takeover claims and reconnect-safe lease cookies.

This module owns only edge credentials. Browser ownership remains in
``BrowserTakeoverCoordinator`` and viewer endpoints never enter public DTOs or
logs.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import math
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import quote, urlsplit

from gateway.browser_takeover import (
    BrowserTakeoverCoordinator,
    BrowserTakeoverError,
    TakeoverScope,
    ViewerProxyTarget,
)


TAKEOVER_RESPONSE_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
}


class TakeoverAccessError(RuntimeError):
    """Base class for intentionally nonspecific access failures."""


class TakeoverClaimInvalid(TakeoverAccessError):
    """Claim/cookie is unknown, consumed, expired, revoked, or stale."""


class TakeoverOriginRejected(TakeoverAccessError):
    """Request origin does not match the configured HTTPS takeover origin."""


class TakeoverScopeRejected(TakeoverAccessError):
    """Request scope does not exactly own the takeover access record."""


class TakeoverAccessCapacityExceeded(TakeoverAccessError):
    """The bounded credential store has no expired or revoked slot."""


@dataclass(frozen=True, repr=False)
class TakeoverLink:
    lease_id: str
    url: str
    expires_at: float

    def __repr__(self) -> str:
        return f"TakeoverLink(lease_id={self.lease_id!r}, url=<redacted>, expires_at={self.expires_at!r})"


@dataclass(frozen=True, repr=False)
class TakeoverCookie:
    value: str
    path: str
    expires_at: float
    secure: bool = True
    http_only: bool = True
    same_site: str = "Strict"

    def __repr__(self) -> str:
        return (
            "TakeoverCookie(value=<redacted>, "
            f"path={self.path!r}, expires_at={self.expires_at!r})"
        )


@dataclass(frozen=True)
class AccessRecordInspection:
    lease_id: str
    scope: TakeoverScope
    claim_digest: bytes
    cookie_digest: Optional[bytes]
    expires_at: float
    consumed: bool
    revoked: bool


@dataclass
class _AccessRecord:
    lease_id: str
    scope: TakeoverScope
    claim_digest: bytes
    target_digest: bytes
    expires_at: float
    cookie_digest: Optional[bytes] = None
    consumed: bool = False
    revoked: bool = False


class TakeoverAccessManager:
    """Bind one high-entropy claim and cookie to one exact active lease."""

    def __init__(
        self,
        coordinator: BrowserTakeoverCoordinator,
        *,
        base_url: str,
        clock: Optional[Callable[[], float]] = None,
        max_records: int = 128,
    ) -> None:
        parsed = urlsplit(str(base_url).strip())
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("takeover base_url must be an origin-only HTTPS URL")
        self._base_url = f"https://{parsed.netloc.lower()}"
        self._origin = self._base_url
        self._coordinator = coordinator
        self._clock = clock if clock is not None else time.time
        if (
            not isinstance(max_records, int)
            or isinstance(max_records, bool)
            or max_records < 1
        ):
            raise ValueError("max_records must be a positive integer")
        self._max_records = max_records
        self._lock = threading.RLock()
        self._records: dict[str, _AccessRecord] = {}

    def __repr__(self) -> str:
        with self._lock:
            count = len(self._records)
        return f"TakeoverAccessManager(origin={self._origin!r}, records={count})"

    def issue(
        self,
        lease_id: str,
        scope: TakeoverScope,
        *,
        ttl_seconds: float = 300.0,
    ) -> TakeoverLink:
        if not isinstance(ttl_seconds, (int, float)) or not 0 < ttl_seconds <= 900:
            raise ValueError(
                "claim ttl_seconds must be greater than zero and at most 900"
            )
        target = self._target(lease_id, scope)
        token = secrets.token_urlsafe(32)
        now = self._clock()
        expires_at = now + float(ttl_seconds)
        record = _AccessRecord(
            lease_id=lease_id,
            scope=scope,
            claim_digest=self._digest(token),
            target_digest=self._target_digest(target),
            expires_at=expires_at,
        )
        with self._lock:
            self._prune_records_locked(now)
            if (
                lease_id not in self._records
                and len(self._records) >= self._max_records
            ):
                raise TakeoverAccessCapacityExceeded(
                    "takeover access record capacity is exhausted"
                )
            self._records[lease_id] = record
        path = self._lease_path(scope, lease_id)
        url = f"{self._base_url}{path}#claim={token}"
        return TakeoverLink(lease_id=lease_id, url=url, expires_at=expires_at)

    def claim(
        self,
        lease_id: str,
        claim_token: str,
        *,
        origin: str,
        scope: TakeoverScope,
    ) -> TakeoverCookie:
        self._check_origin(origin)
        with self._lock:
            self._check_scope(self._record(lease_id), scope)
        target = self._target(lease_id, scope)
        now = self._clock()
        claim_digest = self._digest(claim_token)
        cookie_value = secrets.token_urlsafe(32)
        cookie_digest = self._digest(cookie_value)
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            if (
                record.revoked
                or record.consumed
                or now >= record.expires_at
                or not hmac.compare_digest(record.claim_digest, claim_digest)
                or not hmac.compare_digest(
                    record.target_digest, self._target_digest(target)
                )
            ):
                raise TakeoverClaimInvalid("takeover claim is not valid")
            record.consumed = True
            record.cookie_digest = cookie_digest
            return TakeoverCookie(
                value=cookie_value,
                path=self._lease_path(scope, lease_id),
                expires_at=record.expires_at,
            )

    def authorize(
        self,
        lease_id: str,
        cookie_value: str,
        *,
        origin: str,
        scope: TakeoverScope,
    ) -> ViewerProxyTarget:
        self._check_origin(origin)
        with self._lock:
            self._check_scope(self._record(lease_id), scope)
        target = self._target(lease_id, scope)
        supplied = self._digest(cookie_value)
        now = self._clock()
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            if (
                record.revoked
                or not record.consumed
                or record.cookie_digest is None
                or now >= record.expires_at
                or not hmac.compare_digest(record.cookie_digest, supplied)
                or not hmac.compare_digest(
                    record.target_digest, self._target_digest(target)
                )
            ):
                raise TakeoverClaimInvalid("takeover cookie is not valid")
        return target

    def revoke(self, lease_id: str, scope: TakeoverScope) -> None:
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            record.revoked = True
            record.claim_digest = b""
            record.cookie_digest = None

    def inspect(self, lease_id: str) -> AccessRecordInspection:
        with self._lock:
            record = self._record(lease_id)
            return AccessRecordInspection(
                lease_id=record.lease_id,
                scope=record.scope,
                claim_digest=record.claim_digest,
                cookie_digest=record.cookie_digest,
                expires_at=record.expires_at,
                consumed=record.consumed,
                revoked=record.revoked,
            )

    @property
    def origin(self) -> str:
        return self._origin

    @property
    def record_count(self) -> int:
        with self._lock:
            return len(self._records)

    def scope_for_profile(self, lease_id: str, profile_id: str) -> TakeoverScope:
        """Resolve a public route only inside the lease profile prefix."""
        with self._lock:
            record = self._record(lease_id)
            if record.revoked or record.scope.profile_id != profile_id:
                raise TakeoverClaimInvalid("takeover claim is not valid")
            return record.scope

    def remaining_seconds(self, lease_id: str, scope: TakeoverScope) -> int:
        """Return the browser-cookie lifetime without extending server authority."""
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            if record.revoked:
                raise TakeoverClaimInvalid("takeover claim is not valid")
            return max(0, math.ceil(record.expires_at - self._clock()))

    def _target(self, lease_id: str, scope: TakeoverScope) -> ViewerProxyTarget:
        try:
            return self._coordinator.viewer_proxy_target(lease_id, scope)
        except BrowserTakeoverError as exc:
            raise TakeoverClaimInvalid("takeover lease is not active") from exc

    def _record(self, lease_id: str) -> _AccessRecord:
        record = self._records.get(str(lease_id))
        if record is None:
            raise TakeoverClaimInvalid("takeover claim is not valid")
        return record

    def _prune_records_locked(self, now: float) -> None:
        if len(self._records) < self._max_records:
            return
        for lease_id, record in tuple(self._records.items()):
            if record.revoked or now >= record.expires_at:
                self._records.pop(lease_id, None)
                if len(self._records) < self._max_records:
                    return

    @staticmethod
    def _check_scope(record: _AccessRecord, scope: TakeoverScope) -> None:
        if record.scope != scope:
            raise TakeoverScopeRejected("takeover scope does not exactly match")

    def _check_origin(self, origin: str) -> None:
        if not isinstance(origin, str) or not hmac.compare_digest(origin, self._origin):
            raise TakeoverOriginRejected("takeover origin is not allowed")

    @staticmethod
    def _digest(value: str) -> bytes:
        if not isinstance(value, str) or not value:
            return b""
        return hashlib.sha256(value.encode("utf-8")).digest()

    @staticmethod
    def _target_digest(target: ViewerProxyTarget) -> bytes:
        material = "\0".join((
            target.adapter_id,
            target.viewer_session_id,
            target.http_url,
            target.websocket_url,
        ))
        return hashlib.sha256(material.encode("utf-8")).digest()

    @staticmethod
    def _lease_path(scope: TakeoverScope, lease_id: str) -> str:
        profile = quote(scope.profile_id, safe="")
        lease = quote(str(lease_id), safe="")
        return f"/p/{profile}/v1/browser-takeover/{lease}"
