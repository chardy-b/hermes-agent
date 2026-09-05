"""Single-use takeover claims and reconnect-safe lease cookies.

This module owns only edge credentials. Browser ownership remains in
``BrowserTakeoverCoordinator`` and viewer endpoints never enter public DTOs or
logs.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import quote, urlsplit

from gateway.browser_takeover import (
    BrowserTakeoverCoordinator,
    BrowserTakeoverError,
    TakeoverCompletionReport,
    TakeoverExpired,
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


class TakeoverCompletionFailed(TakeoverAccessError):
    """Ownership did not return safely after edge credentials were revoked."""


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
    completing: bool = False
    completion_cookie_digest: Optional[bytes] = None
    completion_report: Optional[TakeoverCompletionReport] = None
    completion_failed: bool = False
    websocket_authorizations: int = 0
    completion_event: threading.Event = field(default_factory=threading.Event)


class TakeoverAccessManager:
    """Bind one high-entropy claim and cookie to one exact active lease."""

    def __init__(
        self,
        coordinator: BrowserTakeoverCoordinator,
        *,
        base_url: str,
        clock: Optional[Callable[[], float]] = None,
        max_records: int = 128,
        max_websocket_connections: int = 8,
        completion_wait_timeout: float = 10.0,
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
        if (
            not isinstance(max_websocket_connections, int)
            or isinstance(max_websocket_connections, bool)
            or max_websocket_connections < 1
        ):
            raise ValueError("max_websocket_connections must be a positive integer")
        self._max_websocket_connections = max_websocket_connections
        if completion_wait_timeout <= 0:
            raise ValueError("completion_wait_timeout must be positive")
        self._completion_wait_timeout = float(completion_wait_timeout)
        self._lock = threading.RLock()
        self._records: dict[str, _AccessRecord] = {}
        self._revocation_listeners: list[Callable[[str, TakeoverScope], None]] = []

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

    def authorize_websocket(
        self,
        lease_id: str,
        cookie_value: str,
        *,
        origin: str,
        scope: TakeoverScope,
    ) -> ViewerProxyTarget:
        """Authorize one bounded initial WebSocket or reconnect."""
        target = self.authorize(lease_id, cookie_value, origin=origin, scope=scope)
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            if record.revoked or self._clock() >= record.expires_at:
                raise TakeoverClaimInvalid("takeover cookie is not valid")
            if record.websocket_authorizations >= self._max_websocket_connections:
                raise TakeoverClaimInvalid("takeover cookie is not valid")
            record.websocket_authorizations += 1
        return target

    def remaining_lifetime(self, lease_id: str, scope: TakeoverScope) -> float:
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            return max(0.0, record.expires_at - self._clock())

    def register_revocation_listener(
        self, listener: Callable[[str, TakeoverScope], None]
    ) -> None:
        with self._lock:
            if listener not in self._revocation_listeners:
                self._revocation_listeners.append(listener)

    def _notify_revoked(self, lease_id: str, scope: TakeoverScope) -> None:
        with self._lock:
            listeners = tuple(self._revocation_listeners)
        for listener in listeners:
            try:
                listener(lease_id, scope)
            except Exception:
                continue

    def revoke(self, lease_id: str, scope: TakeoverScope) -> None:
        notify = False
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            notify = not record.revoked
            record.revoked = True
            record.claim_digest = b""
            record.cookie_digest = None
        if notify:
            self._notify_revoked(lease_id, scope)

    def invalidate_all(self) -> None:
        """Invalidate every edge credential before process shutdown reset."""
        revoked: list[tuple[str, TakeoverScope]] = []
        with self._lock:
            for record in self._records.values():
                if not record.revoked:
                    revoked.append((record.lease_id, record.scope))
                record.revoked = True
                record.claim_digest = b""
                record.cookie_digest = None
        for lease_id, scope in revoked:
            self._notify_revoked(lease_id, scope)

    def complete(
        self,
        lease_id: str,
        cookie_value: str,
        *,
        origin: str,
        scope: TakeoverScope,
    ) -> TakeoverCompletionReport:
        """Revoke edge credentials before returning browser ownership."""
        self._check_origin(origin)
        supplied = self._digest(cookie_value)
        wait_event: Optional[threading.Event] = None

        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            terminal = self._terminal_completion_locked(record, supplied)
            if terminal is not None:
                return terminal
            expired_report = self._expired_completion_locked(record, supplied)
            if expired_report is not None:
                return expired_report
            if record.completing:
                wait_event = record.completion_event
            elif (
                record.revoked
                or not record.consumed
                or record.cookie_digest is None
                or not hmac.compare_digest(record.cookie_digest, supplied)
            ):
                raise TakeoverClaimInvalid("takeover cookie is not valid")

        if wait_event is not None:
            return self._wait_for_completion(record, supplied, wait_event)

        target = self._target(lease_id, scope)
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            terminal = self._terminal_completion_locked(record, supplied)
            if terminal is not None:
                return terminal
            expired_report = self._expired_completion_locked(record, supplied)
            if expired_report is not None:
                return expired_report
            if record.completing:
                wait_event = record.completion_event
            elif (
                record.revoked
                or record.cookie_digest is None
                or not hmac.compare_digest(record.cookie_digest, supplied)
                or not hmac.compare_digest(
                    record.target_digest, self._target_digest(target)
                )
            ):
                raise TakeoverClaimInvalid("takeover cookie is not valid")
            else:
                record.completing = True
                record.revoked = True
                record.claim_digest = b""
                record.completion_cookie_digest = record.cookie_digest
                record.cookie_digest = None
                record.completion_event.clear()

        if wait_event is not None:
            return self._wait_for_completion(record, supplied, wait_event)

        self._notify_revoked(lease_id, scope)
        return self._complete_coordinator(record, lease_id, scope)

    def complete_scoped(
        self,
        lease_id: str,
        scope: TakeoverScope,
    ) -> TakeoverCompletionReport:
        """Complete from an already-authenticated exact gateway session.

        This path intentionally does not accept a browser cookie. The caller must
        first resolve the full scope from trusted session context. Edge claim and
        cookie material is revoked under the access lock before the coordinator
        can return ownership to the agent.
        """
        wait_event: Optional[threading.Event] = None
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            if record.completion_report is not None:
                return record.completion_report
            if record.completion_failed:
                raise TakeoverCompletionFailed(
                    "takeover completion did not return browser ownership"
                )
            if record.completing:
                wait_event = record.completion_event
            else:
                target = self._target(lease_id, scope)
                if not hmac.compare_digest(
                    record.target_digest, self._target_digest(target)
                ):
                    raise TakeoverClaimInvalid("takeover claim is not valid")
                record.completing = True
                record.revoked = True
                record.claim_digest = b""
                record.completion_cookie_digest = record.cookie_digest
                record.cookie_digest = None
                record.completion_event.clear()

        if wait_event is not None:
            return self._wait_for_scoped_completion(record, wait_event)
        self._notify_revoked(lease_id, scope)
        return self._complete_coordinator(record, lease_id, scope)

    def cancel_scoped(
        self, lease_id: str, scope: TakeoverScope
    ) -> TakeoverCompletionReport:
        """Revoke edge credentials then cancel one trusted exact session."""
        wait_event: Optional[threading.Event] = None
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            if record.completion_report is not None:
                return record.completion_report
            if record.completing:
                wait_event = record.completion_event
            else:
                record.completing = True
                record.revoked = True
                record.claim_digest = b""
                record.completion_cookie_digest = record.cookie_digest
                record.cookie_digest = None
                record.completion_event.clear()
        if wait_event is not None:
            return self._wait_for_scoped_completion(record, wait_event)
        self._notify_revoked(lease_id, scope)
        try:
            report = self._coordinator.cancel(lease_id, scope)
        except BrowserTakeoverError as exc:
            self._record_completion_failure(record)
            raise TakeoverCompletionFailed(
                "takeover cancellation did not revoke browser ownership"
            ) from exc
        self._record_completion_success(record, report)
        return report

    def _complete_coordinator(
        self,
        record: _AccessRecord,
        lease_id: str,
        scope: TakeoverScope,
    ) -> TakeoverCompletionReport:
        try:
            report = self._coordinator.complete(lease_id, scope)
        except TakeoverExpired:
            try:
                report = self._coordinator.completion_report(lease_id, scope)
            except BrowserTakeoverError as exc:
                self._record_completion_failure(record)
                raise TakeoverCompletionFailed(
                    "takeover completion did not return browser ownership"
                ) from exc
        except BrowserTakeoverError as exc:
            self._record_completion_failure(record)
            raise TakeoverCompletionFailed(
                "takeover completion did not return browser ownership"
            ) from exc
        except Exception as exc:
            self._record_completion_failure(record)
            raise TakeoverCompletionFailed(
                "takeover completion did not return browser ownership"
            ) from exc

        self._record_completion_success(record, report)
        return report

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

    def scope_for_profile(
        self, lease_id: str, profile_id: str, *, allow_terminal: bool = False
    ) -> TakeoverScope:
        """Resolve a public route only inside the lease profile prefix."""
        with self._lock:
            record = self._record(lease_id)
            if record.scope.profile_id != profile_id or (
                record.revoked and not allow_terminal
            ):
                raise TakeoverClaimInvalid("takeover claim is not valid")
            return record.scope

    def cookie_path(self, lease_id: str, scope: TakeoverScope) -> str:
        return self._lease_path(scope, lease_id)

    def remaining_seconds(self, lease_id: str, scope: TakeoverScope) -> int:
        """Return the browser-cookie lifetime without extending server authority."""
        with self._lock:
            record = self._record(lease_id)
            self._check_scope(record, scope)
            if record.revoked:
                raise TakeoverClaimInvalid("takeover claim is not valid")
            return max(0, math.ceil(record.expires_at - self._clock()))

    @staticmethod
    def _terminal_completion_locked(
        record: _AccessRecord, supplied: bytes
    ) -> Optional[TakeoverCompletionReport]:
        if not (
            record.completing
            or record.completion_report is not None
            or record.completion_failed
        ):
            return None
        expected = record.completion_cookie_digest
        if expected is None or not hmac.compare_digest(expected, supplied):
            raise TakeoverClaimInvalid("takeover cookie is not valid")
        if record.completion_failed:
            raise TakeoverCompletionFailed(
                "takeover completion did not return browser ownership"
            )
        return record.completion_report

    def _wait_for_completion(
        self,
        record: _AccessRecord,
        supplied: bytes,
        event: threading.Event,
    ) -> TakeoverCompletionReport:
        if not event.wait(self._completion_wait_timeout):
            raise TakeoverCompletionFailed("takeover completion is still in progress")
        with self._lock:
            report = self._terminal_completion_locked(record, supplied)
            if report is None:
                raise TakeoverCompletionFailed(
                    "takeover completion did not return browser ownership"
                )
            return report

    def _wait_for_scoped_completion(
        self,
        record: _AccessRecord,
        event: threading.Event,
    ) -> TakeoverCompletionReport:
        if not event.wait(self._completion_wait_timeout):
            raise TakeoverCompletionFailed("takeover completion is still in progress")
        with self._lock:
            if record.completion_failed or record.completion_report is None:
                raise TakeoverCompletionFailed(
                    "takeover completion did not return browser ownership"
                )
            return record.completion_report

    def _expired_completion_locked(
        self,
        record: _AccessRecord,
        supplied: bytes,
    ) -> Optional[TakeoverCompletionReport]:
        if self._clock() < record.expires_at:
            return None
        if (
            record.revoked
            or not record.consumed
            or record.cookie_digest is None
            or not hmac.compare_digest(record.cookie_digest, supplied)
        ):
            raise TakeoverClaimInvalid("takeover cookie is not valid")
        record.completion_cookie_digest = record.cookie_digest
        record.cookie_digest = None
        record.claim_digest = b""
        record.revoked = True
        report = TakeoverCompletionReport(
            lease_id=record.lease_id,
            outcome="expired",
            continuity_verified=False,
            active_tab_id="",
        )
        record.completion_report = report
        record.completion_event.set()
        return report

    def _record_completion_success(
        self, record: _AccessRecord, report: TakeoverCompletionReport
    ) -> None:
        with self._lock:
            record.completion_report = report
            record.completing = False
            record.completion_event.set()

    def _record_completion_failure(self, record: _AccessRecord) -> None:
        with self._lock:
            record.completing = False
            record.completion_failed = True
            record.completion_event.set()

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
            if not record.completing and (record.revoked or now >= record.expires_at):
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
