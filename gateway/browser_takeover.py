"""Provider-neutral, fail-closed browser human-takeover coordination.

Viewer transports remain private adapter details.  Public grants never contain CDP,
VNC, or noVNC endpoints; ownership is the coordinator's single source of truth.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlsplit


_ACTIVE_OWNERSHIP = frozenset({
    "acquiring",
    "cancelled_acquire",
    "human",
    "expiring",
    "returning",
    "revocation_failed",
    "observation_failed",
})
_OBSERVATION_STATES = frozenset({
    "success",
    "still_blocked",
    "browser_lost",
    "expired",
    "revoked",
    "canceled",
})

logger = logging.getLogger(__name__)


class BrowserTakeoverError(RuntimeError):
    """Base class for browser-takeover contract failures."""


class TakeoverConflict(BrowserTakeoverError):
    """The browser session or dedicated display already has an active lease."""


class TakeoverNotFound(BrowserTakeoverError):
    """The requested lease does not exist."""


class TakeoverScopeMismatch(BrowserTakeoverError):
    """The caller does not exactly own the requested lease."""


class TakeoverSecurityError(BrowserTakeoverError):
    """A viewer binding violates the local-only isolation contract."""


class TakeoverRevocationError(BrowserTakeoverError):
    """Viewer revocation was not confirmed, so agent ownership remains blocked."""


class TakeoverExpired(BrowserTakeoverError):
    """The lease expired and no longer accepts human completion."""


@dataclass(frozen=True)
class TakeoverScope:
    """Complete stable identity for one browser session takeover."""

    principal_id: str
    profile_id: str
    hermes_session_id: str
    browser_profile_id: str
    browser_session_id: str
    transport_family: str

    def __post_init__(self) -> None:
        for field_name, value in self.__dict__.items():
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(f"{field_name} must be a non-empty canonical string")


@dataclass(frozen=True)
class BrowserObservation:
    """Content-free state observed from the browser after ownership changes."""

    state: str
    active_tab_id: str = ""
    storage_fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.state not in _OBSERVATION_STATES:
            raise ValueError("unsupported browser observation state")


@dataclass(frozen=True, repr=False)
class ViewerBinding:
    """Private adapter binding; raw listener addresses must never leave the core."""

    adapter_id: str
    viewer_session_id: str
    browser_profile_id: str
    browser_session_id: str
    transport_family: str
    display_id: str
    dedicated_display: bool
    cdp_endpoint: Optional[str]
    vnc_endpoint: Optional[str]
    novnc_endpoint: str
    novnc_websocket_endpoint: str
    initial_observation: BrowserObservation

    def __repr__(self) -> str:
        return (
            "ViewerBinding(viewer_session_id=<redacted>, display_id=<redacted>, "
            f"dedicated_display={self.dedicated_display!r}, endpoints=<redacted>)"
        )


class BrowserViewerAdapter(ABC):
    """Provider-neutral lifecycle seam for one exact human viewer session."""

    adapter_id: str

    @abstractmethod
    def acquire(self, scope: TakeoverScope) -> ViewerBinding:
        """Acquire a dedicated viewer binding for ``scope``."""

    @abstractmethod
    def revoke(self, binding: ViewerBinding) -> None:
        """Synchronously revoke human input and viewer access."""

    @abstractmethod
    def observe(self, binding: ViewerBinding) -> BrowserObservation:
        """Observe browser state after viewer revocation, without page content."""


@dataclass(frozen=True)
class TakeoverGrant:
    """Safe public lease metadata; it deliberately has no viewer address."""

    lease_id: str
    scope: TakeoverScope
    adapter_id: str
    ownership: str
    expires_at: float


@dataclass(frozen=True)
class TakeoverCompletionReport:
    lease_id: str
    outcome: str
    continuity_verified: bool
    active_tab_id: str


@dataclass(frozen=True)
class TakeoverLifecycleEvent:
    event: str
    ownership: str
    adapter_id: str


@dataclass(frozen=True, repr=False)
class ViewerProxyTarget:
    """Private exact noVNC upstream used only by the authenticated proxy."""

    adapter_id: str
    viewer_session_id: str
    http_url: str
    websocket_url: str

    def __repr__(self) -> str:
        return (
            "ViewerProxyTarget("
            f"adapter_id={self.adapter_id!r}, viewer_session_id=<redacted>)"
        )


@dataclass
class _LeaseRecord:
    grant: TakeoverGrant
    adapter: BrowserViewerAdapter
    generation: int
    ownership: str = "acquiring"
    binding: Optional[ViewerBinding] = None
    report: Optional[TakeoverCompletionReport] = None
    completion_event: threading.Event = field(default_factory=threading.Event)


class BrowserTakeoverCoordinator:
    """Own exclusive browser ownership transfer and revocation ordering."""

    def __init__(
        self,
        *,
        clock: Optional[Callable[[], float]] = None,
        completion_wait_timeout: float = 10.0,
        max_terminal_leases: int = 128,
        max_lifecycle_events: int = 256,
    ) -> None:
        self._clock = clock if clock is not None else time.time
        if completion_wait_timeout <= 0:
            raise ValueError("completion_wait_timeout must be positive")
        if not isinstance(max_terminal_leases, int) or max_terminal_leases < 1:
            raise ValueError("max_terminal_leases must be a positive integer")
        if not isinstance(max_lifecycle_events, int) or max_lifecycle_events < 1:
            raise ValueError("max_lifecycle_events must be a positive integer")
        self._completion_wait_timeout = float(completion_wait_timeout)
        self._max_terminal_leases = max_terminal_leases
        self._lock = threading.RLock()
        self._leases: dict[str, _LeaseRecord] = {}
        self._generation = 0
        self._lifecycle_events: deque[TakeoverLifecycleEvent] = deque(
            maxlen=max_lifecycle_events
        )
        self._lifecycle_counts: dict[str, int] = {}

    @property
    def lifecycle_events(self) -> tuple[TakeoverLifecycleEvent, ...]:
        with self._lock:
            return tuple(self._lifecycle_events)

    @property
    def lifecycle_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._lifecycle_counts)

    def _record_event_locked(self, event: str, record: _LeaseRecord) -> None:
        item = TakeoverLifecycleEvent(
            event=event,
            ownership=record.ownership,
            adapter_id=record.grant.adapter_id,
        )
        self._lifecycle_events.append(item)
        self._lifecycle_counts[event] = self._lifecycle_counts.get(event, 0) + 1
        logger.info(
            "browser takeover lifecycle event=%s ownership=%s adapter=%s",
            item.event,
            item.ownership,
            item.adapter_id,
        )

    def acquire(
        self,
        scope: TakeoverScope,
        adapter: BrowserViewerAdapter,
        *,
        ttl_seconds: float = 300.0,
    ) -> TakeoverGrant:
        if not isinstance(adapter, BrowserViewerAdapter):
            raise TypeError("adapter must implement BrowserViewerAdapter")
        if not isinstance(adapter.adapter_id, str) or not adapter.adapter_id.strip():
            raise ValueError("adapter_id is required")
        if not isinstance(ttl_seconds, (int, float)) or not 0 < ttl_seconds <= 3600:
            raise ValueError("ttl_seconds must be greater than zero and at most 3600")

        now = self._clock()
        lease_id = secrets.token_urlsafe(24)
        grant = TakeoverGrant(
            lease_id=lease_id,
            scope=scope,
            adapter_id=adapter.adapter_id,
            ownership="human",
            expires_at=now + float(ttl_seconds),
        )
        with self._lock:
            if self._active_for_browser_locked(scope.browser_session_id):
                raise TakeoverConflict(
                    "browser session already has active human ownership"
                )
            record = _LeaseRecord(
                grant=grant,
                adapter=adapter,
                generation=self._generation,
            )
            self._leases[lease_id] = record

        binding: Optional[ViewerBinding] = None
        try:
            binding = adapter.acquire(scope)
            self._validate_binding(
                binding,
                expected_adapter_id=adapter.adapter_id,
                expected_scope=scope,
            )
            with self._lock:
                if (
                    record.generation != self._generation
                    or record.ownership != "acquiring"
                ):
                    raise TakeoverConflict("takeover acquisition was cancelled")
                if self._display_in_use_locked(binding.display_id, excluding=lease_id):
                    raise TakeoverConflict(
                        "dedicated display already belongs to another lease"
                    )
                record.binding = binding
                record.ownership = "human"
                self._record_event_locked("acquired", record)
            return grant
        except Exception:
            if binding is not None:
                try:
                    adapter.revoke(binding)
                except Exception as exc:
                    with self._lock:
                        record.binding = binding
                        record.ownership = "revocation_failed"
                        self._record_event_locked("revocation_failed", record)
                    raise TakeoverRevocationError(
                        "unsafe viewer binding could not be revoked"
                    ) from exc
            with self._lock:
                self._leases.pop(lease_id, None)
            raise

    def active_grant_for_session(
        self,
        *,
        principal_id: str,
        profile_id: str,
        hermes_session_id: str,
        transport_family: str,
    ) -> Optional[TakeoverGrant]:
        """Return the sole active grant for one exact outer session.

        Browser identities stay inside the coordinator. Multiple active browsers
        in one outer session are ambiguous and therefore fail closed.
        """
        identity = tuple(
            str(value or "").strip()
            for value in (
                principal_id,
                profile_id,
                hermes_session_id,
                transport_family,
            )
        )
        if not all(identity):
            return None
        principal, profile, session, transport = identity
        self.expire_due(hermes_session_id=session)
        with self._lock:
            matches = [
                record.grant
                for record in self._leases.values()
                if record.ownership in _ACTIVE_OWNERSHIP
                and record.grant.scope.principal_id == principal
                and record.grant.scope.profile_id == profile
                and record.grant.scope.hermes_session_id == session
                and record.grant.scope.transport_family == transport
            ]
        if len(matches) > 1:
            raise TakeoverConflict(
                "multiple browser takeovers are active for this session"
            )
        return matches[0] if matches else None

    def guard_browser_action(
        self,
        *,
        hermes_session_id: str,
        browser_session_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        profile_id: Optional[str] = None,
        browser_profile_id: Optional[str] = None,
        transport_family: Optional[str] = None,
    ) -> Optional[dict]:
        """Return a safe structured block while matching human ownership is active."""
        session = str(hermes_session_id or "").strip()
        browser = str(browser_session_id or "").strip()
        if not session:
            return None
        self.expire_due(
            hermes_session_id=session,
            browser_session_id=browser or None,
        )
        with self._lock:
            matches = [
                record
                for record in self._leases.values()
                if record.ownership in _ACTIVE_OWNERSHIP
                and record.grant.scope.hermes_session_id == session
                and (not browser or record.grant.scope.browser_session_id == browser)
            ]
            if not matches:
                return None
            # Ambiguity and partial identity remain blocked. Never reveal lease
            # metadata unless every caller identity component matches exactly.
            record = matches[0]
            scope = record.grant.scope
            exact_identity = (
                len(matches) == 1
                and bool(principal_id)
                and bool(profile_id)
                and bool(browser_profile_id)
                and bool(browser)
                and bool(transport_family)
                and principal_id == scope.principal_id
                and profile_id == scope.profile_id
                and browser_profile_id == scope.browser_profile_id
                and browser == scope.browser_session_id
                and transport_family == scope.transport_family
            )
            generic = {
                "ok": False,
                "error": {
                    "code": "human_control_active",
                    "message": "Browser input is disabled while human control is active.",
                },
            }
            if not exact_identity:
                return generic
            ownership = record.ownership
            if ownership == "acquiring":
                ownership = "human"
            elif ownership in {
                "expiring",
                "revocation_failed",
                "observation_failed",
            }:
                ownership = "returning"
            return {
                **generic,
                "lease_id": record.grant.lease_id,
                "ownership": ownership,
                "expires_at": record.grant.expires_at,
            }

    def complete(self, lease_id: str, scope: TakeoverScope) -> TakeoverCompletionReport:
        """Revoke viewer access, observe browser state, then return agent ownership."""
        wait_for_owner = False
        expired = False
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                raise TakeoverNotFound("takeover lease not found")
            if record.grant.scope != scope:
                raise TakeoverScopeMismatch("takeover scope does not exactly match")
            expired = self._clock() >= record.grant.expires_at
            if expired:
                pass
            elif record.report is not None:
                return record.report
            elif record.binding is None:
                raise TakeoverConflict("takeover is not ready for completion")
            elif record.ownership == "returning":
                wait_for_owner = True
            elif record.ownership == "human":
                record.ownership = "returning"
                record.completion_event.clear()
            elif not expired:
                raise TakeoverConflict("takeover is not ready for completion")
            binding = record.binding

        if expired:
            self._expire_lease(lease_id)
            raise TakeoverExpired("takeover lease expired")
        assert binding is not None

        if wait_for_owner:
            if not record.completion_event.wait(self._completion_wait_timeout):
                raise TakeoverConflict("takeover completion is still in progress")
            with self._lock:
                if record.report is not None:
                    return record.report
                if record.ownership == "revocation_failed":
                    raise TakeoverRevocationError(
                        "viewer revocation was not confirmed; agent input remains disabled"
                    )
                raise TakeoverConflict(
                    "takeover completion did not return browser ownership"
                )

        try:
            record.adapter.revoke(binding)
        except Exception as exc:
            with self._lock:
                record.ownership = "revocation_failed"
                self._record_event_locked("revocation_failed", record)
                record.completion_event.set()
            raise TakeoverRevocationError(
                "viewer revocation was not confirmed; agent input remains disabled"
            ) from exc

        try:
            observation = record.adapter.observe(binding)
        except Exception as exc:
            with self._lock:
                record.ownership = "observation_failed"
                self._record_event_locked("observation_failed", record)
                record.completion_event.set()
            raise BrowserTakeoverError(
                "post-return browser observation failed; agent input remains disabled"
            ) from exc
        initial = binding.initial_observation
        continuity = bool(
            observation.active_tab_id
            and observation.storage_fingerprint
            and observation.active_tab_id == initial.active_tab_id
            and observation.storage_fingerprint == initial.storage_fingerprint
        )
        report = TakeoverCompletionReport(
            lease_id=lease_id,
            outcome=observation.state,
            continuity_verified=continuity,
            active_tab_id=observation.active_tab_id,
        )
        with self._lock:
            record.report = report
            record.ownership = (
                "agent" if observation.state != "browser_lost" else "browser_lost"
            )
            self._record_event_locked(observation.state, record)
            record.completion_event.set()
            self._prune_terminal_locked()
        return report

    def completion_report(
        self, lease_id: str, scope: TakeoverScope
    ) -> TakeoverCompletionReport:
        """Return a terminal content-free report for one exact lease."""
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                raise TakeoverNotFound("takeover lease not found")
            if record.grant.scope != scope:
                raise TakeoverScopeMismatch("takeover scope does not exactly match")
            if record.report is None:
                raise TakeoverConflict("takeover has no terminal report")
            return record.report

    def lease_ownership(self, lease_id: str, scope: TakeoverScope) -> str:
        """Return one exact lease's safe ownership state for diagnostics."""
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                raise TakeoverNotFound("takeover lease not found")
            if record.grant.scope != scope:
                raise TakeoverScopeMismatch("takeover scope does not exactly match")
            return record.ownership

    def cancel(self, lease_id: str, scope: TakeoverScope) -> TakeoverCompletionReport:
        """Revoke one exact lease and record a content-free cancellation."""
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                raise TakeoverNotFound("takeover lease not found")
            if record.grant.scope != scope:
                raise TakeoverScopeMismatch("takeover scope does not exactly match")
            if record.report is not None:
                return record.report
            if record.binding is None or record.ownership != "human":
                raise TakeoverConflict("takeover is not ready for cancellation")
            record.ownership = "returning"
            record.completion_event.clear()
            binding = record.binding
        try:
            record.adapter.revoke(binding)
        except Exception as exc:
            with self._lock:
                record.ownership = "revocation_failed"
                self._record_event_locked("revocation_failed", record)
                record.completion_event.set()
            raise TakeoverRevocationError(
                "viewer revocation was not confirmed; agent input remains disabled"
            ) from exc
        report = TakeoverCompletionReport(lease_id, "canceled", False, "")
        with self._lock:
            record.report = report
            record.ownership = "canceled"
            self._record_event_locked("canceled", record)
            record.completion_event.set()
            self._prune_terminal_locked()
        return report

    def expire_due(
        self,
        *,
        hermes_session_id: Optional[str] = None,
        browser_session_id: Optional[str] = None,
    ) -> tuple[str, ...]:
        """Revoke due leases before they stop blocking agent input."""
        now = self._clock()
        with self._lock:
            due = [
                lease_id
                for lease_id, record in self._leases.items()
                if record.ownership == "human"
                and now >= record.grant.expires_at
                and (
                    not hermes_session_id
                    or record.grant.scope.hermes_session_id == hermes_session_id
                )
                and (
                    not browser_session_id
                    or record.grant.scope.browser_session_id == browser_session_id
                )
            ]
        expired = []
        for lease_id in due:
            try:
                self._expire_lease(lease_id)
            except BrowserTakeoverError:
                # The record remains active/fail-closed when cleanup or fresh
                # observation cannot be confirmed.
                continue
            expired.append(lease_id)
        return tuple(expired)

    def viewer_proxy_target(
        self, lease_id: str, scope: TakeoverScope
    ) -> ViewerProxyTarget:
        """Return the private noVNC target for one exact active human lease."""
        self.expire_due(
            hermes_session_id=scope.hermes_session_id,
            browser_session_id=scope.browser_session_id,
        )
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                raise TakeoverNotFound("takeover lease not found")
            if record.grant.scope != scope:
                raise TakeoverScopeMismatch("takeover scope does not exactly match")
            if record.ownership != "human" or record.binding is None:
                raise TakeoverConflict("takeover viewer is not active")
            binding = record.binding
            return ViewerProxyTarget(
                adapter_id=record.grant.adapter_id,
                viewer_session_id=binding.viewer_session_id,
                http_url=binding.novnc_endpoint,
                websocket_url=binding.novnc_websocket_endpoint,
            )

    def _expire_lease(self, lease_id: str) -> TakeoverCompletionReport:
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                raise TakeoverNotFound("takeover lease not found")
            if record.ownership == "expired" and record.report is not None:
                return record.report
            if record.ownership != "human" or record.binding is None:
                raise TakeoverConflict("takeover cannot expire from its current state")
            record.ownership = "expiring"
            record.completion_event.clear()
            binding = record.binding

        try:
            record.adapter.revoke(binding)
        except Exception as exc:
            with self._lock:
                record.ownership = "revocation_failed"
                self._record_event_locked("revocation_failed", record)
                record.completion_event.set()
            raise TakeoverRevocationError(
                "expired viewer revocation was not confirmed; agent input remains disabled"
            ) from exc

        try:
            observation = record.adapter.observe(binding)
        except Exception as exc:
            with self._lock:
                record.ownership = "observation_failed"
                self._record_event_locked("observation_failed", record)
                record.completion_event.set()
            raise BrowserTakeoverError(
                "expired takeover observation failed; agent input remains disabled"
            ) from exc
        initial = binding.initial_observation
        report = TakeoverCompletionReport(
            lease_id=lease_id,
            outcome="expired",
            continuity_verified=bool(
                observation.active_tab_id
                and observation.storage_fingerprint
                and observation.active_tab_id == initial.active_tab_id
                and observation.storage_fingerprint == initial.storage_fingerprint
            ),
            active_tab_id=observation.active_tab_id,
        )
        with self._lock:
            record.report = report
            record.ownership = "expired"
            self._record_event_locked("expired", record)
            record.completion_event.set()
            self._prune_terminal_locked()
        return report

    def reset(self) -> None:
        """Revoke every active viewer; failures stay fail-closed in memory."""
        with self._lock:
            self._generation += 1
            for record in self._leases.values():
                if record.ownership == "acquiring":
                    record.ownership = "cancelled_acquire"
            records = [
                record
                for record in self._leases.values()
                if record.ownership in _ACTIVE_OWNERSHIP and record.binding is not None
            ]
        for record in records:
            binding = record.binding
            if binding is None:  # narrowed above; tolerate a concurrent test reset
                continue
            try:
                record.adapter.revoke(binding)
            except Exception:
                with self._lock:
                    record.ownership = "revocation_failed"
                    self._record_event_locked("revocation_failed", record)
            else:
                with self._lock:
                    record.ownership = "revoked"
                    self._record_event_locked("revoked", record)
                    self._prune_terminal_locked()

    @property
    def lease_count(self) -> int:
        """Bounded coordinator record count for diagnostics and tests."""
        with self._lock:
            return len(self._leases)

    def _prune_terminal_locked(self) -> None:
        terminal_ids = [
            lease_id
            for lease_id, record in self._leases.items()
            if record.ownership not in _ACTIVE_OWNERSHIP
        ]
        overflow = len(terminal_ids) - self._max_terminal_leases
        for lease_id in terminal_ids[: max(0, overflow)]:
            self._leases.pop(lease_id, None)

    def _active_for_browser_locked(self, browser_session_id: str) -> bool:
        return any(
            record.ownership in _ACTIVE_OWNERSHIP
            and record.grant.scope.browser_session_id == browser_session_id
            for record in self._leases.values()
        )

    def _display_in_use_locked(self, display_id: str, *, excluding: str) -> bool:
        return any(
            lease_id != excluding
            and record.ownership in _ACTIVE_OWNERSHIP
            and record.binding is not None
            and record.binding.display_id == display_id
            for lease_id, record in self._leases.items()
        )

    @staticmethod
    def _validate_binding(
        binding: ViewerBinding,
        *,
        expected_adapter_id: str,
        expected_scope: TakeoverScope,
    ) -> None:
        if not isinstance(binding, ViewerBinding):
            raise TakeoverSecurityError("viewer adapter returned an invalid binding")
        if binding.adapter_id != expected_adapter_id:
            raise TakeoverSecurityError(
                "viewer binding adapter identity does not match"
            )
        if (
            binding.browser_profile_id != expected_scope.browser_profile_id
            or binding.browser_session_id != expected_scope.browser_session_id
            or binding.transport_family != expected_scope.transport_family
        ):
            raise TakeoverSecurityError(
                "viewer binding browser scope does not exactly match"
            )
        if not binding.viewer_session_id or not binding.display_id:
            raise TakeoverSecurityError("viewer binding identity is incomplete")
        if binding.dedicated_display is not True:
            raise TakeoverSecurityError("takeover requires one dedicated display")
        for label, endpoint, schemes in (
            ("CDP", binding.cdp_endpoint, {"http", "https", "ws", "wss"}),
            ("VNC", binding.vnc_endpoint, {"vnc", "tcp"}),
            ("noVNC", binding.novnc_endpoint, {"http", "https", "ws", "wss"}),
            (
                "noVNC WebSocket",
                binding.novnc_websocket_endpoint,
                {"ws", "wss"},
            ),
        ):
            if endpoint is None:
                if label in {"CDP", "VNC"}:
                    continue
                raise TakeoverSecurityError(f"{label} listener address is missing")
            parsed = urlsplit(endpoint)
            if (
                parsed.scheme not in schemes
                or not parsed.hostname
                or parsed.port is None
            ):
                raise TakeoverSecurityError(f"{label} listener address is invalid")
            if parsed.username or parsed.password:
                raise TakeoverSecurityError(
                    f"{label} listener must not embed credentials"
                )
            if parsed.query or parsed.fragment:
                raise TakeoverSecurityError(
                    f"{label} listener must not contain query data or fragments"
                )
            if label == "VNC" and parsed.path not in {"", "/"}:
                raise TakeoverSecurityError("VNC listener path is not allowed")
            if label == "noVNC" and parsed.path not in {
                "",
                "/",
                "/vnc.html",
                "/vnc_lite.html",
            }:
                raise TakeoverSecurityError("noVNC listener path is not allowed")
            if label == "noVNC WebSocket" and parsed.path != "/websockify":
                raise TakeoverSecurityError("noVNC WebSocket path is not allowed")
            if label == "CDP" and not (
                parsed.path in {"", "/"}
                or parsed.path.startswith("/json/")
                or parsed.path.startswith("/devtools/browser/")
            ):
                raise TakeoverSecurityError("CDP listener path is not allowed")
            host = parsed.hostname.lower()
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
            if not is_loopback:
                raise TakeoverSecurityError(f"{label} listener must bind to loopback")


_GLOBAL_COORDINATOR = BrowserTakeoverCoordinator()


def get_browser_takeover_coordinator() -> BrowserTakeoverCoordinator:
    return _GLOBAL_COORDINATOR
