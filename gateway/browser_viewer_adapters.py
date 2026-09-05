"""Viewer transport adapters for browser takeover.

Adapters expose lifecycle operations to the coordinator, not authorization to
callers. Raw listener addresses remain inside the coordinator/adapter boundary.
"""

from __future__ import annotations

import hashlib
import ipaddress
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

from gateway.browser_takeover import (
    BrowserObservation,
    BrowserViewerAdapter,
    TakeoverScope,
    ViewerBinding,
)


class ViewerSessionUnavailable(RuntimeError):
    """The exact viewer session is absent, unhealthy, or already leased."""


@dataclass(frozen=True, repr=False)
class DedicatedBrowserViewerSession:
    """One already-provisioned display/browser/viewer stack.

    Provisioning belongs to the browser provider. This descriptor gives the
    transport adapter exact-scope lookup plus narrow health, observe, and
    revoke capabilities; it does not create a second authorization state
    machine.
    """

    scope: TakeoverScope
    viewer_session_id: str
    display_id: str
    cdp_endpoint: Optional[str]
    vnc_endpoint: Optional[str]
    novnc_endpoint: str
    novnc_websocket_endpoint: str
    observe: Callable[[], BrowserObservation]
    revoke: Callable[[], None]
    healthy: Callable[[], bool]

    def __repr__(self) -> str:
        return (
            "DedicatedBrowserViewerSession("
            f"scope={self.scope!r}, viewer_session_id={self.viewer_session_id!r}, "
            f"display_id={self.display_id!r}, endpoints=<redacted>)"
        )


class LoopbackNoVNCViewerAdapter(BrowserViewerAdapter):
    """Adapt dedicated local noVNC sessions to the shared coordinator contract."""

    adapter_id = "local-loopback-novnc"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: Dict[TakeoverScope, DedicatedBrowserViewerSession] = {}
        self._by_viewer_id: Dict[str, DedicatedBrowserViewerSession] = {}
        self._active: set[str] = set()

    def register(self, session: DedicatedBrowserViewerSession) -> None:
        """Register provider-owned transport resources for one exact scope."""
        if not isinstance(session, DedicatedBrowserViewerSession):
            raise TypeError("session must be a DedicatedBrowserViewerSession")
        if not session.viewer_session_id or not session.display_id:
            raise ValueError("viewer session and display identifiers are required")
        if not all(
            callable(fn) for fn in (session.observe, session.revoke, session.healthy)
        ):
            raise TypeError("viewer lifecycle callbacks must be callable")
        with self._lock:
            if session.scope in self._sessions:
                raise ValueError("takeover scope is already registered")
            if session.viewer_session_id in self._by_viewer_id:
                raise ValueError("viewer session identifier is already registered")
            self._sessions[session.scope] = session
            self._by_viewer_id[session.viewer_session_id] = session

    def acquire(self, scope: TakeoverScope) -> ViewerBinding:
        with self._lock:
            session = self._sessions.get(scope)
            if session is None or session.viewer_session_id in self._active:
                raise ViewerSessionUnavailable("exact viewer session is unavailable")
            if not session.healthy():
                raise ViewerSessionUnavailable("exact viewer session is unhealthy")
            observation = session.observe()
            self._active.add(session.viewer_session_id)
            return ViewerBinding(
                adapter_id=self.adapter_id,
                viewer_session_id=session.viewer_session_id,
                browser_profile_id=session.scope.browser_profile_id,
                browser_session_id=session.scope.browser_session_id,
                transport_family=session.scope.transport_family,
                display_id=session.display_id,
                dedicated_display=True,
                cdp_endpoint=session.cdp_endpoint,
                vnc_endpoint=session.vnc_endpoint,
                novnc_endpoint=session.novnc_endpoint,
                novnc_websocket_endpoint=session.novnc_websocket_endpoint,
                initial_observation=observation,
            )

    def revoke(self, binding: ViewerBinding) -> None:
        with self._lock:
            session = self._binding_session_locked(binding)
            if binding.viewer_session_id not in self._active:
                return
            # Keep ownership active until the provider confirms revocation.
            session.revoke()
            self._active.remove(binding.viewer_session_id)

    def observe(self, binding: ViewerBinding) -> BrowserObservation:
        with self._lock:
            session = self._binding_session_locked(binding)
            return session.observe()

    def health(self, binding: ViewerBinding) -> bool:
        with self._lock:
            try:
                session = self._binding_session_locked(binding)
            except ViewerSessionUnavailable:
                return False
            return bool(session.healthy())

    def _binding_session_locked(
        self, binding: ViewerBinding
    ) -> DedicatedBrowserViewerSession:
        session = self._by_viewer_id.get(binding.viewer_session_id)
        if session is None or binding.adapter_id != self.adapter_id:
            raise ViewerSessionUnavailable("viewer binding is unavailable")
        return session


class CamofoxVNCViewerAdapter(LoopbackNoVNCViewerAdapter):
    """Adapt Camofox's health-discovered noVNC listener without exposing it."""

    adapter_id = "camofox-vnc"

    @staticmethod
    def browser_scope_ids(*, task_id: str, profile_id: str) -> tuple[str, str]:
        """Derive the profile ID and routed task/session ID for exact scope."""
        from tools import browser_camofox

        identity = browser_camofox.get_camofox_takeover_identity(
            task_id, profile_id=profile_id
        )
        if identity is None:
            raise ViewerSessionUnavailable(
                "exact task-scoped Camofox browser session is unavailable"
            )
        return _camofox_scope_ids(profile_id, task_id, identity)

    def register_task(
        self,
        *,
        scope: TakeoverScope,
        task_id: str,
        observe: Optional[Callable[[], BrowserObservation]] = None,
        revoke: Optional[Callable[[], None]] = None,
    ) -> None:
        """Bind one existing task-scoped Camofox tab to the shared contract."""
        from tools import browser_camofox

        identity = browser_camofox.get_camofox_takeover_identity(
            task_id, profile_id=scope.profile_id
        )
        if identity is None:
            raise ViewerSessionUnavailable(
                "exact task-scoped Camofox browser session is unavailable"
            )
        expected_profile_id, expected_session_id = _camofox_scope_ids(
            scope.profile_id, task_id, identity
        )
        if (
            scope.browser_profile_id != expected_profile_id
            or scope.browser_session_id != expected_session_id
        ):
            raise ViewerSessionUnavailable(
                "Camofox browser scope does not match the exact task session"
            )
        opaque_identity = hashlib.sha256(
            "\0".join((scope.browser_session_id, *identity)).encode("utf-8")
        ).hexdigest()[:24]
        revoked = [False]

        def provider_observation() -> BrowserObservation:
            current = browser_camofox.get_camofox_takeover_identity(
                task_id, profile_id=scope.profile_id
            )
            if (
                current != identity
                or not browser_camofox.camofox_takeover_session_healthy(
                    task_id,
                    identity,
                    profile_id=scope.profile_id,
                )
            ):
                return BrowserObservation(state="browser_lost")
            user_id, tab_id = identity
            tab_fingerprint = hashlib.sha256(
                "\0".join((scope.profile_id, user_id, tab_id)).encode("utf-8")
            ).hexdigest()[:24]
            profile_fingerprint = hashlib.sha256(
                "\0".join((scope.profile_id, user_id)).encode("utf-8")
            ).hexdigest()
            return BrowserObservation(
                state="revoked" if revoked[0] else "still_blocked",
                active_tab_id=f"camofox-tab-{tab_fingerprint}",
                storage_fingerprint=f"sha256:{profile_fingerprint}",
            )

        def provider_revoke() -> None:
            revoked[0] = True

        self.register_discovered(
            scope=scope,
            viewer_session_id=f"camofox-{opaque_identity}",
            discover_vnc_url=browser_camofox.get_vnc_url,
            observe=observe or provider_observation,
            revoke=revoke or provider_revoke,
            healthy=lambda: browser_camofox.camofox_takeover_session_healthy(
                task_id,
                identity,
                profile_id=scope.profile_id,
            ),
        )

    def register_discovered(
        self,
        *,
        scope: TakeoverScope,
        viewer_session_id: str,
        discover_vnc_url: Callable[[], Optional[str]],
        observe: Callable[[], BrowserObservation],
        revoke: Callable[[], None],
        healthy: Callable[[], bool],
    ) -> None:
        """Register one exact Camofox tab using the existing health discovery."""
        try:
            discovered = _normalize_camofox_vnc_url(discover_vnc_url())
        except (TypeError, ValueError) as exc:
            raise ViewerSessionUnavailable(
                "Camofox VNC discovery did not return a loopback listener"
            ) from exc
        parsed = urlsplit(discovered)
        websocket_scheme = "wss" if parsed.scheme == "https" else "ws"
        websocket_url = urlunsplit((
            websocket_scheme,
            parsed.netloc,
            "/websockify",
            "",
            "",
        ))
        novnc_url = urlunsplit((parsed.scheme, parsed.netloc, "/vnc.html", "", ""))

        def discovered_healthy() -> bool:
            try:
                current = _normalize_camofox_vnc_url(discover_vnc_url())
            except (TypeError, ValueError):
                return False
            return current == discovered and bool(healthy())

        self.register(
            DedicatedBrowserViewerSession(
                scope=scope,
                viewer_session_id=viewer_session_id,
                display_id=f"camofox:{parsed.netloc}",
                cdp_endpoint=None,
                vnc_endpoint=None,
                novnc_endpoint=novnc_url,
                novnc_websocket_endpoint=websocket_url,
                observe=observe,
                revoke=revoke,
                healthy=discovered_healthy,
            )
        )


def _camofox_scope_ids(
    profile_id: str, task_id: str, identity: tuple[str, str]
) -> tuple[str, str]:
    user_id, _tab_id = identity
    profile_digest = hashlib.sha256(
        "\0".join((profile_id, user_id)).encode("utf-8")
    ).hexdigest()[:24]
    if not isinstance(task_id, str) or not task_id or task_id != task_id.strip():
        raise ViewerSessionUnavailable("Camofox task scope is invalid")
    return f"camofox-profile-{profile_digest}", task_id


def _normalize_camofox_vnc_url(value: Optional[str]) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Camofox VNC listener is unavailable")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.port is None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/", "/vnc.html", "/vnc_lite.html"}
    ):
        raise ValueError("Camofox VNC listener is invalid")
    host = parsed.hostname.lower()
    if host == "localhost":
        host = "127.0.0.1"
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("Camofox VNC listener must be loopback")
    except ValueError as exc:
        raise ValueError("Camofox VNC listener must be loopback") from exc
    authority_host = f"[{host}]" if ":" in host else host
    return urlunsplit((parsed.scheme, f"{authority_host}:{parsed.port}", "", "", ""))
