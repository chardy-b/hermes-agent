"""Viewer transport adapters for browser takeover.

Adapters expose lifecycle operations to the coordinator, not authorization to
callers. Raw listener addresses remain inside the coordinator/adapter boundary.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Dict

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
    cdp_endpoint: str
    vnc_endpoint: str
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
