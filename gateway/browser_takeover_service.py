"""Production entry points for scoped browser human takeovers.

The service composes provider transport discovery with the provider-neutral
coordinator and claim manager. It never returns private viewer endpoints.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from gateway.browser_takeover import (
    BrowserTakeoverCoordinator,
    BrowserTakeoverError,
    TakeoverCompletionReport,
    TakeoverConflict,
    TakeoverGrant,
    TakeoverScope,
)
from gateway.browser_takeover_access import TakeoverAccessManager, TakeoverLink
from gateway.browser_viewer_adapters import (
    CamofoxVNCViewerAdapter,
    ViewerSessionUnavailable,
)


_INSTRUCTIONS = "Open the private link. When finished, select Done or reply Done."
_REASON_CODES = {
    "verification": "human_verification_required",
    "authentication": "authentication_required",
    "consent": "consent_required",
    "other": "human_input_required",
}


class BrowserTakeoverProvisioningError(BrowserTakeoverError):
    """A link could not be issued after browser ownership was transferred."""


@dataclass(frozen=True)
class HumanAssistRequired:
    """Safe, shared browser-result/API/chat delivery contract."""

    lease_id: str
    url: str
    expires_at: float
    reason: str
    adapter_id: str
    scope: TakeoverScope
    status: str = "human_assist_required"
    done_label: str = "Done"
    instructions: str = _INSTRUCTIONS

    @classmethod
    def from_link(
        cls,
        *,
        lease_id: str,
        url: str,
        expires_at: float,
        adapter_id: str,
        scope: TakeoverScope,
        reason: str,
    ) -> "HumanAssistRequired":
        return cls(
            lease_id=lease_id,
            url=url,
            expires_at=expires_at,
            reason=_REASON_CODES.get(str(reason or "").strip(), "human_input_required"),
            adapter_id=adapter_id,
            scope=scope,
        )

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "lease_id": self.lease_id,
            "url": self.url,
            "expires_at": self.expires_at,
            "done_label": self.done_label,
            "instructions": self.instructions,
            "adapter_id": self.adapter_id,
            "scope": {
                "principal_id": self.scope.principal_id,
                "profile_id": self.scope.profile_id,
                "hermes_session_id": self.scope.hermes_session_id,
                "session_id": self.scope.hermes_session_id,
                "browser_profile_id": self.scope.browser_profile_id,
                "browser_session_id": self.scope.browser_session_id,
                "transport_family": self.scope.transport_family,
            },
        }


@dataclass(frozen=True)
class IssuedBrowserTakeover:
    """Public takeover metadata without viewer transport details."""

    grant: TakeoverGrant
    link: TakeoverLink

    def human_assist(self, reason: str) -> HumanAssistRequired:
        return HumanAssistRequired.from_link(
            lease_id=self.grant.lease_id,
            url=self.link.url,
            expires_at=self.link.expires_at,
            reason=reason,
            adapter_id=self.grant.adapter_id,
            scope=self.grant.scope,
        )


class BrowserTakeoverService:
    """Acquire, issue, and complete one exact session through the shared core."""

    def __init__(
        self,
        coordinator: BrowserTakeoverCoordinator,
        access: TakeoverAccessManager,
        *,
        adapter_id: str,
    ) -> None:
        if adapter_id != CamofoxVNCViewerAdapter.adapter_id:
            raise ValueError("unsupported browser takeover adapter")
        self._coordinator = coordinator
        self._access = access
        self._adapter_id = adapter_id

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    def issue_for_session(
        self,
        *,
        principal_id: str,
        profile_id: str,
        hermes_session_id: str,
        transport_family: str,
        ttl_seconds: float = 300.0,
    ) -> IssuedBrowserTakeover:
        """Acquire the session-bound Camofox viewer and mint one edge claim."""
        if (
            self._coordinator.active_grant_for_session(
                principal_id=principal_id,
                profile_id=profile_id,
                hermes_session_id=hermes_session_id,
                transport_family=transport_family,
            )
            is not None
        ):
            raise TakeoverConflict("session already has active human ownership")

        adapter = CamofoxVNCViewerAdapter()
        try:
            browser_profile_id, browser_session_id = adapter.browser_scope_ids(
                task_id=hermes_session_id,
                profile_id=profile_id,
            )
        except ViewerSessionUnavailable as exc:
            raise BrowserTakeoverProvisioningError(
                "exact takeover-capable browser session is unavailable"
            ) from exc
        scope = TakeoverScope(
            principal_id=principal_id,
            profile_id=profile_id,
            hermes_session_id=hermes_session_id,
            browser_profile_id=browser_profile_id,
            browser_session_id=browser_session_id,
            transport_family=transport_family,
        )
        try:
            adapter.register_task(scope=scope, task_id=hermes_session_id)
        except ViewerSessionUnavailable as exc:
            raise BrowserTakeoverProvisioningError(
                "exact takeover-capable browser session is unavailable"
            ) from exc
        grant = self._coordinator.acquire(
            scope,
            adapter,
            ttl_seconds=ttl_seconds,
        )
        try:
            link = self._access.issue(
                grant.lease_id,
                scope,
                ttl_seconds=ttl_seconds,
            )
        except Exception:
            try:
                self._coordinator.complete(grant.lease_id, scope)
            except Exception as cleanup_error:
                raise BrowserTakeoverProvisioningError(
                    "takeover link issuance failed and browser ownership remains blocked"
                ) from cleanup_error
            raise
        return IssuedBrowserTakeover(grant=grant, link=link)

    def issue_human_assist_for_session(
        self,
        *,
        principal_id: str,
        profile_id: str,
        hermes_session_id: str,
        transport_family: str,
        reason: str,
        ttl_seconds: float = 300.0,
    ) -> HumanAssistRequired:
        issued = self.issue_for_session(
            principal_id=principal_id,
            profile_id=profile_id,
            hermes_session_id=hermes_session_id,
            transport_family=transport_family,
            ttl_seconds=ttl_seconds,
        )
        return issued.human_assist(reason)

    def issue_human_assist_from_context(
        self,
        *,
        reason: str,
        task_id: Optional[str],
        ttl_seconds: float = 300.0,
    ) -> HumanAssistRequired:
        principal, profile, session, transport = _current_session_identity()
        normalized_task = str(task_id or session).strip()
        if normalized_task != session:
            raise BrowserTakeoverProvisioningError(
                "browser task does not match the active Hermes session"
            )
        return self.issue_human_assist_for_session(
            principal_id=principal,
            profile_id=profile,
            hermes_session_id=session,
            transport_family=transport,
            reason=reason,
            ttl_seconds=ttl_seconds,
        )

    def complete_for_session(
        self,
        *,
        principal_id: str,
        profile_id: str,
        hermes_session_id: str,
        transport_family: str,
    ) -> Optional[TakeoverCompletionReport]:
        grant = self._coordinator.active_grant_for_session(
            principal_id=principal_id,
            profile_id=profile_id,
            hermes_session_id=hermes_session_id,
            transport_family=transport_family,
        )
        if grant is None:
            return None
        return self._access.complete_scoped(grant.lease_id, grant.scope)

    def complete_from_context(self) -> Optional[TakeoverCompletionReport]:
        principal, profile, session, transport = _current_session_identity()
        return self.complete_for_session(
            principal_id=principal,
            profile_id=profile,
            hermes_session_id=session,
            transport_family=transport,
        )

    def cancel_from_context(self) -> Optional[TakeoverCompletionReport]:
        principal, profile, session, transport = _current_session_identity()
        grant = self._coordinator.active_grant_for_session(
            principal_id=principal,
            profile_id=profile,
            hermes_session_id=session,
            transport_family=transport,
        )
        if grant is None:
            return None
        return self._access.cancel_scoped(grant.lease_id, grant.scope)

    def shutdown(self) -> None:
        """Invalidate public access before revoking all process-local viewers."""
        self._access.invalidate_all()
        self._coordinator.reset()


def _current_session_identity() -> tuple[str, str, str, str]:
    from gateway.session_context import get_session_env

    identity = tuple(
        str(get_session_env(name, "") or "").strip()
        for name in (
            "HERMES_BROWSER_CONTROL_PRINCIPAL",
            "HERMES_SESSION_PROFILE",
            "HERMES_SESSION_ID",
            "HERMES_BROWSER_CONTROL_TRANSPORT_FAMILY",
        )
    )
    if not all(identity):
        raise BrowserTakeoverProvisioningError(
            "exact authenticated session context is unavailable"
        )
    return identity  # type: ignore[return-value]


_registry_lock = threading.RLock()
_registered_service: Optional[BrowserTakeoverService] = None


def install_browser_takeover_service(
    service: Optional[BrowserTakeoverService],
) -> None:
    """Install one process-wide facade without cross-listener overwrite."""
    if service is not None and not isinstance(service, BrowserTakeoverService):
        raise TypeError("service must be BrowserTakeoverService or None")
    global _registered_service
    with _registry_lock:
        if (
            service is not None
            and _registered_service is not None
            and _registered_service is not service
        ):
            raise ValueError(
                "a different browser takeover service is already installed"
            )
        _registered_service = service


def get_browser_takeover_service() -> Optional[BrowserTakeoverService]:
    with _registry_lock:
        return _registered_service


def uninstall_browser_takeover_service(service: BrowserTakeoverService) -> None:
    """Remove only the facade owned by the disconnecting API listener."""
    global _registered_service
    with _registry_lock:
        if _registered_service is service:
            _registered_service = None
