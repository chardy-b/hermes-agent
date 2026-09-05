"""Production entry point for scoped browser human takeovers.

The service composes provider transport discovery with the provider-neutral
coordinator and claim manager. It never returns private viewer endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass

from gateway.browser_takeover import (
    BrowserTakeoverCoordinator,
    BrowserTakeoverError,
    TakeoverGrant,
    TakeoverScope,
)
from gateway.browser_takeover_access import TakeoverAccessManager, TakeoverLink
from gateway.browser_viewer_adapters import (
    CamofoxVNCViewerAdapter,
    ViewerSessionUnavailable,
)


class BrowserTakeoverProvisioningError(BrowserTakeoverError):
    """A link could not be issued after browser ownership was transferred."""


@dataclass(frozen=True)
class IssuedBrowserTakeover:
    """Public takeover metadata without viewer transport details."""

    grant: TakeoverGrant
    link: TakeoverLink


class BrowserTakeoverService:
    """Acquire and issue one exact provider session through the shared core."""

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
        """Acquire the session-bound Camofox viewer and mint one edge claim.

        The Camofox task is the Hermes session ID used by browser tool routing.
        Browser profile/session scope is derived from provider-owned state rather
        than accepted from the requester.
        """
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
