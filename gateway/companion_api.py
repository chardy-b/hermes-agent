"""Thin aiohttp adapter for the companion-v1 pairing vertical slice."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from aiohttp import web

from gateway.pairing_invitations import (
    BOOTSTRAP_SCOPE,
    DevicePrincipal,
    PairingError,
    PairingInvitationStore,
    canonical_gateway_origin,
    parse_json_object,
)
from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)

_BASE_PATH = "/companion/v1"
_PAIRING_CREATE_SCOPE = "companion.pairing.create"
_DEVICE_READ_SCOPE = "companion.devices.read"
_DEVICE_REVOKE_SCOPE = "companion.devices.revoke"
_SESSION_READ_SCOPE = "companion.sessions.read"
_SESSION_REVOKE_SCOPE = "companion.sessions.revoke"
_REVOKED_WS_CODE = 4401

_ERROR_STATUS = {
    "invalid_request": 400,
    "invalid_invitation": 401,
    "invitation_expired": 409,
    "invitation_consumed": 409,
    "invalid_key": 401,
    "invalid_signature": 401,
    "replay_detected": 409,
    "invalid_token": 401,
    "proof_required": 401,
    "proof_invalid": 401,
    "device_revoked": 401,
    "session_revoked": 401,
    "refresh_reuse_detected": 409,
    "pairing_protocol_upgrade_required": 426,
    "forbidden": 403,
    "not_found": 404,
    "conflict": 409,
}
_RETRYABLE_CODES = frozenset()


class WebSocketCloseTimeout(Exception):
    """Durable revocation committed, but socket close was not confirmed."""


def _safe_outcome_response(
    *,
    message: str,
    retryable: bool,
    details: dict[str, str],
    status: int = 503,
) -> web.Response:
    response = web.json_response(
        {
            "code": "conflict",
            "message": message,
            "retryable": retryable,
            "details": details,
        },
        status=status,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _storage_failure_response(
    exc: BaseException, *, outcome: str
) -> web.Response | None:
    """Classify storage readiness without returning paths or raw DB errors."""
    if isinstance(exc, PermissionError):
        category, retryable = "unwritable", False
    elif isinstance(exc, sqlite3.DatabaseError):
        message = str(exc).lower()
        if any(token in message for token in ("locked", "busy")):
            category, retryable = "locked", True
        elif any(
            token in message
            for token in ("malformed", "not a database", "database corrupt")
        ):
            category, retryable = "corrupt", False
        elif any(
            token in message
            for token in (
                "readonly",
                "read-only",
                "disk i/o",
                "database or disk is full",
            )
        ):
            category, retryable = "unwritable", False
        else:
            category, retryable = "unavailable", True
    elif isinstance(exc, OSError):
        category, retryable = "unwritable", False
    else:
        return None
    logger.error(
        "[api_server] companion state unavailable (category=%s, retryable=%s)",
        category,
        retryable,
    )
    return _safe_outcome_response(
        message="Companion state is unavailable.",
        retryable=retryable,
        details={
            "readiness": "unavailable",
            "outcome": outcome,
            "storageCategory": category,
        },
    )


@dataclass
class _CompanionSocket:
    principal: DevicePrincipal
    revoke_event: asyncio.Event
    closed_event: asyncio.Event
    reason: str = "authentication_revoked"


def _error_response(code: str) -> web.Response:
    status = _ERROR_STATUS.get(code, 400)
    # Authentication failures deliberately do not identify whether the token,
    # invitation, key, or signature component was wrong.
    if status == 401:
        message = "Authentication or proof was rejected."
    elif code == "pairing_protocol_upgrade_required":
        message = "Client must implement pairing-proof-1."
    elif status == 403:
        message = "Authenticated principal lacks the required scope."
    elif status == 409:
        message = "The request conflicts with current pairing state."
    else:
        message = "The request is invalid."
    response = web.json_response(
        {"code": code, "message": message, "retryable": code in _RETRYABLE_CODES},
        status=status,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _success_response(body: dict[str, Any], *, status: int = 200) -> web.Response:
    response = web.json_response(body, status=status)
    response.headers["Cache-Control"] = "no-store"
    return response


def _is_loopback_peer(request: web.Request) -> bool:
    """Accept only a direct loopback peer as the trusted reverse-proxy hop."""
    remote = request.remote or ""
    try:
        return ipaddress.ip_address(remote).is_loopback
    except ValueError:
        return False


class CompanionAPI:
    """Contract routes, enabled through ``api_server.extra.companion`` config."""

    def __init__(self, adapter: Any, raw_config: Any):
        self.adapter = adapter
        config = raw_config if isinstance(raw_config, dict) else {}
        self.enabled = bool(config.get("enabled", False))
        self.gateway_origin = ""
        self.invitation_ttl_seconds = 300
        self.operator_scopes: frozenset[str] = frozenset()
        self.trusted_loopback_proxy = False
        self._stores: dict[str, PairingInvitationStore] = {}
        self._store_lock = asyncio.Lock()
        self._websockets: dict[web.WebSocketResponse, _CompanionSocket] = {}
        self._websocket_lock = asyncio.Lock()

        if not self.enabled:
            return
        try:
            self.gateway_origin = canonical_gateway_origin(
                config.get("gateway_origin", "")
            )
            ttl = int(config.get("invitation_ttl_seconds", 300))
            if not 1 <= ttl <= 300:
                raise ValueError("invitation_ttl_seconds must be from 1 to 300")
            self.invitation_ttl_seconds = ttl
            raw_scopes = config.get("operator_scopes", [])
            if not isinstance(raw_scopes, list) or any(
                not isinstance(scope, str) or not scope for scope in raw_scopes
            ):
                raise ValueError("operator_scopes must be a list of strings")
            self.operator_scopes = frozenset(raw_scopes)
            self.trusted_loopback_proxy = bool(
                config.get("trusted_loopback_proxy", False)
            )
        except (PairingError, TypeError, ValueError) as exc:
            logger.error(
                "[api_server] companion routes disabled: invalid "
                "platforms.api_server.extra.companion config (%s)",
                type(exc).__name__,
            )
            self.enabled = False
            self.gateway_origin = ""

    def routes(
        self,
    ) -> list[tuple[str, str, Callable[..., Awaitable[web.StreamResponse]]]]:
        if not self.enabled:
            return []
        return [
            ("POST", f"{_BASE_PATH}/pairing/invitations", self.create_invitation),
            ("POST", f"{_BASE_PATH}/pairing/redeem", self.redeem_invitation),
            # Deprecated aliases are exact security-equivalent paths, never
            # downgrade handlers.
            ("POST", f"{_BASE_PATH}/pairing/start", self.create_invitation),
            ("POST", f"{_BASE_PATH}/pairing/complete", self.redeem_invitation),
            ("POST", f"{_BASE_PATH}/auth/refresh", self.refresh_credentials),
            ("GET", f"{_BASE_PATH}/bootstrap", self.bootstrap),
            ("GET", f"{_BASE_PATH}/devices", self.list_devices),
            (
                "POST",
                f"{_BASE_PATH}/devices/{{device_id}}/keys/rotate",
                self.rotate_device_key,
            ),
            (
                "POST",
                f"{_BASE_PATH}/devices/{{device_id}}/revoke",
                self.revoke_device,
            ),
            ("GET", f"{_BASE_PATH}/sessions", self.list_sessions),
            (
                "POST",
                f"{_BASE_PATH}/sessions/{{session_id}}/revoke",
                self.revoke_session,
            ),
            ("GET", f"{_BASE_PATH}/events", self.websocket_events),
        ]

    @staticmethod
    def _unexpected_failure(
        exc: Exception, operation: str, *, outcome: str = "unknown"
    ) -> web.Response:
        storage_response = _storage_failure_response(exc, outcome=outcome)
        if storage_response is not None:
            return storage_response
        logger.exception("[api_server] companion %s failed", operation)
        return _error_response("invalid_request")

    async def _store(self) -> PairingInvitationStore:
        home = Path(get_hermes_home())
        key = str(home)
        existing = self._stores.get(key)
        if existing is not None:
            return existing
        async with self._store_lock:
            existing = self._stores.get(key)
            if existing is None:
                existing = await asyncio.to_thread(
                    PairingInvitationStore,
                    gateway_origin=self.gateway_origin,
                    ttl_seconds=self.invitation_ttl_seconds,
                    db_path=home / "state.db",
                )
                self._stores[key] = existing
            return existing

    def _transport_allowed(self, request: web.Request) -> bool:
        # The API server has no TLS listener today. Production deployment uses
        # an HTTPS reverse proxy to the default loopback listener. We trust the
        # socket peer only, never X-Forwarded-*; a public/plaintext listener is
        # therefore rejected even if it forges proxy headers.
        if request.secure:
            return True
        return bool(
            self.trusted_loopback_proxy
            and self.adapter._host in {"127.0.0.1", "::1", "localhost"}
            and _is_loopback_peer(request)
        )

    @staticmethod
    async def _body(request: web.Request) -> dict[str, Any]:
        if request.content_type != "application/json":
            raise PairingError("invalid_request")
        try:
            raw = await request.text()
        except (UnicodeError, OSError) as exc:
            raise PairingError("invalid_request") from exc
        return parse_json_object(raw)

    @staticmethod
    def _idempotency_key(request: web.Request) -> str:
        value = request.headers.get("Idempotency-Key", "")
        if (
            not isinstance(value, str)
            or not 8 <= len(value) <= 128
            or not value.isascii()
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
        ):
            raise PairingError("invalid_request")
        return value

    @staticmethod
    def _fingerprint(body: dict[str, Any]) -> str:
        canonical = json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _pagination(self, request: web.Request) -> tuple[int, str | None, bytes]:
        if (
            len(request.query.getall("limit", [])) > 1
            or len(request.query.getall("cursor", [])) > 1
        ):
            raise PairingError("invalid_request")
        raw_limit = request.query.get("limit")
        if raw_limit is None:
            limit = 50
        else:
            if not raw_limit.isascii() or not raw_limit.isdecimal():
                raise PairingError("invalid_request")
            limit = int(raw_limit)
            if not 1 <= limit <= 100:
                raise PairingError("invalid_request")
        cursor = request.query.get("cursor")
        if cursor == "":
            raise PairingError("invalid_request")
        secret = self.adapter._expected_api_key()
        if not secret:
            raise PairingError("invalid_request")
        cursor_key = hmac.new(
            secret.encode("utf-8"),
            b"HERMES-COMPANION-PAGINATION-V1",
            hashlib.sha256,
        ).digest()
        return limit, cursor, cursor_key

    def _operator_error(self, request: web.Request, scope: str) -> web.Response | None:
        auth_error = self.adapter._check_auth(request)
        if auth_error is not None:
            return auth_error
        if scope not in self.operator_scopes:
            return _error_response("forbidden")
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        return None

    async def _authenticate_device(
        self, request: web.Request, *, required_scope: str = BOOTSTRAP_SCOPE
    ) -> tuple[PairingInvitationStore, DevicePrincipal]:
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise PairingError("invalid_token")
        access_token = authorization[7:].strip()
        store = await self._store()
        principal = await asyncio.to_thread(
            store.authenticate_access,
            access_token=access_token,
            dpop_proof=request.headers.get("DPoP", ""),
            method=request.method,
            htu=self.gateway_origin + request.path,
            required_scope=required_scope,
        )
        return store, principal

    async def _close_websockets(
        self,
        *,
        device_id: str | None = None,
        session_id: str | None = None,
        reason: str,
    ) -> None:
        async with self._websocket_lock:
            connections = [
                connection
                for connection in self._websockets.values()
                if (device_id is None or connection.principal.device_id == device_id)
                and (
                    session_id is None or connection.principal.session_id == session_id
                )
            ]
            for connection in connections:
                connection.reason = reason
                connection.revoke_event.set()
        # The owning handler sends the close frame. Never call
        # ``WebSocketResponse.close`` concurrently with its receive loop
        # (aiohttp treats that as an abnormal 1006 shutdown). Success is held
        # until each owning handler confirms it sent the close.
        if connections:
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        *(connection.closed_event.wait() for connection in connections)
                    ),
                    timeout=5,
                )
            except TimeoutError as exc:
                raise WebSocketCloseTimeout from exc

    async def list_devices(self, request: web.Request) -> web.Response:
        error = self._operator_error(request, _DEVICE_READ_SCOPE)
        if error is not None:
            return error
        try:
            limit, cursor, cursor_key = self._pagination(request)
            store = await self._store()
            return _success_response(
                await asyncio.to_thread(
                    store.list_devices,
                    limit=limit,
                    cursor=cursor,
                    cursor_key=cursor_key,
                )
            )
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(
                exc, "device listing", outcome="not_applicable"
            )

    async def list_sessions(self, request: web.Request) -> web.Response:
        error = self._operator_error(request, _SESSION_READ_SCOPE)
        if error is not None:
            return error
        try:
            limit, cursor, cursor_key = self._pagination(request)
            store = await self._store()
            return _success_response(
                await asyncio.to_thread(
                    store.list_sessions,
                    limit=limit,
                    cursor=cursor,
                    cursor_key=cursor_key,
                )
            )
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(
                exc, "session listing", outcome="not_applicable"
            )

    async def rotate_device_key(self, request: web.Request) -> web.Response:
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        try:
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                raise PairingError("invalid_token")
            access_token = authorization[7:].strip()
            body = await self._body(request)
            idempotency_key = self._idempotency_key(request)
            derivation_secret = self.adapter._expected_api_key()
            if not derivation_secret:
                raise PairingError("invalid_request")
            device_id = request.match_info.get("device_id", "")
            store = await self._store()
            result = await asyncio.to_thread(
                store.rotate_device_key,
                access_token=access_token,
                dpop_proof=request.headers.get("DPoP", ""),
                method="POST",
                htu=self.gateway_origin + request.path,
                device_id=device_id,
                payload=body,
                idempotency_key=idempotency_key,
                request_fingerprint=self._fingerprint(body),
                token_derivation_key=derivation_secret.encode("utf-8"),
            )
            await self._close_websockets(
                device_id=device_id, reason="key_rotation_required"
            )
            return _success_response(result)
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(exc, "key rotation")

    async def revoke_device(self, request: web.Request) -> web.Response:
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        try:
            device_id = request.match_info.get("device_id", "")
            if request.headers.get("DPoP"):
                _store, principal = await self._authenticate_device(request)
                if principal.device_id != device_id:
                    raise PairingError("forbidden")
                actor = principal.device_id
            else:
                error = self._operator_error(request, _DEVICE_REVOKE_SCOPE)
                if error is not None:
                    return error
                actor = "operator:api_server"
            body = await self._body(request)
            if set(body) != {"reason"}:
                raise PairingError("invalid_request")
            idempotency_key = self._idempotency_key(request)
            derivation_secret = self.adapter._expected_api_key()
            if not derivation_secret:
                raise PairingError("invalid_request")
            store = await self._store()
            result = await asyncio.to_thread(
                store.revoke_device,
                actor,
                device_id,
                body["reason"],
                operation=f"device.revoke:{request.path}",
                idempotency_key=idempotency_key,
                request_fingerprint=self._fingerprint(body),
                token_derivation_key=derivation_secret.encode("utf-8"),
            )
            # The durable state changes first; active channels are closed before
            # success is returned, satisfying the five-second contract deadline.
            await self._close_websockets(
                device_id=result["deviceId"], reason="device_revoked"
            )
            return _success_response(result)
        except WebSocketCloseTimeout:
            return _safe_outcome_response(
                message="Revocation committed; channel closure is still pending.",
                retryable=True,
                details={
                    "readiness": "degraded",
                    "outcome": "committed",
                    "delivery": "websocket_close_timeout",
                },
            )
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(exc, "device revocation")

    async def revoke_session(self, request: web.Request) -> web.Response:
        error = self._operator_error(request, _SESSION_REVOKE_SCOPE)
        if error is not None:
            return error
        try:
            body = await self._body(request)
            if set(body) != {"reason"}:
                raise PairingError("invalid_request")
            idempotency_key = self._idempotency_key(request)
            derivation_secret = self.adapter._expected_api_key()
            if not derivation_secret:
                raise PairingError("invalid_request")
            store = await self._store()
            result = await asyncio.to_thread(
                store.revoke_session,
                "operator:api_server",
                request.match_info.get("session_id"),
                body["reason"],
                operation=f"session.revoke:{request.path}",
                idempotency_key=idempotency_key,
                request_fingerprint=self._fingerprint(body),
                token_derivation_key=derivation_secret.encode("utf-8"),
            )
            await self._close_websockets(
                session_id=result["sessionId"], reason="session_revoked"
            )
            return _success_response(result)
        except WebSocketCloseTimeout:
            return _safe_outcome_response(
                message="Revocation committed; channel closure is still pending.",
                retryable=True,
                details={
                    "readiness": "degraded",
                    "outcome": "committed",
                    "delivery": "websocket_close_timeout",
                },
            )
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(exc, "session revocation")

    async def websocket_events(self, request: web.Request) -> web.StreamResponse:
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        try:
            store, principal = await self._authenticate_device(request)
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(
                exc, "WebSocket authentication", outcome="not_applicable"
            )

        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=64 * 1024)
        await ws.prepare(request)
        connection = _CompanionSocket(
            principal=principal,
            revoke_event=asyncio.Event(),
            closed_event=asyncio.Event(),
        )
        async with self._websocket_lock:
            self._websockets[ws] = connection
        try:
            if not await asyncio.to_thread(store.principal_active, principal):
                await ws.close(code=_REVOKED_WS_CODE, message=b"authentication_revoked")
                return ws
            await ws.send_json({
                "type": "authenticated",
                "deviceId": principal.device_id,
                "sessionId": principal.session_id,
                "revocationEpoch": principal.revocation_epoch,
            })
            while not ws.closed:
                if connection.revoke_event.is_set():
                    await ws.close(
                        code=_REVOKED_WS_CODE,
                        message=connection.reason.encode("ascii"),
                    )
                    break
                try:
                    message = await asyncio.wait_for(ws.receive(), timeout=0.25)
                except TimeoutError:
                    if connection.revoke_event.is_set():
                        await ws.close(
                            code=_REVOKED_WS_CODE,
                            message=connection.reason.encode("ascii"),
                        )
                        break
                    if not await asyncio.to_thread(store.principal_active, principal):
                        await ws.close(
                            code=_REVOKED_WS_CODE, message=b"authentication_revoked"
                        )
                    continue
                if message.type in {
                    web.WSMsgType.CLOSE,
                    web.WSMsgType.CLOSED,
                    web.WSMsgType.ERROR,
                }:
                    break
                if message.type == web.WSMsgType.TEXT and message.data == "ping":
                    if not await asyncio.to_thread(store.principal_active, principal):
                        await ws.close(
                            code=_REVOKED_WS_CODE, message=b"authentication_revoked"
                        )
                        break
                    await ws.send_json({"type": "pong"})
                elif message.type == web.WSMsgType.TEXT:
                    await ws.close(code=1008, message=b"unsupported_message")
            return ws
        finally:
            connection.closed_event.set()
            async with self._websocket_lock:
                self._websockets.pop(ws, None)

    async def create_invitation(self, request: web.Request) -> web.Response:
        auth_error = self.adapter._check_auth(request)
        if auth_error is not None:
            return auth_error
        if _PAIRING_CREATE_SCOPE not in self.operator_scopes:
            return _error_response("forbidden")
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        try:
            body = await self._body(request)
            if set(body) != {"deviceName"}:
                raise PairingError("invalid_request")
            store = await self._store()
            idempotency_key = self._idempotency_key(request)
            derivation_secret = self.adapter._expected_api_key()
            if not derivation_secret:
                raise PairingError("invalid_request")
            invitation = await asyncio.to_thread(
                store.create_invitation,
                "operator:api_server",
                body["deviceName"],
                operation=f"pairing.invitation.create:{request.path}",
                idempotency_key=idempotency_key,
                request_fingerprint=self._fingerprint(body),
                token_derivation_key=derivation_secret.encode("utf-8"),
            )
            return _success_response(invitation.as_dict(), status=201)
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(exc, "invitation creation")

    async def redeem_invitation(self, request: web.Request) -> web.Response:
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        try:
            body = await self._body(request)
            store = await self._store()
            idempotency_key = self._idempotency_key(request)
            derivation_secret = self.adapter._expected_api_key()
            if not derivation_secret:
                raise PairingError("invalid_request")
            result = await asyncio.to_thread(
                store.redeem_invitation,
                body,
                operation=f"pairing.invitation.redeem:{request.path}",
                idempotency_key=idempotency_key,
                request_fingerprint=self._fingerprint(body),
                token_derivation_key=derivation_secret.encode("utf-8"),
            )
            return _success_response(result.as_dict())
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(exc, "invitation redemption")

    async def refresh_credentials(self, request: web.Request) -> web.Response:
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        try:
            body = await self._body(request)
            if set(body) != {"refreshToken"}:
                raise PairingError("invalid_request")
            refresh_token = body["refreshToken"]
            if not isinstance(refresh_token, str) or len(refresh_token) < 43:
                raise PairingError("invalid_request")
            store = await self._store()
            dpop_proof = request.headers.get("DPoP", "")
            htu = self.gateway_origin + request.path
            idempotency_key = self._idempotency_key(request)
            request_fingerprint = self._fingerprint(body)
            derivation_secret = self.adapter._expected_api_key()
            if not derivation_secret:
                raise PairingError("invalid_request")

            credentials = await asyncio.to_thread(
                store.refresh_credentials,
                refresh_token=refresh_token,
                dpop_proof=dpop_proof,
                method="POST",
                htu=htu,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                token_derivation_key=derivation_secret.encode("utf-8"),
            )
            return _success_response(credentials)
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(exc, "credential refresh")

    async def bootstrap(self, request: web.Request) -> web.Response:
        if not self._transport_allowed(request):
            return _error_response("invalid_request")
        try:
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                raise PairingError("invalid_token")
            access_token = authorization[7:].strip()
            dpop_proof = request.headers.get("DPoP", "")
            store = await self._store()
            # request.path is the actual externally visible fixed route path,
            # including the validated /p/<profile> prefix when multiplexed.
            htu = self.gateway_origin + request.path
            principal = await asyncio.to_thread(
                store.authenticate_access,
                access_token=access_token,
                dpop_proof=dpop_proof,
                method="GET",
                htu=htu,
                required_scope=BOOTSTRAP_SCOPE,
            )
            body = await asyncio.to_thread(store.bootstrap, principal)
            return _success_response(body)
        except PairingError as exc:
            return _error_response(exc.code)
        except Exception as exc:
            return self._unexpected_failure(exc, "bootstrap", outcome="not_applicable")
