import asyncio
import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import pytest
from aiohttp import WSMsgType, web
from aiohttp.client_exceptions import WSServerHandshakeError
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from gateway.config import Platform, PlatformConfig, load_gateway_config
from gateway.pairing_invitations import (
    canonical_pairing_challenge,
    canonical_rotation_challenge,
    derive_key_id,
)
from gateway.platforms.api_server import APIServerAdapter

ORIGIN = "https://gateway.example.test"
API_KEY = "operator-api-key-with-32-bytes-minimum"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def pairing_payload(invitation, private_key, *, client_nonce=b"0123456789abcdef"):
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    material = b64url(spki)
    key_id = derive_key_id(spki)
    fields = {
        "clientNonce": b64url(client_nonce),
        "deviceName": "Pixel",
        "gatewayOrigin": invitation["gatewayOrigin"],
        "invitationCode": invitation["invitationCode"],
        "invitationId": invitation["invitationId"],
        "keyId": key_id,
        "protocolRevision": "pairing-proof-1",
        "publicKey": material,
    }
    signature = private_key.sign(
        canonical_pairing_challenge(fields), ec.ECDSA(hashes.SHA256())
    )
    return {
        "protocolRevision": fields["protocolRevision"],
        "invitationId": fields["invitationId"],
        "invitationCode": fields["invitationCode"],
        "gatewayOrigin": fields["gatewayOrigin"],
        "deviceName": fields["deviceName"],
        "devicePublicKey": {
            "keyId": key_id,
            "algorithm": "ES256",
            "encoding": "spki-der-base64url",
            "material": material,
            "androidKeystoreApiFloor": 23,
        },
        "clientNonce": fields["clientNonce"],
        "proof": {
            "algorithm": "ES256",
            "signatureFormat": "asn1-der-base64url",
            "signature": b64url(signature),
        },
    }


def rotation_payload(device_id, current_key_id, new_private_key):
    spki = new_private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    material = b64url(spki)
    new_key_id = derive_key_id(spki)
    issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    fields = {
        "clientNonce": b64url(b"rotation-nonce-01"),
        "currentKeyId": current_key_id,
        "deviceId": device_id,
        "issuedAt": issued_at,
        "newKeyId": new_key_id,
        "newPublicKey": material,
        "protocolRevision": "pairing-proof-1",
    }
    signature = new_private_key.sign(
        canonical_rotation_challenge(fields), ec.ECDSA(hashes.SHA256())
    )
    return {
        "protocolRevision": "pairing-proof-1",
        "currentKeyId": current_key_id,
        "newDevicePublicKey": {
            "keyId": new_key_id,
            "algorithm": "ES256",
            "encoding": "spki-der-base64url",
            "material": material,
            "androidKeystoreApiFloor": 23,
        },
        "clientNonce": fields["clientNonce"],
        "issuedAt": issued_at,
        "newKeyProof": {
            "algorithm": "ES256",
            "signatureFormat": "asn1-der-base64url",
            "signature": b64url(signature),
        },
    }


def dpop(private_key, token, *, path, jti, method="GET"):
    numbers = private_key.public_key().public_numbers()
    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        },
    }
    claims = {
        "jti": jti,
        "htm": method,
        "htu": ORIGIN + path,
        "iat": int(__import__("time").time()),
        "ath": b64url(hashlib.sha256(token.encode("ascii")).digest()),
    }
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_claims = b64url(json.dumps(claims, separators=(",", ":")).encode())
    der = private_key.sign(
        f"{encoded_header}.{encoded_claims}".encode(), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{encoded_header}.{encoded_claims}.{b64url(signature)}"


async def make_client(*, operator_scopes=None, trusted_loopback_proxy=True):
    adapter = APIServerAdapter(
        PlatformConfig(
            enabled=True,
            extra={
                "key": API_KEY,
                "companion": {
                    "enabled": True,
                    "gateway_origin": ORIGIN,
                    "invitation_ttl_seconds": 300,
                    "operator_scopes": (
                        [
                            "companion.pairing.create",
                            "companion.devices.read",
                            "companion.devices.revoke",
                            "companion.sessions.read",
                            "companion.sessions.revoke",
                        ]
                        if operator_scopes is None
                        else operator_scopes
                    ),
                    "trusted_loopback_proxy": trusted_loopback_proxy,
                },
            },
        )
    )
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        if path.startswith("/companion/v1"):
            app.router.add_route(method, path, handler)
    client = TestClient(TestServer(app))
    await client.start_server()
    return adapter, client


async def pair_device(client, private_key, *, suffix="1", nonce=b"pair-helper-nonce"):
    created = await client.post(
        "/companion/v1/pairing/invitations",
        json={"deviceName": "Pixel"},
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Idempotency-Key": f"pair-helper-create-{suffix}",
        },
    )
    assert created.status == 201
    redeemed = await client.post(
        "/companion/v1/pairing/redeem",
        json=pairing_payload(await created.json(), private_key, client_nonce=nonce),
        headers={"Idempotency-Key": f"pair-helper-redeem-{suffix}"},
    )
    assert redeemed.status == 200
    return await redeemed.json()


@pytest.mark.asyncio
async def test_companion_routes_are_config_gated_and_operator_authenticated():
    disabled = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": API_KEY}))
    assert not any(
        path.startswith("/companion/v1")
        for _method, path, _handler in disabled._http_route_table()
    )

    _adapter, client = await make_client()
    try:
        unauthenticated = await client.post(
            "/companion/v1/pairing/invitations",
            json={"deviceName": "Pixel"},
            headers={"Idempotency-Key": "create-0001"},
        )
        assert unauthenticated.status == 401

        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Idempotency-Key": "create-0001",
        }
        created = await client.post(
            "/companion/v1/pairing/invitations",
            json={"deviceName": "Pixel"},
            headers=headers,
        )
        assert created.status == 201
        invitation = await created.json()
        assert invitation["protocolRevision"] == "pairing-proof-1"
        assert invitation["gatewayOrigin"] == ORIGIN

        repeated = await client.post(
            "/companion/v1/pairing/invitations",
            json={"deviceName": "Pixel"},
            headers=headers,
        )
        assert repeated.status == 201
        assert await repeated.json() == invitation

        conflict = await client.post(
            "/companion/v1/pairing/invitations",
            json={"deviceName": "Other"},
            headers=headers,
        )
        assert conflict.status == 409
        assert (await conflict.json())["code"] == "conflict"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_companion_requires_explicit_operator_scope_and_tls_boundary():
    _adapter, no_scope = await make_client(operator_scopes=[])
    try:
        response = await no_scope.post(
            "/companion/v1/pairing/invitations",
            json={"deviceName": "Pixel"},
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Idempotency-Key": "scope-denied-001",
            },
        )
        assert response.status == 403
        assert (await response.json())["code"] == "forbidden"
    finally:
        await no_scope.close()

    _adapter, plaintext = await make_client(trusted_loopback_proxy=False)
    try:
        response = await plaintext.post(
            "/companion/v1/pairing/invitations",
            json={"deviceName": "Pixel"},
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Idempotency-Key": "plaintext-denied-001",
            },
        )
        assert response.status == 400
        assert (await response.json())["code"] == "invalid_request"
    finally:
        await plaintext.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "body", "idempotency_key"),
    [
        (
            "POST",
            "/companion/v1/pairing/invitations",
            {"deviceName": "Pixel"},
            "scope-create-01",
        ),
        (
            "POST",
            "/companion/v1/pairing/start",
            {"deviceName": "Pixel"},
            "scope-start-001",
        ),
        ("GET", "/companion/v1/devices", None, None),
        (
            "POST",
            "/companion/v1/devices/device_missing/revoke",
            {"reason": "user_requested"},
            "scope-device-revoke",
        ),
        ("GET", "/companion/v1/sessions", None, None),
        (
            "POST",
            "/companion/v1/sessions/session_missing/revoke",
            {"reason": "user_requested"},
            "scope-session-revoke",
        ),
    ],
)
async def test_each_operator_management_route_denies_missing_scope(
    method, path, body, idempotency_key
):
    _adapter, client = await make_client(operator_scopes=[])
    try:
        headers = {"Authorization": f"Bearer {API_KEY}"}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        response = await client.request(method, path, json=body, headers=headers)
        assert response.status == 403
        assert (await response.json())["code"] == "forbidden"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_plaintext_boundary_denies_management_and_websocket_upgrade(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    _adapter, trusted = await make_client()
    private_key = ec.generate_private_key(ec.SECP256R1())
    try:
        paired = await pair_device(trusted, private_key, suffix="tls-boundary")
    finally:
        await trusted.close()

    _adapter, plaintext = await make_client(trusted_loopback_proxy=False)
    try:
        management = await plaintext.get(
            "/companion/v1/devices",
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        assert management.status == 400
        credentials = paired["credentials"]
        ws_path = "/companion/v1/events"
        with pytest.raises(WSServerHandshakeError) as exc_info:
            await plaintext.ws_connect(
                ws_path,
                headers={
                    "Authorization": f"Bearer {credentials['accessToken']}",
                    "DPoP": dpop(
                        private_key,
                        credentials["accessToken"],
                        path=ws_path,
                        jti="plaintext-ws-denied",
                    ),
                },
            )
        assert exc_info.value.status == 400
    finally:
        await plaintext.close()


@pytest.mark.asyncio
async def test_pair_redeem_and_dpop_bootstrap_real_http_path():
    _adapter, client = await make_client()
    try:
        create = await client.post(
            "/companion/v1/pairing/invitations",
            json={"deviceName": "Pixel"},
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Idempotency-Key": "create-0002",
            },
        )
        invitation = await create.json()
        private_key = ec.generate_private_key(ec.SECP256R1())
        payload = pairing_payload(invitation, private_key)
        redeemed = await client.post(
            "/companion/v1/pairing/redeem",
            json=payload,
            headers={"Idempotency-Key": "redeem-0002"},
        )
        assert redeemed.status == 200
        result = await redeemed.json()
        assert result["device"]["status"] == "paired"
        assert result["credentials"]["tokenType"] == "DPoP"

        path = "/companion/v1/bootstrap"
        proof = dpop(
            private_key,
            result["credentials"]["accessToken"],
            path=path,
            jti="http-bootstrap-1",
        )
        bootstrapped = await client.get(
            path,
            headers={
                "Authorization": f"Bearer {result['credentials']['accessToken']}",
                "DPoP": proof,
            },
        )
        assert bootstrapped.status == 200
        body = await bootstrapped.json()
        assert body["contractVersion"] == "companion-v1"
        assert body["device"]["id"] == result["device"]["id"]
        assert "accessToken" not in json.dumps(body)

        refresh_path = "/companion/v1/auth/refresh"
        refresh_proof = dpop(
            private_key,
            result["credentials"]["refreshToken"],
            path=refresh_path,
            jti="http-refresh-1",
            method="POST",
        )
        refreshed = await client.post(
            refresh_path,
            json={"refreshToken": result["credentials"]["refreshToken"]},
            headers={
                "DPoP": refresh_proof,
                "Idempotency-Key": "refresh-0002",
            },
        )
        assert refreshed.status == 200
        rotated = await refreshed.json()
        assert rotated["accessToken"] != result["credentials"]["accessToken"]
        assert rotated["refreshToken"] != result["credentials"]["refreshToken"]

        # Simulate process-local cache/store loss. Durable idempotency must
        # reconstruct the same rotated pair without persisting raw tokens or
        # misclassifying the retry as refresh-token reuse.
        _adapter._companion_api._idempotency.clear()
        _adapter._companion_api._stores.clear()
        retried = await client.post(
            refresh_path,
            json={"refreshToken": result["credentials"]["refreshToken"]},
            headers={
                "DPoP": refresh_proof,
                "Idempotency-Key": "refresh-0002",
            },
        )
        assert retried.status == 200
        assert await retried.json() == rotated

        old_access = await client.get(
            path,
            headers={
                "Authorization": f"Bearer {result['credentials']['accessToken']}",
                "DPoP": dpop(
                    private_key,
                    result["credentials"]["accessToken"],
                    path=path,
                    jti="http-bootstrap-old-access",
                ),
            },
        )
        assert old_access.status == 401
        assert (await old_access.json())["code"] == "invalid_token"

        rotated_bootstrap = await client.get(
            path,
            headers={
                "Authorization": f"Bearer {rotated['accessToken']}",
                "DPoP": dpop(
                    private_key,
                    rotated["accessToken"],
                    path=path,
                    jti="http-bootstrap-rotated",
                ),
            },
        )
        assert rotated_bootstrap.status == 200

        reuse = await client.post(
            refresh_path,
            json={"refreshToken": result["credentials"]["refreshToken"]},
            headers={
                "DPoP": dpop(
                    private_key,
                    result["credentials"]["refreshToken"],
                    path=refresh_path,
                    jti="http-refresh-reuse",
                    method="POST",
                ),
                "Idempotency-Key": "refresh-reuse-0002",
            },
        )
        assert reuse.status == 409
        assert (await reuse.json())["code"] == "refresh_reuse_detected"

        revoked_family = await client.get(
            path,
            headers={
                "Authorization": f"Bearer {rotated['accessToken']}",
                "DPoP": dpop(
                    private_key,
                    rotated["accessToken"],
                    path=path,
                    jti="http-bootstrap-revoked-family",
                ),
            },
        )
        assert revoked_family.status == 401
        assert (await revoked_family.json())["code"] == "session_revoked"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_refresh_idempotency_is_namespaced_per_device_and_survives_restart(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    adapter, client = await make_client()
    try:
        paired = []
        for index in range(2):
            created = await client.post(
                "/companion/v1/pairing/invitations",
                json={"deviceName": "Pixel"},
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Idempotency-Key": f"cross-device-create-{index}",
                },
            )
            invitation = await created.json()
            private_key = ec.generate_private_key(ec.SECP256R1())
            redeemed = await client.post(
                "/companion/v1/pairing/redeem",
                json=pairing_payload(
                    invitation,
                    private_key,
                    client_nonce=f"cross-device-{index:03d}".encode(),
                ),
                headers={"Idempotency-Key": f"cross-device-redeem-{index}"},
            )
            assert redeemed.status == 200
            paired.append((private_key, await redeemed.json()))

        refresh_path = "/companion/v1/auth/refresh"
        rotated = []
        for index, (private_key, result) in enumerate(paired):
            refresh_token = result["credentials"]["refreshToken"]
            response = await client.post(
                refresh_path,
                json={"refreshToken": refresh_token},
                headers={
                    "DPoP": dpop(
                        private_key,
                        refresh_token,
                        path=refresh_path,
                        jti=f"cross-device-refresh-{index}",
                        method="POST",
                    ),
                    # Deliberately identical across two authenticated devices.
                    "Idempotency-Key": "shared-refresh-idempotency-key",
                },
            )
            assert response.status == 200
            rotated.append(await response.json())

        assert rotated[0]["deviceId"] != rotated[1]["deviceId"]
        assert rotated[0]["sessionId"] != rotated[1]["sessionId"]
        assert rotated[0]["accessToken"] != rotated[1]["accessToken"]

        # Process/cache loss must still reconstruct each device's own result.
        adapter._companion_api._idempotency.clear()
        adapter._companion_api._stores.clear()
        for index, (private_key, result) in enumerate(paired):
            refresh_token = result["credentials"]["refreshToken"]
            retried = await client.post(
                refresh_path,
                json={"refreshToken": refresh_token},
                headers={
                    "DPoP": dpop(
                        private_key,
                        refresh_token,
                        path=refresh_path,
                        jti=f"cross-device-retry-{index}",
                        method="POST",
                    ),
                    "Idempotency-Key": "shared-refresh-idempotency-key",
                },
            )
            assert retried.status == 200
            assert await retried.json() == rotated[index]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_authenticated_management_and_websocket_revocation_surface(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    _adapter, client = await make_client()
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        paired = await pair_device(client, private_key)
        credentials = paired["credentials"]
        operator_headers = {"Authorization": f"Bearer {API_KEY}"}

        unauthorized = await client.get("/companion/v1/devices")
        assert unauthorized.status == 401
        devices = await client.get("/companion/v1/devices", headers=operator_headers)
        assert devices.status == 200
        assert [item["id"] for item in (await devices.json())["items"]] == [
            credentials["deviceId"]
        ]
        sessions = await client.get("/companion/v1/sessions", headers=operator_headers)
        assert sessions.status == 200
        assert [item["id"] for item in (await sessions.json())["items"]] == [
            credentials["sessionId"]
        ]

        ws_path = "/companion/v1/events"
        ws = await client.ws_connect(
            ws_path,
            headers={
                "Authorization": f"Bearer {credentials['accessToken']}",
                "DPoP": dpop(
                    private_key,
                    credentials["accessToken"],
                    path=ws_path,
                    jti="ws-session-revoke",
                ),
            },
        )
        hello = await ws.receive_json(timeout=2)
        assert hello == {
            "type": "authenticated",
            "deviceId": credentials["deviceId"],
            "sessionId": credentials["sessionId"],
            "revocationEpoch": 0,
        }

        session_path = f"/companion/v1/sessions/{credentials['sessionId']}/revoke"
        revoked_task = asyncio.create_task(
            client.post(
                session_path,
                json={"reason": "administrative"},
                headers={
                    **operator_headers,
                    "Idempotency-Key": "revoke-session-0001",
                },
            )
        )
        message = await ws.receive(timeout=2)
        revoked = await asyncio.wait_for(revoked_task, timeout=2)
        assert revoked.status == 200
        revoked_body = await revoked.json()
        assert revoked_body["sessionId"] == credentials["sessionId"]
        assert revoked_body["status"] == "revoked"
        assert message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED}
        assert ws.close_code == 4401

        denied = await client.get(
            "/companion/v1/bootstrap",
            headers={
                "Authorization": f"Bearer {credentials['accessToken']}",
                "DPoP": dpop(
                    private_key,
                    credentials["accessToken"],
                    path="/companion/v1/bootstrap",
                    jti="session-revoked-rest",
                ),
            },
        )
        assert denied.status == 401
        assert (await denied.json())["code"] == "session_revoked"

        second_key = ec.generate_private_key(ec.SECP256R1())
        second = await pair_device(
            client,
            second_key,
            suffix="2",
            nonce=b"pair-helper-nonce-2",
        )
        second_credentials = second["credentials"]
        second_ws = await client.ws_connect(
            ws_path,
            headers={
                "Authorization": f"Bearer {second_credentials['accessToken']}",
                "DPoP": dpop(
                    second_key,
                    second_credentials["accessToken"],
                    path=ws_path,
                    jti="ws-device-revoke",
                ),
            },
        )
        await second_ws.receive_json(timeout=2)
        device_path = f"/companion/v1/devices/{second_credentials['deviceId']}/revoke"
        device_revoked_task = asyncio.create_task(
            client.post(
                device_path,
                json={"reason": "device_lost"},
                headers={
                    **operator_headers,
                    "Idempotency-Key": "revoke-device-0002",
                },
            )
        )
        message = await second_ws.receive(timeout=2)
        device_revoked = await asyncio.wait_for(device_revoked_task, timeout=2)
        assert device_revoked.status == 200
        effects = (await device_revoked.json())["effects"]
        assert effects == {
            "restDenied": True,
            "refreshDenied": True,
            "webSocketsClosed": True,
            "pendingDeliveryCanceled": True,
            "localEraseRequired": True,
        }
        assert message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED}
        assert second_ws.close_code == 4401

        denied_upgrade = await client.get(
            ws_path,
            headers={
                "Authorization": f"Bearer {second_credentials['accessToken']}",
                "DPoP": dpop(
                    second_key,
                    second_credentials["accessToken"],
                    path=ws_path,
                    jti="ws-upgrade-after-device-revoke",
                ),
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": b64url(b"0123456789abcdef"),
            },
        )
        assert denied_upgrade.status == 401
        assert (await denied_upgrade.json())["code"] in {
            "device_revoked",
            "session_revoked",
        }

        assert _adapter._companion_api is not None
        store = await _adapter._companion_api._store()
        audit_records = await asyncio.to_thread(store.audit_records)
        serialized_audit = json.dumps(audit_records)
        for secret in (
            credentials["accessToken"],
            credentials["refreshToken"],
            second_credentials["accessToken"],
            second_credentials["refreshToken"],
            "revoke-session-0001",
            "revoke-device-0002",
        ):
            assert secret not in serialized_audit
        with sqlite3.connect(tmp_path / ".hermes" / "state.db") as conn:
            audit_columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(companion_audit)").fetchall()
            }
        assert audit_columns == {
            "id",
            "occurred_at",
            "actor",
            "device_id",
            "action",
            "outcome",
            "scope",
            "policy_revision",
        }
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_device_can_revoke_itself_and_response_waits_for_4401(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    _adapter, operator = await make_client()
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        paired = await pair_device(operator, private_key, suffix="self-revoke")
    finally:
        await operator.close()

    _adapter, client = await make_client(operator_scopes=[])
    try:
        credentials = paired["credentials"]
        ws_path = "/companion/v1/events"
        ws = await client.ws_connect(
            ws_path,
            headers={
                "Authorization": f"Bearer {credentials['accessToken']}",
                "DPoP": dpop(
                    private_key,
                    credentials["accessToken"],
                    path=ws_path,
                    jti="self-revoke-ws",
                ),
            },
        )
        await ws.receive_json(timeout=2)
        path = f"/companion/v1/devices/{credentials['deviceId']}/revoke"
        response_task = asyncio.create_task(
            client.post(
                path,
                json={"reason": "user_requested"},
                headers={
                    "Authorization": f"Bearer {credentials['accessToken']}",
                    "DPoP": dpop(
                        private_key,
                        credentials["accessToken"],
                        path=path,
                        jti="self-revoke-request",
                        method="POST",
                    ),
                    "Idempotency-Key": "self-revoke-device-01",
                },
            )
        )
        close_message = await ws.receive(timeout=2)
        assert close_message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED}
        assert ws.close_code == 4401
        response = await asyncio.wait_for(response_task, timeout=2)
        assert response.status == 200
        assert (await response.json())["deviceId"] == credentials["deviceId"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_key_rotation_replaces_credentials_without_repairing(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    adapter, client = await make_client()
    try:
        old_key = ec.generate_private_key(ec.SECP256R1())
        paired = await pair_device(client, old_key)
        old_credentials = paired["credentials"]
        new_key = ec.generate_private_key(ec.SECP256R1())
        path = f"/companion/v1/devices/{old_credentials['deviceId']}/keys/rotate"
        payload = rotation_payload(
            old_credentials["deviceId"], old_credentials["keyId"], new_key
        )
        proof = dpop(
            old_key,
            old_credentials["accessToken"],
            path=path,
            jti="rotate-old-key",
            method="POST",
        )
        rotation_headers = {
            "Authorization": f"Bearer {old_credentials['accessToken']}",
            "DPoP": proof,
            "Idempotency-Key": "rotate-device-key-0001",
        }
        ws_path = "/companion/v1/events"
        old_ws = await client.ws_connect(
            ws_path,
            headers={
                "Authorization": f"Bearer {old_credentials['accessToken']}",
                "DPoP": dpop(
                    old_key,
                    old_credentials["accessToken"],
                    path=ws_path,
                    jti="old-key-ws-before-rotation",
                ),
            },
        )
        await old_ws.receive_json(timeout=2)
        response_task = asyncio.create_task(
            client.post(
                path,
                json=payload,
                headers=rotation_headers,
            )
        )
        close_message = await old_ws.receive(timeout=2)
        response = await asyncio.wait_for(response_task, timeout=2)
        assert response.status == 200
        rotated = await response.json()
        assert rotated["device"]["id"] == old_credentials["deviceId"]
        assert rotated["device"]["keyId"] != old_credentials["keyId"]
        assert rotated["credentials"]["sessionId"] != old_credentials["sessionId"]
        assert rotated["previousKeyRevokedAt"]
        assert close_message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED}
        assert old_ws.close_code == 4401

        adapter._companion_api._idempotency.clear()
        adapter._companion_api._stores.clear()
        retried = await client.post(path, json=payload, headers=rotation_headers)
        assert retried.status == 200
        assert await retried.json() == rotated

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_key_headers = dict(rotation_headers)
        wrong_key_headers["DPoP"] = dpop(
            wrong_key,
            old_credentials["accessToken"],
            path=path,
            jti="rotation-retry-wrong-old-key",
            method="POST",
        )
        wrong_key_retry = await client.post(
            path, json=payload, headers=wrong_key_headers
        )
        assert wrong_key_retry.status == 401

        wrong_device_path = "/companion/v1/devices/device_not_the_owner/keys/rotate"
        wrong_device_retry = await client.post(
            wrong_device_path,
            json=payload,
            headers={
                **rotation_headers,
                "DPoP": dpop(
                    old_key,
                    old_credentials["accessToken"],
                    path=wrong_device_path,
                    jti="rotation-retry-wrong-device",
                    method="POST",
                ),
            },
        )
        assert wrong_device_retry.status == 401

        bootstrap_path = "/companion/v1/bootstrap"
        bootstrapped = await client.get(
            bootstrap_path,
            headers={
                "Authorization": f"Bearer {rotated['credentials']['accessToken']}",
                "DPoP": dpop(
                    new_key,
                    rotated["credentials"]["accessToken"],
                    path=bootstrap_path,
                    jti="bootstrap-after-rotation",
                ),
            },
        )
        assert bootstrapped.status == 200
        assert (await bootstrapped.json())["device"]["keyId"] == rotated["device"][
            "keyId"
        ]

        old_denied = await client.get(
            bootstrap_path,
            headers={
                "Authorization": f"Bearer {old_credentials['accessToken']}",
                "DPoP": dpop(
                    old_key,
                    old_credentials["accessToken"],
                    path=bootstrap_path,
                    jti="bootstrap-old-key-after-rotation",
                ),
            },
        )
        assert old_denied.status == 401

        db_path = tmp_path / ".hermes" / "state.db"
        raw_key = rotation_headers["Idempotency-Key"]
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM companion_rotation_idempotency"
            ).fetchall()
        assert rows
        assert raw_key.encode() not in {
            value for row in rows for value in row if isinstance(value, bytes)
        }
        assert raw_key not in {
            value for row in rows for value in row if isinstance(value, str)
        }
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_concurrent_rotation_is_idempotent_and_nonce_race_is_atomic(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    _adapter, client = await make_client()
    try:
        old_key = ec.generate_private_key(ec.SECP256R1())
        paired = await pair_device(client, old_key, suffix="concurrent-rotation")
        credentials = paired["credentials"]
        new_key = ec.generate_private_key(ec.SECP256R1())
        path = f"/companion/v1/devices/{credentials['deviceId']}/keys/rotate"
        payload = rotation_payload(
            credentials["deviceId"], credentials["keyId"], new_key
        )
        headers = {
            "Authorization": f"Bearer {credentials['accessToken']}",
            "DPoP": dpop(
                old_key,
                credentials["accessToken"],
                path=path,
                jti="concurrent-rotation-proof",
                method="POST",
            ),
            "Idempotency-Key": "concurrent-rotation-key",
        }
        first, second = await asyncio.gather(
            client.post(path, json=payload, headers=headers),
            client.post(path, json=payload, headers=headers),
        )
        assert first.status == second.status == 200
        assert await first.json() == await second.json()

        replay_old_key = ec.generate_private_key(ec.SECP256R1())
        replay_device = await pair_device(
            client,
            replay_old_key,
            suffix="nonce-replay-device",
            nonce=b"nonce-replay-pair",
        )
        replay_credentials = replay_device["credentials"]
        replay_path = (
            f"/companion/v1/devices/{replay_credentials['deviceId']}/keys/rotate"
        )
        competing_payloads = [
            rotation_payload(
                replay_credentials["deviceId"],
                replay_credentials["keyId"],
                ec.generate_private_key(ec.SECP256R1()),
            )
            for _index in range(2)
        ]
        competing = await asyncio.gather(
            *(
                client.post(
                    replay_path,
                    json=competing_payloads[index],
                    headers={
                        "Authorization": (
                            f"Bearer {replay_credentials['accessToken']}"
                        ),
                        "DPoP": dpop(
                            replay_old_key,
                            replay_credentials["accessToken"],
                            path=replay_path,
                            jti=f"rotation-nonce-race-{index}",
                            method="POST",
                        ),
                        "Idempotency-Key": f"rotation-nonce-race-key-{index}",
                    },
                )
                for index in range(2)
            )
        )
        assert sorted(response.status for response in competing) == [200, 401]
        rejected = next(response for response in competing if response.status == 401)
        assert (await rejected.json())["code"] == "session_revoked"

        with sqlite3.connect(tmp_path / ".hermes" / "state.db") as conn:
            active_sessions = conn.execute(
                "SELECT COUNT(*) FROM companion_credential_sessions "
                "WHERE device_id = ? AND revoked_at IS NULL",
                (credentials["deviceId"],),
            ).fetchone()[0]
            cached_rotations = conn.execute(
                "SELECT COUNT(*) FROM companion_rotation_idempotency "
                "WHERE device_id = ?",
                (credentials["deviceId"],),
            ).fetchone()[0]
            race_active_sessions = conn.execute(
                "SELECT COUNT(*) FROM companion_credential_sessions "
                "WHERE device_id = ? AND revoked_at IS NULL",
                (replay_credentials["deviceId"],),
            ).fetchone()[0]
            race_cached_rotations = conn.execute(
                "SELECT COUNT(*) FROM companion_rotation_idempotency "
                "WHERE device_id = ?",
                (replay_credentials["deviceId"],),
            ).fetchone()[0]
        assert active_sessions == 1
        assert cached_rotations == 1
        assert race_active_sessions == 1
        assert race_cached_rotations == 1
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_deprecated_aliases_preserve_auth_and_upgrade_guards():
    _adapter, client = await make_client()
    try:
        start = await client.post(
            "/companion/v1/pairing/start",
            json={"deviceName": "Pixel"},
            headers={"Idempotency-Key": "legacy-001"},
        )
        assert start.status == 401

        complete = await client.post(
            "/companion/v1/pairing/complete",
            json={"deviceName": "Pixel", "invitationCode": "obsolete"},
            headers={"Idempotency-Key": "legacy-002"},
        )
        assert complete.status == 426
        assert (await complete.json())["code"] == "pairing_protocol_upgrade_required"
    finally:
        await client.close()


def test_gateway_config_bridges_companion_block_without_env_vars(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        """gateway:
  api_server:
    enabled: true
    companion:
      enabled: true
      gateway_origin: https://gateway.example.test
      invitation_ttl_seconds: 120
      operator_scopes: [companion.pairing.create]
      trusted_loopback_proxy: true
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    config = load_gateway_config()
    companion = config.platforms[Platform.API_SERVER].extra["companion"]
    assert companion == {
        "enabled": True,
        "gateway_origin": ORIGIN,
        "invitation_ttl_seconds": 120,
        "operator_scopes": ["companion.pairing.create"],
        "trusted_loopback_proxy": True,
    }
