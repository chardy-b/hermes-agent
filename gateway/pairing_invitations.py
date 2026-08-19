"""Secure ``pairing-proof-1`` primitives and durable companion state.

This module owns protocol validation and profile-scoped persistence.  HTTP
routing and operator authentication stay in the API-server adapter.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
import unicodedata
import urllib.parse
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from hermes_constants import get_hermes_home
from hermes_state import apply_wal_with_fallback

PROTOCOL_REVISION = "pairing-proof-1"
CONTRACT_VERSION = "companion-v1"
PAIRING_CONTEXT = b"HERMES-COMPANION-PAIRING-V1\0"
ROTATION_CONTEXT = b"HERMES-COMPANION-ROTATE-V1\0"
PAIRING_FIELDS = frozenset({
    "clientNonce",
    "deviceName",
    "gatewayOrigin",
    "invitationCode",
    "invitationId",
    "keyId",
    "protocolRevision",
    "publicKey",
})
PAIRING_REQUEST_FIELDS = frozenset({
    "protocolRevision",
    "invitationId",
    "invitationCode",
    "gatewayOrigin",
    "deviceName",
    "devicePublicKey",
    "clientNonce",
    "proof",
})
DEVICE_KEY_FIELDS = frozenset({
    "keyId",
    "algorithm",
    "encoding",
    "material",
    "androidKeystoreApiFloor",
})
PROOF_FIELDS = frozenset({"algorithm", "signatureFormat", "signature"})
ROTATION_FIELDS = frozenset({
    "clientNonce",
    "currentKeyId",
    "deviceId",
    "issuedAt",
    "newKeyId",
    "newPublicKey",
    "protocolRevision",
})
ROTATION_REQUEST_FIELDS = frozenset({
    "protocolRevision",
    "currentKeyId",
    "newDevicePublicKey",
    "clientNonce",
    "issuedAt",
    "newKeyProof",
})
REVOCATION_REASONS = frozenset({
    "user_requested",
    "device_lost",
    "suspected_compromise",
    "key_replaced",
    "administrative",
})
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
PUBLIC_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
KEY_ID_RE = re.compile(r"^pk_[A-Za-z0-9_-]{43}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
BOOTSTRAP_SCOPE = "companion.bootstrap.read"
AUDIT_SCOPE = "companion"
AUDIT_POLICY_REVISION = PROTOCOL_REVISION
ACCESS_TOKEN_TTL_SECONDS = 900
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_INVITATION_TTL_SECONDS = 300
DPOP_MAX_AGE_SECONDS = 60
DPOP_FUTURE_SKEW_SECONDS = 5
# Replays are guaranteed for 24 hours. After expiry the key is fresh; the
# underlying single-use/resource-state rules still prevent replaying a consumed
# invitation or undoing a revocation.
IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60


class PairingError(Exception):
    """Stable companion contract error."""

    def __init__(self, code: str, *, audited: bool = False):
        self.code = code
        self.audited = audited
        super().__init__(code)


@dataclass(frozen=True)
class PairingInvitation:
    protocol_revision: str
    invitation_id: str
    invitation_code: str
    gateway_origin: str
    expires_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocolRevision": self.protocol_revision,
            "invitationId": self.invitation_id,
            "invitationCode": self.invitation_code,
            "gatewayOrigin": self.gateway_origin,
            "expiresAt": self.expires_at,
        }


@dataclass(frozen=True)
class PairingResult:
    device: dict[str, Any]
    credentials: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"device": self.device, "credentials": self.credentials}


@dataclass(frozen=True)
class DevicePrincipal:
    device_id: str
    session_id: str
    key_id: str
    scopes: tuple[str, ...]
    device: dict[str, Any]
    access_expires_at: str
    refresh_expires_at: str
    revocation_epoch: int


class _DuplicateName(ValueError):
    pass


def _reject_duplicate_names(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateName(key)
        result[key] = value
    return result


def parse_json_object(raw: str) -> dict[str, Any]:
    """Parse one JSON object while rejecting duplicate member names."""
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_names)
    except (json.JSONDecodeError, UnicodeError, _DuplicateName, TypeError) as exc:
        raise PairingError("invalid_request") from exc
    if not isinstance(value, dict):
        raise PairingError("invalid_request")
    return value


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _derive_refresh_tokens(
    derivation_key: bytes, session_id: str, idempotency_key: str
) -> tuple[str, str]:
    context = (
        b"HERMES-COMPANION-REFRESH-IDEMPOTENCY-V1\0"
        + session_id.encode("ascii")
        + b"\0"
        + idempotency_key.encode("ascii")
    )
    seed = hmac.new(derivation_key, context, hashlib.sha256).digest()
    access = hmac.new(seed, b"access-token", hashlib.sha256).digest()
    refresh = hmac.new(seed, b"refresh-token", hashlib.sha256).digest()
    return _encode_base64url(access), _encode_base64url(refresh)


def _refresh_idempotency_id(
    derivation_key: bytes,
    session_id: str,
    token_family_id: str,
    idempotency_key: str,
) -> bytes:
    """Return a profile-local, session/family-bound opaque durable identity."""
    context = (
        b"HERMES-COMPANION-REFRESH-IDEMPOTENCY-LOOKUP-V1\0"
        + session_id.encode("ascii")
        + b"\0"
        + token_family_id.encode("ascii")
        + b"\0"
        + idempotency_key.encode("ascii")
    )
    return hmac.new(derivation_key, context, hashlib.sha256).digest()


def _operation_idempotency_id(
    derivation_key: bytes,
    operation: str,
    actor_binding: str,
    idempotency_key: str,
) -> bytes:
    """Derive a scoped durable lookup without persisting caller-chosen keys."""
    context = b"\0".join((
        b"HERMES-COMPANION-OPERATION-IDEMPOTENCY-V1",
        operation.encode("utf-8"),
        actor_binding.encode("utf-8"),
        idempotency_key.encode("ascii"),
    ))
    return hmac.new(derivation_key, context, hashlib.sha256).digest()


def _derive_operation_secret(
    derivation_key: bytes, idempotency_id: bytes, purpose: bytes
) -> str:
    return _encode_base64url(
        hmac.new(
            derivation_key,
            b"HERMES-COMPANION-OPERATION-RESULT-V1\0"
            + purpose
            + b"\0"
            + idempotency_id,
            hashlib.sha256,
        ).digest()
    )


def _derive_public_id(prefix: str, idempotency_id: bytes, purpose: bytes) -> str:
    digest = hashlib.sha256(purpose + b"\0" + idempotency_id).hexdigest()
    return prefix + digest[:32]


def _encode_page_cursor(resource: str, key: list[Any], signing_key: bytes) -> str:
    payload = json.dumps(
        {"v": 1, "r": resource, "k": key},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(signing_key, payload, hashlib.sha256).digest()
    return f"{_encode_base64url(payload)}.{_encode_base64url(signature)}"


def _decode_page_cursor(resource: str, cursor: str, signing_key: bytes) -> list[Any]:
    if not isinstance(cursor, str) or not 1 <= len(cursor) <= 1024:
        raise PairingError("invalid_request")
    parts = cursor.split(".")
    if len(parts) != 2:
        raise PairingError("invalid_request")
    payload = _decode_base64url(parts[0])
    signature = _decode_base64url(parts[1])
    if (
        _encode_base64url(payload) != parts[0]
        or _encode_base64url(signature) != parts[1]
        or not hmac.compare_digest(
            signature, hmac.new(signing_key, payload, hashlib.sha256).digest()
        )
    ):
        raise PairingError("invalid_request")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise PairingError("invalid_request") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"v", "r", "k"}
        or value["v"] != 1
        or value["r"] != resource
        or not isinstance(value["k"], list)
        or len(value["k"]) != 2
    ):
        raise PairingError("invalid_request")
    return value["k"]


def _derive_rotation_tokens(
    derivation_key: bytes, session_id: str, idempotency_key: str
) -> tuple[str, str]:
    context = (
        b"HERMES-COMPANION-ROTATION-IDEMPOTENCY-V1\0"
        + session_id.encode("ascii")
        + b"\0"
        + idempotency_key.encode("ascii")
    )
    seed = hmac.new(derivation_key, context, hashlib.sha256).digest()
    access = hmac.new(seed, b"access-token", hashlib.sha256).digest()
    refresh = hmac.new(seed, b"refresh-token", hashlib.sha256).digest()
    return _encode_base64url(access), _encode_base64url(refresh)


def _rotation_idempotency_id(
    derivation_key: bytes,
    old_session_id: str,
    token_family_id: str,
    idempotency_key: str,
) -> bytes:
    context = (
        b"HERMES-COMPANION-ROTATION-IDEMPOTENCY-LOOKUP-V1\0"
        + old_session_id.encode("ascii")
        + b"\0"
        + token_family_id.encode("ascii")
        + b"\0"
        + idempotency_key.encode("ascii")
    )
    return hmac.new(derivation_key, context, hashlib.sha256).digest()


def _decode_base64url(value: Any, *, error: str = "invalid_request") -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or B64URL_RE.fullmatch(value) is None
    ):
        raise PairingError(error)
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise PairingError(error) from exc


def _timestamp(value: float) -> str:
    return (
        datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    )


def canonical_gateway_origin(value: Any) -> str:
    """Validate the contract's exact HTTPS RFC 6454 origin serialization."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise PairingError("invalid_request")
    if not value.isascii() or not value.startswith("https://"):
        raise PairingError("invalid_request")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise PairingError("invalid_request") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port == 443
        or hostname != hostname.lower()
        or "%" in hostname
    ):
        raise PairingError("invalid_request")
    canonical_host = f"[{hostname}]" if ":" in hostname else hostname
    canonical = f"https://{canonical_host}"
    if port is not None:
        canonical += f":{port}"
    if value != canonical:
        raise PairingError("invalid_request")
    return canonical


def _validate_public_id(value: Any) -> str:
    if not isinstance(value, str) or PUBLIC_ID_RE.fullmatch(value) is None:
        raise PairingError("invalid_request")
    return value


def _load_p256_spki(material: Any) -> tuple[bytes, ec.EllipticCurvePublicKey]:
    raw = _decode_base64url(material, error="invalid_key")
    try:
        key = serialization.load_der_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise PairingError("invalid_key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise PairingError("invalid_key")
    canonical = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical != raw:
        raise PairingError("invalid_key")
    return raw, key


def derive_key_id(spki_der: bytes) -> str:
    return "pk_" + _encode_base64url(hashlib.sha256(spki_der).digest())


def canonical_pairing_challenge(fields: dict[str, Any]) -> bytes:
    """Build the normative pairing-proof-1 challenge bytes.

    RFC 8785 JCS is equivalent to this serialization because the field names
    are a fixed ASCII allowlist and every value is required to be a string.
    """
    if set(fields) != PAIRING_FIELDS or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in fields.items()
    ):
        raise PairingError("invalid_request")
    if fields["protocolRevision"] != PROTOCOL_REVISION:
        raise PairingError("pairing_protocol_upgrade_required")
    if fields["deviceName"] != unicodedata.normalize("NFC", fields["deviceName"]):
        raise PairingError("invalid_request")
    canonical_gateway_origin(fields["gatewayOrigin"])
    _validate_public_id(fields["invitationId"])
    invitation_code = _decode_base64url(fields["invitationCode"])
    client_nonce = _decode_base64url(fields["clientNonce"])
    if not 32 <= len(invitation_code) <= 96 or len(client_nonce) < 16:
        raise PairingError("invalid_request")
    body = json.dumps(
        fields,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return PAIRING_CONTEXT + body


def canonical_rotation_challenge(fields: dict[str, Any]) -> bytes:
    """Build the normative pairing-proof-1 key-rotation challenge bytes."""
    if set(fields) != ROTATION_FIELDS or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in fields.items()
    ):
        raise PairingError("invalid_request")
    if fields["protocolRevision"] != PROTOCOL_REVISION:
        raise PairingError("pairing_protocol_upgrade_required")
    _validate_public_id(fields["deviceId"])
    if (
        KEY_ID_RE.fullmatch(fields["currentKeyId"]) is None
        or KEY_ID_RE.fullmatch(fields["newKeyId"]) is None
        or fields["currentKeyId"] == fields["newKeyId"]
    ):
        raise PairingError("invalid_key")
    nonce = _decode_base64url(fields["clientNonce"])
    if len(nonce) < 16:
        raise PairingError("invalid_request")
    _decode_base64url(fields["newPublicKey"], error="invalid_key")
    _parse_contract_timestamp(fields["issuedAt"])
    body = json.dumps(
        fields,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ROTATION_CONTEXT + body


def _parse_contract_timestamp(value: Any) -> float:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PairingError("invalid_request")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PairingError("invalid_request") from exc
    if parsed.tzinfo != timezone.utc:
        raise PairingError("invalid_request")
    timestamp = parsed.timestamp()
    if _timestamp(timestamp) != value:
        raise PairingError("invalid_request")
    return timestamp


def _validate_der_signature(signature: bytes) -> None:
    """Reject non-minimal ASN.1 DER ECDSA signatures before verification."""
    if len(signature) < 8 or signature[0] != 0x30:
        raise PairingError("invalid_signature")
    if signature[1] & 0x80 or signature[1] != len(signature) - 2:
        raise PairingError("invalid_signature")
    offset = 2
    values: list[int] = []
    for _ in range(2):
        if offset + 2 > len(signature) or signature[offset] != 0x02:
            raise PairingError("invalid_signature")
        length = signature[offset + 1]
        offset += 2
        integer = signature[offset : offset + length]
        offset += length
        if (
            not integer
            or len(integer) > 33
            or integer[0] & 0x80
            or (len(integer) > 1 and integer[0] == 0 and not integer[1] & 0x80)
        ):
            raise PairingError("invalid_signature")
        values.append(int.from_bytes(integer, "big"))
    if offset != len(signature) or any(
        value <= 0 or value >= P256_ORDER for value in values
    ):
        raise PairingError("invalid_signature")


def _pairing_proof_inputs(
    payload: dict[str, Any],
) -> tuple[str, str, bytes, str, ec.EllipticCurvePublicKey, bytes]:
    if set(payload) != PAIRING_REQUEST_FIELDS:
        # The obsolete prototype sent only a code/device name. Fail with the
        # contract's explicit upgrade signal, never a compatibility downgrade.
        if "protocolRevision" not in payload or "proof" not in payload:
            raise PairingError("pairing_protocol_upgrade_required")
        raise PairingError("invalid_request")
    if payload.get("protocolRevision") != PROTOCOL_REVISION:
        raise PairingError("pairing_protocol_upgrade_required")

    invitation_id = _validate_public_id(payload.get("invitationId"))
    invitation_code = payload.get("invitationCode")
    if not isinstance(invitation_code, str) or not 43 <= len(invitation_code) <= 128:
        raise PairingError("invalid_request")
    gateway_origin = canonical_gateway_origin(payload.get("gatewayOrigin"))
    device_name = payload.get("deviceName")
    if (
        not isinstance(device_name, str)
        or not 1 <= len(device_name) <= 100
        or device_name != unicodedata.normalize("NFC", device_name)
    ):
        raise PairingError("invalid_request")
    client_nonce = payload.get("clientNonce")
    if not isinstance(client_nonce, str) or not 22 <= len(client_nonce) <= 64:
        raise PairingError("invalid_request")

    device_key = payload.get("devicePublicKey")
    if not isinstance(device_key, dict) or not set(device_key).issubset(
        DEVICE_KEY_FIELDS
    ):
        raise PairingError("invalid_request")
    if not {"keyId", "algorithm", "encoding", "material"}.issubset(device_key):
        raise PairingError("invalid_request")
    if (
        device_key.get("algorithm") != "ES256"
        or device_key.get("encoding") != "spki-der-base64url"
        or (
            "androidKeystoreApiFloor" in device_key
            and device_key["androidKeystoreApiFloor"] != 23
        )
    ):
        raise PairingError("invalid_key")
    material = device_key.get("material")
    if not isinstance(material, str) or not 80 <= len(material) <= 256:
        raise PairingError("invalid_key")
    spki, public_key = _load_p256_spki(material)
    key_id = derive_key_id(spki)
    if not hmac.compare_digest(str(device_key.get("keyId", "")), key_id):
        raise PairingError("invalid_key")

    proof = payload.get("proof")
    if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
        raise PairingError("invalid_request")
    if (
        proof.get("algorithm") != "ES256"
        or proof.get("signatureFormat") != "asn1-der-base64url"
    ):
        raise PairingError("invalid_signature")
    signature_value = proof.get("signature")
    if not isinstance(signature_value, str) or not 80 <= len(signature_value) <= 128:
        raise PairingError("invalid_signature")
    signature = _decode_base64url(signature_value, error="invalid_signature")
    _validate_der_signature(signature)

    fields = {
        "clientNonce": client_nonce,
        "deviceName": device_name,
        "gatewayOrigin": gateway_origin,
        "invitationCode": invitation_code,
        "invitationId": invitation_id,
        "keyId": key_id,
        "protocolRevision": PROTOCOL_REVISION,
        "publicKey": material,
    }
    challenge = canonical_pairing_challenge(fields)
    try:
        public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise PairingError("invalid_signature") from exc
    return invitation_id, invitation_code, spki, key_id, public_key, challenge


def _rotation_proof_inputs(
    payload: dict[str, Any], *, device_id: str, now: float
) -> tuple[str, bytes, str, bytes]:
    if set(payload) != ROTATION_REQUEST_FIELDS:
        raise PairingError("invalid_request")
    if payload.get("protocolRevision") != PROTOCOL_REVISION:
        raise PairingError("pairing_protocol_upgrade_required")
    device_id = _validate_public_id(device_id)
    current_key_id = payload.get("currentKeyId")
    if (
        not isinstance(current_key_id, str)
        or KEY_ID_RE.fullmatch(current_key_id) is None
    ):
        raise PairingError("invalid_key")

    new_device_key = payload.get("newDevicePublicKey")
    if not isinstance(new_device_key, dict) or not set(new_device_key).issubset(
        DEVICE_KEY_FIELDS
    ):
        raise PairingError("invalid_request")
    if not {"keyId", "algorithm", "encoding", "material"}.issubset(new_device_key):
        raise PairingError("invalid_request")
    if (
        new_device_key.get("algorithm") != "ES256"
        or new_device_key.get("encoding") != "spki-der-base64url"
        or (
            "androidKeystoreApiFloor" in new_device_key
            and new_device_key["androidKeystoreApiFloor"] != 23
        )
    ):
        raise PairingError("invalid_key")
    material = new_device_key.get("material")
    if not isinstance(material, str) or not 80 <= len(material) <= 256:
        raise PairingError("invalid_key")
    new_spki, new_public_key = _load_p256_spki(material)
    new_key_id = derive_key_id(new_spki)
    if not hmac.compare_digest(
        str(new_device_key.get("keyId", "")), new_key_id
    ) or hmac.compare_digest(current_key_id, new_key_id):
        raise PairingError("invalid_key")

    client_nonce = payload.get("clientNonce")
    if not isinstance(client_nonce, str) or not 22 <= len(client_nonce) <= 64:
        raise PairingError("invalid_request")
    nonce_hash = hashlib.sha256(
        _decode_base64url(client_nonce) + device_id.encode("ascii")
    ).digest()
    issued_at = payload.get("issuedAt")
    issued_timestamp = _parse_contract_timestamp(issued_at)
    if abs(now - issued_timestamp) > MAX_INVITATION_TTL_SECONDS:
        raise PairingError("invalid_signature")

    proof = payload.get("newKeyProof")
    if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
        raise PairingError("invalid_request")
    if (
        proof.get("algorithm") != "ES256"
        or proof.get("signatureFormat") != "asn1-der-base64url"
    ):
        raise PairingError("invalid_signature")
    signature = _decode_base64url(proof.get("signature"), error="invalid_signature")
    _validate_der_signature(signature)
    fields = {
        "clientNonce": client_nonce,
        "currentKeyId": current_key_id,
        "deviceId": device_id,
        "issuedAt": issued_at,
        "newKeyId": new_key_id,
        "newPublicKey": material,
        "protocolRevision": PROTOCOL_REVISION,
    }
    try:
        new_public_key.verify(
            signature,
            canonical_rotation_challenge(fields),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise PairingError("invalid_signature") from exc
    return current_key_id, new_spki, new_key_id, nonce_hash


def verify_pairing_proof(payload: dict[str, Any]) -> str:
    """Verify a contract request without consulting invitation state."""
    _invitation_id, _code, _spki, key_id, _key, _challenge = _pairing_proof_inputs(
        payload
    )
    return key_id


class PairingInvitationStore:
    """Durable profile-aware invitation, device, and credential store."""

    def __init__(
        self,
        *,
        gateway_origin: str,
        ttl_seconds: int = MAX_INVITATION_TTL_SECONDS,
        db_path: Path | None = None,
        clock=time.time,
    ):
        self.gateway_origin = canonical_gateway_origin(gateway_origin)
        self.ttl_seconds = min(MAX_INVITATION_TTL_SECONDS, max(1, int(ttl_seconds)))
        self.db_path = (
            Path(db_path) if db_path is not None else get_hermes_home() / "state.db"
        )
        self.clock = clock
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            apply_wal_with_fallback(conn, db_label="state.db (companion pairing)")
        except Exception:
            conn.close()
            raise
        return conn

    @contextmanager
    def _transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            if immediate:
                conn.execute("BEGIN IMMEDIATE")
            else:
                conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize_schema(self) -> None:
        with self._transaction() as conn:
            legacy_columns = {
                row["name"]
                for row in conn.execute(
                    "PRAGMA table_info(companion_refresh_idempotency)"
                ).fetchall()
            }
            if "idempotency_key" in legacy_columns:
                # The pre-release WIL-47 candidate persisted caller-chosen keys
                # globally. It was never shipped; discard that unsafe cache
                # before creating the scoped, opaque identity schema.
                conn.execute("DROP TABLE companion_refresh_idempotency")
            rotation_columns = {
                row["name"]
                for row in conn.execute(
                    "PRAGMA table_info(companion_rotation_idempotency)"
                ).fetchall()
            }
            if rotation_columns and not {
                "old_key_id",
                "old_public_key_spki",
            }.issubset(rotation_columns):
                conn.execute("DROP TABLE companion_rotation_idempotency")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS companion_pairing_invitations (
                    invitation_id TEXT PRIMARY KEY,
                    code_hash BLOB NOT NULL,
                    requested_device_name TEXT NOT NULL,
                    gateway_origin TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE TABLE IF NOT EXISTS companion_pairing_nonces (
                    nonce_hash BLOB PRIMARY KEY,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS companion_devices (
                    device_id TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    status TEXT NOT NULL,
                    key_id TEXT NOT NULL UNIQUE,
                    public_key_spki BLOB NOT NULL,
                    paired_at REAL NOT NULL,
                    revoked_at REAL,
                    revocation_epoch INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS companion_credential_sessions (
                    session_id TEXT PRIMARY KEY,
                    token_family_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    access_token_hash BLOB NOT NULL UNIQUE,
                    refresh_token_hash BLOB NOT NULL UNIQUE,
                    access_expires_at REAL NOT NULL,
                    refresh_expires_at REAL NOT NULL,
                    audience TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    revocation_epoch INTEGER NOT NULL,
                    revoked_at REAL,
                    FOREIGN KEY(device_id) REFERENCES companion_devices(device_id)
                );
                CREATE TABLE IF NOT EXISTS companion_dpop_replay (
                    session_id TEXT NOT NULL,
                    jti TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY(session_id, jti)
                );
                CREATE TABLE IF NOT EXISTS companion_consumed_refresh_tokens (
                    token_hash BLOB PRIMARY KEY,
                    token_family_id TEXT NOT NULL,
                    consumed_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS companion_refresh_idempotency (
                    idempotency_id BLOB PRIMARY KEY,
                    request_fingerprint TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    access_expires_at REAL NOT NULL,
                    refresh_expires_at REAL NOT NULL,
                    revocation_epoch INTEGER NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS companion_rotation_nonces (
                    nonce_hash BLOB PRIMARY KEY,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS companion_rotation_idempotency (
                    idempotency_id BLOB PRIMARY KEY,
                    request_fingerprint TEXT NOT NULL,
                    old_session_id TEXT NOT NULL,
                    new_session_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    old_key_id TEXT NOT NULL,
                    old_public_key_spki BLOB NOT NULL,
                    new_key_id TEXT NOT NULL,
                    access_expires_at REAL NOT NULL,
                    refresh_expires_at REAL NOT NULL,
                    revocation_epoch INTEGER NOT NULL,
                    previous_key_revoked_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS companion_operation_idempotency (
                    idempotency_id BLOB PRIMARY KEY,
                    operation TEXT NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    result_metadata_json TEXT NOT NULL,
                    committed_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS companion_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at REAL NOT NULL,
                    actor TEXT,
                    device_id TEXT,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    policy_revision TEXT NOT NULL
                );
                """
            )

    def _audit(
        self,
        conn: sqlite3.Connection,
        *,
        actor: str | None,
        device_id: str | None,
        action: str,
        outcome: str,
    ) -> None:
        conn.execute(
            """INSERT INTO companion_audit
               (occurred_at, actor, device_id, action, outcome, scope,
                policy_revision) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                self.clock(),
                actor,
                device_id,
                action,
                outcome,
                AUDIT_SCOPE,
                AUDIT_POLICY_REVISION,
            ),
        )

    def _audit_failure(self, action: str, outcome: str) -> None:
        with self._transaction(immediate=True) as conn:
            self._audit(
                conn,
                actor=None,
                device_id=None,
                action=action,
                outcome=outcome,
            )

    @staticmethod
    def _validate_idempotency_inputs(
        idempotency_key: Any,
        request_fingerprint: Any,
        derivation_key: Any,
    ) -> tuple[str, str, bytes]:
        if (
            not isinstance(idempotency_key, str)
            or not 8 <= len(idempotency_key) <= 128
            or not idempotency_key.isascii()
            or not isinstance(request_fingerprint, str)
            or len(request_fingerprint) != 64
            or not isinstance(derivation_key, bytes)
            or len(derivation_key) < 16
        ):
            raise PairingError("invalid_request")
        return idempotency_key, request_fingerprint, derivation_key

    def _load_operation_result(
        self,
        conn: sqlite3.Connection,
        *,
        idempotency_id: bytes,
        operation: str,
        request_fingerprint: str,
        now: float,
    ) -> dict[str, Any] | None:
        """Return a committed result or claim absence inside the write txn.

        ``BEGIN IMMEDIATE`` makes one transaction the owner for a duplicate
        in-flight key. Other processes wait at SQLite (not on a process-global
        asyncio lock), then observe its committed result. If the owner dies,
        SQLite rolls the transaction back and the next caller safely owns the
        operation. A mismatched fingerprint always conflicts while the record
        is live; expired records are deleted and the key becomes fresh.
        """
        conn.execute(
            "DELETE FROM companion_operation_idempotency WHERE expires_at <= ?",
            (now,),
        )
        row = conn.execute(
            """SELECT operation, request_fingerprint, result_metadata_json
               FROM companion_operation_idempotency
               WHERE idempotency_id = ?""",
            (idempotency_id,),
        ).fetchone()
        if row is None:
            return None
        if row["operation"] != operation or not hmac.compare_digest(
            row["request_fingerprint"], request_fingerprint
        ):
            raise PairingError("conflict")
        try:
            metadata = json.loads(row["result_metadata_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PairingError("conflict") from exc
        if not isinstance(metadata, dict):
            raise PairingError("conflict")
        return metadata

    def _store_operation_result(
        self,
        conn: sqlite3.Connection,
        *,
        idempotency_id: bytes,
        operation: str,
        request_fingerprint: str,
        metadata: dict[str, Any],
        now: float,
    ) -> None:
        # Metadata contains identifiers/timestamps only. Secret response values
        # are deterministically reconstructed from the profile-local derivation
        # key and opaque request id, never serialized to SQLite.
        conn.execute(
            """INSERT INTO companion_operation_idempotency
               (idempotency_id, operation, request_fingerprint,
                result_metadata_json, committed_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                idempotency_id,
                operation,
                request_fingerprint,
                json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                now,
                now + IDEMPOTENCY_TTL_SECONDS,
            ),
        )

    def create_invitation(
        self,
        actor: str,
        device_name: Any,
        *,
        operation: str | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
        token_derivation_key: bytes | None = None,
    ) -> PairingInvitation:
        if (
            not isinstance(actor, str)
            or not actor
            or len(actor) > 200
            or not isinstance(device_name, str)
            or not 1 <= len(device_name) <= 100
            or device_name != unicodedata.normalize("NFC", device_name)
        ):
            raise PairingError("invalid_request")
        durable = operation is not None
        if durable:
            idempotency_key, request_fingerprint, token_derivation_key = (
                self._validate_idempotency_inputs(
                    idempotency_key, request_fingerprint, token_derivation_key
                )
            )
            idempotency_id = _operation_idempotency_id(
                token_derivation_key, operation, actor, idempotency_key
            )
        else:
            idempotency_id = b""

        now = self.clock()
        with self._transaction(immediate=True) as conn:
            if durable:
                cached = self._load_operation_result(
                    conn,
                    idempotency_id=idempotency_id,
                    operation=operation,
                    request_fingerprint=request_fingerprint,
                    now=now,
                )
                if cached is not None:
                    return PairingInvitation(
                        protocol_revision=PROTOCOL_REVISION,
                        invitation_id=cached["invitationId"],
                        invitation_code=_derive_operation_secret(
                            token_derivation_key,
                            idempotency_id,
                            b"invitation-code:"
                            + cached["invitationId"].encode("ascii"),
                        ),
                        gateway_origin=self.gateway_origin,
                        expires_at=cached["expiresAt"],
                    )
                invitation_id = "inv_" + uuid.uuid4().hex
                invitation_code = _derive_operation_secret(
                    token_derivation_key,
                    idempotency_id,
                    b"invitation-code:" + invitation_id.encode("ascii"),
                )
            else:
                invitation_id = "inv_" + uuid.uuid4().hex
                invitation_code = _encode_base64url(secrets.token_bytes(32))
            expires_at = now + self.ttl_seconds
            conn.execute(
                """INSERT INTO companion_pairing_invitations
                   (invitation_id, code_hash, requested_device_name,
                    gateway_origin, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    invitation_id,
                    hashlib.sha256(invitation_code.encode("ascii")).digest(),
                    device_name,
                    self.gateway_origin,
                    now,
                    expires_at,
                ),
            )
            self._audit(
                conn,
                actor=actor,
                device_id=None,
                action="pairing.invitation.create",
                outcome="success",
            )
            if durable:
                self._store_operation_result(
                    conn,
                    idempotency_id=idempotency_id,
                    operation=operation,
                    request_fingerprint=request_fingerprint,
                    metadata={
                        "invitationId": invitation_id,
                        "expiresAt": _timestamp(expires_at),
                    },
                    now=now,
                )
        return PairingInvitation(
            protocol_revision=PROTOCOL_REVISION,
            invitation_id=invitation_id,
            invitation_code=invitation_code,
            gateway_origin=self.gateway_origin,
            expires_at=_timestamp(expires_at),
        )

    def redeem_invitation(
        self,
        payload: dict[str, Any],
        *,
        operation: str | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
        token_derivation_key: bytes | None = None,
    ) -> PairingResult:
        try:
            invitation_id, invitation_code, spki, key_id, _key, _challenge = (
                _pairing_proof_inputs(payload)
            )
            now = self.clock()
            durable = operation is not None
            if durable:
                idempotency_key, request_fingerprint, token_derivation_key = (
                    self._validate_idempotency_inputs(
                        idempotency_key, request_fingerprint, token_derivation_key
                    )
                )
                idempotency_id = _operation_idempotency_id(
                    token_derivation_key, operation, invitation_id, idempotency_key
                )
                access_token = _derive_operation_secret(
                    token_derivation_key, idempotency_id, b"access-token"
                )
                refresh_token = _derive_operation_secret(
                    token_derivation_key, idempotency_id, b"refresh-token"
                )
                device_id = _derive_public_id("device_", idempotency_id, b"device-id")
                session_id = _derive_public_id(
                    "session_", idempotency_id, b"session-id"
                )
                token_family_id = _derive_public_id(
                    "family_", idempotency_id, b"family-id"
                )
            else:
                idempotency_id = b""
                access_token = _encode_base64url(secrets.token_bytes(32))
                refresh_token = _encode_base64url(secrets.token_bytes(32))
                device_id = "device_" + uuid.uuid4().hex
                session_id = "session_" + uuid.uuid4().hex
                token_family_id = "family_" + uuid.uuid4().hex
            nonce_hash = hashlib.sha256(payload["clientNonce"].encode("ascii")).digest()
            code_hash = hashlib.sha256(invitation_code.encode("ascii")).digest()

            with self._transaction(immediate=True) as conn:
                if durable:
                    cached = self._load_operation_result(
                        conn,
                        idempotency_id=idempotency_id,
                        operation=operation,
                        request_fingerprint=request_fingerprint,
                        now=now,
                    )
                    if cached is not None:
                        return PairingResult(
                            device={
                                "id": cached["deviceId"],
                                "name": cached["deviceName"],
                                "platform": "android",
                                "status": "paired",
                                "keyId": cached["keyId"],
                                "pairedAt": cached["pairedAt"],
                                "revocationEpoch": 0,
                            },
                            credentials={
                                "tokenType": "DPoP",
                                "accessToken": access_token,
                                "accessExpiresAt": cached["accessExpiresAt"],
                                "refreshToken": refresh_token,
                                "refreshExpiresAt": cached["refreshExpiresAt"],
                                "deviceId": cached["deviceId"],
                                "keyId": cached["keyId"],
                                "sessionId": cached["sessionId"],
                                "revocationEpoch": 0,
                            },
                        )
                conn.execute(
                    "DELETE FROM companion_pairing_nonces WHERE expires_at <= ?",
                    (now,),
                )
                row = conn.execute(
                    """SELECT code_hash, requested_device_name, gateway_origin,
                              expires_at, consumed_at
                       FROM companion_pairing_invitations
                       WHERE invitation_id = ?""",
                    (invitation_id,),
                ).fetchone()
                if row is None or not hmac.compare_digest(row["code_hash"], code_hash):
                    raise PairingError("invalid_invitation")
                if row["consumed_at"] is not None:
                    raise PairingError("invitation_consumed")
                if now >= float(row["expires_at"]):
                    raise PairingError("invitation_expired")
                if row["gateway_origin"] != payload["gatewayOrigin"]:
                    raise PairingError("invalid_invitation")
                if row["requested_device_name"] != payload["deviceName"]:
                    raise PairingError("invalid_invitation")
                try:
                    conn.execute(
                        """INSERT INTO companion_pairing_nonces
                           (nonce_hash, expires_at) VALUES (?, ?)""",
                        (nonce_hash, row["expires_at"]),
                    )
                except sqlite3.IntegrityError as exc:
                    raise PairingError("replay_detected") from exc
                updated = conn.execute(
                    """UPDATE companion_pairing_invitations
                       SET consumed_at = ?
                       WHERE invitation_id = ? AND consumed_at IS NULL""",
                    (now, invitation_id),
                ).rowcount
                if updated != 1:
                    raise PairingError("invitation_consumed")
                conn.execute(
                    """INSERT INTO companion_devices
                       (device_id, device_name, platform, status, key_id,
                        public_key_spki, paired_at, revocation_epoch)
                       VALUES (?, ?, 'android', 'paired', ?, ?, ?, 0)""",
                    (device_id, payload["deviceName"], key_id, spki, now),
                )
                conn.execute(
                    """INSERT INTO companion_credential_sessions
                       (session_id, token_family_id, device_id, key_id,
                        access_token_hash, refresh_token_hash,
                        access_expires_at, refresh_expires_at, audience,
                        scopes_json, revocation_epoch)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'companion-api', ?, 0)""",
                    (
                        session_id,
                        token_family_id,
                        device_id,
                        key_id,
                        hashlib.sha256(access_token.encode("ascii")).digest(),
                        hashlib.sha256(refresh_token.encode("ascii")).digest(),
                        now + ACCESS_TOKEN_TTL_SECONDS,
                        now + REFRESH_TOKEN_TTL_SECONDS,
                        json.dumps([BOOTSTRAP_SCOPE], separators=(",", ":")),
                    ),
                )
                self._audit(
                    conn,
                    actor=None,
                    device_id=device_id,
                    action="pairing.invitation.redeem",
                    outcome="success",
                )
                if durable:
                    self._store_operation_result(
                        conn,
                        idempotency_id=idempotency_id,
                        operation=operation,
                        request_fingerprint=request_fingerprint,
                        metadata={
                            "deviceId": device_id,
                            "deviceName": payload["deviceName"],
                            "keyId": key_id,
                            "pairedAt": _timestamp(now),
                            "sessionId": session_id,
                            "accessExpiresAt": _timestamp(
                                now + ACCESS_TOKEN_TTL_SECONDS
                            ),
                            "refreshExpiresAt": _timestamp(
                                now + REFRESH_TOKEN_TTL_SECONDS
                            ),
                        },
                        now=now,
                    )
        except PairingError as exc:
            self._audit_failure("pairing.invitation.redeem", exc.code)
            raise

        device = {
            "id": device_id,
            "name": payload["deviceName"],
            "platform": "android",
            "status": "paired",
            "keyId": key_id,
            "pairedAt": _timestamp(now),
            "revocationEpoch": 0,
        }
        credentials = {
            "tokenType": "DPoP",
            "accessToken": access_token,
            "accessExpiresAt": _timestamp(now + ACCESS_TOKEN_TTL_SECONDS),
            "refreshToken": refresh_token,
            "refreshExpiresAt": _timestamp(now + REFRESH_TOKEN_TTL_SECONDS),
            "deviceId": device_id,
            "keyId": key_id,
            "sessionId": session_id,
            "revocationEpoch": 0,
        }
        return PairingResult(device=device, credentials=credentials)

    @staticmethod
    def _decode_dpop_json(segment: str) -> dict[str, Any]:
        raw = _decode_base64url(segment, error="proof_invalid")
        try:
            value = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_names
            )
        except (UnicodeError, json.JSONDecodeError, _DuplicateName, TypeError) as exc:
            raise PairingError("proof_invalid") from exc
        if not isinstance(value, dict):
            raise PairingError("proof_invalid")
        return value

    @staticmethod
    def _dpop_public_key(jwk: Any) -> tuple[bytes, ec.EllipticCurvePublicKey]:
        if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x", "y"}:
            raise PairingError("proof_invalid")
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise PairingError("proof_invalid")
        x = _decode_base64url(jwk.get("x"), error="proof_invalid")
        y = _decode_base64url(jwk.get("y"), error="proof_invalid")
        if len(x) != 32 or len(y) != 32:
            raise PairingError("proof_invalid")
        try:
            key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
        except ValueError as exc:
            raise PairingError("proof_invalid") from exc
        spki = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return spki, key

    def _verify_dpop_binding(
        self,
        *,
        bound_token: str,
        dpop_proof: Any,
        method: str,
        htu: str,
    ) -> tuple[bytes, str, float]:
        """Verify RFC 9449 proof syntax/signature/claims for one token value."""
        if not isinstance(bound_token, str) or not bound_token.isascii():
            raise PairingError("invalid_token")
        if not isinstance(dpop_proof, str) or not dpop_proof:
            raise PairingError("proof_required")
        parts = dpop_proof.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            raise PairingError("proof_invalid")
        header = self._decode_dpop_json(parts[0])
        claims = self._decode_dpop_json(parts[1])
        if (
            header.get("typ") != "dpop+jwt"
            or header.get("alg") != "ES256"
            or "jwk" not in header
        ):
            raise PairingError("proof_invalid")
        spki, public_key = self._dpop_public_key(header["jwk"])
        signature = _decode_base64url(parts[2], error="proof_invalid")
        if len(signature) != 64:
            raise PairingError("proof_invalid")
        der_signature = encode_dss_signature(
            int.from_bytes(signature[:32], "big"),
            int.from_bytes(signature[32:], "big"),
        )
        try:
            public_key.verify(
                der_signature,
                f"{parts[0]}.{parts[1]}".encode("ascii"),
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature as exc:
            raise PairingError("proof_invalid") from exc

        if not {"jti", "htm", "htu", "iat", "ath"}.issubset(claims):
            raise PairingError("proof_invalid")
        jti = claims["jti"]
        iat = claims["iat"]
        now = self.clock()
        if (
            not isinstance(jti, str)
            or not 1 <= len(jti) <= 200
            or isinstance(iat, bool)
            or not isinstance(iat, int)
            or iat < now - DPOP_MAX_AGE_SECONDS
            or iat > now + DPOP_FUTURE_SKEW_SECONDS
            or claims["htm"] != method.upper()
            or claims["htu"] != htu
        ):
            raise PairingError("proof_invalid")
        expected_ath = _encode_base64url(
            hashlib.sha256(bound_token.encode("ascii")).digest()
        )
        if not isinstance(claims["ath"], str) or not hmac.compare_digest(
            claims["ath"], expected_ath
        ):
            raise PairingError("proof_invalid")
        return spki, jti, now

    def authenticate_access(
        self,
        *,
        access_token: Any,
        dpop_proof: Any,
        method: str,
        htu: str,
        required_scope: str,
    ) -> DevicePrincipal:
        """Authenticate one scoped RFC 9449 DPoP request and cache its JTI."""
        try:
            if not isinstance(access_token, str) or not access_token.isascii():
                raise PairingError("invalid_token")
            if not isinstance(dpop_proof, str) or not dpop_proof:
                raise PairingError("proof_required")
            parts = dpop_proof.split(".")
            if len(parts) != 3 or any(not part for part in parts):
                raise PairingError("proof_invalid")
            header = self._decode_dpop_json(parts[0])
            claims = self._decode_dpop_json(parts[1])
            if (
                header.get("typ") != "dpop+jwt"
                or header.get("alg") != "ES256"
                or "jwk" not in header
            ):
                raise PairingError("proof_invalid")
            spki, public_key = self._dpop_public_key(header["jwk"])
            signature = _decode_base64url(parts[2], error="proof_invalid")
            if len(signature) != 64:
                raise PairingError("proof_invalid")
            der_signature = encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            try:
                public_key.verify(
                    der_signature,
                    f"{parts[0]}.{parts[1]}".encode("ascii"),
                    ec.ECDSA(hashes.SHA256()),
                )
            except InvalidSignature as exc:
                raise PairingError("proof_invalid") from exc

            required_claims = {"jti", "htm", "htu", "iat", "ath"}
            if not required_claims.issubset(claims):
                raise PairingError("proof_invalid")
            jti = claims["jti"]
            iat = claims["iat"]
            now = self.clock()
            if (
                not isinstance(jti, str)
                or not 1 <= len(jti) <= 200
                or isinstance(iat, bool)
                or not isinstance(iat, int)
                or iat < now - DPOP_MAX_AGE_SECONDS
                or iat > now + DPOP_FUTURE_SKEW_SECONDS
                or claims["htm"] != method.upper()
                or claims["htu"] != htu
            ):
                raise PairingError("proof_invalid")
            expected_ath = _encode_base64url(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            if not isinstance(claims["ath"], str) or not hmac.compare_digest(
                claims["ath"], expected_ath
            ):
                raise PairingError("proof_invalid")

            token_hash = hashlib.sha256(access_token.encode("ascii")).digest()
            with self._transaction(immediate=True) as conn:
                conn.execute(
                    "DELETE FROM companion_dpop_replay WHERE expires_at <= ?", (now,)
                )
                row = conn.execute(
                    """SELECT s.session_id, s.device_id, s.key_id,
                              s.access_expires_at, s.refresh_expires_at,
                              s.audience, s.scopes_json,
                              s.revocation_epoch AS session_epoch,
                              s.revoked_at AS session_revoked_at,
                              d.device_name, d.platform, d.status,
                              d.public_key_spki, d.paired_at, d.revoked_at,
                              d.revocation_epoch AS device_epoch
                       FROM companion_credential_sessions s
                       JOIN companion_devices d ON d.device_id = s.device_id
                       WHERE s.access_token_hash = ?""",
                    (token_hash,),
                ).fetchone()
                if row is None:
                    raise PairingError("invalid_token")
                if row["session_revoked_at"] is not None:
                    raise PairingError("session_revoked")
                if row["status"] == "revoked" or row["revoked_at"] is not None:
                    raise PairingError("device_revoked")
                if (
                    now >= float(row["access_expires_at"])
                    or row["audience"] != "companion-api"
                    or int(row["session_epoch"]) != int(row["device_epoch"])
                ):
                    raise PairingError("invalid_token")
                if row["public_key_spki"] != spki or row["key_id"] != derive_key_id(
                    spki
                ):
                    raise PairingError("proof_invalid")
                try:
                    scopes = tuple(json.loads(row["scopes_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise PairingError("invalid_token") from exc
                if required_scope not in scopes:
                    raise PairingError("forbidden")
                try:
                    conn.execute(
                        """INSERT INTO companion_dpop_replay
                           (session_id, jti, expires_at) VALUES (?, ?, ?)""",
                        (row["session_id"], jti, now + DPOP_MAX_AGE_SECONDS),
                    )
                except sqlite3.IntegrityError as exc:
                    raise PairingError("replay_detected") from exc
                self._audit(
                    conn,
                    actor=row["device_id"],
                    device_id=row["device_id"],
                    action="device.access.authenticate",
                    outcome="success",
                )
                device = {
                    "id": row["device_id"],
                    "name": row["device_name"],
                    "platform": row["platform"],
                    "status": row["status"],
                    "keyId": row["key_id"],
                    "pairedAt": _timestamp(row["paired_at"]),
                    "revocationEpoch": int(row["device_epoch"]),
                }
                principal = DevicePrincipal(
                    device_id=row["device_id"],
                    session_id=row["session_id"],
                    key_id=row["key_id"],
                    scopes=scopes,
                    device=device,
                    access_expires_at=_timestamp(row["access_expires_at"]),
                    refresh_expires_at=_timestamp(row["refresh_expires_at"]),
                    revocation_epoch=int(row["device_epoch"]),
                )
        except PairingError as exc:
            self._audit_failure("device.access.authenticate", exc.code)
            raise
        return principal

    def refresh_credentials(
        self,
        *,
        refresh_token: str,
        dpop_proof: Any,
        method: str,
        htu: str,
        idempotency_key: str,
        request_fingerprint: str,
        token_derivation_key: bytes,
    ) -> dict[str, Any]:
        """Atomically rotate one DPoP-bound refresh/access credential pair."""
        try:
            if (
                not isinstance(idempotency_key, str)
                or not 8 <= len(idempotency_key) <= 128
                or not idempotency_key.isascii()
                or not isinstance(request_fingerprint, str)
                or len(request_fingerprint) != 64
                or not isinstance(token_derivation_key, bytes)
                or len(token_derivation_key) < 16
            ):
                raise PairingError("invalid_request")
            spki, jti, now = self._verify_dpop_binding(
                bound_token=refresh_token,
                dpop_proof=dpop_proof,
                method=method,
                htu=htu,
            )
            token_hash = hashlib.sha256(refresh_token.encode("ascii")).digest()
            reused = False
            with self._transaction(immediate=True) as conn:
                conn.execute(
                    "DELETE FROM companion_dpop_replay WHERE expires_at <= ?", (now,)
                )
                conn.execute(
                    "DELETE FROM companion_refresh_idempotency WHERE expires_at <= ?",
                    (now,),
                )
                row = conn.execute(
                    """SELECT s.session_id, s.token_family_id, s.device_id,
                              s.key_id, s.refresh_expires_at, s.audience,
                              s.scopes_json, s.revocation_epoch AS session_epoch,
                              s.revoked_at AS session_revoked_at,
                              d.status, d.public_key_spki, d.revoked_at,
                              d.revocation_epoch AS device_epoch
                       FROM companion_credential_sessions s
                       JOIN companion_devices d ON d.device_id = s.device_id
                       WHERE s.refresh_token_hash = ?""",
                    (token_hash,),
                ).fetchone()
                consumed = row is None
                if consumed:
                    row = conn.execute(
                        """SELECT s.session_id, s.token_family_id, s.device_id,
                                  s.key_id, s.refresh_expires_at, s.audience,
                                  s.scopes_json,
                                  s.revocation_epoch AS session_epoch,
                                  s.revoked_at AS session_revoked_at,
                                  d.status, d.public_key_spki, d.revoked_at,
                                  d.revocation_epoch AS device_epoch
                           FROM companion_consumed_refresh_tokens c
                           JOIN companion_credential_sessions s
                             ON s.token_family_id = c.token_family_id
                           JOIN companion_devices d
                             ON d.device_id = s.device_id
                           WHERE c.token_hash = ?""",
                        (token_hash,),
                    ).fetchone()
                if row is None:
                    raise PairingError("invalid_token")
                if row["public_key_spki"] != spki or row["key_id"] != derive_key_id(
                    spki
                ):
                    raise PairingError("proof_invalid")

                idempotency_id = _refresh_idempotency_id(
                    token_derivation_key,
                    row["session_id"],
                    row["token_family_id"],
                    idempotency_key,
                )
                cached = conn.execute(
                    """SELECT request_fingerprint, session_id, device_id,
                              key_id, access_expires_at, refresh_expires_at,
                              revocation_epoch
                       FROM companion_refresh_idempotency
                       WHERE idempotency_id = ?""",
                    (idempotency_id,),
                ).fetchone()
                if cached is not None:
                    if not hmac.compare_digest(
                        cached["request_fingerprint"], request_fingerprint
                    ):
                        raise PairingError("conflict")
                    if row["session_revoked_at"] is not None:
                        raise PairingError("session_revoked")
                    if row["status"] == "revoked" or row["revoked_at"] is not None:
                        raise PairingError("device_revoked")
                    if (
                        cached["session_id"] != row["session_id"]
                        or cached["device_id"] != row["device_id"]
                        or cached["key_id"] != derive_key_id(spki)
                        or int(row["session_epoch"]) != int(row["device_epoch"])
                        or int(cached["revocation_epoch"]) != int(row["device_epoch"])
                    ):
                        raise PairingError("proof_invalid")
                    cached_access, cached_refresh = _derive_refresh_tokens(
                        token_derivation_key,
                        cached["session_id"],
                        idempotency_key,
                    )
                    return {
                        "tokenType": "DPoP",
                        "accessToken": cached_access,
                        "accessExpiresAt": _timestamp(cached["access_expires_at"]),
                        "refreshToken": cached_refresh,
                        "refreshExpiresAt": _timestamp(cached["refresh_expires_at"]),
                        "deviceId": cached["device_id"],
                        "keyId": cached["key_id"],
                        "sessionId": cached["session_id"],
                        "revocationEpoch": int(cached["revocation_epoch"]),
                    }
                if consumed:
                    new_access_token, new_refresh_token = _derive_refresh_tokens(
                        token_derivation_key, row["session_id"], idempotency_key
                    )
                    try:
                        conn.execute(
                            """INSERT INTO companion_dpop_replay
                               (session_id, jti, expires_at) VALUES (?, ?, ?)""",
                            (row["session_id"], jti, now + DPOP_MAX_AGE_SECONDS),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise PairingError("replay_detected") from exc
                    conn.execute(
                        """UPDATE companion_credential_sessions
                           SET revoked_at = ? WHERE token_family_id = ?""",
                        (now, row["token_family_id"]),
                    )
                    self._audit(
                        conn,
                        actor=row["device_id"],
                        device_id=row["device_id"],
                        action="device.credentials.refresh",
                        outcome="refresh_reuse_detected",
                    )
                    reused = True
                else:
                    if row["session_revoked_at"] is not None:
                        raise PairingError("session_revoked")
                    if row["status"] == "revoked" or row["revoked_at"] is not None:
                        raise PairingError("device_revoked")
                    if (
                        now >= float(row["refresh_expires_at"])
                        or row["audience"] != "companion-api"
                        or int(row["session_epoch"]) != int(row["device_epoch"])
                    ):
                        raise PairingError("invalid_token")
                    if row["public_key_spki"] != spki or row["key_id"] != derive_key_id(
                        spki
                    ):
                        raise PairingError("proof_invalid")
                    new_access_token, new_refresh_token = _derive_refresh_tokens(
                        token_derivation_key, row["session_id"], idempotency_key
                    )
                    try:
                        conn.execute(
                            """INSERT INTO companion_dpop_replay
                               (session_id, jti, expires_at) VALUES (?, ?, ?)""",
                            (row["session_id"], jti, now + DPOP_MAX_AGE_SECONDS),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise PairingError("replay_detected") from exc
                    conn.execute(
                        """INSERT INTO companion_consumed_refresh_tokens
                           (token_hash, token_family_id, consumed_at)
                           VALUES (?, ?, ?)""",
                        (token_hash, row["token_family_id"], now),
                    )
                    updated = conn.execute(
                        """UPDATE companion_credential_sessions
                           SET access_token_hash = ?, refresh_token_hash = ?,
                               access_expires_at = ?, refresh_expires_at = ?
                           WHERE session_id = ? AND refresh_token_hash = ?
                             AND revoked_at IS NULL""",
                        (
                            hashlib.sha256(new_access_token.encode("ascii")).digest(),
                            hashlib.sha256(new_refresh_token.encode("ascii")).digest(),
                            now + ACCESS_TOKEN_TTL_SECONDS,
                            now + REFRESH_TOKEN_TTL_SECONDS,
                            row["session_id"],
                            token_hash,
                        ),
                    ).rowcount
                    if updated != 1:
                        raise PairingError("conflict")
                    conn.execute(
                        """INSERT INTO companion_refresh_idempotency
                           (idempotency_id, request_fingerprint, session_id,
                            device_id, key_id, access_expires_at,
                            refresh_expires_at, revocation_epoch, expires_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            idempotency_id,
                            request_fingerprint,
                            row["session_id"],
                            row["device_id"],
                            row["key_id"],
                            now + ACCESS_TOKEN_TTL_SECONDS,
                            now + REFRESH_TOKEN_TTL_SECONDS,
                            int(row["device_epoch"]),
                            now + MAX_INVITATION_TTL_SECONDS,
                        ),
                    )
                    self._audit(
                        conn,
                        actor=row["device_id"],
                        device_id=row["device_id"],
                        action="device.credentials.refresh",
                        outcome="success",
                    )
            if reused:
                raise PairingError("refresh_reuse_detected", audited=True)
        except PairingError as exc:
            if not exc.audited:
                self._audit_failure("device.credentials.refresh", exc.code)
            raise

        return {
            "tokenType": "DPoP",
            "accessToken": new_access_token,
            "accessExpiresAt": _timestamp(now + ACCESS_TOKEN_TTL_SECONDS),
            "refreshToken": new_refresh_token,
            "refreshExpiresAt": _timestamp(now + REFRESH_TOKEN_TTL_SECONDS),
            "deviceId": row["device_id"],
            "keyId": row["key_id"],
            "sessionId": row["session_id"],
            "revocationEpoch": int(row["device_epoch"]),
        }

    def rotate_device_key(
        self,
        *,
        access_token: str,
        dpop_proof: Any,
        method: str,
        htu: str,
        device_id: str,
        payload: dict[str, Any],
        idempotency_key: str,
        request_fingerprint: str,
        token_derivation_key: bytes,
    ) -> dict[str, Any]:
        """Atomically prove a new key, revoke the old family, and issue credentials."""
        try:
            if (
                not isinstance(idempotency_key, str)
                or not 8 <= len(idempotency_key) <= 128
                or not idempotency_key.isascii()
                or not isinstance(request_fingerprint, str)
                or len(request_fingerprint) != 64
                or not isinstance(token_derivation_key, bytes)
                or len(token_derivation_key) < 16
            ):
                raise PairingError("invalid_request")
            device_id = _validate_public_id(device_id)
            old_spki, jti, now = self._verify_dpop_binding(
                bound_token=access_token,
                dpop_proof=dpop_proof,
                method=method,
                htu=htu,
            )
            current_key_id, new_spki, new_key_id, nonce_hash = _rotation_proof_inputs(
                payload, device_id=device_id, now=now
            )
            access_hash = hashlib.sha256(access_token.encode("ascii")).digest()
            with self._transaction(immediate=True) as conn:
                conn.execute(
                    "DELETE FROM companion_dpop_replay WHERE expires_at <= ?", (now,)
                )
                conn.execute(
                    "DELETE FROM companion_rotation_nonces WHERE expires_at <= ?",
                    (now,),
                )
                conn.execute(
                    "DELETE FROM companion_rotation_idempotency WHERE expires_at <= ?",
                    (now,),
                )
                row = conn.execute(
                    """SELECT s.session_id, s.token_family_id, s.device_id,
                              s.key_id AS session_key_id, s.access_expires_at,
                              s.scopes_json, s.audience,
                              s.revocation_epoch AS session_epoch,
                              s.revoked_at AS session_revoked_at,
                              d.device_name, d.platform, d.status,
                              d.key_id AS device_key_id, d.public_key_spki,
                              d.paired_at, d.revoked_at AS device_revoked_at,
                              d.revocation_epoch AS device_epoch
                       FROM companion_credential_sessions s
                       JOIN companion_devices d ON d.device_id = s.device_id
                       WHERE s.access_token_hash = ?""",
                    (access_hash,),
                ).fetchone()
                if row is None or row["device_id"] != device_id:
                    raise PairingError("invalid_token")
                idempotency_id = _rotation_idempotency_id(
                    token_derivation_key,
                    row["session_id"],
                    row["token_family_id"],
                    idempotency_key,
                )
                cached = conn.execute(
                    """SELECT request_fingerprint, old_session_id,
                              new_session_id, device_id, old_key_id,
                              old_public_key_spki, new_key_id,
                              access_expires_at, refresh_expires_at,
                              revocation_epoch, previous_key_revoked_at
                       FROM companion_rotation_idempotency
                       WHERE idempotency_id = ?""",
                    (idempotency_id,),
                ).fetchone()
                if cached is not None:
                    if not hmac.compare_digest(
                        cached["request_fingerprint"], request_fingerprint
                    ):
                        raise PairingError("conflict")
                    if (
                        cached["old_session_id"] != row["session_id"]
                        or cached["device_id"] != device_id
                        or cached["old_key_id"] != row["session_key_id"]
                        or cached["old_key_id"] != current_key_id
                        or not hmac.compare_digest(
                            cached["old_public_key_spki"], old_spki
                        )
                    ):
                        raise PairingError("proof_invalid")
                    state = conn.execute(
                        """SELECT s.revoked_at AS session_revoked_at,
                                  s.key_id AS session_key_id,
                                  s.revocation_epoch AS session_epoch,
                                  d.device_name, d.platform, d.status,
                                  d.key_id AS device_key_id, d.paired_at,
                                  d.revoked_at AS device_revoked_at,
                                  d.revocation_epoch AS device_epoch
                           FROM companion_credential_sessions s
                           JOIN companion_devices d ON d.device_id = s.device_id
                           WHERE s.session_id = ? AND s.device_id = ?""",
                        (cached["new_session_id"], cached["device_id"]),
                    ).fetchone()
                    if state is None:
                        raise PairingError("invalid_token")
                    if state["session_revoked_at"] is not None:
                        raise PairingError("session_revoked")
                    if (
                        state["status"] != "paired"
                        or state["device_revoked_at"] is not None
                    ):
                        raise PairingError("device_revoked")
                    if (
                        state["session_key_id"] != cached["new_key_id"]
                        or state["device_key_id"] != cached["new_key_id"]
                        or int(state["session_epoch"])
                        != int(cached["revocation_epoch"])
                        or int(state["device_epoch"]) != int(cached["revocation_epoch"])
                    ):
                        raise PairingError("invalid_token")
                    access_token_out, refresh_token_out = _derive_rotation_tokens(
                        token_derivation_key,
                        cached["new_session_id"],
                        idempotency_key,
                    )
                    return self._rotation_result(
                        device_id=cached["device_id"],
                        device_name=state["device_name"],
                        platform=state["platform"],
                        key_id=cached["new_key_id"],
                        paired_at=state["paired_at"],
                        epoch=int(cached["revocation_epoch"]),
                        session_id=cached["new_session_id"],
                        access_token=access_token_out,
                        refresh_token=refresh_token_out,
                        access_expires_at=float(cached["access_expires_at"]),
                        refresh_expires_at=float(cached["refresh_expires_at"]),
                        previous_key_revoked_at=float(
                            cached["previous_key_revoked_at"]
                        ),
                    )

                if row["session_revoked_at"] is not None:
                    raise PairingError("session_revoked")
                if row["status"] != "paired" or row["device_revoked_at"] is not None:
                    raise PairingError("device_revoked")
                if (
                    now >= float(row["access_expires_at"])
                    or row["audience"] != "companion-api"
                    or not hmac.compare_digest(row["public_key_spki"], old_spki)
                    or row["session_key_id"] != current_key_id
                    or row["device_key_id"] != current_key_id
                    or int(row["session_epoch"]) != int(row["device_epoch"])
                ):
                    raise PairingError("invalid_token")
                try:
                    conn.execute(
                        """INSERT INTO companion_dpop_replay
                           (session_id, jti, expires_at) VALUES (?, ?, ?)""",
                        (row["session_id"], jti, now + DPOP_MAX_AGE_SECONDS),
                    )
                    conn.execute(
                        """INSERT INTO companion_rotation_nonces
                           (nonce_hash, expires_at) VALUES (?, ?)""",
                        (nonce_hash, now + MAX_INVITATION_TTL_SECONDS),
                    )
                except sqlite3.IntegrityError as exc:
                    raise PairingError("replay_detected") from exc

                new_epoch = int(row["device_epoch"]) + 1
                new_session_id = "session_" + uuid.uuid4().hex
                new_family_id = "family_" + uuid.uuid4().hex
                access_token_out, refresh_token_out = _derive_rotation_tokens(
                    token_derivation_key, new_session_id, idempotency_key
                )
                access_expires_at = now + ACCESS_TOKEN_TTL_SECONDS
                refresh_expires_at = now + REFRESH_TOKEN_TTL_SECONDS
                try:
                    updated = conn.execute(
                        """UPDATE companion_devices
                           SET key_id = ?, public_key_spki = ?, revocation_epoch = ?
                           WHERE device_id = ? AND status = 'paired'
                             AND revoked_at IS NULL AND key_id = ?""",
                        (new_key_id, new_spki, new_epoch, device_id, current_key_id),
                    ).rowcount
                except sqlite3.IntegrityError as exc:
                    raise PairingError("invalid_key") from exc
                if updated != 1:
                    raise PairingError("conflict")
                conn.execute(
                    """UPDATE companion_credential_sessions SET revoked_at = ?
                       WHERE device_id = ? AND revoked_at IS NULL""",
                    (now, device_id),
                )
                conn.execute(
                    """INSERT INTO companion_credential_sessions
                       (session_id, token_family_id, device_id, key_id,
                        access_token_hash, refresh_token_hash,
                        access_expires_at, refresh_expires_at, audience,
                        scopes_json, revocation_epoch)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'companion-api', ?, ?)""",
                    (
                        new_session_id,
                        new_family_id,
                        device_id,
                        new_key_id,
                        hashlib.sha256(access_token_out.encode("ascii")).digest(),
                        hashlib.sha256(refresh_token_out.encode("ascii")).digest(),
                        access_expires_at,
                        refresh_expires_at,
                        row["scopes_json"],
                        new_epoch,
                    ),
                )
                conn.execute(
                    """INSERT INTO companion_rotation_idempotency
                       (idempotency_id, request_fingerprint, old_session_id,
                        new_session_id, device_id, old_key_id,
                        old_public_key_spki, new_key_id,
                        access_expires_at, refresh_expires_at, revocation_epoch,
                        previous_key_revoked_at, expires_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        idempotency_id,
                        request_fingerprint,
                        row["session_id"],
                        new_session_id,
                        device_id,
                        row["session_key_id"],
                        old_spki,
                        new_key_id,
                        access_expires_at,
                        refresh_expires_at,
                        new_epoch,
                        now,
                        now + MAX_INVITATION_TTL_SECONDS,
                    ),
                )
                self._audit(
                    conn,
                    actor=device_id,
                    device_id=device_id,
                    action="device.key.rotate",
                    outcome="success",
                )
            return self._rotation_result(
                device_id=device_id,
                device_name=row["device_name"],
                platform=row["platform"],
                key_id=new_key_id,
                paired_at=row["paired_at"],
                epoch=new_epoch,
                session_id=new_session_id,
                access_token=access_token_out,
                refresh_token=refresh_token_out,
                access_expires_at=access_expires_at,
                refresh_expires_at=refresh_expires_at,
                previous_key_revoked_at=now,
            )
        except PairingError as exc:
            if not exc.audited:
                self._audit_failure("device.key.rotate", exc.code)
            raise

    @staticmethod
    def _rotation_result(
        *,
        device_id: str,
        device_name: str,
        platform: str,
        key_id: str,
        paired_at: float,
        epoch: int,
        session_id: str,
        access_token: str,
        refresh_token: str,
        access_expires_at: float,
        refresh_expires_at: float,
        previous_key_revoked_at: float,
    ) -> dict[str, Any]:
        return {
            "device": {
                "id": device_id,
                "name": device_name,
                "platform": platform,
                "status": "paired",
                "keyId": key_id,
                "pairedAt": _timestamp(paired_at),
                "revocationEpoch": epoch,
            },
            "credentials": {
                "tokenType": "DPoP",
                "accessToken": access_token,
                "accessExpiresAt": _timestamp(access_expires_at),
                "refreshToken": refresh_token,
                "refreshExpiresAt": _timestamp(refresh_expires_at),
                "deviceId": device_id,
                "keyId": key_id,
                "sessionId": session_id,
                "revocationEpoch": epoch,
            },
            "previousKeyRevokedAt": _timestamp(previous_key_revoked_at),
        }

    def list_devices(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        cursor_key: bytes,
    ) -> dict[str, Any]:
        after: tuple[float, str] | None = None
        if cursor is not None:
            values = _decode_page_cursor("devices", cursor, cursor_key)
            if (
                isinstance(values[0], bool)
                or not isinstance(values[0], (int, float))
                or not isinstance(values[1], str)
            ):
                raise PairingError("invalid_request")
            after = (float(values[0]), values[1])
        conn = self._connect()
        try:
            query = """SELECT device_id, device_name, platform, status, key_id,
                              paired_at, revoked_at, revocation_epoch
                       FROM companion_devices"""
            params: list[Any] = []
            if after is not None:
                query += " WHERE paired_at > ? OR (paired_at = ? AND device_id > ?)"
                params.extend((after[0], after[0], after[1]))
            query += " ORDER BY paired_at, device_id LIMIT ?"
            params.append(limit + 1)
            rows = conn.execute(query, params).fetchall()
            has_more = len(rows) > limit
            page_rows = rows[:limit]
            items = []
            for row in page_rows:
                device = {
                    "id": row["device_id"],
                    "name": row["device_name"],
                    "platform": row["platform"],
                    "status": row["status"],
                    "keyId": row["key_id"],
                    "pairedAt": _timestamp(row["paired_at"]),
                    "revocationEpoch": int(row["revocation_epoch"]),
                }
                if row["revoked_at"] is not None:
                    device["revokedAt"] = _timestamp(row["revoked_at"])
                items.append(device)
            result: dict[str, Any] = {"items": items, "hasMore": has_more}
            if has_more:
                last = page_rows[-1]
                result["nextCursor"] = _encode_page_cursor(
                    "devices",
                    [float(last["paired_at"]), last["device_id"]],
                    cursor_key,
                )
            return result
        finally:
            conn.close()

    def list_sessions(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        cursor_key: bytes,
    ) -> dict[str, Any]:
        after: tuple[float, str] | None = None
        if cursor is not None:
            values = _decode_page_cursor("sessions", cursor, cursor_key)
            if (
                isinstance(values[0], bool)
                or not isinstance(values[0], (int, float))
                or not isinstance(values[1], str)
            ):
                raise PairingError("invalid_request")
            after = (float(values[0]), values[1])
        conn = self._connect()
        try:
            sessions_exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions'"
            ).fetchone()
            if sessions_exists is None:
                return {"items": [], "hasMore": False}
            updated_sql = "COALESCE(last_activity_at, ended_at, started_at)"
            query = f"""SELECT id, COALESCE(title, display_name, '') AS title,
                                started_at, {updated_sql} AS updated_at
                         FROM sessions
                         WHERE LOWER(source) != 'cron'"""
            params: list[Any] = []
            if after is not None:
                query += f" AND ({updated_sql} > ? OR ({updated_sql} = ? AND id > ?))"
                params.extend((after[0], after[0], after[1]))
            query += f" ORDER BY {updated_sql}, id LIMIT ?"
            params.append(limit + 1)
            rows = conn.execute(query, params).fetchall()
            has_more = len(rows) > limit
            page_rows = rows[:limit]
            result: dict[str, Any] = {
                "items": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "createdAt": _timestamp(row["started_at"]),
                        "updatedAt": _timestamp(row["updated_at"]),
                    }
                    for row in page_rows
                ],
                "hasMore": has_more,
            }
            if has_more:
                last = page_rows[-1]
                result["nextCursor"] = _encode_page_cursor(
                    "sessions",
                    [float(last["updated_at"]), last["id"]],
                    cursor_key,
                )
            return result
        finally:
            conn.close()

    def principal_active(self, principal: DevicePrincipal) -> bool:
        """Revalidate durable state for a long-lived authenticated connection."""
        conn = self._connect()
        try:
            row = conn.execute(
                """SELECT s.revoked_at AS session_revoked_at,
                          s.revocation_epoch AS session_epoch,
                          d.status, d.revoked_at AS device_revoked_at,
                          d.revocation_epoch AS device_epoch, d.key_id
                   FROM companion_credential_sessions s
                   JOIN companion_devices d ON d.device_id = s.device_id
                   WHERE s.session_id = ? AND s.device_id = ?""",
                (principal.session_id, principal.device_id),
            ).fetchone()
            return bool(
                row is not None
                and row["session_revoked_at"] is None
                and row["device_revoked_at"] is None
                and row["status"] == "paired"
                and row["key_id"] == principal.key_id
                and int(row["session_epoch"]) == principal.revocation_epoch
                and int(row["device_epoch"]) == principal.revocation_epoch
            )
        finally:
            conn.close()

    @staticmethod
    def _validate_revocation_reason(reason: Any) -> str:
        if reason not in REVOCATION_REASONS:
            raise PairingError("invalid_request")
        return reason

    def revoke_session(
        self,
        actor: str,
        session_id: Any,
        reason: Any,
        *,
        operation: str | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
        token_derivation_key: bytes | None = None,
    ) -> dict[str, Any]:
        session_id = _validate_public_id(session_id)
        self._validate_revocation_reason(reason)
        now = self.clock()
        durable = operation is not None
        if durable:
            idempotency_key, request_fingerprint, token_derivation_key = (
                self._validate_idempotency_inputs(
                    idempotency_key, request_fingerprint, token_derivation_key
                )
            )
            idempotency_id = _operation_idempotency_id(
                token_derivation_key,
                operation,
                f"{actor}\0{session_id}",
                idempotency_key,
            )
        with self._transaction(immediate=True) as conn:
            if durable:
                cached = self._load_operation_result(
                    conn,
                    idempotency_id=idempotency_id,
                    operation=operation,
                    request_fingerprint=request_fingerprint,
                    now=now,
                )
                if cached is not None:
                    return cached
            row = conn.execute(
                """SELECT device_id, revoked_at
                   FROM companion_credential_sessions WHERE session_id = ?""",
                (session_id,),
            ).fetchone()
            if row is None:
                raise PairingError("not_found")
            revoked_at = (
                float(row["revoked_at"]) if row["revoked_at"] is not None else now
            )
            conn.execute(
                """UPDATE companion_credential_sessions SET revoked_at = ?
                   WHERE session_id = ? AND revoked_at IS NULL""",
                (revoked_at, session_id),
            )
            result = {
                "sessionId": session_id,
                "deviceId": row["device_id"],
                "status": "revoked",
                "revokedAt": _timestamp(revoked_at),
            }
            self._audit(
                conn,
                actor=actor,
                device_id=row["device_id"],
                action="session.revoke",
                outcome="success",
            )
            if durable:
                self._store_operation_result(
                    conn,
                    idempotency_id=idempotency_id,
                    operation=operation,
                    request_fingerprint=request_fingerprint,
                    metadata=result,
                    now=now,
                )
        return result

    def revoke_device(
        self,
        actor: str,
        device_id: Any,
        reason: Any,
        *,
        operation: str | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
        token_derivation_key: bytes | None = None,
    ) -> dict[str, Any]:
        device_id = _validate_public_id(device_id)
        self._validate_revocation_reason(reason)
        now = self.clock()
        durable = operation is not None
        if durable:
            idempotency_key, request_fingerprint, token_derivation_key = (
                self._validate_idempotency_inputs(
                    idempotency_key, request_fingerprint, token_derivation_key
                )
            )
            idempotency_id = _operation_idempotency_id(
                token_derivation_key,
                operation,
                f"{actor}\0{device_id}",
                idempotency_key,
            )
        with self._transaction(immediate=True) as conn:
            if durable:
                cached = self._load_operation_result(
                    conn,
                    idempotency_id=idempotency_id,
                    operation=operation,
                    request_fingerprint=request_fingerprint,
                    now=now,
                )
                if cached is not None:
                    return cached
            row = conn.execute(
                """SELECT status, revoked_at, revocation_epoch
                   FROM companion_devices WHERE device_id = ?""",
                (device_id,),
            ).fetchone()
            if row is None:
                raise PairingError("not_found")
            if row["revoked_at"] is None:
                revoked_at = now
                epoch = int(row["revocation_epoch"]) + 1
                conn.execute(
                    """UPDATE companion_devices
                       SET status = 'revoked', revoked_at = ?, revocation_epoch = ?
                       WHERE device_id = ? AND revoked_at IS NULL""",
                    (revoked_at, epoch, device_id),
                )
            else:
                revoked_at = float(row["revoked_at"])
                epoch = int(row["revocation_epoch"])
            conn.execute(
                """UPDATE companion_credential_sessions SET revoked_at = ?
                   WHERE device_id = ? AND revoked_at IS NULL""",
                (revoked_at, device_id),
            )
            result = {
                "deviceId": device_id,
                "status": "revoked",
                "revokedAt": _timestamp(revoked_at),
                "revocationEpoch": epoch,
                "effects": {
                    "restDenied": True,
                    "refreshDenied": True,
                    "webSocketsClosed": True,
                    "pendingDeliveryCanceled": True,
                    "localEraseRequired": True,
                },
            }
            self._audit(
                conn,
                actor=actor,
                device_id=device_id,
                action="device.revoke",
                outcome="success",
            )
            if durable:
                self._store_operation_result(
                    conn,
                    idempotency_id=idempotency_id,
                    operation=operation,
                    request_fingerprint=request_fingerprint,
                    metadata=result,
                    now=now,
                )
        return result

    def bootstrap(self, principal: DevicePrincipal) -> dict[str, Any]:
        """Return truthful bootstrap metadata for the currently empty slice."""
        updated_at = principal.device["pairedAt"]
        return {
            "contractVersion": CONTRACT_VERSION,
            "protocolRevision": PROTOCOL_REVISION,
            "device": principal.device,
            "authentication": {
                "tokenType": "DPoP",
                "proofAlgorithm": "ES256",
                "keyId": principal.key_id,
                "accessExpiresAt": principal.access_expires_at,
                "refreshExpiresAt": principal.refresh_expires_at,
                "revocationEpoch": principal.revocation_epoch,
            },
            "policy": {
                "deviceId": principal.device_id,
                "capabilities": [],
                "updatedAt": updated_at,
            },
            "capabilities": [],
            "eventCursor": "cursor_initial",
        }

    def audit_records(self) -> list[dict[str, Any]]:
        """Test/diagnostic helper; the schema intentionally has no secret columns."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT actor, device_id, action, outcome, scope,
                          policy_revision
                   FROM companion_audit ORDER BY id"""
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()
