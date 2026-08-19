"""Safe companion-v1 pairing invitation primitive.

This module deliberately owns no HTTP, persistence, or bearer authentication. A
thin adapter can provide authenticated creation and map ``PairingError.code``
to the contract's 400/409 responses. Invitation secrets remain in memory only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_TTL_SECONDS = 300
_BOOTSTRAP_TTL_SECONDS = 300


class PairingError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PairingInvitation:
    invitation_id: str
    secret: str
    uri: str
    expires_at: str


@dataclass(frozen=True)
class PairingResult:
    device_id: str
    access_token: str
    expires_at: str


class PairingInvitationStore:
    """In-memory invitation store with atomic consume and redacted audit events."""

    def __init__(self, *, ttl_seconds: int = MAX_TTL_SECONDS, require_tls: bool = True,
                 clock=time.time):
        self._ttl = min(max(1, int(ttl_seconds)), MAX_TTL_SECONDS)
        self._require_tls = require_tls
        self._clock = clock
        self._lock = threading.Lock()
        self._invitations: dict[str, dict[str, Any]] = {}
        self.audit_events: list[dict[str, Any]] = []

    @staticmethod
    def canonical_registration(invitation_id: str, registration: dict[str, Any]) -> bytes:
        """Canonical proof bytes bind invitation and all registration fields."""
        return json.dumps({"invitationId": invitation_id, "registration": registration},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def _check_tls(self, secure: bool) -> None:
        if self._require_tls and not secure:
            raise PairingError("tls_required")

    def _audit(self, actor: str | None, device: str | None, action: str, outcome: str) -> None:
        self.audit_events.append({"actor": actor, "device": device, "scope": "companion",
                                  "action": action, "outcome": outcome,
                                  "policy_revision": "companion-v1"})

    def create(self, actor: str, device_name: str, *, transport_secure: bool = True) -> PairingInvitation:
        self._check_tls(transport_secure)
        if not isinstance(device_name, str) or not 1 <= len(device_name) <= 100:
            raise PairingError("malformed")
        now = self._clock()
        invitation_id = "inv_" + uuid.uuid4().hex
        secret = secrets.token_urlsafe(32)  # 256 bits, never persisted/audited
        expires = datetime.fromtimestamp(now + self._ttl, timezone.utc).isoformat().replace("+00:00", "Z")
        with self._lock:
            self._invitations[invitation_id] = {"digest": hashlib.sha256(secret.encode()).digest(),
                                                 "expires": now + self._ttl, "used": False}
            self._audit(actor, None, "create", "success")
        return PairingInvitation(invitation_id, secret, f"hermes://pairing/{invitation_id}/{secret}", expires)

    def redeem(self, invitation_uri: str, registration: dict[str, Any], proof: str,
               *, transport_secure: bool = True) -> PairingResult:
        self._check_tls(transport_secure)
        try:
            scheme, _, rest = invitation_uri.partition("://")
            kind, invitation_id, secret = rest.split("/", 2)
            if scheme != "hermes" or kind != "pairing" or not invitation_id or not secret:
                raise ValueError
        except (ValueError, AttributeError):
            raise PairingError("malformed")
        if not isinstance(registration, dict) or not isinstance(proof, str):
            raise PairingError("malformed")
        try:
            public_key = base64.b64decode(registration["publicKey"], validate=True)
            if registration.get("keyAlgorithm") != "Ed25519" or len(public_key) != 32:
                raise ValueError
            signature = base64.b64decode(proof, validate=True)
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, self.canonical_registration(invitation_id, registration))
        except (KeyError, ValueError, TypeError, InvalidSignature):
            self._audit(None, None, "redeem", "proof_failed")
            raise PairingError("proof_failed")
        digest = hashlib.sha256(secret.encode()).digest()
        with self._lock:
            item = self._invitations.get(invitation_id)
            if not item or not hmac.compare_digest(item["digest"], digest):
                self._audit(None, None, "redeem", "malformed")
                raise PairingError("malformed")
            if self._clock() >= item["expires"]:
                self._audit(None, None, "redeem", "expired")
                raise PairingError("expired")
            if item["used"]:
                self._audit(None, None, "redeem", "reused")
                raise PairingError("reused")
            item["used"] = True
            device_id = "device_" + uuid.uuid4().hex
            expires = datetime.fromtimestamp(self._clock() + _BOOTSTRAP_TTL_SECONDS, timezone.utc).isoformat().replace("+00:00", "Z")
            token = secrets.token_urlsafe(32)
            self._audit(None, device_id, "redeem", "success")
            return PairingResult(device_id, token, expires)
