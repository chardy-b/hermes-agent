import base64
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.pairing_invitations import PairingInvitationStore, PairingError


def payload(invitation, private_key):
    registration = {"deviceName": "Pixel", "publicKey": base64.b64encode(private_key.public_key().public_bytes_raw()).decode(), "keyAlgorithm": "Ed25519"}
    canonical = PairingInvitationStore.canonical_registration(invitation.invitation_id, registration)
    return registration, base64.b64encode(private_key.sign(canonical)).decode()


def test_invitation_is_opaque_high_entropy_and_redeems_once():
    store = PairingInvitationStore()
    invitation = store.create("operator-1", "Pixel")
    assert invitation.uri.startswith("hermes://pairing/")
    assert len(invitation.secret) >= 22
    assert invitation.secret not in json.dumps(store.audit_events)
    key = Ed25519PrivateKey.generate()
    registration, proof = payload(invitation, key)
    result = store.redeem(invitation.uri, registration, proof)
    assert result.device_id.startswith("device_")
    assert result.access_token and result.expires_at
    with pytest.raises(PairingError, match="reused"):
        store.redeem(invitation.uri, registration, proof)


def test_invalid_proof_is_deterministic_and_does_not_consume_invitation():
    store = PairingInvitationStore()
    invitation = store.create("operator-1", "Pixel")
    key = Ed25519PrivateKey.generate()
    registration, _ = payload(invitation, key)
    with pytest.raises(PairingError, match="proof_failed"):
        store.redeem(invitation.uri, registration, base64.b64encode(b"bad").decode())
    assert store.redeem(invitation.uri, registration, payload(invitation, key)[1]).device_id


def test_single_use_is_atomic_under_concurrency():
    store = PairingInvitationStore()
    invitation = store.create("operator-1", "Pixel")
    key = Ed25519PrivateKey.generate()
    registration, proof = payload(invitation, key)
    def redeem():
        try:
            return store.redeem(invitation.uri, registration, proof)
        except PairingError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: redeem(), range(8)))
    assert sum(not isinstance(result, str) for result in results) == 1
    assert sum(result == "reused" for result in results) == 7


def test_audit_is_redacted_and_tls_boundary_is_explicit():
    store = PairingInvitationStore(require_tls=True)
    invitation = store.create("operator-1", "Pixel")
    assert store.audit_events[0] == {"actor": "operator-1", "device": None, "scope": "companion", "action": "create", "outcome": "success", "policy_revision": "companion-v1"}
    key = Ed25519PrivateKey.generate()
    registration, proof = payload(invitation, key)
    store.redeem(invitation.uri, registration, proof, transport_secure=True)
    assert all("publicKey" not in json.dumps(event) and invitation.secret not in json.dumps(event) for event in store.audit_events)
    with pytest.raises(PairingError, match="tls_required"):
        store.create("operator-2", "Phone", transport_secure=False)
