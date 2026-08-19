import base64
import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from gateway.pairing_invitations import (
    BOOTSTRAP_SCOPE,
    PairingError,
    PairingInvitationStore,
    canonical_gateway_origin,
    canonical_pairing_challenge,
    canonical_rotation_challenge,
    derive_key_id,
    parse_json_object,
    verify_pairing_proof,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "pairing-proof-es256.json"
ROTATION_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "rotation-proof-es256.json"
)
ORIGIN = "https://gateway.example.test"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def make_pairing_payload(invitation, private_key, *, nonce=None):
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    material = b64url(spki)
    key_id = derive_key_id(spki)
    fields = {
        "clientNonce": nonce or b64url(b"0123456789abcdef"),
        "deviceName": "Fixture Pixel",
        "gatewayOrigin": invitation.gateway_origin,
        "invitationCode": invitation.invitation_code,
        "invitationId": invitation.invitation_id,
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


def make_dpop(private_key, access_token, *, method, htu, jti, iat):
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
        "htu": htu,
        "iat": iat,
        "ath": b64url(hashlib.sha256(access_token.encode("ascii")).digest()),
    }
    encoded_header = b64url(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    )
    encoded_claims = b64url(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    )
    der = private_key.sign(
        f"{encoded_header}.{encoded_claims}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{encoded_header}.{encoded_claims}.{b64url(signature)}"


def test_normative_pairing_proof_fixture_verifies_exact_bytes_and_negatives():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    fields = fixture["challengeFields"]
    challenge = canonical_pairing_challenge(fields)
    assert challenge.decode("utf-8") == fixture["canonicalChallengeUtf8"]
    assert b64url(hashlib.sha256(challenge).digest()) == fixture[
        "canonicalChallengeSha256Base64Url"
    ]

    payload = {
        "protocolRevision": fields["protocolRevision"],
        "invitationId": fields["invitationId"],
        "invitationCode": fields["invitationCode"],
        "gatewayOrigin": fields["gatewayOrigin"],
        "deviceName": fields["deviceName"],
        "devicePublicKey": {
            "keyId": fields["keyId"],
            "algorithm": "ES256",
            "encoding": "spki-der-base64url",
            "material": fields["publicKey"],
        },
        "clientNonce": fields["clientNonce"],
        "proof": {
            "algorithm": "ES256",
            "signatureFormat": fixture["signatureFormat"],
            "signature": fixture["signatureBase64Url"],
        },
    }
    assert verify_pairing_proof(payload) == fixture["keyId"]

    for case in fixture["negativeCases"]:
        altered = dict(fields)
        altered[case.get("replaceField", case.get("addField"))] = case["value"]
        if case["expectedError"] == "invalid_request":
            with pytest.raises(PairingError, match="invalid_request"):
                canonical_pairing_challenge(altered)
        else:
            changed = json.loads(json.dumps(payload))
            field = case["replaceField"]
            if field == "keyId":
                changed["devicePublicKey"]["keyId"] = case["value"]
            else:
                changed[field] = case["value"]
            with pytest.raises(PairingError, match=case["expectedError"]):
                verify_pairing_proof(changed)

    for origin in fixture["invalidGatewayOrigins"]:
        with pytest.raises(PairingError, match="invalid_request"):
            canonical_gateway_origin(origin)


def test_normative_rotation_proof_fixture_matches_merged_wil46_contract():
    fixture = json.loads(ROTATION_FIXTURE_PATH.read_text(encoding="utf-8"))
    fields = fixture["challengeFields"]
    challenge = canonical_rotation_challenge(fields)
    assert challenge.decode("utf-8") == fixture["canonicalChallengeUtf8"]
    assert b64url(hashlib.sha256(challenge).digest()) == fixture[
        "canonicalChallengeSha256Base64Url"
    ]
    spki = base64.urlsafe_b64decode(
        fixture["newPublicKeySpkiDerBase64Url"] + "=="
    )
    public_key = serialization.load_der_public_key(spki)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    signature = base64.urlsafe_b64decode(fixture["signatureBase64Url"] + "==")
    public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    assert derive_key_id(spki) == fixture["newKeyId"]

    for case in fixture["negativeCases"]:
        altered = dict(fields)
        altered[case["replaceField"]] = case["value"]
        assert canonical_rotation_challenge(altered) != challenge


def test_duplicate_json_names_and_obsolete_pairing_shape_fail_closed(tmp_path):
    with pytest.raises(PairingError, match="invalid_request"):
        parse_json_object('{"deviceName":"one","deviceName":"two"}')
    store = PairingInvitationStore(gateway_origin=ORIGIN, db_path=tmp_path / "state.db")
    with pytest.raises(PairingError, match="pairing_protocol_upgrade_required"):
        store.redeem_invitation({"invitationCode": "old", "deviceName": "Phone"})


def test_durable_atomic_registration_and_redacted_audit(tmp_path):
    now = [1_800_000_000]
    db_path = tmp_path / "state.db"
    store = PairingInvitationStore(
        gateway_origin=ORIGIN, db_path=db_path, clock=lambda: now[0]
    )
    invitation = store.create_invitation("operator:api_server", "Fixture Pixel")
    assert len(base64.urlsafe_b64decode(invitation.invitation_code + "=")) == 32
    private_key = ec.generate_private_key(ec.SECP256R1())
    payload = make_pairing_payload(invitation, private_key)

    barrier = threading.Barrier(8)

    def redeem():
        local_store = PairingInvitationStore(
            gateway_origin=ORIGIN, db_path=db_path, clock=lambda: now[0]
        )
        barrier.wait()
        try:
            return local_store.redeem_invitation(payload)
        except PairingError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: redeem(), range(8)))
    successes = [result for result in results if not isinstance(result, str)]
    assert len(successes) == 1
    assert results.count("invitation_consumed") == 7

    result = successes[0]
    assert result.device["platform"] == "android"
    assert result.device["status"] == "paired"
    assert result.credentials["tokenType"] == "DPoP"

    reopened = PairingInvitationStore(
        gateway_origin=ORIGIN, db_path=db_path, clock=lambda: now[0]
    )
    records = reopened.audit_records()
    serialized_audit = json.dumps(records)
    assert any(record["outcome"] == "success" for record in records)
    for secret in (
        invitation.invitation_code,
        result.credentials["accessToken"],
        result.credentials["refreshToken"],
        payload["proof"]["signature"],
        payload["devicePublicKey"]["material"],
        payload["clientNonce"],
    ):
        assert secret not in serialized_audit

    with sqlite3.connect(db_path) as conn:
        invitation_row = conn.execute(
            "SELECT code_hash, consumed_at FROM companion_pairing_invitations"
        ).fetchone()
        credential_row = conn.execute(
            "SELECT access_token_hash, refresh_token_hash FROM companion_credential_sessions"
        ).fetchone()
    assert invitation_row[0] != invitation.invitation_code.encode()
    assert invitation_row[1] == now[0]
    assert credential_row[0] != result.credentials["accessToken"].encode()
    assert credential_row[1] != result.credentials["refreshToken"].encode()


def test_dpop_authentication_is_durable_scoped_and_replay_safe(tmp_path):
    now = [1_800_000_000]
    db_path = tmp_path / "state.db"
    store = PairingInvitationStore(
        gateway_origin=ORIGIN, db_path=db_path, clock=lambda: now[0]
    )
    invitation = store.create_invitation("operator:api_server", "Fixture Pixel")
    private_key = ec.generate_private_key(ec.SECP256R1())
    result = store.redeem_invitation(make_pairing_payload(invitation, private_key))
    access_token = result.credentials["accessToken"]
    htu = ORIGIN + "/companion/v1/bootstrap"
    proof = make_dpop(
        private_key,
        access_token,
        method="GET",
        htu=htu,
        jti="fixture-jti-1",
        iat=now[0],
    )

    reopened = PairingInvitationStore(
        gateway_origin=ORIGIN, db_path=db_path, clock=lambda: now[0]
    )
    principal = reopened.authenticate_access(
        access_token=access_token,
        dpop_proof=proof,
        method="GET",
        htu=htu,
        required_scope=BOOTSTRAP_SCOPE,
    )
    bootstrap = reopened.bootstrap(principal)
    assert bootstrap["device"]["id"] == result.device["id"]
    assert bootstrap["authentication"]["keyId"] == result.device["keyId"]
    assert bootstrap["capabilities"] == []

    with pytest.raises(PairingError, match="replay_detected"):
        reopened.authenticate_access(
            access_token=access_token,
            dpop_proof=proof,
            method="GET",
            htu=htu,
            required_scope=BOOTSTRAP_SCOPE,
        )

    different_proof = make_dpop(
        private_key,
        access_token,
        method="GET",
        htu=htu,
        jti="fixture-jti-2",
        iat=now[0],
    )
    with pytest.raises(PairingError, match="forbidden"):
        reopened.authenticate_access(
            access_token=access_token,
            dpop_proof=different_proof,
            method="GET",
            htu=htu,
            required_scope="companion.unsupported",
        )


def test_invalid_signature_does_not_consume_invitation(tmp_path):
    store = PairingInvitationStore(gateway_origin=ORIGIN, db_path=tmp_path / "state.db")
    invitation = store.create_invitation("operator:api_server", "Fixture Pixel")
    private_key = ec.generate_private_key(ec.SECP256R1())
    payload = make_pairing_payload(invitation, private_key)
    payload["proof"]["signature"] = b64url(b"not-a-der-signature" * 5)
    with pytest.raises(PairingError, match="invalid_signature"):
        store.redeem_invitation(payload)

    valid_payload = make_pairing_payload(invitation, private_key)
    assert store.redeem_invitation(valid_payload).device["id"].startswith("device_")
