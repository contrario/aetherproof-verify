"""Test fixtures — self-contained, zero dependency on production keys or DB."""
from __future__ import annotations

import base64
import hashlib
import json

import jcs
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aetherproof_verify.schema import AetherProofManifest


def _keypair_with_fpr() -> tuple[Ed25519PrivateKey, bytes, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fpr = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    return priv, pub_pem, fpr


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    return _keypair_with_fpr()


@pytest.fixture
def other_keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    return _keypair_with_fpr()


@pytest.fixture
def unsigned_manifest_dict() -> dict:
    return {
        "schema_version": "aetherproof-v1",
        "request_id": "test_01TESTXXX00000000000000000",
        "issued_at_utc": "2026-04-21T12:00:00Z",
        "code_sha256": "a" * 64,
        "prompt_sha256": "b" * 64,
        "verify_status": "green",
        "heal_status": None,
        "total_elapsed_s": 1.5,
        "provider": {
            "provider": "test-provider",
            "upstream_model": "test-model",
            "upstream_request_id": None,
            "response_sha256": "c" * 64,
        },
        "gates": [
            {
                "gate": "syntax",
                "status": "pass",
                "duration_ms": 0,
                "error_type": None,
                "error_nsp": None,
            }
        ],
        "verifier_bundle_sha256": "d" * 64,
        "parent_manifest_ids": [],
    }


def _sign(priv: Ed25519PrivateKey, fpr: str, manifest_dict: dict) -> dict:
    """Produce signed manifest; canonical bytes match the verifier's reconstruction path."""
    model = AetherProofManifest.model_validate(manifest_dict)
    unsigned_normalized = model.model_dump(mode="json", exclude={"signature"})
    canon = jcs.canonicalize(unsigned_normalized)
    sig = priv.sign(canon)
    signed = dict(unsigned_normalized)
    signed["signature"] = {
        "algo": "ed25519",
        "public_key_fpr": fpr,
        "value_b64": base64.b64encode(sig).decode("ascii"),
    }
    return signed


@pytest.fixture
def signed_manifest(keypair, unsigned_manifest_dict) -> dict:
    priv, _pem, fpr = keypair
    return _sign(priv, fpr, unsigned_manifest_dict)


@pytest.fixture
def write_manifest_and_key(tmp_path):
    """Helper: write a manifest dict and a PEM to disk, return (manifest_path, pubkey_path)."""
    def _write(manifest: dict, pub_pem: bytes) -> tuple:
        m_path = tmp_path / "manifest.json"
        k_path = tmp_path / "key.pem"
        m_path.write_text(json.dumps(manifest))
        k_path.write_bytes(pub_pem)
        return m_path, k_path
    return _write
