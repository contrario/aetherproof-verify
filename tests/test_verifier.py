"""Behavioral tests for the aetherproof-verify CLI `check` function."""
from __future__ import annotations

import hashlib
import json

from aetherproof_verify.__main__ import (
    EXIT_FILE_ERROR,
    EXIT_FPR_MISMATCH,
    EXIT_OK,
    EXIT_SCHEMA_ERROR,
    EXIT_SIG_MISMATCH,
    check,
)
from aetherproof_verify.schema import AetherProofManifest


def test_verify_bare_manifest_ok(keypair, signed_manifest, write_manifest_and_key):
    _, pub_pem, _ = keypair
    m_path, k_path = write_manifest_and_key(signed_manifest, pub_pem)
    assert check(m_path, k_path, expected_fpr=None) == EXIT_OK


def test_verify_envelope_format_ok(keypair, signed_manifest, write_manifest_and_key):
    _, pub_pem, _ = keypair
    envelope = {
        "request_id": signed_manifest["request_id"],
        "manifest": signed_manifest,
        "canonical_bytes_len": 999,
    }
    m_path, k_path = write_manifest_and_key(envelope, pub_pem)
    assert check(m_path, k_path, expected_fpr=None) == EXIT_OK


def test_verify_with_explicit_fingerprint_pin_ok(keypair, signed_manifest, write_manifest_and_key):
    _, pub_pem, fpr = keypair
    m_path, k_path = write_manifest_and_key(signed_manifest, pub_pem)
    assert check(m_path, k_path, expected_fpr=fpr) == EXIT_OK


def test_signature_mismatch_when_payload_tampered(keypair, signed_manifest, write_manifest_and_key):
    _, pub_pem, _ = keypair
    tampered = dict(signed_manifest)
    tampered["code_sha256"] = "e" * 64
    m_path, k_path = write_manifest_and_key(tampered, pub_pem)
    assert check(m_path, k_path, expected_fpr=None) == EXIT_SIG_MISMATCH


def test_fingerprint_mismatch_when_wrong_key_file(
    keypair, other_keypair, signed_manifest, write_manifest_and_key
):
    _, _, _ = keypair
    _, other_pem, _ = other_keypair
    m_path, k_path = write_manifest_and_key(signed_manifest, other_pem)
    assert check(m_path, k_path, expected_fpr=None) == EXIT_FPR_MISMATCH


def test_fingerprint_pin_rejects_non_matching_pin(
    keypair, signed_manifest, write_manifest_and_key
):
    _, pub_pem, _ = keypair
    wrong_fpr = "sha256:" + ("0" * 64)
    m_path, k_path = write_manifest_and_key(signed_manifest, pub_pem)
    assert check(m_path, k_path, expected_fpr=wrong_fpr) == EXIT_FPR_MISMATCH


def test_schema_error_when_extra_field_present(
    keypair, signed_manifest, write_manifest_and_key
):
    _, pub_pem, _ = keypair
    polluted = dict(signed_manifest)
    polluted["attacker_injected"] = "payload"
    m_path, k_path = write_manifest_and_key(polluted, pub_pem)
    assert check(m_path, k_path, expected_fpr=None) == EXIT_SCHEMA_ERROR


def test_schema_error_on_malformed_json(keypair, tmp_path):
    _, pub_pem, _ = keypair
    m_path = tmp_path / "manifest.json"
    k_path = tmp_path / "key.pem"
    m_path.write_text("{this is not valid json")
    k_path.write_bytes(pub_pem)
    assert check(m_path, k_path, expected_fpr=None) == EXIT_SCHEMA_ERROR


def test_file_error_when_manifest_missing(keypair, tmp_path):
    _, pub_pem, _ = keypair
    k_path = tmp_path / "key.pem"
    k_path.write_bytes(pub_pem)
    missing = tmp_path / "does_not_exist.json"
    assert check(missing, k_path, expected_fpr=None) == EXIT_FILE_ERROR


def test_schema_parity_fingerprint_locked():
    """Drift-guard: mirror schema MUST hash to locked value.

    If this fails, EITHER the server-side authoritative schema moved (and this
    mirror must be updated), OR the mirror was edited unintentionally. Bump
    `aetherproof-v1` to `aetherproof-v2` before changing this value.

    Recompute expected hash after an intentional schema change:

        import hashlib, json
        from aetherproof_verify.schema import AetherProofManifest
        schema = AetherProofManifest.model_json_schema()
        sep = (",", ":")
        canon = json.dumps(schema, sort_keys=True, separators=sep)
        print(hashlib.sha256(canon.encode()).hexdigest())
    """
    expected = "fd1bcc4080a44d7147068612008a4fb3a0a2b03f9dd32a233fde3a8ae93537a4"
    canonical = json.dumps(
        AetherProofManifest.model_json_schema(),
        sort_keys=True,
        separators=(",", ":"),
    )
    actual = hashlib.sha256(canonical.encode()).hexdigest()
    assert actual == expected, (
        f"Mirror schema drifted. Expected {expected}, got {actual}. "
        "Either server authoritative schema changed (update mirror + this pin), "
        "or mirror was edited (revert or bump schema_version)."
    )


def test_canonicalizer_differential_jcs_vs_rfc8785(unsigned_manifest_dict):
    """Differential oracle: jcs and rfc8785 must produce byte-identical
    canonical output for AetherProof manifests.

    Scope note: AetherProof schema has no float fields, so this test does NOT
    exercise the RFC 8785 number-serialization edge cases (Grisu2/Ryu rounding,
    IEEE 754 boundaries) where canonicalizer implementations are known to
    diverge. If either library regresses on the subset our signing path
    actually produces, CI fails before release.
    """
    import jcs
    import rfc8785

    m = AetherProofManifest.model_validate(unsigned_manifest_dict)
    dumped = m.model_dump(mode="json", exclude={"signature"})

    out_jcs = jcs.canonicalize(dumped)
    out_rfc = rfc8785.dumps(dumped)

    assert out_jcs == out_rfc, (
        "canonicalizer divergence on AetherProof manifest: "
        f"jcs={len(out_jcs)}B sha256[:16]={hashlib.sha256(out_jcs).hexdigest()[:16]} | "
        f"rfc8785={len(out_rfc)}B sha256[:16]={hashlib.sha256(out_rfc).hexdigest()[:16]}"
    )
