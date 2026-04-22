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


def test_canonical_bytes_fixture_roundtrip():
    """Pydantic-version-invariant parity guard.

    Loads the Day-7-locked canonical-bytes fixture, re-parses via
    ``AetherProofManifest``, re-canonicalizes via ``jcs``, asserts
    byte-identical output. Replaces the prior schema-fingerprint test
    which asserted on ``model_json_schema()`` output and was fragile to
    Pydantic minor-version changes (H25 / TD6-mu1).

    Defense-in-depth:
      1. Pre-check: ``sha256(fixture_bytes) == pinned Day-7 invariant``.
      2. Main check: parse -> ``model_dump(exclude={"signature"})``
         -> ``jcs.canonicalize`` yields bytes equal to the fixture.

    Bump ``aetherproof-v1`` to ``aetherproof-v2`` and regenerate the
    fixture via the mu1 parity tool before changing the pinned sha.
    """
    from pathlib import Path

    import jcs

    expected_sha = (
        "b30135afe126440e9e3eb000bd0cdd68d1f2060d7a80a89aff2e57231ca9521f"
    )
    fixture_path = (
        Path(__file__).resolve().parent.parent
        / "tools" / "fixtures" / "parity_fixture_v1.json"
    )

    fixture_bytes = fixture_path.read_bytes()
    actual_sha = hashlib.sha256(fixture_bytes).hexdigest()
    assert actual_sha == expected_sha, (
        f"Fixture bytes drifted. Expected {expected_sha}, got {actual_sha}. "
        "Either fixture was edited (revert) or mu1 parity tool produced a "
        "new canonical form (update pin + bump schema_version)."
    )

    manifest_dict = json.loads(fixture_bytes)
    model = AetherProofManifest.model_validate(manifest_dict)
    redumped = model.model_dump(mode="json", exclude={"signature"})
    recanonicalized = jcs.canonicalize(redumped)

    assert recanonicalized == fixture_bytes, (
        f"Canonical round-trip drifted. "
        f"fixture {len(fixture_bytes)}B sha={actual_sha[:16]} vs "
        f"recomputed {len(recanonicalized)}B "
        f"sha={hashlib.sha256(recanonicalized).hexdigest()[:16]}"
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
