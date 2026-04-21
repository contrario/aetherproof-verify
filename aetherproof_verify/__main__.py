"""CLI entrypoint: python -m aetherproof_verify check ..."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from aetherproof_verify.schema import AetherProofManifest

EXIT_OK = 0
EXIT_SIG_MISMATCH = 1
EXIT_FPR_MISMATCH = 2
EXIT_SCHEMA_ERROR = 3
EXIT_FILE_ERROR = 4


def _pub_fpr_from_pem(pub_pem: bytes) -> str:
    pub = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def check(manifest_path: Path, pubkey_path: Path, expected_fpr: str | None) -> int:
    try:
        raw_json = manifest_path.read_text(encoding="utf-8")
        pub_pem = pubkey_path.read_bytes()
    except OSError as e:
        print(f"[fail] file I/O: {e}", file=sys.stderr)
        return EXIT_FILE_ERROR

    # Parse + validate schema
    try:
        # Manifests served by /manifests/{id} use envelope shape
        # {request_id, manifest, canonical_bytes_len}; also accept a bare manifest.
        data = json.loads(raw_json)
        if "manifest" in data and "request_id" in data and "canonical_bytes_len" in data:
            bare = data["manifest"]
        else:
            bare = data
        manifest = AetherProofManifest.model_validate(bare)
    except (json.JSONDecodeError, ValidationError) as e:
        print(f"[fail] schema: {e}", file=sys.stderr)
        return EXIT_SCHEMA_ERROR

    if manifest.signature is None:
        print("[fail] manifest has no signature", file=sys.stderr)
        return EXIT_SIG_MISMATCH

    # Fingerprint gate: the signing key must match what we expect
    try:
        pub_fpr_computed = _pub_fpr_from_pem(pub_pem)
    except Exception as e:
        print(f"[fail] cannot read public key: {e}", file=sys.stderr)
        return EXIT_FILE_ERROR

    if manifest.signature.public_key_fpr != pub_fpr_computed:
        print(
            f"[fail] fingerprint: manifest says {manifest.signature.public_key_fpr} "
            f"but key file fingerprints to {pub_fpr_computed}",
            file=sys.stderr,
        )
        return EXIT_FPR_MISMATCH

    if expected_fpr and pub_fpr_computed != expected_fpr:
        print(
            f"[fail] fingerprint: key is {pub_fpr_computed} "
            f"but --fingerprint expected {expected_fpr}",
            file=sys.stderr,
        )
        return EXIT_FPR_MISMATCH

    # Crypto gate: reconstruct canonical bytes, verify Ed25519
    unsigned = manifest.model_dump(mode="json", exclude={"signature"})
    canon = jcs.canonicalize(unsigned)
    sig_bytes = base64.b64decode(manifest.signature.value_b64)

    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(sig_bytes, canon)
    except Exception as e:
        print(f"[fail] signature: {e}", file=sys.stderr)
        return EXIT_SIG_MISMATCH

    print(
        json.dumps({
            "ok": True,
            "request_id": manifest.request_id,
            "schema_version": manifest.schema_version,
            "verify_status": manifest.verify_status,
            "public_key_fpr": pub_fpr_computed,
            "canonical_bytes": len(canon),
            "algo": manifest.signature.algo,
        }, indent=2)
    )
    return EXIT_OK


def main() -> int:
    p = argparse.ArgumentParser(prog="aetherproof_verify")
    sub = p.add_subparsers(dest="cmd", required=True)

    chk = sub.add_parser("check", help="verify a manifest offline")
    chk.add_argument("--manifest", required=True, type=Path)
    chk.add_argument("--pubkey", required=True, type=Path)
    chk.add_argument(
        "--fingerprint", default=None,
        help="optional expected sha256:... fingerprint to pin"
    )

    args = p.parse_args()
    if args.cmd == "check":
        return check(args.manifest, args.pubkey, args.fingerprint)
    return 1


if __name__ == "__main__":
    sys.exit(main())
