#!/usr/bin/env python3
"""smoke_ingest.py - end-to-end signing-chain integrity smoke test.

Mechanical verification that the AetherProof signing chain is functional
end-to-end under the currently-running runtime:

    POST /ingest  ->  server Pydantic validate  ->  JCS canonicalize
                  ->  Ed25519 sign  ->  SQLite persist
                  ->  GET /manifests/{id}  ->  offline CLI verify
                  ->  rc=0 required

Codifies the Day 9 Phase-3 procedure as a reusable tool (TD8-beta).

Section 5.3 classification
--------------------------
This is NOT a byte-wise 5.3 probe. `issued_at_utc` in the manifest freezes
at signing time, so two invocations never produce the same canonical bytes
or the same Ed25519 signature. See DETERMINISM_INTEGRATION.md 6.4.

This IS a new verification class: end-to-end signing-chain integrity.
Complementary to mu1 (frozen fixture parity), mu2 (CI differential oracle),
and the storage probe (continuous historical row). The ONE byte-wise
invariant asserted is `public_key_fpr == pinned_fpr` - everything else is
validated by the chain returning rc=0 from the independent offline verifier.

Exit codes
----------
    0  - all 5 gates passed
    1  - integrity violation (fpr mismatch or offline-verify rc != 0)
    2  - HTTP error (connection refused, non-2xx from server)
    3  - missing resource (pubkey, fingerprint file, or verify CLI)
    4  - subprocess crashed (OSError invoking verify CLI)

Design notes
------------
- stdlib only. Runs from either venv.
- request_id prefix `aps_smoke_` makes rows grep-able in manifests.db.
- Expected fpr defaults to runtime contents of the on-disk fingerprint
  file (/etc/aetherproof/signing-key.fingerprint) - a locked invariant
  maintained alongside the signing key. Avoids dual-source-of-truth drift
  on future key rotation.
- Footprint: each run appends 1 row to manifests.db.

H-heuristics applied
--------------------
- H32: runs against mirror-venv CLI; assumes both venvs have coherent
  aetherproof-verify. Verified at Day 9 close.
- H33: synthetic IngestRequest matches ingest_schema.py source, not
  inferred from stored manifest output.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ENDPOINT = "http://127.0.0.1:9990"
DEFAULT_PUBKEY = "/etc/aetherproof/signing-key.pub"
DEFAULT_FPR_FILE = "/etc/aetherproof/signing-key.fingerprint"
DEFAULT_VERIFY_CLI = "/opt/aetherproof-verify/.venv/bin/aetherproof-verify"
DEFAULT_TIMEOUT = 10
DEFAULT_PREFIX = "aps_smoke"


def _log(gate: str, status: str, detail: str = "") -> None:
    line = f"[{gate}] {status}"
    if detail:
        line += f" {detail}"
    print(line, flush=True)


def _die(code: int, gate: str, detail: str) -> None:
    _log(gate, "FAIL", detail)
    sys.exit(code)


def _build_request_id(prefix: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = uuid.uuid4().hex[:12]
    return f"{prefix}_{ts}_{suffix}"


def _build_payload(request_id: str) -> dict:
    return {
        "request_id": request_id,
        "code": "def add(a, b):\n    return a + b\n",
        "prompt": "write a function that adds two numbers",
        "verify_status": "green",
        "heal_status": None,
        "total_elapsed_s": 0.123,
        "gates": [
            {"gate": "syntax", "status": "pass", "duration_s": 0.01,
             "error_type": None, "error_nsp": None},
            {"gate": "static", "status": "pass", "duration_s": 0.05,
             "error_type": None, "error_nsp": None},
            {"gate": "import", "status": "pass", "duration_s": 0.02,
             "error_type": None, "error_nsp": None},
            {"gate": "smoke", "status": "pass", "duration_s": 0.03,
             "error_type": None, "error_nsp": None},
            {"gate": "contract", "status": "pass", "duration_s": 0.01,
             "error_type": None, "error_nsp": None},
        ],
        "provider": {
            "provider": "smoke-test",
            "upstream_model": "synthetic",
            "upstream_request_id": None,
            "raw_response_text": "synthetic-response-body-for-smoke-test",
        },
        "verifier_bundle_id": "smoke-v1",
        "parent_request_ids": [],
    }


def _http_request(method: str, url: str, body: bytes | None,
                  timeout: int) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"http_network_error: {e!r}") from e


def _load_expected_fpr(cli_value: str | None, fpr_file: Path) -> str:
    if cli_value:
        return cli_value.strip()
    if not fpr_file.is_file():
        _die(3, "resolve_fpr",
             f"fpr file not found: {fpr_file} (and --expect-fpr not given)")
    try:
        contents = fpr_file.read_text(encoding="utf-8").strip()
    except OSError as e:
        _die(3, "resolve_fpr", f"cannot read {fpr_file}: {e!r}")
    if not contents.startswith("sha256:"):
        _die(3, "resolve_fpr",
             f"fpr file malformed (head={contents[:16]!r})")
    return contents


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="smoke_ingest.py",
        description="End-to-end signing-chain integrity smoke test.",
    )
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p.add_argument("--pubkey", default=DEFAULT_PUBKEY)
    p.add_argument("--expect-fpr", default=None,
                   help="Override fpr pin. Default: read from --fpr-file.")
    p.add_argument("--fpr-file", default=DEFAULT_FPR_FILE)
    p.add_argument("--verify-cli", default=DEFAULT_VERIFY_CLI)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--keep-artifacts", action="store_true")
    p.add_argument("--request-id-prefix", default=DEFAULT_PREFIX)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    pubkey_path = Path(args.pubkey)
    verify_cli_path = Path(args.verify_cli)
    fpr_file_path = Path(args.fpr_file)

    if not pubkey_path.is_file():
        _die(3, "preflight", f"pubkey not found: {pubkey_path}")
    if not verify_cli_path.is_file():
        _die(3, "preflight", f"verify-cli not found: {verify_cli_path}")

    expect_fpr = _load_expected_fpr(args.expect_fpr, fpr_file_path)
    _log("preflight", "OK",
         f"endpoint={args.endpoint} pubkey={pubkey_path} "
         f"expect_fpr={expect_fpr[:24]}...")

    request_id = _build_request_id(args.request_id_prefix)
    payload = _build_payload(request_id)
    body = json.dumps(payload).encode("utf-8")
    _log("G1_build_payload", "OK", f"request_id={request_id}")

    t0 = time.monotonic()
    try:
        code, raw = _http_request("POST", f"{args.endpoint}/ingest",
                                  body, args.timeout)
    except RuntimeError as e:
        _die(2, "G2_http_ingest", str(e))
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    if code != 200:
        _die(2, "G2_http_ingest", f"http={code} body={raw[:200]!r}")
    try:
        ingest_resp = json.loads(raw)
    except json.JSONDecodeError as e:
        _die(2, "G2_http_ingest", f"bad_json: {e!r}")
    _log("G2_http_ingest", "OK", f"http=200 elapsed_ms={elapsed_ms}")

    got_fpr = ingest_resp.get("public_key_fpr", "")
    if got_fpr != expect_fpr:
        _die(1, "G3_fpr_invariant",
             f"got={got_fpr!r} expected={expect_fpr!r}")
    _log("G3_fpr_invariant", "OK", f"fpr={got_fpr[:24]}...")

    t0 = time.monotonic()
    try:
        code, raw = _http_request("GET",
                                  f"{args.endpoint}/manifests/{request_id}",
                                  None, args.timeout)
    except RuntimeError as e:
        _die(2, "G4_http_fetch", str(e))
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    if code != 200:
        _die(2, "G4_http_fetch", f"http={code} body={raw[:200]!r}")
    try:
        manifest_out = json.loads(raw)
    except json.JSONDecodeError as e:
        _die(2, "G4_http_fetch", f"bad_json: {e!r}")
    manifest_dict = manifest_out.get("manifest")
    if not isinstance(manifest_dict, dict):
        _die(2, "G4_http_fetch", "manifest field missing or not dict")
    _log("G4_http_fetch", "OK",
         f"http=200 elapsed_ms={elapsed_ms} "
         f"canonical_bytes_len={manifest_out.get('canonical_bytes_len')}")

    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".json",
        prefix="smoke_manifest_", delete=False,
    )
    try:
        json.dump(manifest_dict, tmp)
        tmp.flush()
        tmp.close()
        cmd = [
            str(verify_cli_path), "check",
            "--manifest", tmp.name,
            "--pubkey", str(pubkey_path),
            "--fingerprint", expect_fpr,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=args.timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            _die(4, "G5_offline_verify", f"subprocess_error: {e!r}")
        if proc.returncode != 0:
            _die(1, "G5_offline_verify",
                 f"rc={proc.returncode} stderr={proc.stderr[:300]!r}")
        _log("G5_offline_verify", "OK",
             f"rc=0 stdout={proc.stdout.strip()[:100]!r}")
        if args.verbose:
            print(f"[artifact] manifest_json_path={tmp.name}", flush=True)
    finally:
        if not args.keep_artifacts:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    _log("DONE", "OK", f"request_id={request_id} all_5_gates_pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
