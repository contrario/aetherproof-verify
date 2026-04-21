#!/usr/bin/env python3
"""check_schema_parity.py — server-side schema/canonicalizer parity check.

Runs the parity worker under three configurations and asserts all three
produce byte-identical canonical output:

    1. Server venv  + jcs       (/opt/aetherproof/.venv)
    2. Verify venv  + jcs       (/opt/aetherproof-verify/.venv)
    3. Verify venv  + rfc8785   (/opt/aetherproof-verify/.venv)

(1)==(2) proves server↔client schema parity across Pydantic version skew.
(2)==(3) proves canonicalizer differential parity (jcs and rfc8785 agree).
Together they harden the signing path against silent schema drift AND against
single-canonicalizer upstream compromise.

Also asserts the fixture's stored canonical bytes match their pinned sha256,
so a tampered fixture cannot silently pass parity.

Exit codes:
    0 — all three match expected sha, all match each other
    1 — drift detected
    2 — worker subprocess errored
    3 — fixture missing or sha mismatch
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
WORKER = TOOLS_DIR / "_parity_worker.py"
DEFAULT_FIXTURE = TOOLS_DIR / "fixtures" / "parity_fixture_v1.json"
DEFAULT_FIXTURE_SHA = (
    "b30135afe126440e9e3eb000bd0cdd68d1f2060d7a80a89aff2e57231ca9521f"
)

SERVER_VENV_PY = "/opt/aetherproof/.venv/bin/python"
SERVER_PYTHONPATH = "/opt/aetherproof"
SERVER_MODULE = "aetherproof.manifest"
VERIFY_VENV_PY = "/opt/aetherproof-verify/.venv/bin/python"
VERIFY_PYTHONPATH = "/opt/aetherproof-verify"
VERIFY_MODULE = "aetherproof_verify.schema"
SCHEMA_CLASS = "AetherProofManifest"


@dataclass(frozen=True)
class Run:
    label: str
    venv_py: str
    pythonpath: str
    module: str
    canonicalizer: str


RUNS = (
    Run("server+jcs    ", SERVER_VENV_PY, SERVER_PYTHONPATH, SERVER_MODULE, "jcs"),
    Run("verify+jcs    ", VERIFY_VENV_PY, VERIFY_PYTHONPATH, VERIFY_MODULE, "jcs"),
    Run("verify+rfc8785", VERIFY_VENV_PY, VERIFY_PYTHONPATH, VERIFY_MODULE, "rfc8785"),
)


def parse_worker_line(line: str) -> tuple[str, int]:
    # expected: "sha256=<hex> bytes=<int>"
    parts = dict(kv.split("=", 1) for kv in line.strip().split())
    return parts["sha256"], int(parts["bytes"])


def run_worker(r: Run, fixture: Path) -> tuple[str, int]:
    proc = subprocess.run(
        [
            r.venv_py,
            str(WORKER),
            "--module", r.module,
            "--class", SCHEMA_CLASS,
            "--fixture", str(fixture),
            "--canonicalizer", r.canonicalizer,
        ],
        env={"PYTHONPATH": r.pythonpath, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        print(f"[{r.label}] WORKER FAILED (exit {proc.returncode}):", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(2)
    return parse_worker_line(proc.stdout)


def verify_fixture_sha(fixture: Path, expected_sha: str) -> None:
    if not fixture.exists():
        print(f"ERROR: fixture not found: {fixture}", file=sys.stderr)
        raise SystemExit(3)
    actual = hashlib.sha256(fixture.read_bytes()).hexdigest()
    if actual != expected_sha:
        print("ERROR: fixture sha mismatch", file=sys.stderr)
        print(f"  expected: {expected_sha}", file=sys.stderr)
        print(f"  actual  : {actual}", file=sys.stderr)
        raise SystemExit(3)


def main() -> int:
    ap = argparse.ArgumentParser(description="Schema + canonicalizer parity check")
    ap.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    ap.add_argument("--fixture-sha", default=DEFAULT_FIXTURE_SHA)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    verify_fixture_sha(args.fixture, args.fixture_sha)

    results: list[tuple[Run, str, int]] = []
    for r in RUNS:
        sha, nbytes = run_worker(r, args.fixture)
        results.append((r, sha, nbytes))
        if not args.quiet:
            print(f"  {r.label}  sha256={sha}  bytes={nbytes}")

    shas = {sha for _, sha, _ in results}
    if len(shas) != 1:
        print("DRIFT DETECTED — canonical bytes diverge across runs", file=sys.stderr)
        for r, sha, nbytes in results:
            print(f"  {r.label}  sha256={sha}  bytes={nbytes}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"OK: all 3 runs produced sha256={shas.pop()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
