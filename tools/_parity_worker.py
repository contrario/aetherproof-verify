#!/usr/bin/env python3
"""Parity worker — invoked by check_schema_parity.py under a specific venv.

Loads a schema class, validates a fixture manifest, canonicalizes via the
requested implementation, and prints a single machine-parseable line to stdout:

    sha256=<hex> bytes=<int>

Exit codes:
    0 — success, line printed
    2 — schema import failed
    3 — fixture read/parse failed
    4 — schema validate/dump failed
    5 — canonicalizer import failed
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Parity canonicalization worker")
    ap.add_argument("--module", required=True, help="e.g. aetherproof.manifest")
    ap.add_argument("--class", dest="cls", required=True, help="e.g. AetherProofManifest")
    ap.add_argument("--fixture", required=True, type=Path)
    ap.add_argument("--canonicalizer", required=True, choices=["jcs", "rfc8785"])
    args = ap.parse_args()

    try:
        mod = importlib.import_module(args.module)
        schema_cls = getattr(mod, args.cls)
    except (ImportError, AttributeError) as e:
        print(f"ERROR: schema import failed: {args.module}:{args.cls}: {e}", file=sys.stderr)
        return 2

    try:
        fixture_bytes = args.fixture.read_bytes()
        fixture_dict = json.loads(fixture_bytes)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: fixture {args.fixture}: {e}", file=sys.stderr)
        return 3

    try:
        instance = schema_cls.model_validate(fixture_dict)
        dumped = instance.model_dump(mode="json", exclude={"signature"})
    except Exception as e:  # noqa: BLE001 — worker script, final boundary
        print(f"ERROR: schema validate/dump failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 4

    try:
        if args.canonicalizer == "jcs":
            import jcs
            out = jcs.canonicalize(dumped)
        else:
            import rfc8785
            out = rfc8785.dumps(dumped)
    except ImportError as e:
        print(f"ERROR: canonicalizer {args.canonicalizer} unavailable: {e}", file=sys.stderr)
        return 5

    sha = hashlib.sha256(out).hexdigest()
    print(f"sha256={sha} bytes={len(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
