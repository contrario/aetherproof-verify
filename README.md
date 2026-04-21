# aetherproof-verify

**Offline, zero-trust verifier for AetherProof v1 signed manifests.**

AetherProof is a cryptographic provenance system for AI-generated code. Every
code artifact produced by an AetherProof-enabled pipeline is paired with a
signed manifest containing the exact SHA-256 of the code, the prompt that
generated it, the verifier gate evidence, the provider attestation, and the
timestamp — all signed with an Ed25519 key and canonicalized per RFC 8785
(JCS).

This package lets any auditor, buyer, or third party verify those manifests
**entirely offline**, without contacting any AetherProof server.

---

## Install

```bash
pip install aetherproof-verify
```

All wheels published to PyPI are signed with
[PEP 740 attestations](https://peps.python.org/pep-0740/) via PyPI Trusted
Publishers (OIDC → Sigstore), bound to this package's public GitHub repository.
See [Supply-chain posture](#supply-chain-posture) below.

## Usage

You need three inputs to verify a manifest:

1. **The manifest JSON** — fetched from `https://api.aetherlang.online/v1/manifests/{id}`, or delivered out-of-band.
2. **The public key** — fetched from `https://keys.aetherlang.online/keys.json` and converted to PEM, or pinned out-of-band.
3. **(Optional) The expected fingerprint** — pinned from a trusted source. Belt-and-suspenders: catches silent key rotation.

### CLI

```bash
aetherproof-verify check \
  --manifest ./manifest.json \
  --pubkey ./key.pem \
  --fingerprint sha256:f95a45bdc15db8f6ef61fa853366e860726aefe16474e943ebe79b132a17e022
```

Or via module invocation (equivalent):

```bash
python -m aetherproof_verify check --manifest ./m.json --pubkey ./k.pem
```

### Library

```python
from pathlib import Path
from aetherproof_verify.__main__ import check

rc = check(Path("manifest.json"), Path("key.pem"), expected_fpr=None)
assert rc == 0  # EXIT_OK
```

You can also import the Pydantic schema directly for custom integrations:

```python
from aetherproof_verify.schema import AetherProofManifest
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | OK — signature valid and fingerprint matches |
| `1`  | Signature mismatch — payload was tampered or wrong key used |
| `2`  | Fingerprint mismatch — wrong key or silent rotation |
| `3`  | Schema validation error — malformed manifest |
| `4`  | File I/O error — cannot read manifest or key |

## What this verifier does

1. **Parses** the manifest JSON (supports both bare manifest and the
   `{request_id, manifest, canonical_bytes_len}` envelope returned by
   `api.aetherlang.online`).
2. **Schema-validates** the payload against the frozen Pydantic v1 schema
   mirror (`extra="forbid"`, `frozen=True`).
3. **Fingerprint-gates** — computes SHA-256 of the raw Ed25519 public key bytes
   and matches against the `public_key_fpr` embedded in the manifest. If
   `--fingerprint` is passed, additionally pin-checks against it.
4. **Cryptographically verifies** — reconstructs canonical bytes via
   RFC 8785 JCS over the manifest with the `signature` field removed, and
   verifies the Ed25519 signature.

No network calls. No telemetry. No side channels.

## Trust boundaries

AetherProof operates four **independent** trust boundaries:

| Boundary                          | Role                                   |
|-----------------------------------|----------------------------------------|
| `github.com/contrario/aetherproof-verify` | Source of this verifier       |
| `keys.aetherlang.online`          | Public key distribution (keys.json)    |
| `releases.aetherlang.online`      | Reproducible demo bundle (tarball)     |
| `api.aetherlang.online`           | Manifest lookup (`/v1/manifests/{id}`) |

A compromise of any one boundary does not grant control of the others.
Buyers should verify each independently.

## Supply-chain posture

- **Build provenance:** every release wheel is built in GitHub Actions and
  attested via [PEP 740](https://peps.python.org/pep-0740/) / Sigstore. The
  attestation binds the artifact digest to this repository's workflow
  identity.
- **Trusted Publishers:** publishing to PyPI uses OIDC token exchange (no
  long-lived API tokens). See
  [PyPI docs](https://docs.pypi.org/trusted-publishers/).
- **Reproducible builds:** deterministic tarball and wheel construction; same
  source tree + same build environment → byte-identical artifact.
- **Pinned dependencies:** all transitive dependencies locked in
  `pyproject.toml`; `cryptography>=46.0.7` (no known CVEs at release time).
- **Zero-network verify:** the CLI makes no network calls. Everything needed
  is passed as file paths.

## Security model assumptions

- You trust your own Python interpreter and the `cryptography` library built
  against your OpenSSL.
- You obtained the public key through a channel you trust (HTTPS to
  `keys.aetherlang.online` with a modern CA root bundle, or out-of-band
  delivery).
- You obtained this package through PyPI with trusted-publisher attestation
  intact, or built it from source yourself after auditing.

If any of these assumptions fail, verification results are meaningless. Verify
your chain of custody before relying on verification output.

## Development

```bash
git clone https://github.com/contrario/aetherproof-verify
cd aetherproof-verify
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

## Security contact

Report vulnerabilities privately to `security@aetherlang.online`.
Do not open public issues for suspected security flaws.
