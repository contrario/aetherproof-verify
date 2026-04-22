# Changelog

All notable changes to `aetherproof-verify` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Replaced `test_schema_parity_fingerprint_locked` with
  `test_canonical_bytes_fixture_roundtrip`. The new test asserts byte-identity
  of the canonical-bytes fixture after a Pydantic parse / dump / jcs round-trip,
  instead of hashing `model_json_schema()` output. Closes TD6-mu1; defends
  against H25 (Pydantic minor-version fragility of schema-hash pins).

## [0.1.0] - 2026-04-21

### Added
- Initial public release of the offline verifier.
- CLI `aetherproof-verify check <manifest> <key>` with structured exit codes.
- Mirror `AetherProofManifest` schema (Pydantic v2, `extra="forbid"`).
- `tools/check_schema_parity.py` (mu1): server<->mirror canonical-bytes parity.
- `tools/check_canonicalizer_differential.py` (mu2): jcs vs rfc8785 differential.
- PEP 740 attestations via GitHub trusted publishing.
