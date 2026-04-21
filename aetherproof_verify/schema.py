"""Minimal schema mirror — MUST stay bit-exact with signing server's schema."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class GateEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    gate: Literal["syntax", "static", "import", "smoke", "contract"]
    status: Literal["pass", "fail", "skip"]
    duration_ms: int = Field(ge=0)
    error_type: str | None = None
    error_nsp: str | None = None


class ProviderAttestation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    provider: str
    upstream_model: str
    upstream_request_id: str | None = None
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Signature(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    algo: Literal["ed25519"]
    public_key_fpr: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    value_b64: str


class AetherProofManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["aetherproof-v1"]
    request_id: str
    issued_at_utc: datetime
    code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verify_status: Literal["green", "red", "skipped"]
    heal_status: str | None = None
    total_elapsed_s: float = Field(ge=0)
    provider: ProviderAttestation
    gates: tuple[GateEvidence, ...]
    verifier_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    parent_manifest_ids: tuple[str, ...] = ()
    signature: Signature | None = None
