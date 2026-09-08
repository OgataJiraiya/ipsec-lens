"""Trusted user-assisted normalized JSON. Never execute swanctl or XFRM from a web request.
Do not export raw XFRM state: it can contain encryption keys. Only normalized allowlisted fields.
"""
from datetime import datetime
from ipaddress import ip_address
from typing import Literal
from pydantic import Field, field_validator
from backend.schemas.models import StrictModel, SecurityAssociation, Evidence, Source


class TelemetrySA(StrictModel):
    source: str
    destination: str
    spi: str = Field(pattern=r"^0x[0-9a-fA-F]{1,8}$")
    protocol: Literal["ESP", "AH"] = "ESP"
    mode: Literal["TUNNEL", "TRANSPORT"] | None = None
    encryption_algorithm: Literal["3DES", "AES-CBC", "AES-CTR", "AES-GCM-8", "AES-GCM-12",
                                  "AES-GCM-16", "CHACHA20-POLY1305", "OTHER"] | None = None
    encryption_key_bits: int | None = Field(default=None, ge=1, le=4096)
    integrity_algorithm: Literal["NONE", "HMAC-SHA1-96", "HMAC-SHA2-256-128",
                                 "HMAC-SHA2-384-192", "HMAC-SHA2-512-256", "OTHER"] | None = None
    pfs_enabled: bool | None = None
    dh_group: int | None = Field(default=None, ge=0, le=65535)
    configured_lifetime: int | None = Field(default=None, ge=0, le=315360000)
    replay_window: int | None = Field(default=None, ge=0, le=2**32)
    esn: bool | None = None
    selectors: str | None = Field(default=None, max_length=512)
    ike_association_reference: str | None = Field(default=None, max_length=128)

    @field_validator("source", "destination")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value))


class Telemetry(StrictModel):
    adapter: Literal["strongswan-normalized", "xfrm-normalized"]
    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collected_at: datetime
    provenance: str = Field(min_length=1, max_length=512)
    synthetic: bool = False
    sas: list[TelemetrySA] = Field(max_length=4096)

    @field_validator("collected_at")
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None:
            raise ValueError("Telemetry collection time requires a timezone")
        return value


RESOLVED_FIELDS = tuple(TelemetrySA.model_fields.keys())[4:]


def apply_telemetry(sas: list[SecurityAssociation], telemetry: Telemetry, capture_hash: str) -> list[str]:
    if telemetry.capture_sha256 != capture_hash:
        raise ValueError("Telemetry capture identity does not match")
    index = {(s.source, s.destination, s.protocol, int(s.spi, 16)): s for s in sas}
    matched = set()
    for item in telemetry.sas:
        key = (item.source, item.destination, item.protocol, int(item.spi, 16))
        if key not in index:
            raise ValueError("Telemetry contains an SA absent from this capture")
        if key in matched:
            raise ValueError("Duplicate telemetry SA")
        matched.add(key)
    # All identity checks precede mutation. Timestamp/accuracy remains an operator assertion.
    for item in telemetry.sas:
        sa = index[(item.source, item.destination, item.protocol, int(item.spi, 16))]
        for name in RESOLVED_FIELDS:
            value = getattr(item, name)
            if value is not None:
                setattr(sa, name, Evidence(value=value, source=Source.ASSISTED, confidence=0.9,
                        evidence=[telemetry.adapter, telemetry.provenance,
                                  telemetry.collected_at.isoformat(), f"capture_sha256={capture_hash}",
                                  "SYNTHETIC FIXTURE" if telemetry.synthetic else "Operator-supplied; not cryptographically attested"]))
    return [f"{telemetry.adapter}: {telemetry.provenance}; collected={telemetry.collected_at.isoformat()}; "
            f"synthetic={telemetry.synthetic}; operator assertion, not endpoint attestation"]
