"""Common evidence contract. UNKNOWN != SECURE; confidence is not attack probability."""
from enum import StrEnum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Source(StrEnum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    ASSISTED = "ASSISTED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Evidence(StrictModel):
    value: str | int | float | bool | None = None
    source: Source = Source.UNKNOWN
    confidence: float = Field(default=0, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def honest_unknown(self):
        if self.value is None and (self.source != Source.UNKNOWN or self.confidence != 0):
            raise ValueError("Missing values must be UNKNOWN with zero confidence")
        if self.source == Source.UNKNOWN and self.value is not None:
            raise ValueError("UNKNOWN cannot assert a value")
        return self


Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Recommendation = Literal["ACCEPT", "REVIEW", "HARDEN", "QUARANTINE"]
PolicyName = Literal["MODERN", "COMPATIBILITY", "STRICT"]


class Finding(StrictModel):
    finding_id: str
    category: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    source: Source
    reason: str
    evidence: list[str]
    recommendation: Recommendation
    remediation: str
    limitations: list[str] = Field(default_factory=list)


class Transform(StrictModel):
    proposal: int
    protocol_id: int
    transform_type: int
    transform_id: int
    name: str
    key_length: int | None = None
    scope: str = "IKE_SA_PROPOSAL"
    source: Source = Source.OBSERVED


class IkeMessage(StrictModel):
    src: str
    dst: str
    timestamp: float
    initiator_spi: str
    responder_spi: str
    version: str
    exchange_type: int
    exchange: str
    flags: int
    message_id: int
    next_payload: int
    payload_types: list[int] = Field(default_factory=list)
    transforms: list[Transform] = Field(default_factory=list)
    ke_group: int | None = None
    encrypted: bool = False
    source: Source = Source.OBSERVED


class ReplaySignals(StrictModel):
    duplicates: int = 0
    regressions: int = 0
    large_gaps: int = 0
    zero_sequences: int = 0


class SecurityAssociation(StrictModel):
    sa_id: str
    spi: str
    direction: str
    source: str
    destination: str
    protocol: Literal["ESP", "AH"]
    ip_version: int
    nat_t: bool
    first_seen: float
    last_seen: float
    observed_duration: float
    packet_count: int
    bytes: int
    mean_packet_size: float
    std_packet_size: float
    packet_rate: float
    sequence_min: int
    sequence_max: int
    replay_signals: ReplaySignals
    mode: Evidence = Field(default_factory=Evidence)
    encryption_algorithm: Evidence = Field(default_factory=Evidence)
    encryption_key_bits: Evidence = Field(default_factory=Evidence)
    integrity_algorithm: Evidence = Field(default_factory=Evidence)
    pfs_enabled: Evidence = Field(default_factory=Evidence)
    dh_group: Evidence = Field(default_factory=Evidence)
    configured_lifetime: Evidence = Field(default_factory=Evidence)
    replay_window: Evidence = Field(default_factory=Evidence)
    esn: Evidence = Field(default_factory=Evidence)
    selectors: Evidence = Field(default_factory=Evidence)
    ike_association_reference: Evidence = Field(default_factory=Evidence)


class ProtocolSummary(StrictModel):
    counts: dict[str, int] = Field(default_factory=dict)
    ike_messages: list[IkeMessage] = Field(default_factory=list)
    ah_next_headers: list[int] = Field(default_factory=list)
    spi_changes: int = 0
    malformed_packets: int = 0
    unsupported_packets: int = 0
    source: Source = Source.OBSERVED


class Prediction(StrictModel):
    flow_id: str
    predicted_class: str
    confidence: float = Field(ge=0, le=1)
    probabilities: dict[str, float]
    features: dict[str, float]
    source: Source = Source.INFERRED
    limitations: list[str]


class Domain(StrictModel):
    name: str
    score: float | None = Field(default=None, ge=0, le=100)
    weight: float
    coverage: float = Field(ge=0, le=1)
    evidence: list[str]
    source: Source = Source.DERIVED


class Score(StrictModel):
    security_score: float | None = None
    risk_score: float | None = None
    assessment_coverage: float = Field(ge=0, le=1)
    score_status: Literal["AVAILABLE", "PROVISIONAL", "UNAVAILABLE"]
    overall_disposition: Recommendation
    domains: list[Domain]


class ThreatRow(StrictModel):
    threat: str
    evidence: list[str]
    status: Literal["DETECTED", "REVIEW", "UNKNOWN"]
    severity: Severity
    confidence: float
    impact: str
    recommendation: str


class Analysis(StrictModel):
    analysis_id: str
    created_at: str
    label: str
    capture_sha256: str
    capture_filename: str
    capture_source: Literal["SYNTHETIC_FIXTURE", "UNVERIFIED"] = "UNVERIFIED"
    capture_size: int
    packet_count: int
    capture_duration: float
    analysis_status: Literal["COMPLETE", "PARTIAL", "FAILED"]
    policy: PolicyName
    protocol_observations: ProtocolSummary
    security_associations: list[SecurityAssociation]
    traffic_predictions: list[Prediction]
    findings: list[Finding]
    score: Score
    threat_matrix: list[ThreatRow]
    limitations: list[str]
    report_references: dict[str, str]
    retain_capture: bool = False
    telemetry_provenance: list[str] = Field(default_factory=list)
    revision: int = 1


SEMANTIC_LIMITATIONS = [
    "UNKNOWN != SECURE. No finding does not mean safe.",
    "IKE_SA_INIT transforms describe IKE SA proposals, not ESP Child-SA algorithms.",
    "Encrypted IKE_AUTH/CREATE_CHILD_SA contents are not decoded.",
    "Passive ESP does not verify mode, Child-SA crypto, PFS, configured lifetime, ESN or replay window.",
    "Observed SA duration differs from configured SA lifetime.",
    "Sequence anomalies can reflect capture duplication, reordering, loss, ESN wrap or SPI reuse; they do not prove replay acceptance.",
    "Encrypted payload was not decrypted. Classification is based on flow metadata.",
    "AI confidence is model confidence, not attack probability.",
    "Protocol identification does not verify configuration; implementation/version/CVEs remain unknown.",
    "Outer endpoints, IP version, sizes, timing, rates, SPI changes and NAT-T remain visible.",
]
