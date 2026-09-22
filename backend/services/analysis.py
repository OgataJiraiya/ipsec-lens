import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from backend.protocol.analyzer import analyze_capture
from backend.ml.classifier import predict
from backend.schemas.models import Analysis, SEMANTIC_LIMITATIONS, PolicyName
from backend.services.policy import assess
from backend.telemetry.importer import Telemetry, apply_telemetry
from backend.core.config import ROOT


def build_analysis(path: Path, analysis_id: str, filename: str, label: str, policy: PolicyName,
                   retain=False, telemetry: Telemetry | None = None) -> Analysis:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    # Fixed local bundled manifests only. A filename/label cannot establish provenance.
    fixture_hashes = {json.loads((ROOT / "demo" / name / "manifest.json").read_text())["capture_sha256"]
                      for name in ("strong", "weak", "replay", "partial", "ipv6")}
    summary, flows, count, duration, warnings = analyze_capture(path)
    sas = [f.result() for f in flows]
    provenance = apply_telemetry(sas, telemetry, digest) if telemetry else []
    findings, score, matrix = assess(summary, sas, policy, bool(warnings))
    predictions = [predict(sa.sa_id, flow.samples) for sa, flow in zip(sas, flows, strict=True) if sa.protocol == "ESP"]
    limitations = list(SEMANTIC_LIMITATIONS) + warnings
    if any(f.count > 2048 for f in flows):
        limitations.append("Classifier features use only the first 2048 packets per directional SA.")
    if not predictions or any(not p.probabilities for p in predictions):
        limitations.append("Traffic classification unavailable for one or more flows.")
    return Analysis(analysis_id=analysis_id, created_at=datetime.now(timezone.utc).isoformat(),
                    label=label, capture_sha256=digest, capture_filename=filename,
                    capture_source="SYNTHETIC_FIXTURE" if digest in fixture_hashes else "UNVERIFIED",
                    capture_size=path.stat().st_size, packet_count=count, capture_duration=duration,
                    analysis_status="PARTIAL" if warnings else "COMPLETE", policy=policy,
                    protocol_observations=summary, security_associations=sas, traffic_predictions=predictions,
                    findings=findings, score=score, threat_matrix=matrix, limitations=limitations,
                    report_references={kind: f"/api/analyses/{analysis_id}/report/{kind}"
                                       for kind in ("executive", "technical")},
                    retain_capture=retain, telemetry_provenance=provenance)
