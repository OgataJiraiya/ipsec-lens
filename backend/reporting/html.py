"""Standalone escaped HTML reports; no external assets, scripts, or remote requests."""
import html
import json
from backend.core.security_policy import hardening


def render(analysis, kind: str) -> str:
    def esc(value):
        return html.escape(str(value), quote=True)
    score = analysis.score
    metrics = "".join(f"<div><small>{esc(k)}</small><strong>{esc(v)}</strong></div>" for k, v in [
        ("Security score", score.security_score if score.security_score is not None else "UNKNOWN"),
        ("Risk score", score.risk_score if score.risk_score is not None else "UNKNOWN"),
        ("Coverage", f"{score.assessment_coverage:.0%}"), ("Score status", score.score_status),
        ("Disposition", score.overall_disposition)])
    rows = "".join(f"<tr><td>{esc(f.severity)}</td><td>{esc(f.category)}</td><td>{esc(f.source)}</td>"
                   f"<td>{esc(f.reason)}</td><td>{esc(f.remediation)}</td></tr>" for f in analysis.findings)
    limitations = "".join(f"<li>{esc(x)}</li>" for x in analysis.limitations)
    technical = ""
    if kind == "technical":
        sections = {"Protocol observations": analysis.protocol_observations.model_dump(mode="json"),
                    "Security associations": [s.model_dump(mode="json") for s in analysis.security_associations],
                    "Traffic predictions": [p.model_dump(mode="json") for p in analysis.traffic_predictions],
                    "Threat matrix": [r.model_dump(mode="json") for r in analysis.threat_matrix],
                    "Domain scores": [d.model_dump(mode="json") for d in score.domains],
                    "Telemetry provenance": analysis.telemetry_provenance,
                    "Finding evidence": [f.model_dump(mode="json") for f in analysis.findings]}
        technical = "".join(f"<h2>{esc(title)}</h2><pre>{esc(json.dumps(value, indent=2))}</pre>"
                            for title, value in sections.items())
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>IPsecLens {esc(kind)} report</title><style>
body{{font:15px system-ui;max-width:1120px;margin:40px auto;padding:24px;color:#142639}}
h1{{font-size:32px}} h2{{margin-top:32px}} small{{display:block;color:#486577}} strong{{font-size:24px}}
.metrics{{display:flex;gap:28px;flex-wrap:wrap;padding:24px;background:#eef5f7}}
table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;border-bottom:1px solid #cdd9df;padding:10px;vertical-align:top}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef5f7;padding:18px;font-size:12px}}
li{{margin:8px 0}}@media print{{body{{margin:0}}pre{{break-inside:auto}}}}</style>
<header>IPsecLens AI · SIH 26160</header><h1>{esc(kind.title())} assessment report</h1>
<p>{esc(analysis.label or analysis.capture_filename)} · Policy {esc(analysis.policy)}</p>
<p>Capture source: {esc(analysis.capture_source.replace("_", " "))}. UNVERIFIED means capture origin is not established.</p>
<p>Analysis {esc(analysis.analysis_id)} · Revision {analysis.revision} · {esc(analysis.created_at)}</p>
<p>Capture: {esc(analysis.capture_filename)} · {analysis.capture_size} bytes · {analysis.packet_count} packets<br>
SHA-256: {esc(analysis.capture_sha256)}</p><div class="metrics">{metrics}</div>
<p>Assessment reflects available evidence under a prototype policy. ACCEPT is not a safety certification.
AI confidence is not attack probability. Missing evidence receives no secure credit.</p>
<h2>Findings and recommendations</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Source</th>
<th>Reason</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Configuration hardening · RECOMMENDATION</h2><pre>{esc(hardening(analysis.policy))}</pre>
{technical}<h2>Limitations</h2><ul>{limitations}</ul></html>"""
