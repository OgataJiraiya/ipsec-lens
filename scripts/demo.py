"""Run actual analyzer against labelled synthetic fixtures and write reports, no injected results."""
import json
import uuid
from scripts.fixtures import generate
from backend.services.analysis import build_analysis
from backend.telemetry.importer import Telemetry
from backend.reporting.html import render
from backend.database.store import Store
from backend.core.config import DATA_DIR


def main():
    store = Store(DATA_DIR)
    reports = DATA_DIR / "demo-reports"
    reports.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, path in generate().items():
        telemetry_path = path.parent / "telemetry.json"
        telemetry = Telemetry.model_validate_json(telemetry_path.read_text(), strict=True) if telemetry_path.exists() else None
        run = build_analysis(path, uuid.uuid4().hex, path.name, f"SYNTHETIC FIXTURE · {name}", "MODERN", telemetry=telemetry)
        store.save(run)
        for kind in ("executive", "technical"):
            (reports / f"{name}-{kind}.html").write_text(render(run, kind))
        (reports / f"{name}.json").write_text(run.model_dump_json(indent=2))
        results[name] = {"analysis_id": run.analysis_id, "packets": run.packet_count,
                         "status": run.analysis_status, **run.score.model_dump(exclude={"domains"}),
                         "findings": sorted({f.category for f in run.findings})}
    assert results["strong"]["security_score"] >= 90
    assert results["weak"]["overall_disposition"] == "HARDEN"
    assert "ESP_DUPLICATE_SEQUENCE" in results["replay"]["findings"]
    assert results["partial"]["score_status"] == "UNAVAILABLE"
    (reports / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
