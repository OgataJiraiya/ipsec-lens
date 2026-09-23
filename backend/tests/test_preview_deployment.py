"""Exercise the same-origin deployment shell with the bundled synthetic fixtures."""
import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.main import create_app
from deploy.render_app import create_preview_app

STRONG_CAPTURE = Path(__file__).resolve().parents[2] / "demo" / "strong" / "strong.pcap"


def test_preview_image_packages_canonical_model():
    root = Path(__file__).resolve().parents[2]
    expected = "ccf24a3017e7715ff203e5ee311ac97957d6168702b63f26ff7f19cc5c78ecad"
    assert (root / "models" / "classifier.sha256").read_text().strip() == expected
    assert hashlib.sha256((root / "models" / "classifier.json").read_bytes()).hexdigest() == expected
    assert "!models/classifier.json" in (root / ".dockerignore").read_text().splitlines()
    dockerfile = (root / "Dockerfile.preview").read_text()
    assert "python -m training.train" not in dockerfile
    assert "COPY models/classifier.json ./models/classifier.json" in dockerfile
    assert "COPY models/classifier.sha256 ./models/classifier.sha256" in dockerfile
    assert "assert actual==expected" in dockerfile
    assert "COPY --from=python-build /app/models/classifier.json ./models/classifier.json" in dockerfile
    assert "COPY --from=python-build /app/models/classifier.sha256 ./models/classifier.sha256" in dockerfile


def test_preview_workflow_and_static_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSECLENS_SUBMISSION_PREVIEW", "true")
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>preview shell</html>")
    (dist / "assets" / "app.js").write_text("preview asset")
    app = create_preview_app(dist=dist, data_dir=tmp_path / "runtime")
    with TestClient(app, base_url="https://preview.onrender.com") as client:
        assert client.get("/").text == "<html>preview shell</html>"
        assert client.get("/reports").text == "<html>preview shell</html>"
        assert client.get("/assets/app.js").text == "preview asset"
        assert client.get("/api/health").json()["status"] == "ok"
        assert client.get("/api/no-such-route").status_code == 404
        assert client.get("/fixtures/weak/private.pcap").status_code == 404
        for scenario in ("weak", "strong"):
            capture = client.get(f"/fixtures/{scenario}/{scenario}.pcap")
            telemetry = client.get(f"/fixtures/{scenario}/telemetry.json")
            assert capture.status_code == telemetry.status_code == 200
            assert b"SYNTHETIC FIXTURE" in telemetry.content
            response = client.post("/api/analyses", files={"capture": (f"{scenario}.pcap", capture.content)},
                                   data={"policy": "MODERN", "telemetry": telemetry.text,
                                         "retain_capture": "true"},
                                   headers={"Origin": "https://preview.onrender.com"})
            assert response.status_code == 201, response.text
            run = response.json()
            assert run["capture_source"] == "SYNTHETIC_FIXTURE"
            assert run["policy"] == "MODERN"
            assert run["retain_capture"] is False
            assert not (tmp_path / "runtime" / "captures").exists()
            identity = run["analysis_id"]
            assert client.get(f"/api/analyses/{identity}").status_code == 200
            assert any(item["analysis_id"] == identity for item in client.get("/api/analyses").json())
            for route in ("protocol", "sas", "findings", "score"):
                assert client.get(f"/api/analyses/{identity}/{route}").status_code == 200
            for method, suffix in ((client.delete, ""), (client.get, "/export")):
                blocked = method(f"/api/analyses/{identity}{suffix}")
                assert blocked.status_code == 403
                assert blocked.json() == {"detail": "Disabled in submission preview"}
            assert client.get(f"/api/analyses/{identity}").status_code == 200
            for kind in ("executive", "technical"):
                report = client.get(f"/api/analyses/{identity}/report/{kind}")
                assert report.status_code == 200
                assert b"SYNTHETIC FIXTURE" in report.content
                pdf = client.get(f"/api/analyses/{identity}/report/{kind}?format=pdf")
                assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
            if scenario == "weak":
                assert run["score"]["overall_disposition"] != "ACCEPT"
                assert any("sequence" in item["category"].lower() for item in run["findings"])
        no_telemetry = client.post("/api/analyses", files={"capture": ("weak.pcap", capture.content)},
                                   data={"policy": "MODERN"},
                                   headers={"Origin": "https://preview.onrender.com"})
        assert no_telemetry.status_code == 201
        assert all(sa["encryption_algorithm"]["source"] == "UNKNOWN"
                   for sa in no_telemetry.json()["security_associations"])
        imported = json.loads(telemetry.text)
        imported["expected_revision"] = 1
        import_response = client.post(
            f"/api/analyses/{no_telemetry.json()['analysis_id']}/telemetry", json=imported,
            headers={"Origin": "https://preview.onrender.com"})
        assert import_response.status_code == 200, import_response.text
        assert import_response.json()["revision"] == 2
        blocked = client.post("/api/analyses", files={"capture": ("weak.pcap", capture.content)},
                              headers={"Origin": "https://foreign.example"})
        assert blocked.status_code == 403
    app.state.store.engine.dispose()


def test_preview_flag_applies_to_direct_api(tmp_path, monkeypatch):
    monkeypatch.setenv("IPSECLENS_SUBMISSION_PREVIEW", "true")
    app = create_app(tmp_path / "preview")
    with TestClient(app) as client:
        response = client.post("/api/analyses", files={"capture": ("strong.pcap", STRONG_CAPTURE.read_bytes())},
                               data={"retain_capture": "true"})
        assert response.status_code == 201, response.text
        run = response.json()
        assert run["retain_capture"] is False
        assert not (tmp_path / "preview" / "captures").exists()
        identity = run["analysis_id"]
        assert client.delete(f"/api/analyses/{identity}").json() == {
            "detail": "Disabled in submission preview"}
        assert client.get(f"/api/analyses/{identity}/export").status_code == 403
    app.state.store.engine.dispose()


def test_normal_mode_keeps_export_delete_and_retention(tmp_path, monkeypatch):
    monkeypatch.delenv("IPSECLENS_SUBMISSION_PREVIEW", raising=False)
    app = create_app(tmp_path / "normal")
    with TestClient(app) as client:
        response = client.post("/api/analyses", files={"capture": ("strong.pcap", STRONG_CAPTURE.read_bytes())},
                               data={"retain_capture": "true"})
        assert response.status_code == 201, response.text
        run = response.json()
        assert run["retain_capture"] is True
        identity = run["analysis_id"]
        assert (tmp_path / "normal" / "captures" / f"{identity}.pcap").exists()
        assert client.get(f"/api/analyses/{identity}/export").status_code == 200
        assert client.delete(f"/api/analyses/{identity}").json()["status"] == "DELETED"
        assert client.get(f"/api/analyses/{identity}").status_code == 404
    app.state.store.engine.dispose()
