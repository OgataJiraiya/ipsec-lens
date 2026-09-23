"""Exercise the same-origin deployment shell with the bundled synthetic fixtures."""
from fastapi.testclient import TestClient

from deploy.render_app import create_preview_app


def test_preview_workflow_and_static_routes(tmp_path):
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
            assert not (tmp_path / "runtime" / "captures").exists()
            identity = run["analysis_id"]
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
        blocked = client.post("/api/analyses", files={"capture": ("weak.pcap", capture.content)},
                              headers={"Origin": "https://foreign.example"})
        assert blocked.status_code == 403
    app.state.store.engine.dispose()
