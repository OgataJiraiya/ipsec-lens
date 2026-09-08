import json
import pytest
from backend.core import config


def upload(client,path,**data):
    return client.post("/api/analyses",files={"capture":(path.name,path.read_bytes(),"application/octet-stream")},data=data)


def test_full_workflow(client,strong):
    telemetry=(strong.parent/"telemetry.json").read_text()
    response=upload(client,strong,telemetry=telemetry,label="API test")
    assert response.status_code==201,response.text
    run=response.json()
    identity=run["analysis_id"]
    assert run["score"]["security_score"]==97.5
    assert client.get("/api/analyses").json()[0]["analysis_id"]==identity
    for route in ("","/protocol","/sas","/traffic","/findings","/score","/hardening"):
        assert client.get("/api/analyses/"+identity+route).status_code==200
    for kind in ("executive","technical"):
        report=client.get(f"/api/analyses/{identity}/report/{kind}")
        assert report.status_code==200 and "attachment" in report.headers["content-disposition"]
    from pathlib import Path
    assert not list((Path(client.app.state.store.engine.url.database).parent/"work").iterdir())


def test_telemetry_update_and_revision(client,strong):
    run=upload(client,strong).json()
    t=json.loads((strong.parent/"telemetry.json").read_text())
    t["expected_revision"]=1
    url=f"/api/analyses/{run['analysis_id']}/telemetry"
    response=client.post(url,json=t)
    assert response.status_code==200,response.text
    assert response.json()["score"]["security_score"]==97.5
    assert response.json()["revision"]==2
    assert client.post(url,json=t).status_code==409


def test_bad_json(client,strong):
    assert upload(client,strong,telemetry="{").status_code==422


@pytest.mark.parametrize("name",["../../evil.pcap","..\\..\\evil.pcap",'<script>.pcap'])
def test_filename_safety(client,strong,name):
    response=client.post("/api/analyses",files={"capture":(name,strong.read_bytes())})
    assert response.status_code==201
    filename=response.json()["capture_filename"]
    assert "/" not in filename and "\\" not in filename and "<" not in filename


def test_unsupported_file(client):
    response=client.post("/api/analyses",files={"capture":("payload.py",b"print(1)")})
    assert response.status_code==422 and "Traceback" not in response.text


def test_oversize_actual_bytes(client,strong,monkeypatch):
    monkeypatch.setattr(config,"MAX_UPLOAD",100)
    assert upload(client,strong).status_code==413


def test_request_body_limit(client,monkeypatch):
    monkeypatch.setattr(config,"MAX_TELEMETRY",32)
    response=client.post("/api/analyses/"+("a"*32)+"/telemetry",content=b"x"*33,
                         headers={"content-type":"application/json"})
    assert response.status_code==413


def test_cross_origin_write(client,strong):
    response=client.post("/api/analyses",files={"capture":(strong.name,strong.read_bytes())},
                         headers={"Origin":"https://untrusted.example"})
    assert response.status_code==403


def test_invalid_policy(client,strong):
    assert upload(client,strong,policy="FAKE").status_code==422


def test_missing_and_traversal(client):
    assert client.get("/api/analyses/"+"z"*32).status_code==404
    assert client.get("/api/analyses/..%2Fetc%2Fpasswd").status_code==404


def test_health_model_policies(client):
    for endpoint in ("/health","/model/info","/policies"):
        assert client.get("/api"+endpoint).status_code==200


def test_retain_capture(client,strong):
    from pathlib import Path
    run=upload(client,strong,retain_capture="true").json()
    folder=Path(client.app.state.store.engine.url.database).parent
    assert (folder/"captures"/(run["analysis_id"]+".pcap")).exists()
