import json
import random
import pytest
from pydantic import ValidationError
from backend.telemetry.importer import Telemetry
from backend.core.security_policy import POLICIES, hardening
from testbed.scripts.generate import generate, PROFILES


@pytest.mark.parametrize("profile",list(PROFILES))
@pytest.mark.parametrize("mode",["tunnel","transport"])
def test_lab_configuration_generation(tmp_path,profile,mode):
    generate(profile,mode,ipv6=True,pfs=False,output=tmp_path)
    left=(tmp_path/"left/swanctl.conf").read_text()
    right=(tmp_path/"right/swanctl.conf").read_text()
    assert f"mode = {mode}" in left and "fd26:160::10" in left
    assert "remote_addrs = fd26:160::10" in right
    assert (tmp_path/"left/swanctl.conf").stat().st_mode & 0o777 == 0o600
    line=next(line for line in left.splitlines() if "esp_proposals =" in line)
    assert not any(group in line for group in ("ecp","modp","curve"))
    assert json.loads((tmp_path/"scenario.json").read_text())["status"]=="GENERATED_NOT_VERIFIED"


def test_hardening_profiles():
    for name,policy in POLICIES.items():
        snippet=hardening(name)
        assert "RECOMMENDATION" in snippet and policy.ike in snippet and "keyexchange=ikev2" in snippet


def test_validation_does_not_reflect_input(client):
    response=client.post("/api/analyses/"+"a"*32+"/telemetry",json={"private_key":"DO_NOT_ECHO"})
    assert response.status_code==422 and "DO_NOT_ECHO" not in response.text


def test_host_header_rejected(client):
    assert client.get("/api/health",headers={"host":"attacker.invalid"}).status_code==400


def test_telemetry_bounded_mutations(strong):
    original=json.loads((strong.parent/"telemetry.json").read_text())
    rng=random.Random(26160)
    for _ in range(100):
        obj=json.loads(json.dumps(original))
        field=rng.choice(["replay_window","configured_lifetime","mode","dh_group"])
        obj["sas"][0][field]=rng.choice([None,-1,10**30,[],{},"unexpected"])
        try:
            result=Telemetry.model_validate(obj)
            assert len(result.sas)==2
        except ValidationError:
            pass


def test_spi_change_visibility(tmp_path):
    import struct
    from scripts.fixtures import ip_packet, write_pcap
    from backend.protocol.analyzer import analyze_capture
    p=tmp_path/"change.pcap"
    write_pcap(p,[(i,ip_packet(struct.pack("!II",spi,1)+b"x"*16,50))
                  for i,spi in enumerate((0x1234,0x1235))])
    summary,flows,_,_,_=analyze_capture(p)
    assert summary.spi_changes==1 and len(flows)==2
