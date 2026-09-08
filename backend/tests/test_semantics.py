import json
import pytest
from pydantic import ValidationError
from backend.services.analysis import build_analysis
from backend.services.policy import assess
from backend.telemetry.importer import Telemetry, apply_telemetry
from backend.schemas.models import Evidence, Source
from backend.reporting.html import render


def test_unknown_is_not_secure(fixtures):
    run=build_analysis(fixtures["partial"],"b"*32,"partial.pcap","","MODERN")
    assert run.score.security_score is None and run.score.score_status=="UNAVAILABLE"
    assert run.score.assessment_coverage==.05
    for sa in run.security_associations:
        for field in ("mode","encryption_algorithm","integrity_algorithm","pfs_enabled","replay_window",
                      "configured_lifetime","esn","dh_group"):
            assert getattr(sa,field).value is None
            assert getattr(sa,field).source==Source.UNKNOWN


def test_ike_not_esp(strong):
    run=build_analysis(strong,"b"*32,"strong.pcap","","MODERN")
    assert run.protocol_observations.ike_messages[0].transforms
    assert all(s.encryption_algorithm.value is None for s in run.security_associations)
    assert run.score.security_score is None


def test_strong_assisted(strong_run):
    assert strong_run.score.security_score==97.5
    assert strong_run.score.assessment_coverage==1
    assert not any(f.severity in ("HIGH","CRITICAL") for f in strong_run.findings)
    assert all(s.mode.source==Source.ASSISTED for s in strong_run.security_associations)


def test_weak(fixtures):
    p=fixtures["weak"]
    t=Telemetry.model_validate_json((p.parent/"telemetry.json").read_bytes())
    r=build_analysis(p,"c"*32,p.name,"","MODERN",telemetry=t)
    assert r.score.security_score==30.5 and r.score.overall_disposition=="HARDEN"
    assert {"WEAK_DH_GROUP","PFS_DISABLED","LONG_SA_LIFETIME","REPLAY_PROTECTION_DISABLED"} <= {f.category for f in r.findings}


def test_gaps_not_attack(strong_run):
    strong_run.security_associations[0].replay_signals.large_gaps=1
    findings,_,_=assess(strong_run.protocol_observations,strong_run.security_associations,"MODERN")
    f=next(f for f in findings if f.category=="ESP_SEQUENCE_GAP")
    assert f.severity=="INFO" and "not replay attacks" in f.limitations[0]


def test_partial_sa_coverage(strong_run):
    strong_run.security_associations[0].pfs_enabled=Evidence()
    _,score,_=assess(strong_run.protocol_observations,strong_run.security_associations,"MODERN")
    assert score.score_status=="PROVISIONAL" and score.assessment_coverage<1


def test_partial_parser_caps_score(strong_run):
    _,score,_=assess(strong_run.protocol_observations,strong_run.security_associations,"MODERN",True)
    assert score.assessment_coverage==.5 and score.score_status=="PROVISIONAL"


def test_severe_finding_overrides_score(strong_run):
    strong_run.security_associations[0].pfs_enabled=Evidence(value=False,source=Source.ASSISTED,confidence=.9)
    _,score,_=assess(strong_run.protocol_observations,strong_run.security_associations,"MODERN")
    assert score.security_score>80 and score.overall_disposition=="HARDEN"


def test_policies_differ(strong_run):
    for s in strong_run.security_associations:
        s.encryption_algorithm.value="AES-CBC"
        s.integrity_algorithm.value="HMAC-SHA2-256-128"
        s.dh_group.value=14
    _,modern,_=assess(strong_run.protocol_observations,strong_run.security_associations,"MODERN")
    _,compat,_=assess(strong_run.protocol_observations,strong_run.security_associations,"COMPATIBILITY")
    assert compat.security_score>modern.security_score


def test_telemetry_identity_mismatch(strong_run,strong):
    t=Telemetry.model_validate_json((strong.parent/"telemetry.json").read_bytes())
    with pytest.raises(ValueError):
        apply_telemetry(strong_run.security_associations,t,"0"*64)


def test_telemetry_unmatched_no_mutation(strong_run,strong):
    t=Telemetry.model_validate_json((strong.parent/"telemetry.json").read_bytes())
    t.sas[-1].spi="0x9999"
    original=strong_run.model_dump_json()
    with pytest.raises(ValueError):
        apply_telemetry(strong_run.security_associations,t,strong_run.capture_sha256)
    assert original==strong_run.model_dump_json()


def test_telemetry_rejects_keys(strong):
    data=json.loads((strong.parent/"telemetry.json").read_text())
    data["sas"][0]["encryption_key"]="secret"
    with pytest.raises(ValidationError):
        Telemetry.model_validate(data)


@pytest.mark.parametrize("value",[{"value":None,"source":"ASSISTED","confidence":.9},
                                  {"value":True,"source":"UNKNOWN","confidence":0},
                                  {"value":True,"source":"OBSERVED","confidence":1.1}])
def test_evidence_contract(value):
    with pytest.raises(ValidationError):
        Evidence.model_validate(value)


@pytest.mark.parametrize("kind",["executive","technical"])
def test_report_escaping(strong_run,kind):
    strong_run.label='<img src=x onerror="alert(1)">'
    result=render(strong_run,kind)
    assert "<img" not in result and "&lt;img" in result
    assert strong_run.capture_sha256 in result and "UNKNOWN" in result
    if kind=="technical":
        assert "Threat matrix" in result and "Traffic predictions" in result
