from pathlib import Path
import pytest
from backend.telemetry.raw import parse_swanctl, parse_xfrm_state, parse_xfrm_policy, raw_events, merge_endpoint_records
from backend.protocol.network import decode, PacketError
from scripts.fixtures import ip_packet
from training.real_evaluate import assert_split

FIXTURES=Path(__file__).parent/"fixtures/live"


@pytest.mark.parametrize("scenario,mode", [("strong","TUNNEL"),("weak","TUNNEL"),("transport","TRANSPORT"),("ipv6","TUNNEL"),("natt","TUNNEL")])
def test_actual_swanctl(scenario,mode):
    folder=FIXTURES/scenario
    result=parse_swanctl((folder/"left-sas.raw").read_text(),(folder/"left-conns.raw").read_text())
    assert len(result)==2
    assert all(sa.mode==mode for sa in result)
    assert all(sa.configured_lifetime is None and sa.replay_window is None for sa in result)
    if scenario=="weak":
        assert all(sa.encryption_algorithm=="AES-CBC" and sa.encryption_key_bits==128 for sa in result)
        assert all(sa.pfs_enabled is False and sa.dh_group is None for sa in result)
    else:
        assert all(sa.encryption_algorithm=="AES-GCM-16" and sa.encryption_key_bits==256 for sa in result)
        assert all(sa.pfs_enabled is True and sa.dh_group==20 for sa in result)


def test_swanctl_no_config_does_not_infer_pfs():
    result=parse_swanctl((FIXTURES/"weak/left-sas.raw").read_text())
    assert all(sa.pfs_enabled is None and sa.dh_group is None for sa in result)


@pytest.mark.parametrize("scenario",["strong","weak","transport","ipv6","natt"])
def test_actual_xfrm(scenario):
    states=parse_xfrm_state((FIXTURES/scenario/"left-xfrm-state.txt").read_text())
    assert states
    for sa,direction in states:
        assert sa.configured_lifetime==(7200 if scenario=="weak" else 3600)
        assert sa.encryption_key_bits==(128 if scenario=="weak" else 256)
        assert sa.esn is False  # Extended replay bitmap does not imply ESN negotiation.
        assert sa.replay_window==(64 if direction=="in" else None)
        assert sa.pfs_enabled is None and sa.dh_group is None


def test_exact_endpoint_merge():
    folder=FIXTURES/"strong"
    swan,states=[],[]
    for side in ("left","right"):
        swan+=parse_swanctl((folder/(side+"-sas.raw")).read_text(),(folder/(side+"-conns.raw")).read_text())
        states+=parse_xfrm_state((folder/(side+"-xfrm-state.txt")).read_text())
    merged=merge_endpoint_records(swan,states)
    active=[s for s in merged if s.pfs_enabled is True]
    assert len(active)==2 and all(s.replay_window==64 for s in active)


def test_conflicting_telemetry_rejected():
    folder=FIXTURES/"strong"
    swan=parse_swanctl((folder/"left-sas.raw").read_text())
    conflicting=swan[0].model_copy(update={"mode":"TRANSPORT"})
    with pytest.raises(ValueError,match="Conflicting"):
        merge_endpoint_records(swan,[(conflicting,"in")])


def test_xfrm_policy_actual_templates():
    rows=parse_xfrm_policy((FIXTURES/"transport/left-xfrm-policy.txt").read_text())
    assert rows and all(row["mode"]=="TRANSPORT" for row in rows)
    assert {r["direction"] for r in rows}<={"in","out","fwd"}


@pytest.mark.parametrize("payload",["list-sa event {lab {","list-sa event {x=1 x=2}","list-sa event {"+"x {"*18+"}"*19])
def test_raw_parser_clean_errors(payload):
    with pytest.raises(ValueError):
        raw_events(payload,"list-sa")


def test_unknown_raw_output():
    assert parse_swanctl("no records")==[]
    assert parse_xfrm_state("unsupported output")==[]


@pytest.mark.parametrize("version",[False,True])
def test_ethertype_disagreement_rejected(version):
    raw=bytearray(ip_packet(b"x"*16,50,version))
    raw[12:14]=b"\x08\x00" if version else b"\x86\xdd"
    with pytest.raises(PacketError):
        decode(bytes(raw),1)


def test_real_split_manifest():
    import json
    path=Path("datasets/manifests/real_testbed.json")
    rows=json.loads(path.read_text())
    assert len(rows)==120
    assert_split(rows)
    assert len({row["group_id"] for row in rows})==12
    assert all(row["source"]=="REAL_TESTBED_GENERATED_WORKLOAD" for row in rows)


def test_split_rejects_related_sessions_across_sets():
    with pytest.raises(ValueError):
        assert_split([{"group_id":"same","session_id":"a","capture_sha256":"a","split":"train"},
                      {"group_id":"same","session_id":"b","capture_sha256":"b","split":"test"}])


def test_optional_dh_policy_is_unknown():
    folder=FIXTURES/"strong"
    conns=(folder/"left-conns.raw").read_text().replace("ke=[ECP_384]","ke=[ECP_384 NONE]")
    result=parse_swanctl((folder/"left-sas.raw").read_text(),conns)
    assert all(sa.pfs_enabled is None for sa in result)


@pytest.mark.parametrize("payload",[
    "list-sa event {lab {state=ESTABLISHED local-host=172.29.160.10 remote-host=172.29.160.20 child-sas=bad}}",
    "list-sa event {lab {state=ESTABLISHED local-host=172.29.160.10 remote-host=172.29.160.20 child-sas {x=bad}}}",
])
def test_invalid_swanctl_shapes_are_clean_errors(payload):
    with pytest.raises(ValueError):
        parse_swanctl(payload)
