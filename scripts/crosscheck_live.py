"""Read-only tshark comparison of supplied local captures. No shell or external traffic."""
from collections import Counter
import json
from pathlib import Path
import subprocess
import uuid
from backend.protocol.analyzer import analyze_capture
from backend.services.analysis import build_analysis
from backend.database.store import Store
from backend.core.config import DATA_DIR
from backend.reporting.html import render
from scripts.import_live_telemetry import normalize

FIELDS = ["frame.number","ip.src","ip.dst","ipv6.src","ipv6.dst","isakmp.version","isakmp.exchangetype",
          "isakmp.ispi","isakmp.rspi","esp.spi","esp.sequence","isakmp.tf.id.encr",
          "isakmp.tf.id.prf","isakmp.tf.id.integ","isakmp.tf.id.dh"]


def crosscheck(path: Path):
    command=["tshark","-r",str(path),"-T","fields"]
    for field in FIELDS:
        command.extend(["-e",field])
    response=subprocess.run(command,check=True,capture_output=True,text=True,timeout=60)
    rows=[dict(zip(FIELDS,line.split("\t"),strict=True)) for line in response.stdout.splitlines()]
    summary,flows,count,_,warnings=analyze_capture(path)
    ike=[r for r in rows if r["isakmp.version"]]
    esp=[r for r in rows if r["esp.spi"]]
    assert count==len(rows)
    assert summary.counts.get("IKE",0)==len(ike)
    assert summary.counts.get("ESP",0)==len(esp)
    for observed,external in zip(summary.ike_messages,ike,strict=True):
        assert observed.version=="IKEv"+str(int(external["isakmp.version"],0)>>4)
        assert observed.exchange_type==int(external["isakmp.exchangetype"])
        assert observed.initiator_spi==external["isakmp.ispi"].replace(":","")
        assert observed.responder_spi==external["isakmp.rspi"].replace(":","")
        for kind,name in [(1,"encr"),(2,"prf"),(3,"integ"),(4,"dh")]:
            actual=Counter(t.transform_id for t in observed.transforms if t.transform_type==kind)
            reference=Counter(int(v,0) for v in external["isakmp.tf.id."+name].split(",") if v)
            assert actual==reference
    for flow in flows:
        matching=[r for r in esp if (r["ip.src"] or r["ipv6.src"],r["ip.dst"] or r["ipv6.dst"],
                                     int(r["esp.spi"],0))==(flow.src,flow.dst,flow.spi)]
        assert flow.count==len(matching)
        assert flow.seen=={int(r["esp.sequence"],0) for r in matching}
    return {"packet_count":count,"ike_count":len(ike),"esp_count":len(esp),
            "ipsec_lens_counts":summary.counts,"warnings":warnings,
            "header_spi_sequence_transform_comparison":"PASS"}


def main():
    output={}
    store=Store(DATA_DIR)
    for name in ("strong","weak","transport","ipv6","natt"):
        folder=Path("runtime/live")/name
        capture=folder/"negotiation.pcap"
        telemetry=normalize(folder)
        (folder/"telemetry.json").write_text(telemetry.model_dump_json(indent=2)+"\n")
        result=crosscheck(capture)
        passive=build_analysis(capture,uuid.uuid4().hex,capture.name,"REAL LAB · "+name+" passive","MODERN")
        assert all(sa.mode.value is None and sa.pfs_enabled.value is None for sa in passive.security_associations)
        assisted=build_analysis(capture,uuid.uuid4().hex,capture.name,"REAL LAB · "+name,"MODERN",telemetry=telemetry)
        store.save(assisted)
        (folder/"analysis.json").write_text(assisted.model_dump_json(indent=2)+"\n")
        for kind in ("executive","technical"):
            (folder/(kind+".html")).write_text(render(assisted,kind))
        result.update(score=assisted.score.model_dump(),findings=[f.category for f in assisted.findings],
                      analysis_id=assisted.analysis_id,capture_sha256=assisted.capture_sha256,
                      sas=[s.model_dump(mode="json") for s in telemetry.sas])
        output[name]=result
    Path("docs/LIVE_PROTOCOL_VALIDATION.json").write_text(json.dumps(output,indent=2)+"\n")
    print(json.dumps({k:{x:v[x] for x in ("packet_count","ike_count","esp_count","header_spi_sequence_transform_comparison")} for k,v in output.items()},indent=2))


if __name__=="__main__":
    main()
