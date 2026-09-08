"""Offline import of local lab output. Raw XFRM secrets never enter normalized artifacts."""
import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from backend.telemetry.raw import parse_swanctl, parse_xfrm_state, parse_xfrm_policy, merge_endpoint_records
from backend.telemetry.importer import Telemetry
from backend.protocol.analyzer import analyze_capture


def normalize(folder: Path) -> Telemetry:
    capture = folder / "negotiation.pcap"
    summary, flows, _, _, _ = analyze_capture(capture)
    wanted = {(f.src,f.dst,f.protocol,f.spi) for f in flows}
    swan, xfrm = [], []
    for side in ("left","right"):
        swan.extend(parse_swanctl((folder/side/"sas.raw").read_text(),(folder/side/"conns.raw").read_text()))
        xfrm.extend(parse_xfrm_state((folder/side/"xfrm-state.private").read_text()))
        policies = parse_xfrm_policy((folder/side/"xfrm-policy.txt").read_text())
        # Cross-check mode only against exact SPI-bearing policy templates.
        for sa in swan:
            for policy in policies:
                if (policy["source"],policy["destination"],policy["spi"]) == (sa.source,sa.destination,sa.spi):
                    if sa.mode != policy["mode"]:
                        raise ValueError("XFRM policy/SA mode mismatch")
    records = merge_endpoint_records(swan,xfrm)
    records = [s for s in records if (s.source,s.destination,s.protocol,int(s.spi,16)) in wanted]
    with capture.open("rb") as stream:
        digest = hashlib.file_digest(stream,"sha256").hexdigest()
    return Telemetry(adapter="strongswan-normalized", capture_sha256=digest,
        collected_at=datetime.fromtimestamp((folder/"left/sas.raw").stat().st_mtime,timezone.utc),
        provenance="REAL TESTBED: swanctl list-sas/list-conns + XFRM state/policy from both endpoints; replay policy from receiving state",
        synthetic=False, sas=records)


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("folder",type=Path)
    args=p.parse_args()
    (args.folder/"telemetry.json").write_text(normalize(args.folder).model_dump_json(indent=2)+"\n")
    print("Wrote capture-bound normalized telemetry; key material discarded.")
