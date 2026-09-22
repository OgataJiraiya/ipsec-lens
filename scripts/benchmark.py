"""Measured local benchmark; run each size in a fresh subprocess to isolate peak RSS."""
import argparse
import json
import platform
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from backend.protocol.analyzer import analyze_capture
from backend.ml.features import extract
from backend.ml.classifier import predict
from backend.services.analysis import build_analysis
from backend.reporting.html import render
from scripts.fixtures import ip_packet, write_pcap
import struct


def worker(count):
    with tempfile.TemporaryDirectory(prefix="ipseclens-benchmark-") as folder:
        path=Path(folder)/"benchmark.pcap"
        packets=((1700000000+i*.02,ip_packet(struct.pack("!II",0x1234,i+1)+b"x"*160,50)) for i in range(count))
        write_pcap(path,packets)
        start=time.perf_counter()
        _,flows,actual,_,_=analyze_capture(path)
        parse=time.perf_counter()-start
        start=time.perf_counter()
        extract(flows[0].samples)
        features=time.perf_counter()-start
        start=time.perf_counter()
        predict("bench",flows[0].samples)
        inference=time.perf_counter()-start
        run=build_analysis(path,"f"*32,"benchmark.pcap","Benchmark","MODERN")
        start=time.perf_counter()
        report=render(run,"technical")
        report_time=time.perf_counter()-start
        return {"packets":actual,"capture_bytes":path.stat().st_size,"parse_seconds":parse,
                "feature_seconds":features,"inference_seconds_including_first_model_load":inference,
                "report_seconds":report_time,"report_bytes":len(report.encode()),
                "peak_process_rss_mib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--worker",type=int)
    args=p.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return
    results=[]
    for size in (10000,100000,500000):
        completed=subprocess.run([sys.executable,"-m","scripts.benchmark","--worker",str(size)],
                                 capture_output=True,text=True,check=True,timeout=180)
        results.append(json.loads(completed.stdout))
    cpu="unknown"
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu=line.split(":",1)[1].strip()
            break
    output={"platform":platform.platform(),"python":platform.python_version(),"cpu":cpu,
            "caveats":["One synthetic directional ESP flow; not representative of all captures.",
                       "Classifier samples first 2048 packets; sequence tracking covers all packets.",
                       "Peak RSS includes imports, model and repeated full analysis; Linux ru_maxrss.",
                       "Wall-clock measurements on shared host, no throughput SLA."],"measurements":results}
    Path("docs/BENCHMARK.json").write_text(json.dumps(output,indent=2)+"\n")
    print(json.dumps(output,indent=2))


if __name__=="__main__":
    main()
