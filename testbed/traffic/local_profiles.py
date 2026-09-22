"""Synthetic application-like UDP workloads to the isolated lab subnet, not application ground truth."""
import argparse
import ipaddress
import socket
import time
from training.generate_manifest import samples, LABELS

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--peer",required=True)
    p.add_argument("--class-name",choices=LABELS,required=True)
    p.add_argument("--port",type=int,default=19000)
    a=p.parse_args()
    peer=ipaddress.ip_address(a.peer)
    allowed = ipaddress.ip_network("fd26:160::/64") if peer.version==6 else ipaddress.ip_network("172.29.160.0/24")
    if peer not in allowed:
        p.error("Peer must belong to the isolated IPsecLens testbed subnet")
    if not 1024 <= a.port <= 65535:
        p.error("Port must be unprivileged")
    family=socket.AF_INET6 if peer.version==6 else socket.AF_INET
    with socket.socket(family,socket.SOCK_DGRAM) as s:
        previous=0.0
        for stamp,size in samples({"seed":26160,"label":a.class_name}):
            time.sleep(min(stamp-previous,2))
            s.sendto(bytes(max(1,size-60)),(a.peer,a.port))
            previous=stamp
