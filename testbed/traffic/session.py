"""Generated workloads over actual lab networking. Labels describe workload, not organic applications."""
import argparse
import random
import socket
import struct
import time
import ipaddress


def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=["serve","send"])
    p.add_argument("--peer",required=True)
    p.add_argument("--label",choices=["VOIP","MESSAGING","VIDEO"],default="VOIP")
    p.add_argument("--seed",type=int,default=1)
    args=p.parse_args()
    peer=ipaddress.ip_address(args.peer)
    if peer not in ipaddress.ip_network("172.29.160.0/24"):
        p.error("Only the isolated lab subnet is allowed")
    rng=random.Random(args.seed)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        if args.mode=="serve":
            sock.bind((str(peer),18081))
            while True:
                data,addr=sock.recvfrom(2048)
                if data.startswith(b"MSG:"):
                    sock.sendto(b"ACK:"+data[4:20],addr)
        else:
            sock.settimeout(.2)
            count=rng.randint(45,70) if args.label=="VOIP" else rng.randint(25,40) if args.label=="MESSAGING" else rng.randint(100,160)
            for i in range(count):
                if args.label=="VOIP":
                    data=struct.pack("!BBHII",0x80,0,i,i*160,1234)+bytes(rng.randint(120,180))
                    gap=rng.uniform(.012,.025)
                elif args.label=="MESSAGING":
                    data=b"MSG:"+bytes(rng.randint(30,190))
                    gap=rng.uniform(.02,.06) if i%6 else rng.uniform(.12,.2)
                else:
                    data=bytes(rng.randint(1100,1350))
                    gap=rng.uniform(.0004,.002)
                sock.sendto(data,(str(peer),18081))
                if args.label=="MESSAGING":
                    sock.recvfrom(2048)
                time.sleep(gap)


if __name__=="__main__":
    main()
