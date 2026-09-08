"""Explicit bounded local capture CLI. No web capture or shell interpretation."""
import argparse
import os
from pathlib import Path
import pwd
import selectors
import signal
import socket
import subprocess
import tempfile
import time

FILTER = "(udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 protochain 50 or ip6 protochain 51)"


def command(interface: str, max_packets: int, full: bool = False) -> list[str]:
    if interface not in {name for _, name in socket.if_nameindex()}:
        raise ValueError("Interface is not a local interface")
    if not 1 <= max_packets <= 1_000_000:
        raise ValueError("Packet limit must be 1..1000000")
    # stdout avoids tcpdump opening/chowning a path. Parent owns an exclusive no-follow descriptor.
    args = ["tcpdump", "-Z", pwd.getpwuid(os.getuid()).pw_name, "--immediate-mode",
            "-i", interface, "-n", "-s", "65535", "-U", "-c", str(max_packets), "-w", "-"]
    if not full:
        args.append(FILTER)
    return args


def capture(interface: str, output: Path, duration: float = 30, max_bytes: int = 256*1024*1024,
            max_packets: int = 1_000_000, full: bool = False):
    if not 0 < duration <= 3600 or not 24 <= max_bytes <= 256*1024*1024:
        raise ValueError("Invalid capture duration or byte ceiling")
    args = command(interface,max_packets,full)
    # Parent directory must already exist and be controlled by the invoking operator.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    success = False
    total = 0
    try:
        with os.fdopen(descriptor,"wb") as file, tempfile.TemporaryFile() as errors:
            with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=errors) as process:
                assert process.stdout is not None
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout,selectors.EVENT_READ)
                    stop_at = time.monotonic()+duration
                    stopped = None
                    try:
                        while True:
                            now = time.monotonic()
                            if now >= stop_at and stopped is None:
                                process.send_signal(signal.SIGINT)
                                stopped = now
                            if stopped is not None and now-stopped > 5:
                                raise RuntimeError("Capture process did not stop promptly")
                            if not selector.select(timeout=.05):
                                continue
                            chunk = os.read(process.stdout.fileno(),65536)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > max_bytes:
                                raise ValueError("Capture byte ceiling reached; incomplete capture removed")
                            file.write(chunk)
                        process.wait(timeout=5)
                        if process.returncode != 0:
                            raise RuntimeError("tcpdump failed; check interface permissions")
                        success = True
                    finally:
                        if process.poll() is None:
                            process.send_signal(signal.SIGINT)
                            try:
                                process.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait()
    finally:
        if not success:
            output.unlink(missing_ok=True)
    return total


def main():
    p=argparse.ArgumentParser(description="Capture on an authorized local laboratory interface only.")
    p.add_argument("--list-interfaces",action="store_true")
    p.add_argument("--interface")
    p.add_argument("--output",type=Path)
    p.add_argument("--duration",type=float,default=30)
    p.add_argument("--max-bytes",type=int,default=256*1024*1024)
    p.add_argument("--max-packets",type=int,default=1_000_000)
    p.add_argument("--full",action="store_true")
    a=p.parse_args()
    if a.list_interfaces:
        print("\n".join(name for _,name in socket.if_nameindex()))
        return
    if a.interface is None or a.output is None:
        p.error("--interface and --output are required")
    try:
        size=capture(a.interface,a.output,a.duration,a.max_bytes,a.max_packets,a.full)
        print(f"Captured {size} bytes")
    except (ValueError,RuntimeError,OSError) as error:
        p.exit(1,f"{error}\n")


if __name__=="__main__":
    main()
