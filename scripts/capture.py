"""Explicit local CLI only. No web-triggered capture; no shell interpolation."""
import argparse
import socket
import subprocess
from pathlib import Path

FILTER = "(udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 protochain 50 or ip6 protochain 51)"


def main():
    parser = argparse.ArgumentParser(description="Capture on an authorized local laboratory interface only.")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--full", action="store_true", help="Full local lab capture; may contain plaintext")
    args = parser.parse_args()
    if args.interface not in {name for _, name in socket.if_nameindex()}:
        parser.error("Interface is not a local interface")
    if not 1 <= args.duration <= 3600:
        parser.error("Duration must be 1..3600 seconds")
    if args.output.exists():
        parser.error("Output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # tcpdump drops privileges on some systems; caller owns output path and root is CLI-only.
    command = ["tcpdump", "-i", args.interface, "-n", "-s", "0", "-U", "-w", str(args.output.resolve())]
    if not args.full:
        command.append(FILTER)
    with subprocess.Popen(command) as process:
        try:
            process.wait(timeout=args.duration)
        except subprocess.TimeoutExpired:
            import signal
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.returncode not in (0, -2):
            raise SystemExit(f"tcpdump exited with status {process.returncode}")


if __name__ == "__main__":
    main()
