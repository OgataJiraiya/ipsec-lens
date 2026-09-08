"""Isolated real strongSwan validation in disposable user-owned network namespaces.
Launch via unshare --user --map-root-user --mount --net. No host network or VPN state is changed.
Runtime captures/keys are private, ignored files. This is a local lab CLI, never a web endpoint.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from testbed.scripts.generate import generate

ROOT = Path(__file__).resolve().parents[2]


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=30, **kwargs)


def ns(pid, args):
    return ["nsenter", "--target", str(pid), "--net", "--mount", *args]


def wait_for(predicate, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.05)
    raise RuntimeError("Local lab readiness timeout")


def scenario(name="strong", mode="tunnel", ipv6=False, nat=False, dataset_group=None):
    if os.getuid() != 0 or Path("/proc/self/uid_map").read_text().split()[1] == "0":
        raise RuntimeError("Run in a disposable mapped-user namespace, not as host root")
    folder = ROOT / "runtime/live" / name
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.umask(0o077)
    profile = "cbc128" if name.startswith("weak") else "modern"
    generate(profile, mode, ipv6, profile != "cbc128", folder)
    peers = ["fd26:160::10", "fd26:160::20"] if ipv6 else ["172.29.160.10", "172.29.160.20"]
    processes = []
    namespaces = []
    files = []
    captures = []
    try:
        for side in ("left", "right"):
            proc = subprocess.Popen(["unshare", "--net", "--mount", "sh", "-c",
                "mount --make-rprivate / && mount -t tmpfs tmpfs /run && exec sleep 3600"])
            namespaces.append(proc)
            processes.append(proc)
        time.sleep(.25)
        run(["ip", "link", "add", "lens-left", "type", "veth", "peer", "name", "lens-right"])
        for i, (side, holder) in enumerate(zip(("left", "right"), namespaces, strict=True)):
            run(["ip", "link", "set", "lens-"+side, "netns", str(holder.pid)])
            run(ns(holder.pid, ["ip", "link", "set", "lo", "up"]))
            run(ns(holder.pid, ["ip", "link", "set", "lens-"+side, "name", "vpn0"]))
            run(ns(holder.pid, ["ip", "addr", "add", peers[i]+("/64" if ipv6 else "/24"), "dev", "vpn0"]))
            run(ns(holder.pid, ["ip", "link", "set", "vpn0", "up"]))
            path = folder / side / "swanctl.conf"
            content = path.read_text().replace("    proposals =", "    mobike = no\n    encap = "+("yes" if nat else "no")+"\n    proposals =")
            # Set an explicit replay window, and retain life_time as a distinct hard lifetime.
            content = content.replace("        start_action", "        replay_window = 64\n        start_action")
            path.write_text(content)
            sock = folder / (side+".vici")
            sock.unlink(missing_ok=True)
            config = folder / side / "strongswan.conf"
            config.write_text(f"""charon {{
  load = random nonce openssl pem x509 pubkey pkcs1 kernel-netlink socket-default vici
  plugins {{
    vici {{
      socket = unix://{sock}
    }}
  }}
  filelog {{
    lab {{
      path = {folder / side / 'daemon.log'}
      default = 1
      flush_line = yes
    }}
  }}
}}
swanctl {{
  load = random nonce openssl pem x509 pubkey pkcs1
}}
""")
            log = (folder / side / "process.log").open("w")
            files.append(log)
            env = {**os.environ, "STRONGSWAN_CONF": str(config)}
            daemon = subprocess.Popen(ns(holder.pid, ["/usr/sbin/charon-systemd"]), env=env, stdout=log, stderr=log)
            processes.append(daemon)
            wait_for(lambda: sock.exists() or daemon.poll() is not None)
            if daemon.poll() is not None:
                raise RuntimeError(f"{side} daemon exited; inspect private runtime logs")
            result = run(["swanctl", "--load-all", "--file", str(path), "--uri", "unix://"+str(sock)], env=env)
            (folder / side / "load.txt").write_text(result.stdout)
        time.sleep(1.5 if ipv6 else .1)
        # Start capture before initiation. Only the isolated peer interface is visible.
        caplog = (folder / "capture.log").open("w")
        files.append(caplog)
        capture = subprocess.Popen(ns(namespaces[0].pid, ["tcpdump", "-Z", "root", "--immediate-mode", "-i", "vpn0", "-n", "-s", "0", "-U",
            "-w", str(folder / "negotiation.pcap"), "udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50"]),
            stdout=caplog, stderr=caplog)
        captures.append(capture)
        wait_for(lambda: "listening on" in (folder / "capture.log").read_text() or capture.poll() is not None)
        if capture.poll() is not None:
            raise RuntimeError("tcpdump failed before VPN initiation")
        uri = "unix://"+str(folder / "left.vici")
        env = {**os.environ, "STRONGSWAN_CONF": str(folder / "left/strongswan.conf")}
        result = run(["swanctl", "--initiate", "--child", "data", "--uri", uri], env=env)
        (folder / "establishment.txt").write_text(result.stdout)
        # Force a real Child-SA rekey: initial IKE_AUTH does not prove separate Child-SA DH.
        result = run(["swanctl", "--rekey", "--child", "data", "--uri", uri], env=env)
        (folder / "rekey.txt").write_text(result.stdout)
        time.sleep(.3)
        serverlog = (folder / "http.log").open("w")
        files.append(serverlog)
        (folder / "payload.bin").write_bytes(bytes(range(256))*4096)
        server = subprocess.Popen(ns(namespaces[1].pid, [sys.executable, "-m", "http.server", "18080",
            "--bind", peers[1], "--directory", str(folder)]), stdout=serverlog, stderr=serverlog)
        processes.append(server)
        time.sleep(.3)
        ping = run(ns(namespaces[0].pid, ["ping", "-c", "5", "-i", ".1", peers[1]]))
        (folder / "ping.txt").write_text(ping.stdout)
        url = f"http://[{peers[1]}]:18080/payload.bin" if ipv6 else f"http://{peers[1]}:18080/payload.bin"
        http = run(ns(namespaces[0].pid, ["curl", "--noproxy", "*", "--fail", "--silent", "--output", "/dev/null", url]))
        (folder / "http-result.txt").write_text(f"curl exit={http.returncode}\n")
        time.sleep(.3)
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=5)
        if capture.returncode != 0 or (folder / "negotiation.pcap").stat().st_size <= 24:
            raise RuntimeError("Capture failed or contains no packets")
        captures.clear()
        for side, holder in zip(("left", "right"), namespaces, strict=True):
            uri = "unix://"+str(folder / (side+".vici"))
            env = {**os.environ, "STRONGSWAN_CONF": str(folder / side / "strongswan.conf")}
            (folder / side / "sas.raw").write_text(run(["swanctl", "--list-sas", "--raw", "--uri", uri], env=env).stdout)
            (folder / side / "conns.raw").write_text(run(["swanctl", "--list-conns", "--raw", "--uri", uri], env=env).stdout)
            # Raw XFRM includes keys: private runtime only, never print or commit.
            (folder / side / "xfrm-state.private").write_text(run(ns(holder.pid, ["ip", "-s", "xfrm", "state"])).stdout)
            (folder / side / "xfrm-policy.txt").write_text(run(ns(holder.pid, ["ip", "xfrm", "policy"])).stdout)
        if dataset_group is not None:
            udp_server = subprocess.Popen(ns(namespaces[1].pid, [sys.executable, str(ROOT / "testbed/traffic/session.py"), "serve", "--peer", peers[1]]), stdout=serverlog, stderr=serverlog)
            processes.append(udp_server)
            time.sleep(.2)
            manifest = []
            for repeat in range(2):
                for index, label in enumerate(("ICMP", "WEB", "VOIP", "MESSAGING", "VIDEO")):
                    session_id = f"{name}-{label.lower()}-{repeat}"
                    capture_path = folder / (session_id + ".pcap")
                    session_log = (folder / (session_id + ".capture.log")).open("w")
                    files.append(session_log)
                    cap = subprocess.Popen(ns(namespaces[0].pid, ["tcpdump", "-Z", "root", "--immediate-mode",
                        "-i", "vpn0", "-n", "-s", "0", "-U", "-w", str(capture_path), "ip proto 50"]),
                        stdout=session_log, stderr=session_log)
                    captures.append(cap)
                    wait_for(lambda: "listening on" in Path(session_log.name).read_text() or cap.poll() is not None)
                    if cap.poll() is not None:
                        raise RuntimeError("Session capture failed")
                    seed = 26160 + dataset_group * 100 + repeat * 10 + index
                    if label == "ICMP":
                        command = ["ping", "-c", str(24 + seed % 12), "-i", ".025", peers[1]]
                        run(ns(namespaces[0].pid, command))
                    elif label == "WEB":
                        for _ in range(2 + seed % 3):
                            run(ns(namespaces[0].pid, ["curl", "--noproxy", "*", "--fail", "--silent",
                                "--range", "0-"+str(16383 + seed % 10000), "--output", "/dev/null", url]))
                            time.sleep(.04)
                    else:
                        run(ns(namespaces[0].pid, [sys.executable, str(ROOT / "testbed/traffic/session.py"), "send",
                            "--peer", peers[1], "--label", label, "--seed", str(seed)]))
                    time.sleep(.08)
                    cap.send_signal(signal.SIGINT)
                    cap.wait(timeout=5)
                    captures.remove(cap)
                    if cap.returncode != 0 or capture_path.stat().st_size <= 24:
                        raise RuntimeError("No encrypted session capture")
                    manifest.append({"session_id": session_id, "group_id": name, "configuration": profile,
                        "split": "train" if dataset_group < 3 else "validation" if dataset_group == 3 else "test",
                        "label": label, "capture": str(capture_path.relative_to(ROOT)),
                        "capture_sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
                        "source": "REAL_TESTBED_GENERATED_WORKLOAD", "seed": seed})
            (folder / "sessions.json").write_text(json.dumps(manifest, indent=2)+"\n")
        result = {"scenario":name, "mechanism":"mapped user + disposable network/mount namespaces",
                  "profile":profile,"mode_requested":mode,"ipv6":ipv6,"nat_forced":nat,
                  "endpoints":peers,"establishment":"SUCCESS","icmp":"SUCCESS","http":"SUCCESS",
                  "capture":str((folder/"negotiation.pcap").relative_to(ROOT))}
        (folder/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result))
    finally:
        for cap in captures:
            if cap.poll() is None:
                cap.send_signal(signal.SIGINT)
                cap.wait(timeout=5)
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for file in files:
            file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", choices=["strong","weak","transport","ipv6","natt"], default="strong")
    parser.add_argument("--dataset", action="store_true")
    args = parser.parse_args()
    if args.dataset:
        for profile in ("strong", "weak"):
            for group in range(6):
                scenario(f"{profile}-g{group}", dataset_group=group)
    else:
        scenario(args.name, "transport" if args.name=="transport" else "tunnel",
                 args.name=="ipv6",args.name=="natt")
