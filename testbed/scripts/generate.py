"""Generate isolated strongSwan configurations; never starts services or changes host networking."""
import argparse
import json
from pathlib import Path
import secrets

PROFILES = {
 "modern": ("aes256gcm16-prfsha384-ecp384", "aes256gcm16-ecp384", "1800s"),
 "cbc128": ("aes128-sha256-modp2048", "aes128-sha256-modp2048", "3600s"),
 "cbc256": ("aes256-sha256-ecp256", "aes256-sha256-ecp256", "3600s"),
 "gcm128": ("aes128gcm16-prfsha256-ecp256", "aes128gcm16-ecp256", "3600s"),
 "gcm256": ("aes256gcm16-prfsha256-curve25519", "aes256gcm16-curve25519", "3600s"),
 "legacy": ("aes128-sha1-modp1024", "aes128-sha1", "86400s"),
}


def generate(profile="modern", mode="tunnel", ipv6=False, pfs=True, output=Path("testbed/generated")):
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    ike, esp, lifetime = PROFILES[profile]
    if not pfs or profile == "legacy":
        esp = "-".join(part for part in esp.split("-") if not part.startswith(("ecp", "modp", "curve")))
    endpoints = ["fd26:160::10", "fd26:160::20"] if ipv6 else ["172.29.160.10", "172.29.160.20"]
    secret = secrets.token_hex(32)
    for i, name in enumerate(("left", "right")):
        peer = 1-i
        folder = output / name
        folder.mkdir(exist_ok=True, mode=0o700)
        config = f"""connections {{
  lab {{
    version = 2
    local_addrs = {endpoints[i]}
    remote_addrs = {endpoints[peer]}
    proposals = {ike}
    local {{
      auth = psk
      id = {name}.lab
    }}
    remote {{
      auth = psk
      id = {('left','right')[peer]}.lab
    }}
    children {{
      data {{
        mode = {mode}
        local_ts = {endpoints[i]}/{'128' if ipv6 else '32'}
        remote_ts = {endpoints[peer]}/{'128' if ipv6 else '32'}
        esp_proposals = {esp}
        rekey_time = {lifetime}
        life_time = {int(lifetime[:-1])*2}s
        start_action = none
      }}
    }}
  }}
}}
secrets {{
  ike-lab {{
    id-1 = left.lab
    id-2 = right.lab
    secret = {secret}
  }}
}}
"""
        target = folder / "swanctl.conf"
        target.write_text(config)
        target.chmod(0o600)
    (output / "scenario.json").write_text(json.dumps({"profile":profile,"mode":mode,"ipv6":ipv6,
        "pfs_requested":pfs and profile!="legacy","endpoints":endpoints,"status":"GENERATED_NOT_VERIFIED"},indent=2))
    print("Generated isolated lab configuration; secrets are local and ignored by Git.")


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--profile",choices=list(PROFILES),default="modern")
    p.add_argument("--mode",choices=["tunnel","transport"],default="tunnel")
    p.add_argument("--ipv6",action="store_true")
    p.add_argument("--no-pfs",action="store_true")
    args=p.parse_args()
    generate(args.profile,args.mode,args.ipv6,not args.no_pfs)
