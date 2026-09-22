# Isolated local strongSwan lab

The default demo uses labelled synthetic PCAPs. The optional lab has two containers
on a Docker internal network, no published ports, no host networking.
NET_ADMIN/NET_RAW apply inside container network namespaces. The web server never runs as root.
Check subnet conflicts before launching. Do not attach this lab to an external network.

The Compose variant below requires Docker and Linux XFRM and remains unverified here. Building its image requires Internet once. The verified namespace alternative requires no Docker; see ../docs/LIVE_VALIDATION.md.
Generated random PSKs are ignored by Git; files are mode 0600.

    .venv/bin/python -m testbed.scripts.generate --profile modern --mode tunnel
    docker compose --profile lab build
    docker compose --profile lab up -d
    docker compose exec left swanctl --initiate --child data
    docker compose exec left swanctl --list-sas
    docker compose exec left ping -c 10 172.29.160.20
    docker compose exec -d left tcpdump -i eth0 -n -s 0 -w /tmp/lab.pcap
    # Generate traffic, stop capture, copy file:
    docker compose exec left pkill -INT tcpdump
    docker compose cp left:/tmp/lab.pcap ./lab.pcap
    docker compose --profile lab down

Profiles: modern (AES256-GCM/ECP384), cbc128 (AES128-CBC/SHA256/DH14),
cbc256 (AES256-CBC/SHA256/DH19), gcm128 (AES128-GCM/DH19),
gcm256 (AES256-GCM/DH31), legacy (CBC/SHA1/DH2, intentionally weak, may be rejected).
Options: --mode tunnel|transport, --ipv6, --no-pfs.
Regenerate only after stopping the lab. IPv6 peer: fd26:160::20.
Selectors are endpoint host addresses: tunnel mode is host-to-host tunneling, not routed LAN gateways.
Child-SA fresh DH may first be used during rekey; verify actual negotiated behavior.

Raw XFRM state can expose encryption keys. Manually create normalized allowlisted JSON following
demo/strong/telemetry.json, bind to the real capture hash, set synthetic=false, and use actual
endpoint configuration. Do not copy fixture assertions.

Live interoperability and crypto plugin availability require target-host verification.
Configuration generation is not evidence of an established VPN. See FINAL_BUILD_REPORT.

## Live validation update

See [../docs/LIVE_VALIDATION.md](../docs/LIVE_VALIDATION.md) for real strong/weak, transport, IPv6 and forced NAT-T verification. Real generated-workload dataset: 120 sessions; group-safe preliminary evaluation is recorded separately from synthetic metrics. Production retains the original synthetic classifier; its held-out real macro F1 is 0.32. HTML and bounded offline server PDF reports are verified.
