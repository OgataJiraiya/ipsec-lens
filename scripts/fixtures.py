"""Small deterministic wire-format fixtures. Opaque ESP bytes are synthetic, not real ciphertext."""
import hashlib
import ipaddress
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from training.generate_manifest import samples


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ip_packet(payload, proto, ipv6=False, reverse=False):
    src, dst = ("2001:db8::1", "2001:db8::2") if ipv6 else ("192.0.2.1", "192.0.2.2")
    if reverse:
        src, dst = dst, src
    a, b = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    if proto == 17 and ipv6:
        length = len(payload)
        pseudo = a + b + struct.pack("!I3xB", length, 17)
        check = checksum(pseudo + payload) or 65535
        payload = payload[:6] + struct.pack("!H", check) + payload[8:]
    if ipv6:
        packet = struct.pack("!IHBB", 6 << 28, len(payload), proto, 64) + a + b + payload
    else:
        header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0) + a + b
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        packet = header + payload
    return b"\x02\0\0\0\0\2\x02\0\0\0\0\1" + (b"\x86\xdd" if ipv6 else b"\x08\x00") + packet


def udp_packet(payload, port=500):
    return struct.pack("!HHHH", port, port, len(payload) + 8, 0) + payload


def ike_packet(weak=False, version=2, unknown=False, response=False):
    transforms = [(1, 12 if weak else 20, 128 if weak else 256),
                  (2, 2 if weak else 6, None), (4, 2 if weak else 20, None)]
    if weak:
        transforms.insert(2, (3, 2, None))
    if unknown:
        transforms.append((1, 65000, None))
    encoded = b""
    for i, (kind, identifier, bits) in enumerate(transforms):
        attrs = struct.pack("!HH", 0x800E, bits) if bits else b""
        encoded += struct.pack("!BBHBBH", 0 if i == len(transforms)-1 else 3, 0, 8+len(attrs),
                               kind, 0, identifier) + attrs
    proposal = struct.pack("!BBHBBBB", 0, 0, 8+len(encoded), 1, 1, 0, len(transforms)) + encoded
    # SA -> KE -> Nonce. Fixed dummy KE bytes are deliberately nonfunctional test values.
    group, ke_size = (2, 128) if weak else (20, 96)
    nonce = struct.pack("!BBH", 0, 0, 36) + bytes(range(32))
    ke = struct.pack("!BBHHH", 40, 0, 8+ke_size, group, 0) + bytes([0x42]) * ke_size
    body = struct.pack("!BBH", 34, 0, 4 + len(proposal)) + proposal + ke + nonce if version == 2 else b""
    return struct.pack("!8s8sBBBBII", b"INIT0001", b"RESP0001" if response else b"\0"*8,
                       33 if version == 2 else 0, version << 4, 34 if version == 2 else 2,
                       0x20 if response else 0x08, 0, 28+len(body)) + body


def write_pcap(path, packets):
    with Path(path).open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, packet in packets:
            sec = int(timestamp)
            frac = int(round((timestamp-sec)*1e6))
            if frac == 1_000_000:
                sec, frac = sec+1, 0
            f.write(struct.pack("<IIII", sec, frac, len(packet), len(packet)))
            f.write(packet)


def generate(root=Path("demo")):
    generated = {}
    for name in ("strong", "weak", "replay", "partial", "ipv6"):
        folder = root / name
        folder.mkdir(parents=True, exist_ok=True)
        v6, weak = name == "ipv6", name == "weak"
        nat = name in ("weak", "ipv6")
        start = 1700000000.0
        packets = []
        if name != "partial":
            ike = ike_packet(weak)
            wire = udp_packet((b"\0"*4 if nat else b"") + ike, 4500 if nat else 500)
            packets.append((start, ip_packet(wire, 17, v6)))
            reply = udp_packet((b"\0"*4 if nat else b"") + ike_packet(weak, response=True), 4500 if nat else 500)
            packets.append((start+.01, ip_packet(reply, 17, v6, True)))
        for direction in range(2):
            flow_samples = samples({"seed": 26161 + direction, "label": "WEB" if weak else "VOIP"})
            for index, (stamp, length) in enumerate(flow_samples):
                seq = index+1
                if name in ("weak", "replay"):
                    if index == 20:
                        seq = 20
                    elif index == 40:
                        seq = 10
                    elif index > 80:
                        seq += 2048
                overhead = (40 if v6 else 20) + (8 if nat else 0)
                payload = struct.pack("!II", 0x1001 + direction, seq) + bytes([0xA5]) * max(16, length-overhead-8)
                packets.append((start + .1 + stamp + direction*.002,
                                ip_packet(udp_packet(payload, 4500) if nat else payload, 17 if nat else 50, v6, bool(direction))))
        if name == "ipv6":
            ah = struct.pack("!BBHII", 59, 4, 0, 0x2001, 1) + b"\0"*12
            packets.append((start+.05, ip_packet(ah, 51, True)))
        packets.sort(key=lambda x: x[0])
        path = folder / f"{name}.pcap"
        write_pcap(path, packets)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        meta = {"source": "SYNTHETIC FIXTURE", "description": "Protocol-format fixture, dummy KE and opaque ESP bytes; not a functioning VPN capture.",
                "capture_sha256": digest, "scenario": name, "packet_count": len(packets)}
        (folder / "manifest.json").write_text(json.dumps(meta, indent=2) + "\n")
        if name in ("strong", "weak", "ipv6"):
            a, b = ("2001:db8::1", "2001:db8::2") if v6 else ("192.0.2.1", "192.0.2.2")
            telemetry = {"adapter": "strongswan-normalized", "capture_sha256": digest,
                         "collected_at": datetime.fromtimestamp(start, timezone.utc).isoformat(),
                         "provenance": f"SYNTHETIC FIXTURE scenario {name}; generated assertions", "synthetic": True,
                         "sas": [{"source": a if i == 0 else b, "destination": b if i == 0 else a,
                                  "spi": f"0x{0x1001+i:08x}", "protocol": "ESP", "mode": "TUNNEL",
                                  "encryption_algorithm": "AES-CBC" if weak else "AES-GCM-16",
                                  "encryption_key_bits": 128 if weak else 256,
                                  "integrity_algorithm": "HMAC-SHA1-96" if weak else "NONE",
                                  "pfs_enabled": not weak, "dh_group": 2 if weak else 20,
                                  "configured_lifetime": 86400 if weak else 1800,
                                  "replay_window": 0 if weak else 64, "esn": False} for i in range(2)]}
            (folder / "telemetry.json").write_text(json.dumps(telemetry, indent=2) + "\n")
        generated[name] = path
    return generated


if __name__ == "__main__":
    for name, path in generate().items():
        print(name, path)
