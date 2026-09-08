"""Decode only visible outer headers; do not infer ESP mode from these headers."""
import ipaddress
import struct
from dataclasses import dataclass


class PacketError(ValueError):
    """Malformed packet; analyzer counts and skips it."""


class UnsupportedPacket(ValueError):
    """Unsupported encapsulation/fragment chain; never silently identify inner traffic."""


@dataclass(slots=True)
class Packet:
    src: str
    dst: str
    version: int
    protocol: int
    length: int
    payload: bytes


def decode(data: bytes, link: int) -> Packet | None:
    if link == 1:
        if len(data) < 14:
            raise PacketError("Ethernet header")
        ethertype = int.from_bytes(data[12:14], "big")
        offset = 14
        for _ in range(4):
            if ethertype not in (0x8100, 0x88A8):
                break
            if len(data) < offset + 4:
                raise PacketError("VLAN header")
            ethertype = int.from_bytes(data[offset+2:offset+4], "big")
            offset += 4
        if ethertype in (0x8100, 0x88A8):
            raise UnsupportedPacket("Excessive VLAN chain")
        if ethertype not in (0x0800, 0x86DD):
            return None
        data = data[offset:]
    elif link in (113, 276):
        size = 16 if link == 113 else 20
        if len(data) < size:
            raise PacketError("Cooked header")
        cooked_proto = data[14:16] if link == 113 else data[:2]
        if int.from_bytes(cooked_proto, "big") not in (0x0800, 0x86DD):
            return None
        data = data[size:]
    if not data:
        raise PacketError("Empty IP")
    version = data[0] >> 4
    if (link == 228 and version != 4) or (link == 229 and version != 6):
        raise PacketError("Link/IP version mismatch")
    if version == 4:
        if len(data) < 20:
            raise PacketError("IPv4 header")
        ihl, total = (data[0] & 15) * 4, int.from_bytes(data[2:4], "big")
        if ihl < 20 or total < ihl or total > len(data):
            raise PacketError("IPv4 length")
        if int.from_bytes(data[6:8], "big") & 0x3FFF:
            raise UnsupportedPacket("IPv4 fragments need reassembly")
        return Packet(str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20])),
                      4, data[9], total, data[ihl:total])
    if version == 6:
        if len(data) < 40:
            raise PacketError("IPv6 header")
        total = 40 + int.from_bytes(data[4:6], "big")
        if total == 40:
            raise UnsupportedPacket("IPv6 jumbogram/empty payload")
        if total > len(data):
            raise PacketError("IPv6 length")
        proto, pos = data[6], 40
        for _ in range(16):
            if proto not in (0, 43, 60, 44):
                break
            if pos + 8 > total:
                raise PacketError("IPv6 extension header")
            next_proto = data[pos]
            size = 8 if proto == 44 else (data[pos+1] + 1) * 8
            if proto == 44 and int.from_bytes(data[pos+2:pos+4], "big") & 0xFFF9:
                raise UnsupportedPacket("IPv6 fragments need reassembly")
            if pos + size > total:
                raise PacketError("IPv6 extension length")
            pos, proto = pos + size, next_proto
        if proto in (0, 43, 60, 44, 135, 139, 140):
            raise UnsupportedPacket("Unsupported IPv6 extension chain")
        return Packet(str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40])),
                      6, proto, total, data[pos:total])
    raise UnsupportedPacket("Unsupported network protocol")


def udp(payload: bytes) -> tuple[int, int, bytes]:
    if len(payload) < 8:
        raise PacketError("UDP header")
    src, dst, length, _ = struct.unpack("!HHHH", payload[:8])
    if length < 8 or length > len(payload):
        raise PacketError("UDP length")
    return src, dst, payload[8:length]
