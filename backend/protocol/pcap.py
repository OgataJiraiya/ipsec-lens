"""Streaming, allocation-bounded classic PCAP and PCAPNG readers (no packet execution)."""
import math
import struct
from collections.abc import Iterator
from typing import BinaryIO
from backend.core.config import MAX_PACKET_SIZE


class CaptureError(ValueError):
    """Safe public parser error; never includes paths or raw packet contents."""


def exact(stream: BinaryIO, count: int) -> bytes:
    if count < 0 or count > MAX_PACKET_SIZE + 65536:
        raise CaptureError("Capture record exceeds parser limit")
    value = stream.read(count)
    if len(value) != count:
        raise CaptureError("Truncated capture record")
    return value


def records(stream: BinaryIO, max_packets: int) -> Iterator[tuple[float, int, bytes]]:
    magic = exact(stream, 4)
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from pcapng(stream, max_packets)
        return
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if magic not in formats:
        raise CaptureError("Unsupported capture format; use PCAP or PCAPNG")
    endian, resolution = formats[magic]
    major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", exact(stream, 20))
    if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_PACKET_SIZE:
        raise CaptureError("Unsupported PCAP version or snapshot size")
    link &= 0xFFFF
    if link not in (1, 101, 113, 228, 229, 276):
        raise CaptureError("Unsupported capture link type")
    count = 0
    while header := stream.read(16):
        if len(header) != 16:
            raise CaptureError("Truncated PCAP record header")
        count += 1
        if count > max_packets:
            raise CaptureError("Packet count exceeds configured limit")
        sec, frac, size, original = struct.unpack(endian + "IIII", header)
        if size > snaplen or size > original or frac >= resolution:
            raise CaptureError("Invalid PCAP record length or timestamp")
        yield sec + frac / resolution, link, exact(stream, size)


def pcapng(stream: BinaryIO, max_packets: int) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, int, float, int]] = []
    count = 0
    block_type = b"\x0a\x0d\x0d\x0a"
    while block_type:
        if len(block_type) != 4:
            raise CaptureError("Truncated PCAPNG block")
        raw_len = exact(stream, 4)
        if block_type == b"\x0a\x0d\x0d\x0a":
            bom = exact(stream, 4)
            if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                raise CaptureError("Invalid PCAPNG byte order")
            endian = "<" if bom[0] == 0x4D else ">"
            length = struct.unpack(endian + "I", raw_len)[0]
            if length < 28 or length % 4:
                raise CaptureError("Invalid PCAPNG section")
            body = bom + exact(stream, length - 16)
            interfaces = []
            if struct.unpack(endian + "HH", body[4:8]) != (1, 0):
                raise CaptureError("Unsupported PCAPNG version")
        else:
            length = struct.unpack(endian + "I", raw_len)[0]
            if length < 12 or length % 4:
                raise CaptureError("Invalid PCAPNG block length")
            body = exact(stream, length - 12)
        if struct.unpack(endian + "I", exact(stream, 4))[0] != length:
            raise CaptureError("PCAPNG block length mismatch")
        kind = struct.unpack(endian + "I", block_type)[0]
        if kind == 1:
            if len(body) < 8 or len(interfaces) >= 256:
                raise CaptureError("Invalid or excessive PCAPNG interfaces")
            link, _, snaplen = struct.unpack(endian + "HHI", body[:8])
            if link not in (1, 101, 113, 228, 229, 276) or not 0 < snaplen <= MAX_PACKET_SIZE:
                raise CaptureError("Unsupported PCAPNG interface")
            resolution, offset, pos = 1e-6, 0, 8
            while pos + 4 <= len(body):
                code, size = struct.unpack(endian + "HH", body[pos:pos+4])
                pos += 4
                if pos + size > len(body):
                    raise CaptureError("Truncated PCAPNG option")
                value = body[pos:pos+size]
                if code == 0:
                    break
                if code == 9 and size == 1:
                    exponent = value[0] & 127
                    resolution = (2 if value[0] & 128 else 10) ** (-exponent)
                if code == 14 and size == 8:
                    offset = struct.unpack(endian + "q", value)[0]
                pos += (size + 3) & ~3
            interfaces.append((link, snaplen, resolution, offset))
        elif kind == 6:
            if len(body) < 20:
                raise CaptureError("Truncated PCAPNG packet")
            iface, hi, lo, size, original = struct.unpack(endian + "IIIII", body[:20])
            if iface >= len(interfaces):
                raise CaptureError("Unknown PCAPNG interface")
            link, snaplen, resolution, offset = interfaces[iface]
            if size > snaplen or size > original or 20 + ((size + 3) & ~3) > len(body):
                raise CaptureError("Invalid PCAPNG packet length")
            count += 1
            if count > max_packets:
                raise CaptureError("Packet count exceeds configured limit")
            stamp = ((hi << 32) | lo) * resolution + offset
            if not math.isfinite(stamp):
                raise CaptureError("Invalid capture timestamp")
            yield stamp, link, body[20:20+size]
        elif kind in (2, 3):
            raise CaptureError("PCAPNG obsolete/simple packet blocks unsupported; export enhanced packet blocks")
        block_type = stream.read(4)
