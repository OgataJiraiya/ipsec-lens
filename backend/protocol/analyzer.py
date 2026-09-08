"""Directional ESP/AH grouping. SPI reuse and passive sequence signals do not prove attacks."""
import hashlib
from typing import Literal
import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from backend.core import config
from backend.core.security_policy import SEQUENCE_GAP
from backend.protocol.ike import parse_ike
from backend.protocol.network import decode, udp, PacketError, UnsupportedPacket
from backend.protocol.pcap import records, CaptureError
from backend.schemas.models import ProtocolSummary, ReplaySignals, SecurityAssociation


@dataclass
class Flow:
    src: str
    dst: str
    spi: int
    protocol: Literal["ESP", "AH"]
    ip_version: int
    nat_t: bool
    first: float
    last: float
    count: int = 0
    byte_count: int = 0
    size_mean: float = 0
    size_m2: float = 0
    seq_min: int = 2**32 - 1
    seq_max: int = 0
    previous: int | None = None
    seen: set[int] = field(default_factory=set)
    signals: ReplaySignals = field(default_factory=ReplaySignals)
    samples: list[tuple[float, int]] = field(default_factory=list)

    def add(self, timestamp: float, length: int, seq: int):
        self.count += 1
        self.byte_count += length
        delta = length - self.size_mean
        self.size_mean += delta / self.count
        self.size_m2 += delta * (length - self.size_mean)
        self.first, self.last = min(self.first, timestamp), max(self.last, timestamp)
        self.signals.duplicates += int(seq in self.seen)
        self.signals.zero_sequences += int(seq == 0)
        if self.previous is not None:
            self.signals.regressions += int(seq < self.previous)
            self.signals.large_gaps += int(seq - self.previous > SEQUENCE_GAP)
        self.seen.add(seq)  # Global packet ceiling bounds all sequence sets together.
        self.previous = seq
        self.seq_min, self.seq_max = min(self.seq_min, seq), max(self.seq_max, seq)
        if len(self.samples) < 2048:
            self.samples.append((timestamp, length))

    def result(self) -> SecurityAssociation:
        duration = self.last - self.first
        identity = f"{self.src}|{self.dst}|{self.protocol}|{self.spi}"
        return SecurityAssociation(
            sa_id=hashlib.sha256(identity.encode()).hexdigest()[:16], spi=f"0x{self.spi:08x}",
            direction=f"{self.src} → {self.dst}", source=self.src, destination=self.dst,
            protocol=self.protocol, ip_version=self.ip_version, nat_t=self.nat_t,
            first_seen=self.first, last_seen=self.last, observed_duration=duration,
            packet_count=self.count, bytes=self.byte_count, mean_packet_size=self.size_mean,
            std_packet_size=math.sqrt(max(0, self.size_m2 / self.count)),
            packet_rate=self.count / duration if duration else 0,
            sequence_min=self.seq_min, sequence_max=self.seq_max, replay_signals=self.signals)


def analyze_capture(path: Path):
    summary = ProtocolSummary()
    counts: Counter[str] = Counter()
    flows: dict[tuple[str, str, str, int], Flow] = {}
    count, first, last = 0, None, None
    retained_transforms = 0
    warnings: set[str] = set()
    with path.open("rb") as stream:
        for timestamp, link, raw in records(stream, config.MAX_PACKETS):
            count += 1
            first = timestamp if first is None else min(first, timestamp)
            last = timestamp if last is None else max(last, timestamp)
            try:
                pkt = decode(raw, link)
                if pkt is None:
                    counts["NON_IP"] += 1
                    continue
                counts[f"IPv{pkt.version}"] += 1
                payload, proto, nat = pkt.payload, pkt.protocol, False
                if proto == 17:
                    sport, dport, payload = udp(payload)
                    counts["UDP"] += 1
                    if 4500 in (sport, dport):
                        counts["NAT_T"] += 1
                        nat = True
                        if payload == b"\xff":
                            counts["NAT_KEEPALIVE"] += 1
                            continue
                        if payload[:4] == b"\0\0\0\0":
                            payload, proto = payload[4:], 500
                        else:
                            proto = 50
                    elif 500 in (sport, dport):
                        proto = 500
                if proto == 500:
                    msg = parse_ike(payload, pkt.src, pkt.dst, timestamp)
                    counts[msg.version] += 1
                    counts["IKE"] += 1
                    if len(summary.ike_messages) < config.MAX_IKE_MESSAGES and retained_transforms + len(msg.transforms) <= 16384:
                        summary.ike_messages.append(msg)
                        retained_transforms += len(msg.transforms)
                    else:
                        warnings.add("IKE message retention limit reached; assessment is partial.")
                    continue
                if proto not in (50, 51):
                    continue
                name: Literal["ESP", "AH"]
                if proto == 50:
                    if len(payload) < 8:
                        raise PacketError("ESP header")
                    spi, seq = struct.unpack("!II", payload[:8])
                    name = "ESP"
                else:
                    if len(payload) < 12 or (payload[1] + 2) * 4 < 12 or (payload[1] + 2) * 4 > len(payload):
                        raise PacketError("AH header")
                    spi, seq = struct.unpack("!II", payload[4:12])
                    name = "AH"
                    if payload[0] not in summary.ah_next_headers:
                        summary.ah_next_headers.append(payload[0])
                if spi == 0:
                    raise PacketError("Reserved zero SPI")
                counts[name] += 1
                key = (pkt.src, pkt.dst, name, spi)
                if key not in flows:
                    if len(flows) >= config.MAX_FLOWS:
                        raise CaptureError("Security association count exceeds configured limit")
                    flows[key] = Flow(pkt.src, pkt.dst, spi, name, pkt.version, nat, timestamp, timestamp)
                flows[key].nat_t |= nat
                flows[key].add(timestamp, pkt.length, seq)
            except PacketError:
                summary.malformed_packets += 1
            except UnsupportedPacket:
                summary.unsupported_packets += 1
    if count == 0:
        raise CaptureError("Capture contains no packets")
    endpoints: dict[tuple[str, str, str], set[int]] = {}
    for src, dst, flow_protocol, spi in flows:
        endpoints.setdefault((src, dst, flow_protocol), set()).add(spi)
    summary.spi_changes = sum(max(0, len(spis) - 1) for spis in endpoints.values())
    summary.counts = dict(counts)
    if summary.malformed_packets:
        warnings.add(f"{summary.malformed_packets} malformed/truncated packets skipped; visibility reduced.")
    if summary.unsupported_packets:
        warnings.add(f"{summary.unsupported_packets} unsupported or fragmented packets skipped; no reassembly.")
    return summary, list(flows.values()), count, (last - first if last is not None and first is not None else 0), sorted(warnings)
