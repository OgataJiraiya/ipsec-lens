"""Regression gates added during the independent GitHub release audit."""
import io
import struct
from types import SimpleNamespace

import pytest

from backend.protocol.pcap import CaptureError, records
from backend.schemas.models import ProtocolSummary
from backend.services.policy import assess
from scripts.capture import command


def _ng_block(kind: int, body: bytes = b"") -> bytes:
    size = 12 + len(body)
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def test_pcapng_nonpacket_blocks_are_cpu_bounded():
    section = _ng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    unknown = _ng_block(0x0BADBEEF)
    # With max_packets=1 the reader permits bounded metadata overhead only.
    raw = section + unknown * 8193
    with pytest.raises(CaptureError, match="block count"):
        list(records(io.BytesIO(raw), 1))


def test_sensor_sudo_drops_to_invoking_nonroot_user(monkeypatch):
    monkeypatch.setattr("scripts.capture.socket.if_nameindex", lambda: [(1, "vpn0")])
    monkeypatch.setattr("scripts.capture.os.getuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr("scripts.capture.pwd.getpwuid", lambda uid: SimpleNamespace(pw_name="kali"))
    args = command("vpn0", 100)
    assert args[args.index("-Z") + 1] == "kali"
    assert args[args.index("-Z") + 1] != "root"


def test_sensor_true_host_root_uses_tcpdump_account(monkeypatch):
    monkeypatch.setattr("scripts.capture.socket.if_nameindex", lambda: [(1, "vpn0")])
    monkeypatch.setattr("scripts.capture.os.getuid", lambda: 0)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setattr("scripts.capture._mapped_user_namespace_root", lambda: False)
    monkeypatch.setattr("scripts.capture.pwd.getpwnam", lambda name: SimpleNamespace(pw_name="tcpdump"))
    args = command("vpn0", 100)
    assert args[args.index("-Z") + 1] == "tcpdump"


def test_ikev1_policy_survives_detailed_message_retention():
    summary = ProtocolSummary(counts={"IKEv1": 1})
    findings, score, _ = assess(summary, [], "MODERN", visibility_partial=True)
    assert any(f.category == "IKEV1" for f in findings)
    protocol = next(domain for domain in score.domains if domain.name == "Protocol Hygiene")
    assert protocol.score == 30
