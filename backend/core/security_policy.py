"""Prototype policy choices, not certification or compliance with an external standard."""
from dataclasses import dataclass

SEQUENCE_GAP = 1024
MIN_FLOW_PACKETS = 20
DOMAIN_WEIGHTS = {"Cryptography": 0.25, "Key Exchange": 0.20, "PFS / Rekey": 0.20,
                  "Replay Protection": 0.15, "Protocol Hygiene": 0.15, "Metadata Exposure": 0.05}


@dataclass(frozen=True)
class Policy:
    name: str
    allow_cbc_sha2: bool
    dh_groups: tuple[int, ...]
    minimum_aes_bits: int
    max_lifetime: int
    ike: str
    esp: str


POLICIES = {
    "MODERN": Policy("MODERN", False, (19, 20, 21, 31, 32), 256, 3600,
                     "aes256gcm16-prfsha384-ecp384", "aes256gcm16-ecp384"),
    "COMPATIBILITY": Policy("COMPATIBILITY", True, (14, 15, 16, 17, 18, 19, 20, 21, 31, 32),
                            128, 14400, "aes256-sha256-modp2048", "aes256-sha256-modp2048"),
    "STRICT": Policy("STRICT", False, (20, 21, 32), 256, 1800,
                     "aes256gcm16-prfsha384-ecp384", "aes256gcm16-ecp384"),
}


def hardening(policy: str) -> str:
    p = POLICIES[policy]
    return (f"# RECOMMENDATION only; review identities, selectors and interoperability before use.\n"
            f"# ipsec.conf-style fragment; not automatically applied\n"
            f"keyexchange=ikev2\nike={p.ike}!\nesp={p.esp}!\n"
            f"rekey=yes\nlifetime={p.max_lifetime}s\n")
