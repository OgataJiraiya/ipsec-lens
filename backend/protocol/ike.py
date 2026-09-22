"""RFC 7296 visible IKE parsing. IKE proposals are NEVER copied to ESP Child-SA fields."""
import struct
from backend.protocol.network import PacketError
from backend.schemas.models import IkeMessage, Transform

ALGORITHMS = {
    1: {3: "3DES", 12: "AES-CBC", 13: "AES-CTR", 18: "AES-GCM-8", 19: "AES-GCM-12",
        20: "AES-GCM-16", 28: "CHACHA20-POLY1305"},
    2: {2: "PRF-HMAC-SHA1", 5: "PRF-HMAC-SHA2-256", 6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512"},
    3: {0: "NONE", 2: "HMAC-SHA1-96", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192",
        14: "HMAC-SHA2-512-256"},
    4: {0: "NONE", 1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048",
        15: "MODP-3072", 16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192",
        19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 31: "Curve25519", 32: "Curve448"},
    5: {0: "NO-ESN", 1: "ESN"},
}
EXCHANGES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}


def parse_sa(body: bytes, scope: str) -> list[Transform]:
    pos = 0
    result: list[Transform] = []
    while pos < len(body):
        if len(body) - pos < 8:
            raise PacketError("IKE proposal header")
        more, _, length, number, protocol, spi_size, count = struct.unpack("!BBHBBBB", body[pos:pos+8])
        if length < 8 + spi_size or pos + length > len(body) or more not in (0, 2):
            raise PacketError("IKE proposal length")
        end, cursor = pos + length, pos + 8 + spi_size
        parsed = 0
        while cursor < end:
            if cursor + 8 > end or len(result) >= 512:
                raise PacketError("IKE transform bounds")
            nxt, _, tlen, kind, _, identifier = struct.unpack("!BBHBBH", body[cursor:cursor+8])
            if tlen < 8 or cursor + tlen > end or nxt not in (0, 3):
                raise PacketError("IKE transform length")
            attr, key_length = cursor + 8, None
            while attr < cursor + tlen:
                if attr + 4 > cursor + tlen:
                    raise PacketError("IKE attribute header")
                atype, value = struct.unpack("!HH", body[attr:attr+4])
                attr += 4
                if atype & 0x8000:
                    if atype & 0x7FFF == 14:
                        key_length = value
                else:
                    if attr + value > cursor + tlen:
                        raise PacketError("IKE attribute length")
                    if atype == 14 and value == 2:
                        key_length = int.from_bytes(body[attr:attr+2], "big")
                    attr += value
            result.append(Transform(proposal=number, protocol_id=protocol, transform_type=kind,
                                    transform_id=identifier, name=ALGORITHMS.get(kind, {}).get(
                                        identifier, f"UNKNOWN({kind}:{identifier})"),
                                    key_length=key_length, scope=scope if protocol == 1 else "UNVERIFIED_VISIBLE_PROPOSAL"))
            cursor += tlen
            parsed += 1
            if (cursor == end) != (nxt == 0):
                raise PacketError("IKE transform chain")
        if parsed != count or (end == len(body)) != (more == 0):
            raise PacketError("IKE proposal chain/count")
        pos = end
    return result


def parse_ike(data: bytes, src: str, dst: str, timestamp: float) -> IkeMessage:
    if len(data) < 28:
        raise PacketError("IKE header")
    init, resp, nxt, version, exchange, flags, mid, length = struct.unpack("!8s8sBBBBII", data[:28])
    major = version >> 4
    if major not in (1, 2) or length != len(data):
        raise PacketError("IKE version/length")
    msg = IkeMessage(src=src, dst=dst, timestamp=timestamp, initiator_spi=init.hex(),
                     responder_spi=resp.hex(), version=f"IKEv{major}", exchange_type=exchange,
                     exchange=EXCHANGES.get(exchange, f"UNKNOWN({exchange})") if major == 2 else f"IKEv1 exchange {exchange}",
                     flags=flags, message_id=mid, next_payload=nxt)
    if major == 1:
        msg.encrypted = bool(flags & 1)
        return msg  # IKEv1 identification only; no claims about its encrypted SA negotiation.
    pos = 28
    for _ in range(64):
        if not nxt:
            if pos != length:
                raise PacketError("Trailing IKE payload data")
            return msg
        if pos + 4 > length:
            raise PacketError("IKE payload header")
        following, _, size = struct.unpack("!BBH", data[pos:pos+4])
        if size < 4 or pos + size > length:
            raise PacketError("IKE payload length")
        msg.payload_types.append(nxt)
        body = data[pos+4:pos+size]
        if nxt in (46, 53):
            msg.encrypted = True
            if pos + size != length:
                raise PacketError("Encrypted payload must be last")
            return msg  # SK next-payload names encrypted contents, not a visible continuation.
        if nxt == 33:
            scope = "IKE_SA_PROPOSAL" if exchange == 34 else "UNVERIFIED_VISIBLE_PROPOSAL"
            msg.transforms.extend(parse_sa(body, scope))
            if len(msg.transforms) > 512:
                raise PacketError("IKE aggregate transform limit")
        elif nxt == 34:
            if len(body) < 4:
                raise PacketError("IKE KE payload")
            msg.ke_group = int.from_bytes(body[:2], "big")
        pos, nxt = pos + size, following
    raise PacketError("IKE payload chain limit")
