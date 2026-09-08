import io
import random
import struct
import pytest
from backend.protocol.pcap import records, CaptureError
from backend.protocol.network import decode, PacketError, UnsupportedPacket
from backend.protocol.ike import parse_ike
from backend.protocol.analyzer import analyze_capture
from scripts.fixtures import ike_packet, ip_packet, udp_packet, write_pcap


def test_classic_pcap(strong):
    with strong.open("rb") as f:
        packets = list(records(f, 1000))
    assert len(packets) == 386
    assert packets[0][1] == 1


@pytest.mark.parametrize("endian,nano", [("<",False),(">",False),("<",True),(">",True)])
def test_pcap_endian_resolution(endian,nano):
    raw=struct.pack(endian+"IHHIIII",0xA1B23C4D if nano else 0xA1B2C3D4,2,4,0,0,65535,1)
    raw+=struct.pack(endian+"IIII",1,500000000 if nano else 500000,1,1)+b"x"
    assert list(records(io.BytesIO(raw),1))[0][0] == 1.5


@pytest.mark.parametrize("raw", [b"",b"abc",b"PK\x03\x04"+b"x"*30,b"\xd4\xc3\xb2\xa1"])
def test_invalid_pcap(raw):
    with pytest.raises(CaptureError):
        list(records(io.BytesIO(raw),100))


def test_truncated_pcap(strong):
    raw=strong.read_bytes()
    with pytest.raises(CaptureError):
        list(records(io.BytesIO(raw[:-1]),1000))


def test_packet_count_limit(strong):
    with strong.open("rb") as f, pytest.raises(CaptureError):
        list(records(f,10))


def test_record_allocation_limit():
    raw=struct.pack("<IHHIIII",0xA1B2C3D4,2,4,0,0,65535,1)+struct.pack("<IIII",0,0,2**32-1,2**32-1)
    with pytest.raises(CaptureError):
        list(records(io.BytesIO(raw),100))


def ng_block(kind,body,endian="<"):
    size=12+len(body)
    return struct.pack(endian+"II",kind,size)+body+struct.pack(endian+"I",size)


@pytest.mark.parametrize("endian",["<",">"])
def test_pcapng(endian):
    packet=ip_packet(struct.pack("!II",0x1234,1)+b"x"*16,50)
    padded=packet+b"\0"*((-len(packet))%4)
    raw=ng_block(0x0A0D0D0A,struct.pack(endian+"IHHq",0x1A2B3C4D,1,0,-1),endian)
    raw+=ng_block(1,struct.pack(endian+"HHI",1,0,65535),endian)
    raw+=ng_block(6,struct.pack(endian+"IIIII",0,0,1500000,len(packet),len(packet))+padded,endian)
    result=list(records(io.BytesIO(raw),10))
    assert result==[(1.5,1,packet)]


def test_pcapng_invalid_trailer():
    raw=ng_block(0x0A0D0D0A,struct.pack("<IHHq",0x1A2B3C4D,1,0,-1))
    with pytest.raises(CaptureError):
        list(records(io.BytesIO(raw[:-4]+b"\0"*4),10))


@pytest.mark.parametrize("ipv6",[False,True])
def test_ip_versions(ipv6):
    pkt=decode(ip_packet(b"x"*16,50,ipv6),1)
    assert pkt is not None
    assert pkt.version==(6 if ipv6 else 4) and pkt.protocol==50


@pytest.mark.parametrize("link",[101,113,228,276])
def test_link_types(link):
    raw=ip_packet(b"x"*16,50)[14:]
    if link==113:
        raw=b"\0"*14+b"\x08\0"+raw
    elif link==276:
        raw=b"\x08\0"+b"\0"*18+raw
    decoded=decode(raw,link)
    assert decoded is not None and decoded.version==4


def test_ipv6_extensions():
    esp=struct.pack("!II",0x1234,1)+b"x"*16
    ext=bytes([50,0])+b"\0"*6
    decoded=decode(ip_packet(ext+esp,0,True),1)
    assert decoded is not None and decoded.protocol==50


def test_ipv6_fragment_not_misclassified():
    frag=bytes([50,0])+struct.pack("!H",1)+b"\0"*4
    with pytest.raises(UnsupportedPacket):
        decode(ip_packet(frag+b"x"*16,44,True),1)


def test_ipv6_unknown_chain():
    with pytest.raises(UnsupportedPacket):
        decode(ip_packet(b"x"*16,135,True),1)


@pytest.mark.parametrize("version",[1,2])
def test_ike_versions(version):
    msg=parse_ike(ike_packet(version=version),"a","b",1)
    assert msg.version==f"IKEv{version}"


def test_transforms():
    msg=parse_ike(ike_packet(),"a","b",1)
    assert msg.transforms[0].name=="AES-GCM-16"
    assert msg.transforms[0].key_length==256
    assert msg.transforms[-1].name=="ECP-384"
    assert msg.ke_group==20
    assert all(t.scope=="IKE_SA_PROPOSAL" for t in msg.transforms)


def test_unknown_transform():
    msg=parse_ike(ike_packet(unknown=True),"a","b",1)
    assert msg.transforms[-1].transform_id==65000
    assert msg.transforms[-1].name.startswith("UNKNOWN")


def test_encrypted_payload_stops_chain():
    body=struct.pack("!BBH",33,0,20)+b"x"*16
    header=struct.pack("!8s8sBBBBII",b"a"*8,b"b"*8,46,32,35,8,1,28+len(body))
    msg=parse_ike(header+body,"a","b",0)
    assert msg.encrypted and not msg.transforms and msg.payload_types==[46]


@pytest.mark.parametrize("offset,value",[(30,0),(34,255),(42,0)])
def test_ike_invalid_lengths(offset,value):
    data=bytearray(ike_packet())
    data[offset]=value
    # Bounded decoder either rejects or preserves a valid changed numeric field.
    try:
        msg=parse_ike(bytes(data),"a","b",0)
        assert len(msg.transforms)<=512
    except PacketError:
        pass


def test_nat_and_ah(fixtures):
    summary,flows,_,_,warnings=analyze_capture(fixtures["ipv6"])
    assert summary.counts["IKEv2"]==2 and summary.counts["ESP"]==384
    assert summary.counts["AH"]==1 and summary.ah_next_headers==[59]
    assert all(f.nat_t for f in flows if f.protocol=="ESP")
    assert not warnings


def test_native_esp(strong):
    summary,flows,_,_,_=analyze_capture(strong)
    assert summary.counts["ESP"]==384 and not any(f.nat_t for f in flows)


def test_nat_keepalive(tmp_path):
    path=tmp_path/"keep.pcap"
    write_pcap(path,[(1,ip_packet(udp_packet(b"\xff",4500),17))])
    summary,flows,_,_,_=analyze_capture(path)
    assert summary.counts["NAT_KEEPALIVE"]==1 and not flows


def test_replay_signals(fixtures):
    _,flows,_,_,_=analyze_capture(fixtures["replay"])
    assert all(f.signals.duplicates==2 and f.signals.regressions==1 and f.signals.large_gaps==1 for f in flows)


def test_zero_spi(tmp_path):
    p=tmp_path/"zero.pcap"
    write_pcap(p,[(1,ip_packet(struct.pack("!II",0,1)+b"x"*16,50))])
    summary,flows,_,_,warnings=analyze_capture(p)
    assert summary.malformed_packets==1 and not flows and warnings


def test_bounded_parser_fuzz():
    rng=random.Random(26160)
    for _ in range(600):
        raw=rng.randbytes(rng.randrange(0,512))
        try:
            list(records(io.BytesIO(raw),10))
        except CaptureError:
            pass
        try:
            decode(raw,1)
        except (PacketError,UnsupportedPacket):
            pass
        try:
            parse_ike(raw,"a","b",0)
        except PacketError:
            pass


def test_ike_structured_mutations():
    rng=random.Random(7)
    base=ike_packet()
    for _ in range(300):
        raw=bytearray(base)
        for _ in range(3):
            raw[rng.randrange(len(raw))]=rng.randrange(256)
        try:
            msg=parse_ike(bytes(raw),"a","b",0)
            assert len(msg.payload_types)<=64 and len(msg.transforms)<=512
        except PacketError:
            pass
