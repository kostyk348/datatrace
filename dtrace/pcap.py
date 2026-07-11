"""PCAP Event Source — ingest packet captures into the pipeline."""

import struct
from dataclasses import dataclass
from typing import Iterator


PCAP_MAGIC_NANO = 0xa1b2c3d4
PCAP_MAGIC_MICRO = 0xa1b2cd34


@dataclass(slots=True)
class Packet:
    ts: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    payload: bytes
    orig_len: int


def _detect_endian(magic_bytes: bytes) -> tuple[str, int, bool] | None:
    """Detect pcap endianness from the 4-byte magic."""
    if len(magic_bytes) < 4:
        return None
    # LE file: magic bytes are d4 c3 b2 a1 (0xa1b2c3d4 stored LE)
    if magic_bytes == b'\xd4\xc3\xb2\xa1':
        magic = struct.unpack("<I", magic_bytes)[0]
        if magic in (PCAP_MAGIC_NANO, PCAP_MAGIC_MICRO):
            return ("<", magic, magic == PCAP_MAGIC_NANO)
    # BE file: magic bytes are a1 b2 c3 d4 (0xa1b2c3d4 stored BE)
    elif magic_bytes == b'\xa1\xb2\xc3\xd4':
        magic = struct.unpack(">I", magic_bytes)[0]
        if magic in (PCAP_MAGIC_NANO, PCAP_MAGIC_MICRO):
            return (">", magic, magic == PCAP_MAGIC_NANO)
    # Try reverse-endian magic (d4 c3 b2 a1 as BE = 0xd4c3b2a1)
    rev_magic = struct.unpack("<I", magic_bytes)[0]
    if rev_magic == PCAP_MAGIC_NANO or rev_magic == PCAP_MAGIC_MICRO:
        return (">", rev_magic, rev_magic == PCAP_MAGIC_NANO)
    return None


def _parse_ip(data: bytes, offset: int) -> tuple[str, str, int, int, int, int] | None:
    if offset + 20 > len(data):
        return None
    ver_ihl = data[offset]
    ihl = (ver_ihl & 0x0f) * 4
    if offset + ihl > len(data):
        return None
    proto = data[offset + 9]
    src_ip = ".".join(str(b) for b in data[offset + 12:offset + 16])
    dst_ip = ".".join(str(b) for b in data[offset + 16:offset + 20])
    total_len = struct.unpack_from("!H", data, offset + 2)[0]
    payload_start = offset + ihl

    if proto == 6:
        if payload_start + 20 > len(data):
            return None
        src_port = struct.unpack_from("!H", data, payload_start)[0]
        dst_port = struct.unpack_from("!H", data, payload_start + 2)[0]
        tcp_hdr_len = ((data[payload_start + 12] >> 4) & 0x0f) * 4
        data_offset = payload_start + tcp_hdr_len
    elif proto == 17:
        if payload_start + 8 > len(data):
            return None
        src_port = struct.unpack_from("!H", data, payload_start)[0]
        dst_port = struct.unpack_from("!H", data, payload_start + 2)[0]
        udp_len = struct.unpack_from("!H", data, payload_start + 4)[0]
        data_offset = payload_start + 8
    else:
        return None

    return src_ip, dst_ip, src_port, dst_port, proto, data_offset


def iter_packets(path: str) -> Iterator[Packet]:
    with open(path, "rb") as f:
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            return

        endian_info = _detect_endian(global_hdr[0:4])
        if endian_info is None:
            return
        endian, magic, is_nano = endian_info

        snaplen = struct.unpack_from(f"{endian}I", global_hdr, 16)[0]
        linktype = struct.unpack_from(f"{endian}I", global_hdr, 20)[0]

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break

            ts_sec = struct.unpack_from(f"{endian}I", pkt_hdr, 0)[0]
            ts_frac = struct.unpack_from(f"{endian}I", pkt_hdr, 4)[0]
            incl_len = struct.unpack_from(f"{endian}I", pkt_hdr, 8)[0]
            orig_len = struct.unpack_from(f"{endian}I", pkt_hdr, 12)[0]

            if incl_len > snaplen or incl_len > 10 * 1024 * 1024:
                break

            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            ts_ns = ts_sec * 1_000_000_000 + (ts_frac * 1000 if not is_nano else ts_frac)

            offset = 0
            if linktype == 1:
                offset = 14
            elif linktype == 0:
                offset = 0
            else:
                continue

            result = _parse_ip(pkt_data, offset)
            if result is None:
                continue
            src_ip, dst_ip, src_port, dst_port, proto, data_offset = result
            payload = pkt_data[data_offset:]
            if not payload:
                continue

            yield Packet(
                ts=ts_ns,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                payload=payload,
                orig_len=orig_len,
            )
