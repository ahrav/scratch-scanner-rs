#!/usr/bin/env python3
"""Generate small Git pack files for regression tests.

The generated packs are intentionally malformed or edge-case heavy so the
decoder and executor paths can be exercised deterministically.
"""
import hashlib
import os
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "tests" / "regression" / "git_packs"


def encode_header(obj_type: int, size: int) -> bytes:
    """Encode a pack object header for the given type and size."""
    out = bytearray()
    first = ((obj_type & 0x07) << 4) | (size & 0x0F)
    size >>= 4
    if size:
        first |= 0x80
    out.append(first)
    while size:
        byte = size & 0x7F
        size >>= 7
        if size:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def encode_ofs_distance(dist: int) -> bytes:
    """Encode the OFS delta backward distance."""
    if dist <= 0:
        raise ValueError("distance must be positive")
    out = [dist & 0x7F]
    dist >>= 7
    while dist > 0:
        dist -= 1
        out.append((dist & 0x7F) | 0x80)
        dist >>= 7
    out.reverse()
    return bytes(out)


def encode_varint(value: int) -> bytes:
    """Encode a little-endian base-128 varint used by Git delta streams."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            break
    return bytes(out)


def build_insert_delta(result: bytes, base_len: int) -> bytes:
    """Build a delta stream that inserts `result` over a base of length `base_len`."""
    out = bytearray()
    out.extend(encode_varint(base_len))
    out.extend(encode_varint(len(result)))
    remaining = result
    while remaining:
        chunk = remaining[:0x7F]
        out.append(len(chunk))
        out.extend(chunk)
        remaining = remaining[len(chunk):]
    return bytes(out)


def compress(data: bytes) -> bytes:
    """Compress data with zlib for pack payloads."""
    return zlib.compress(data)


def build_pack(objects: list[bytes]) -> bytes:
    """Wrap pack objects with header and trailing checksum."""
    buf = bytearray()
    buf.extend(b"PACK")
    buf.extend(struct.pack(">I", 2))
    buf.extend(struct.pack(">I", len(objects)))
    for obj in objects:
        buf.extend(obj)
    buf.extend(b"\x00" * 20)
    return bytes(buf)


def write_pack(name: str, data: bytes) -> None:
    """Write a pack file into the regression corpus directory."""
    path = OUT_DIR / name
    path.write_bytes(data)


def gen_truncated_zlib() -> None:
    """Pack containing a blob entry with a truncated zlib stream."""
    obj = encode_header(3, 4) + b"\x78"
    write_pack("truncated_zlib.pack", build_pack([obj]))


def gen_corrupt_header() -> None:
    """Pack containing an invalid header byte."""
    obj = bytes([0x80])
    write_pack("corrupt_header.pack", build_pack([obj]))


def gen_deep_delta() -> None:
    """Pack with a chain of OFS deltas to stress delta dependency depth."""
    base = b"A"
    result1 = b"AB"
    result2 = b"ABC"

    buf = bytearray()
    buf.extend(b"PACK")
    buf.extend(struct.pack(">I", 2))
    buf.extend(struct.pack(">I", 3))

    base_offset = len(buf)
    buf.extend(encode_header(3, len(base)))
    buf.extend(compress(base))

    delta1_offset = len(buf)
    delta1 = build_insert_delta(result1, len(base))
    buf.extend(encode_header(6, len(result1)))
    buf.extend(encode_ofs_distance(delta1_offset - base_offset))
    buf.extend(compress(delta1))

    delta2_offset = len(buf)
    delta2 = build_insert_delta(result2, len(result1))
    buf.extend(encode_header(6, len(result2)))
    buf.extend(encode_ofs_distance(delta2_offset - delta1_offset))
    buf.extend(compress(delta2))

    buf.extend(b"\x00" * 20)
    write_pack("deep_delta_chain.pack", bytes(buf))


def gen_external_base() -> None:
    """Pack pair that requires an external REF delta base."""
    base = b"BASE"
    base_oid = hashlib.sha1(b"blob 4\0" + base).digest()
    base_obj = encode_header(3, len(base)) + compress(base)
    write_pack("external_base_base.pack", build_pack([base_obj]))

    result = b"BASE!"
    delta = build_insert_delta(result, len(base))
    delta_obj = encode_header(7, len(result)) + base_oid + compress(delta)
    write_pack("external_base_delta.pack", build_pack([delta_obj]))


def gen_tiny_zlib_blocks() -> None:
    """Pack with blob containing tiny zlib blocks (short literal runs)."""
    data = b"X"  # minimal payload
    compressed = compress(data)
    obj = encode_header(3, len(data)) + compressed
    write_pack("tiny_zlib_block.pack", build_pack([obj]))


def gen_many_small_zlib_concat() -> None:
    """Pack with a blob containing concatenated small zlib streams."""
    # After the first valid zlib stream ends, the rest is garbage.
    # inflate should stop at StreamEnd from the first stream.
    data1 = b"ABCD"
    z1 = compress(data1)
    z2 = compress(b"EFGH")
    # Blob size matches first decompressed block only
    obj = encode_header(3, len(data1)) + z1 + z2
    write_pack("concat_zlib_streams.pack", build_pack([obj]))


def gen_zero_length_zlib() -> None:
    """Pack with a blob containing a valid zlib header but empty stream."""
    # zlib header (78 01) followed by empty deflate - just the header bytes
    obj = encode_header(3, 0) + b"\x78\x01"
    write_pack("zero_length_zlib.pack", build_pack([obj]))


def gen_zlib_at_output_cap() -> None:
    """Pack with blob whose decompressed size is exactly 1024 bytes (boundary test)."""
    data = b"A" * 1024
    obj = encode_header(3, len(data)) + compress(data)
    write_pack("zlib_output_cap_1024.pack", build_pack([obj]))


def gen_truncated_zlib_mid_block() -> None:
    """Pack with blob where zlib stream is cut mid-block (not at stream end)."""
    data = b"Hello World! " * 100  # enough to make a multi-byte deflate
    compressed = compress(data)
    # Cut at roughly 60% of compressed data
    cut_point = len(compressed) * 6 // 10
    truncated = compressed[:cut_point]
    obj = encode_header(3, len(data)) + truncated
    write_pack("truncated_zlib_mid_block.pack", build_pack([obj]))


def main() -> None:
    """Generate all regression pack fixtures."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    gen_truncated_zlib()
    gen_corrupt_header()
    gen_deep_delta()
    gen_external_base()
    gen_tiny_zlib_blocks()
    gen_many_small_zlib_concat()
    gen_zero_length_zlib()
    gen_zlib_at_output_cap()
    gen_truncated_zlib_mid_block()


if __name__ == "__main__":
    main()
