#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path


IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64


def generate(source: Path, output: Path) -> int:
    original = source.read_bytes()
    data = bytearray(original)
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("source is not a DOS/PE image")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    machine_offset = pe_offset + 4
    if machine_offset + 2 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("source has no file-backed PE signature or COFF header")

    source_machine = struct.unpack_from("<H", data, machine_offset)[0]
    if source_machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(
            f"source Machine is 0x{source_machine:04x}, expected AMD64 0x8664"
        )

    struct.pack_into("<H", data, machine_offset, IMAGE_FILE_MACHINE_ARM64)
    changed = [index for index, (before, after) in enumerate(zip(original, data)) if before != after]
    expected = bytearray(original)
    struct.pack_into("<H", expected, machine_offset, IMAGE_FILE_MACHINE_ARM64)
    expected_changed = [
        index for index, (before, after) in enumerate(zip(original, expected)) if before != after
    ]
    if changed != expected_changed or data != expected:
        raise AssertionError(f"unexpected changed byte offsets: {changed}")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    return machine_offset


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a deterministic PE32+ sample with an unsupported ARM64 Machine field."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    offset = generate(args.source, args.output)
    print(f"created {args.output} (Machine=0xaa64 at file offset 0x{offset:x})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
