#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def sample_variants(baseline: bytes) -> dict[str, bytes]:
    if len(baseline) < 0x40 or baseline[:2] != b"MZ":
        raise ValueError("baseline is not a DOS/PE image")
    pe_offset = struct.unpack_from("<I", baseline, 0x3C)[0]
    if baseline[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("baseline PE signature is absent")
    machine_offset = pe_offset + 4
    optional_offset = pe_offset + 4 + 20
    if struct.unpack_from("<H", baseline, machine_offset)[0] != 0x8664:
        raise ValueError("baseline is not AMD64")
    if struct.unpack_from("<H", baseline, optional_offset)[0] != 0x20B:
        raise ValueError("baseline is not PE32+")

    def mutate(*changes: tuple[int, str, int]) -> bytes:
        data = bytearray(baseline)
        for offset, fmt, value in changes:
            struct.pack_into(fmt, data, offset, value)
        return bytes(data)

    return {
        "79_static_unsupported_arm64_machine.exe": mutate(
            (machine_offset, "<H", 0xAA64)
        ),
        "80_static_input_invalid_mz.exe": mutate(
            (0, "<H", 0x5A4E)
        ),
        "81_static_input_e_lfanew_oob.exe": mutate(
            (0x3C, "<I", len(baseline) + 0x1000)
        ),
        "82_static_input_invalid_pe_signature.exe": mutate(
            (pe_offset, "<I", 0x214550)
        ),
        "83_static_input_pe32_magic.exe": mutate(
            (optional_offset, "<H", 0x10B)
        ),
        "84_static_input_combined_header_failures.exe": mutate(
            (pe_offset, "<I", 0x214550),
            (machine_offset, "<H", 0x014C),
            (optional_offset, "<H", 0x10B),
        ),
    }


def write_samples(baseline_path: Path, output_dir: Path) -> list[Path]:
    variants = sample_variants(baseline_path.read_bytes())
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for name, data in variants.items():
        path = output_dir / name
        path.write_bytes(data)
        outputs.append(path)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PE input-validation samples")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    for output in write_samples(args.baseline, args.output_dir):
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
