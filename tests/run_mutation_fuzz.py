#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests" / "samples" / "manifest.json"


def mutate(original: bytes, rng: random.Random, index: int) -> bytes:
    data = bytearray(original)
    operation = index % 7

    if operation == 0 and data:
        for _ in range(1 + rng.randrange(min(16, len(data)))):
            offset = rng.randrange(len(data))
            data[offset] ^= 1 << rng.randrange(8)
    elif operation == 1 and data:
        start = rng.randrange(len(data))
        length = min(len(data) - start, 1 + rng.randrange(64))
        data[start:start + length] = bytes([rng.randrange(256)]) * length
    elif operation == 2:
        cut = rng.randrange(len(data) + 1) if data else 0
        del data[cut:]
    elif operation == 3:
        insertion = bytes(rng.randrange(256) for _ in range(1 + rng.randrange(128)))
        offset = rng.randrange(len(data) + 1) if data else 0
        data[offset:offset] = insertion
    elif operation == 4 and data:
        start = rng.randrange(len(data))
        end = min(len(data), start + 1 + rng.randrange(128))
        del data[start:end]
    elif operation == 5 and len(data) >= 0x40:
        for offset in (0x3C, 0x3D, 0x3E, 0x3F):
            data[offset] = rng.randrange(256)
    elif data:
        for offset in (0, 1, len(data) // 2, len(data) - 1):
            data[offset] = rng.randrange(256)

    return bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run deterministic black-box mutations against the PE parser"
    )
    parser.add_argument("tool", type=Path)
    parser.add_argument("--cases", type=int, default=120)
    parser.add_argument("--seed", type=int, default=0x45485541)
    args = parser.parse_args()

    tool = args.tool.resolve()
    if not tool.is_file():
        print("tool not found: %s" % tool, file=sys.stderr)
        return 2
    if args.cases < 1:
        print("--cases must be positive", file=sys.stderr)
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    samples = [ROOT / item["path"] for item in manifest["samples"]]
    missing = [path for path in samples if not path.is_file()]
    if missing:
        print("missing seed sample: %s" % missing[0], file=sys.stderr)
        return 2

    seeds = [path.read_bytes() for path in samples]
    rng = random.Random(args.seed)
    environment = os.environ.copy()
    environment.setdefault("ASAN_OPTIONS", "halt_on_error=1")
    environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    accepted = 0
    rejected = 0

    with tempfile.TemporaryDirectory(prefix="ehua-mutation-") as temp:
        temp_dir = Path(temp)
        for index in range(args.cases):
            sample_path = temp_dir / ("case-%04d.exe" % index)
            report_path = temp_dir / ("case-%04d.json" % index)
            sample_path.write_bytes(mutate(seeds[index % len(seeds)], rng, index))
            try:
                completed = subprocess.run(
                    [
                        str(tool),
                        str(sample_path),
                        "--heuristics",
                        "--json",
                        str(report_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env=environment,
                )
            except subprocess.TimeoutExpired:
                print("[FAIL] mutation %d timed out" % index, file=sys.stderr)
                return 1

            if completed.returncode not in (0, 1):
                print(
                    "[FAIL] mutation %d returned %d\nstdout:\n%s\nstderr:\n%s"
                    % (index, completed.returncode, completed.stdout, completed.stderr),
                    file=sys.stderr,
                )
                return 1
            if completed.returncode == 0:
                accepted += 1
                if not report_path.is_file():
                    print("[FAIL] mutation %d produced no JSON report" % index,
                          file=sys.stderr)
                    return 1
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    print("[FAIL] mutation %d produced invalid JSON: %s" % (index, exc),
                          file=sys.stderr)
                    return 1
                if report.get("report_metadata", {}).get("schema_version") != "1.3.0":
                    print("[FAIL] mutation %d has invalid report metadata" % index,
                          file=sys.stderr)
                    return 1
            else:
                rejected += 1

    print(
        "mutation_fuzz: OK cases=%d accepted=%d rejected=%d seed=%d"
        % (args.cases, accepted, rejected, args.seed)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
