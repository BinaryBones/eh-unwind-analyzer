#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

import jsonschema

from samples.generate_input_validation_samples import write_samples


ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests" / "samples" / "bin" / "benign_minimal.exe"
SCHEMA = ROOT / "docs" / "input-validation-report.schema.json"

EXPECTED_FAILURES = {
    "79_static_unsupported_arm64_machine.exe": {"machine_amd64"},
    "80_static_input_invalid_mz.exe": {"dos_magic"},
    "81_static_input_e_lfanew_oob.exe": {"pe_header_range"},
    "82_static_input_invalid_pe_signature.exe": {"pe_signature"},
    "83_static_input_pe32_magic.exe": {"optional_magic_pe32_plus"},
    "84_static_input_combined_header_failures.exe": {
        "pe_signature", "machine_amd64", "optional_magic_pe32_plus"
    },
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", type=Path)
    args = parser.parse_args()
    tool = args.tool.resolve()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="ehua-input-validation-") as temp:
        root = Path(temp)
        samples = write_samples(BASELINE, root / "samples")
        for sample in samples:
            json_path = root / f"{sample.stem}.json"
            html_path = root / f"{sample.stem}.html"
            result = subprocess.run(
                [
                    str(tool), str(sample), "--heuristics",
                    "--json", str(json_path), "--html", str(html_path),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 1:
                raise AssertionError(f"{sample.name}: exit={result.returncode}, expected 1")
            if not json_path.is_file() or not html_path.is_file():
                raise AssertionError(f"{sample.name}: requested reports were not created")

            report = json.loads(json_path.read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator(schema).validate(report)
            checks = report["input_validation"]["checks"]
            failed = {check["code"] for check in checks if check["status"] == "failed"}
            expected = EXPECTED_FAILURES[sample.name]
            if failed != expected:
                raise AssertionError(f"{sample.name}: failed={failed}, expected={expected}")
            summary = report["input_validation"]
            if summary["passed_count"] + summary["failed_count"] + summary["not_evaluated_count"] != 17:
                raise AssertionError(f"{sample.name}: inconsistent check counters")
            if sample.name.startswith("81_") and summary["not_evaluated_count"] == 0:
                raise AssertionError("invalid e_lfanew did not suppress dependent checks")

            html = html_path.read_text(encoding="utf-8")
            for fragment in (
                "Результат входного контроля PE-образа",
                "Результаты проверок",
                "Диагностика синтаксического разбора",
                "Идентификация входного файла",
            ):
                if fragment not in html:
                    raise AssertionError(f"{sample.name}: HTML misses {fragment!r}")
            for code in expected:
                if code not in html:
                    raise AssertionError(f"{sample.name}: HTML misses failed check {code}")
            for forbidden in ("Score", "verdict", "Ожидаемый отказ", "Ограничение образца"):
                if forbidden in html:
                    raise AssertionError(f"{sample.name}: HTML contains {forbidden!r}")

    print("input-validation reports: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
