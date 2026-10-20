#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "docs" / "input-validation-report.schema.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PE input-validation report corpus")
    parser.add_argument("tool", type=Path)
    parser.add_argument("binary_root", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    tool = args.tool.resolve()
    binary_root = args.binary_root.resolve()
    output_root = args.output_root.resolve()
    html_dir = output_root / "html"
    json_dir = output_root / "json"
    html_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    rows: list[dict[str, str | int]] = []

    samples = sorted(binary_root.glob("*.exe"), key=lambda path: path.name)
    if not samples:
        raise SystemExit(f"no input-validation samples in {binary_root}")
    for sample in samples:
        html_path = html_dir / f"{sample.stem}.html"
        json_path = json_dir / f"{sample.stem}.json"
        result = subprocess.run(
            [
                str(tool), str(sample), "--heuristics",
                "--html", str(html_path), "--json", str(json_path),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 1:
            raise RuntimeError(f"{sample.name}: exit={result.returncode}, expected 1")
        report = json.loads(json_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(report)
        validation = report["input_validation"]
        failed = [
            check["code"]
            for check in validation["checks"]
            if check["status"] == "failed"
        ]
        rows.append(
            {
                "binary": sample.name,
                "exit_code": result.returncode,
                "failed_count": validation["failed_count"],
                "passed_count": validation["passed_count"],
                "not_evaluated_count": validation["not_evaluated_count"],
                "failed_checks": ";".join(failed),
                "html_report": f"html/{html_path.name}",
                "json_report": f"json/{json_path.name}",
            }
        )
        print(f"{sample.name}: {failed}")

    result_csv = output_root / "results_input_validation.csv"
    with result_csv.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"generated {len(rows)} input-validation report sets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
