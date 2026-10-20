#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import jsonschema

from report_semantics import validate_report_semantics


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY_ROOT = ROOT / "бинарники на тестирование" / "бинарники"
DEFAULT_OUTPUT_ROOT = ROOT / "бинарники на тестирование" / "reports_static_extended"
REPORT_SCHEMA = ROOT / "docs" / "report.schema.json"
INPUT_VALIDATION_SCHEMA = ROOT / "docs" / "input-validation-report.schema.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the static HTML/JSON/CSV/Ghidra report corpus."
    )
    parser.add_argument("tool", type=Path)
    parser.add_argument("--binary-root", type=Path, default=DEFAULT_BINARY_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()

    tool = args.tool.resolve()
    binary_root = args.binary_root.resolve()
    output_root = args.output_root.resolve()
    samples = sorted(binary_root.rglob("*.exe"), key=lambda path: path.name.lower())
    if not tool.is_file():
        raise SystemExit(f"analyzer not found: {tool}")
    if not samples:
        raise SystemExit(f"no .exe samples found under {binary_root}")

    duplicate_stems: dict[str, list[Path]] = {}
    for sample in samples:
        duplicate_stems.setdefault(sample.stem, []).append(sample)
    collisions = {stem: paths for stem, paths in duplicate_stems.items() if len(paths) > 1}
    if collisions:
        lines = [f"duplicate output stem {stem}: {paths}" for stem, paths in collisions.items()]
        raise SystemExit("\n".join(lines))

    output_dirs = {
        "json": output_root / "json",
        "html": output_root / "html",
        "csv": output_root / "csv",
        "ghidra": output_root / "ghidra_csv",
    }
    for directory in output_dirs.values():
        directory.mkdir(parents=True, exist_ok=True)

    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    input_validation_schema = json.loads(
        INPUT_VALIDATION_SCHEMA.read_text(encoding="utf-8")
    )
    failures: list[str] = []
    for index, sample in enumerate(samples, start=1):
        outputs = {
            "json": output_dirs["json"] / f"{sample.stem}.json",
            "html": output_dirs["html"] / f"{sample.stem}.html",
            "csv": output_dirs["csv"] / f"{sample.stem}.csv",
            "ghidra": output_dirs["ghidra"] / f"{sample.stem}_ghidra.csv",
        }
        command = [
            str(tool),
            str(sample),
            "--heuristics",
            "--strict-abi",
            "--json",
            str(outputs["json"]),
            "--html",
            str(outputs["html"]),
            "--csv",
            str(outputs["csv"]),
            "--ghidra-csv",
            str(outputs["ghidra"]),
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode not in (0, 1):
            failures.append(
                f"{sample.name}: analyzer exit={result.returncode}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
            continue
        if outputs["json"].is_file():
            try:
                early_report = json.loads(outputs["json"].read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                failures.append(f"{sample.name}: cannot read generated JSON: {exc}")
                continue
            if early_report.get("report_type") == "pe_input_validation":
                if not outputs["html"].is_file():
                    failures.append(f"{sample.name}: input-validation HTML is absent")
                    continue
                try:
                    jsonschema.Draft202012Validator(input_validation_schema).validate(
                        early_report
                    )
                    html = outputs["html"].read_text(encoding="utf-8")
                    if "Результат входного контроля PE-образа" not in html:
                        raise ValueError("HTML misses the input-validation heading")
                except (OSError, jsonschema.ValidationError, ValueError) as exc:
                    failures.append(
                        f"{sample.name}: input-validation report failed validation: {exc}"
                    )
                    continue
                print(f"[{index:02d}/{len(samples):02d}] {sample.name} (input validation)")
                continue

        if not all(path.is_file() for path in outputs.values()):
            failures.append(
                f"{sample.name}: analyzer exit={result.returncode}, but one or more requested reports are absent"
            )
            continue
        try:
            report = json.loads(outputs["json"].read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator(schema).validate(report)
            semantic_errors = validate_report_semantics(report)
            if semantic_errors:
                raise ValueError("; ".join(semantic_errors))
            html = outputs["html"].read_text(encoding="utf-8")
            if "Матрица покрытия 27 эвристических признаков" not in html:
                raise ValueError("HTML misses the 27-feature matrix")
            if "Краткий журнал findings" in html:
                raise ValueError("HTML contains the obsolete duplicate finding log")
            for obsolete in (
                "Сводная экспертная оценка",
                "Уверенность модели",
                "<b>Методика оценки.</b>",
                "Методика расчёта.",
                "Методика расчёта итоговой оценки.",
            ):
                if obsolete in html:
                    raise ValueError(f"HTML contains obsolete wording {obsolete!r}")
            if re.search(r"эксперт", html, flags=re.IGNORECASE):
                raise ValueError("HTML contains an obsolete expert-role reference")
            bad_count_phrase = re.search(
                r"\b\d+\s+(?:нарушений|частных срабатываний|записей-доказательств)\b",
                html,
            )
            if bad_count_phrase:
                raise ValueError(
                    "HTML contains a number-dependent Russian noun form: "
                    f"{bad_count_phrase.group(0)!r}"
                )
            for finding in report.get("heuristic_analysis", {}).get("findings", []):
                code = finding.get("code")
                if f'href="#finding-{code}"' not in html:
                    raise ValueError(f"finding {code!r} has no matrix-to-detail link")
                if f'id="finding-{code}"' not in html:
                    raise ValueError(f"finding {code!r} has no detail anchor")
        except (OSError, json.JSONDecodeError, jsonschema.ValidationError, ValueError) as exc:
            failures.append(f"{sample.name}: generated report validation failed: {exc}")
            continue
        status = "partial structural report" if result.returncode == 1 else "complete"
        print(f"[{index:02d}/{len(samples):02d}] {sample.name} ({status})")

    if failures:
        print("\nGeneration failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated and validated {len(samples)} static report sets in {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
