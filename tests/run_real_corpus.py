#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import jsonschema

from report_semantics import validate_report_semantics


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "docs" / "report.schema.json"
EXTENSIONS = {".exe", ".dll", ".pyd", ".sys"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[index]


def compact_error(text: str, limit: int = 500) -> str:
    return " ".join(text.split())[:limit]


def analyze_one(
    tool: Path,
    input_root: Path,
    output_root: Path,
    binary: Path,
    validator: jsonschema.Draft202012Validator,
    timeout_seconds: int,
) -> dict[str, Any]:
    relative = binary.relative_to(input_root)
    report_path = output_root / "json" / relative.parent / f"{relative.name}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "path": relative.as_posix(),
        "source": relative.parts[0] if len(relative.parts) > 1 else "root",
        "size_bytes": binary.stat().st_size,
        "sha256": sha256_file(binary),
        "returncode": "",
        "elapsed_ms": 0,
        "report_valid": False,
        "functions": "",
        "score": "",
        "verdict": "",
        "evidence_level": "",
        "findings": "",
        "parse_failures": "",
        "unwind_anomalies": "",
        "error": "",
    }

    started = time.perf_counter()
    try:
        process = subprocess.run(
            [
                str(tool),
                str(binary),
                "--heuristics",
                "--json",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
        result["error"] = f"timeout after {timeout_seconds}s"
        return result

    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
    result["returncode"] = process.returncode
    if process.returncode != 0 or not report_path.is_file():
        result["error"] = compact_error(process.stderr or process.stdout)
        return result

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result["error"] = f"invalid JSON: {exc}"
        return result

    schema_errors = sorted(
        validator.iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )
    semantic_errors = validate_report_semantics(report)
    if schema_errors or semantic_errors:
        messages = [
            "schema: "
            + "/".join(str(part) for part in error.absolute_path)
            + f": {error.message}"
            for error in schema_errors[:3]
        ]
        messages.extend(f"semantics: {error}" for error in semantic_errors[:3])
        result["error"] = compact_error("; ".join(messages))
        return result

    heuristic = report.get("heuristic_analysis", {})
    result.update(
        {
            "report_valid": True,
            "functions": len(report.get("functions", [])),
            "score": heuristic.get("score", 0),
            "verdict": heuristic.get("verdict", ""),
            "evidence_level": heuristic.get("evidence_level", ""),
            "findings": len(heuristic.get("findings", [])),
            "parse_failures": heuristic.get("unwind_parse_fail", 0),
            "unwind_anomalies": heuristic.get("unwind_anomalies", 0),
        }
    )
    return result


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, rows: list[dict[str, Any]]) -> None:
    valid = [row for row in rows if row["report_valid"]]
    failed = [row for row in rows if not row["report_valid"]]
    flagged = [row for row in valid if int(row["score"]) > 0]
    timings = [float(row["elapsed_ms"]) for row in valid]
    verdicts = Counter(row["verdict"] for row in valid)
    sources: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        sources[row["source"]].append(row)

    lines = [
        "# Real-World Corpus Report",
        "",
        f"- Files: **{len(rows)}**",
        f"- Successful analyses with valid reports: **{len(valid)}**",
        f"- Failed, timed out or invalid reports: **{len(failed)}**",
        f"- Files with non-zero heuristic score: **{len(flagged)}**",
        f"- Runtime functions parsed: **{sum(int(row['functions']) for row in valid):,}**",
        f"- Total input size: **{sum(int(row['size_bytes']) for row in rows) / 1024 / 1024:.1f} MiB**",
        f"- Median analysis time: **{statistics.median(timings) if timings else 0:.0f} ms**",
        f"- 95th percentile analysis time: **{percentile(timings, 0.95):.0f} ms**",
        f"- Maximum analysis time: **{max(timings) if timings else 0:.0f} ms**",
        "",
        "## Sources",
        "",
        "| Source | Files | Valid | Flagged |",
        "|---|---:|---:|---:|",
    ]
    for source, source_rows in sorted(sources.items()):
        source_valid = sum(bool(row["report_valid"]) for row in source_rows)
        source_flagged = sum(
            bool(row["report_valid"]) and int(row["score"]) > 0
            for row in source_rows
        )
        lines.append(
            f"| {source} | {len(source_rows)} | {source_valid} | {source_flagged} |"
        )

    lines.extend(
        [
            "",
            "## Verdicts",
            "",
            "| Verdict | Count |",
            "|---|---:|",
        ]
    )
    for verdict, count in sorted(verdicts.items()):
        lines.append(f"| {verdict or '(empty)'} | {count} |")

    lines.extend(
        [
            "",
            "## Flagged Files",
            "",
            "These are compatibility observations on an official benign corpus, "
            "not proof of tampering.",
            "",
            "| File | Score | Verdict | Findings | Parse failures | Unwind anomalies |",
            "|---|---:|---|---:|---:|---:|",
        ]
    )
    for row in sorted(
        flagged,
        key=lambda item: (-int(item["score"]), item["path"]),
    ):
        lines.append(
            f"| `{row['path']}` | {row['score']} | {row['verdict']} | "
            f"{row['findings']} | {row['parse_failures']} | "
            f"{row['unwind_anomalies']} |"
        )

    if failed:
        lines.extend(
            [
                "",
                "## Failures",
                "",
                "| File | Return code | Error |",
                "|---|---:|---|",
            ]
        )
        for row in failed:
            lines.append(
                f"| `{row['path']}` | {row['returncode']} | {row['error']} |"
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run EH/Unwind Analyzer against a real-world PE corpus"
    )
    parser.add_argument("tool", type=Path)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    tool = args.tool.resolve()
    input_root = args.input.resolve()
    output_root = args.output.resolve()
    if not tool.is_file() or not input_root.is_dir():
        print("tool or corpus directory is missing", file=sys.stderr)
        return 2
    output_root.mkdir(parents=True, exist_ok=True)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    binaries = sorted(
        path
        for path in input_root.rglob("*")
        if (
            path.is_file()
            and path.name != ".DS_Store"
            and not path.name.startswith("._")
            and path.suffix.lower() in EXTENSIONS
        )
    )
    if not binaries:
        print("no PE candidates found", file=sys.stderr)
        return 2

    rows: list[dict[str, Any]] = []
    for index, binary in enumerate(binaries, 1):
        row = analyze_one(
            tool,
            input_root,
            output_root,
            binary,
            validator,
            args.timeout,
        )
        rows.append(row)
        status = "OK" if row["report_valid"] else "FAIL"
        print(f"[{index:03d}/{len(binaries):03d}] {status} {row['path']}")

    write_csv(output_root / "results.csv", rows)
    (output_root / "summary.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_markdown(output_root / "SUMMARY.md", rows)
    failures = sum(not row["report_valid"] for row in rows)
    print(
        f"Completed: {len(rows) - failures}/{len(rows)} valid; "
        f"reports: {output_root}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
