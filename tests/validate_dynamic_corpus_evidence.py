#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema

from report_semantics import validate_report_semantics
from run_dynamic_corpus import expected_signal_result


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE = ROOT / "reports" / "dynamic_validation_2026-06-08" / "full"
DEFAULT_SCHEMA = ROOT / "docs" / "report.schema.json"
DYNAMIC_FIELDS = (
    "ran",
    "ok",
    "timed_out",
    "target_exited",
    "target_exit_code",
    "dropped_events",
    "exceptions_seen",
    "first_chance_seen",
    "second_chance_seen",
    "unwind_handler_bp_set",
    "unwind_handler_hits",
    "veh_registrations",
    "veh_hits",
    "vch_registrations",
    "vch_hits",
    "uef_set_calls",
    "uef_hits",
    "rtl_add_function_table_calls",
    "rtl_install_function_table_cb_calls",
)


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def report_path(evidence: Path, row: dict[str, Any]) -> Path:
    relative = Path(str(row["path"]))
    return (
        evidence
        / "json"
        / str(row["collection"])
        / relative.parent
        / f"{relative.name}.json"
    )


def source_path(
    row: dict[str, Any],
    synthetic_root: Path | None,
    real_root: Path | None,
) -> Path | None:
    root = synthetic_root if row["collection"] == "synthetic" else real_root
    return None if root is None else root / str(row["path"])


def equal_summary_value(expected: Any, actual: Any) -> bool:
    if isinstance(expected, bool):
        return actual is expected
    if expected == "":
        return actual in ("", None)
    return actual == expected


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate archived Windows dynamic-corpus evidence"
    )
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--synthetic-root", type=Path)
    parser.add_argument("--real-root", type=Path)
    parser.add_argument("--trace-budget", type=int, default=32)
    args = parser.parse_args()

    evidence = args.evidence.resolve()
    rows = json.loads((evidence / "results.json").read_text(encoding="utf-8"))
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    synthetic_root = (
        args.synthetic_root.resolve() if args.synthetic_root is not None else None
    )
    real_root = args.real_root.resolve() if args.real_root is not None else None
    errors: list[str] = []
    seen_paths: set[tuple[str, str]] = set()

    for row in rows:
        key = (str(row["collection"]), str(row["path"]))
        if key in seen_paths:
            errors.append(f"{key}: duplicate summary row")
            continue
        seen_paths.add(key)

        path = report_path(evidence, row)
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{key}: cannot read report: {exc}")
            continue

        schema_errors = sorted(
            validator.iter_errors(report),
            key=lambda error: list(error.absolute_path),
        )
        if schema_errors:
            errors.append(f"{key}: schema: {schema_errors[0].message}")
        semantic_errors = validate_report_semantics(report)
        if semantic_errors:
            errors.append(f"{key}: semantics: {semantic_errors[0]}")

        metadata = report.get("report_metadata", {})
        dynamic = report.get("dynamic_validation", {})
        if metadata.get("input_sha256") != row["sha256"]:
            errors.append(f"{key}: report/input SHA-256 mismatch")
        if metadata.get("input_size") != row["size_bytes"]:
            errors.append(f"{key}: report/input size mismatch")
        if dynamic.get("enabled") is not row["dynamic_enabled"]:
            errors.append(f"{key}: dynamic enabled mismatch")

        for field in DYNAMIC_FIELDS:
            if not equal_summary_value(row[field], dynamic.get(field)):
                errors.append(f"{key}: summary mismatch for {field}")
        if row["event_count"] != len(dynamic.get("events", [])):
            errors.append(f"{key}: event count mismatch")
        if row["trace_count"] != len(dynamic.get("trace", [])):
            errors.append(f"{key}: trace count mismatch")
        if row["trace_count"] > args.trace_budget:
            errors.append(f"{key}: trace budget exceeded")
        if row["dropped_events"] != 0:
            errors.append(f"{key}: dropped dynamic events")

        expected_signal = expected_signal_result(Path(row["path"]).name, dynamic)
        if row["expected_signal"] != expected_signal:
            errors.append(f"{key}: expected-signal result mismatch")

        source = source_path(row, synthetic_root, real_root)
        if source is not None:
            if not source.is_file():
                errors.append(f"{key}: source binary is missing")
            else:
                if source.stat().st_size != row["size_bytes"]:
                    errors.append(f"{key}: source binary size mismatch")
                if sha256_file(source) != row["sha256"]:
                    errors.append(f"{key}: source binary SHA-256 mismatch")

    with (evidence / "results.csv").open(encoding="utf-8", newline="") as stream:
        csv_rows = list(csv.DictReader(stream))
    csv_keys = {(row["collection"], row["path"]) for row in csv_rows}
    if len(csv_rows) != len(rows) or csv_keys != seen_paths:
        errors.append("results.csv and results.json contain different rows")

    expected_smoke = {
        "15_dynamic_veh.exe",
        "16_dynamic_vch.exe",
        "17_dynamic_uef.exe",
        "18_dynamic_rtl_function_table.exe",
    }
    smoke = {
        Path(str(row["path"])).name
        for row in rows
        if row["expected_signal"] == "pass"
    }
    if smoke != expected_smoke:
        errors.append(f"focused smoke set mismatch: {sorted(smoke)}")

    if errors:
        print(f"dynamic corpus evidence: FAILED ({len(errors)} errors)")
        for error in errors[:50]:
            print(f"- {error}")
        return 1

    print(
        "dynamic corpus evidence: OK "
        f"reports={len(rows)} "
        f"ran={sum(row['ran'] is True for row in rows)} "
        f"completed={sum(row['outcome'] == 'completed' for row in rows)} "
        f"timeouts={sum(row['outcome'] == 'controlled_timeout' for row in rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
