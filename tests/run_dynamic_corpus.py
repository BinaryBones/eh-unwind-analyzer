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
PE_EXTENSIONS = {".exe", ".dll", ".pyd", ".sys"}
SIGNAL_FIELDS = (
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
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def compact(text: str, limit: int = 500) -> str:
    return " ".join(text.split())[:limit]


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[index]


def event_types(dynamic: dict[str, Any]) -> set[str]:
    return {
        event.get("type", "")
        for event in dynamic.get("events", [])
        if isinstance(event, dict)
    }


def classify(
    extension: str,
    returncode: int | str,
    report_valid: bool,
    dynamic: dict[str, Any],
    external_timeout: bool,
) -> str:
    if external_timeout:
        return "harness_timeout"
    if not report_valid:
        return "invalid_or_missing_report"

    ran = dynamic.get("ran") is True
    ok = dynamic.get("ok") is True
    timed_out = dynamic.get("timed_out") is True
    target_exited = dynamic.get("target_exited") is True
    events = dynamic.get("events", [])
    types = event_types(dynamic)

    if extension != ".exe" and not ran and returncode != 0:
        return "unsupported_library_launch"
    if not ran:
        return "launch_failure"
    if timed_out:
        if (
            not ok
            and not target_exited
            and returncode != 0
            and "timeout" in types
        ):
            return "controlled_timeout"
        return "timeout_contract_failure"
    if ok and target_exited and returncode == 0 and events:
        return "completed"
    return "dynamic_contract_failure"


def expected_signal_result(name: str, dynamic: dict[str, Any]) -> str:
    checks = {
        "15_dynamic_veh.exe": (
            dynamic.get("exceptions_seen", 0) > 0
            and dynamic.get("veh_registrations", 0) > 0
            and dynamic.get("veh_hits", 0) > 0
        ),
        "16_dynamic_vch.exe": (
            dynamic.get("vch_registrations", 0) > 0
            and dynamic.get("vch_hits", 0) > 0
        ),
        "17_dynamic_uef.exe": (
            dynamic.get("exceptions_seen", 0) > 0
            and dynamic.get("uef_set_calls", 0) > 0
            and dynamic.get("uef_hits", 0) > 0
        ),
        "18_dynamic_rtl_function_table.exe": (
            dynamic.get("rtl_add_function_table_calls", 0) > 0
            and dynamic.get("rtl_install_function_table_cb_calls", 0) > 0
        ),
    }
    if name not in checks:
        return ""
    return "pass" if checks[name] else "fail"


def analyze_one(
    tool: Path,
    collection: str,
    input_root: Path,
    output_root: Path,
    binary: Path,
    validator: jsonschema.Draft202012Validator,
    timeout_ms: int,
    trace_steps: int,
) -> dict[str, Any]:
    relative = binary.relative_to(input_root)
    stem = f"{relative.name}.json"
    report_path = output_root / "json" / collection / relative.parent / stem
    log_path = output_root / "logs" / collection / relative.parent / f"{relative.name}.log"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "collection": collection,
        "source": relative.parts[0] if len(relative.parts) > 1 else "root",
        "path": relative.as_posix(),
        "extension": binary.suffix.lower(),
        "size_bytes": binary.stat().st_size,
        "sha256": sha256_file(binary),
        "returncode": "",
        "elapsed_ms": 0,
        "report_created": False,
        "report_valid": False,
        "dynamic_enabled": False,
        "ran": False,
        "ok": False,
        "timed_out": False,
        "target_exited": False,
        "target_exit_code": "",
        "event_count": 0,
        "dropped_events": 0,
        "exceptions_seen": 0,
        "first_chance_seen": 0,
        "second_chance_seen": 0,
        "unwind_handler_bp_set": 0,
        "unwind_handler_hits": 0,
        "veh_registrations": 0,
        "veh_hits": 0,
        "vch_registrations": 0,
        "vch_hits": 0,
        "uef_set_calls": 0,
        "uef_hits": 0,
        "rtl_add_function_table_calls": 0,
        "rtl_install_function_table_cb_calls": 0,
        "trace_count": 0,
        "expected_signal": "",
        "outcome": "",
        "error": "",
    }

    command = [
        str(tool),
        str(binary),
        "--heuristics",
        "--dynamic",
        "--timeout-ms",
        str(timeout_ms),
        "--trace-steps",
        str(trace_steps),
        "--json",
        str(report_path),
    ]
    started = time.perf_counter()
    external_timeout = False
    output = b""
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=(timeout_ms / 1000.0) + 15.0,
        )
        result["returncode"] = process.returncode
        output = process.stdout
    except subprocess.TimeoutExpired as exc:
        external_timeout = True
        output = (exc.stdout or b"") + b"\nHARNESS TIMEOUT\n"
        result["error"] = "analyzer exceeded its own timeout plus 15 seconds"
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
    log_path.write_bytes(output)

    report: dict[str, Any] = {}
    schema_errors: list[Any] = []
    semantic_errors: list[str] = []
    if report_path.is_file():
        result["report_created"] = True
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result["error"] = f"invalid JSON: {exc}"
        else:
            schema_errors = sorted(
                validator.iter_errors(report),
                key=lambda error: list(error.absolute_path),
            )
            semantic_errors = validate_report_semantics(report)
            if not schema_errors and not semantic_errors:
                result["report_valid"] = True
            else:
                messages = [
                    "schema "
                    + "/".join(str(part) for part in error.absolute_path)
                    + f": {error.message}"
                    for error in schema_errors[:3]
                ]
                messages.extend(f"semantics: {error}" for error in semantic_errors[:3])
                result["error"] = compact("; ".join(messages))
    elif not result["error"]:
        result["error"] = "report was not created"

    dynamic = report.get("dynamic_validation", {})
    if isinstance(dynamic, dict):
        mappings = {
            "dynamic_enabled": "enabled",
            "ran": "ran",
            "ok": "ok",
            "timed_out": "timed_out",
            "target_exited": "target_exited",
            "target_exit_code": "target_exit_code",
            "dropped_events": "dropped_events",
            "exceptions_seen": "exceptions_seen",
            "first_chance_seen": "first_chance_seen",
            "second_chance_seen": "second_chance_seen",
            "unwind_handler_bp_set": "unwind_handler_bp_set",
            "unwind_handler_hits": "unwind_handler_hits",
            "veh_registrations": "veh_registrations",
            "veh_hits": "veh_hits",
            "vch_registrations": "vch_registrations",
            "vch_hits": "vch_hits",
            "uef_set_calls": "uef_set_calls",
            "uef_hits": "uef_hits",
            "rtl_add_function_table_calls": "rtl_add_function_table_calls",
            "rtl_install_function_table_cb_calls": (
                "rtl_install_function_table_cb_calls"
            ),
        }
        for output_field, report_field in mappings.items():
            result[output_field] = dynamic.get(report_field, result[output_field])
        result["event_count"] = len(dynamic.get("events", []))
        result["trace_count"] = len(dynamic.get("trace", []))
        result["expected_signal"] = expected_signal_result(binary.name, dynamic)

    result["outcome"] = classify(
        result["extension"],
        result["returncode"],
        bool(result["report_valid"]),
        dynamic if isinstance(dynamic, dict) else {},
        external_timeout,
    )
    if result["outcome"] == "launch_failure" and b"err=740" in output:
        result["outcome"] = "elevation_required"
    if not result["error"] and result["outcome"] not in (
        "completed",
        "controlled_timeout",
        "elevation_required",
        "unsupported_library_launch",
    ):
        result["error"] = compact(output.decode("utf-8", errors="replace"))
    if result["outcome"] == "elevation_required" and not result["error"]:
        result["error"] = "CreateProcess returned ERROR_ELEVATION_REQUIRED (740)"
    if result["outcome"] == "unsupported_library_launch" and not result["error"]:
        result["error"] = "CreateProcess cannot execute DLL/PYD targets"
    return result


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(
    path: Path,
    rows: list[dict[str, Any]],
    tool: Path,
    timeout_ms: int,
    trace_steps: int,
) -> None:
    outcomes = Counter(row["outcome"] for row in rows)
    valid = [row for row in rows if row["report_valid"]]
    ran = [row for row in valid if row["ran"]]
    completed = [row for row in rows if row["outcome"] == "completed"]
    timings = [float(row["elapsed_ms"]) for row in rows]
    signal_rows = [
        row
        for row in ran
        if any(int(row[field]) > 0 for field in SIGNAL_FIELDS)
        or int(row["exceptions_seen"]) > 0
    ]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["collection"], row["source"])].append(row)

    expected = [row for row in rows if row["expected_signal"]]
    problematic = [
        row
        for row in rows
        if row["outcome"]
        not in (
            "completed",
            "controlled_timeout",
            "elevation_required",
            "unsupported_library_launch",
        )
        or row["expected_signal"] == "fail"
    ]
    timed_out = [row for row in rows if row["outcome"] == "controlled_timeout"]
    elevation_required = [
        row for row in rows if row["outcome"] == "elevation_required"
    ]
    libraries = [
        row for row in rows if row["outcome"] == "unsupported_library_launch"
    ]
    nonzero_targets = [
        row
        for row in completed
        if row["target_exit_code"] not in ("", 0, "0")
    ]

    tool_hash = sha256_file(tool)
    lines = [
        "# Dynamic Corpus Validation",
        "",
        "## Run Configuration",
        "",
        f"- Analyzer: `{tool}`",
        f"- Analyzer SHA-256: `{tool_hash}`",
        f"- Dynamic timeout: **{timeout_ms} ms**",
        f"- Trace budget: **{trace_steps} samples**",
        f"- Inputs: **{len(rows)}**",
        "",
        "## Executive Summary",
        "",
        f"- Schema and semantic valid reports: **{len(valid)}/{len(rows)}**",
        f"- Dynamic sessions started: **{len(ran)}/{len(rows)}**",
        f"- Targets completed naturally: **{outcomes['completed']}**",
        f"- Timeouts handled by the analyzer contract: **{outcomes['controlled_timeout']}**",
        f"- EXE targets requiring elevation before debugging: **{outcomes['elevation_required']}**",
        f"- DLL/PYD targets rejected at CreateProcess: **{outcomes['unsupported_library_launch']}**",
        f"- Unexpected failures: **{len(problematic)}**",
        f"- Reports with dropped events: **{sum(int(row['dropped_events']) > 0 for row in valid)}**",
        f"- Trace budget violations: **{sum(int(row['trace_count']) > trace_steps for row in valid)}**",
        f"- Median wall time: **{statistics.median(timings):.0f} ms**",
        f"- 95th percentile wall time: **{percentile(timings, 0.95):.0f} ms**",
        "",
        "## Outcome Breakdown",
        "",
        "| Outcome | Count |",
        "|---|---:|",
    ]
    for outcome, count in sorted(outcomes.items()):
        lines.append(f"| {outcome} | {count} |")

    lines.extend(
        [
            "",
            "## Corpus Breakdown",
            "",
            "| Collection / source | Files | Valid reports | Ran | Completed | Timeouts | Elevation blocked | Unsupported libraries | Unexpected |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for key, group in sorted(grouped.items()):
        collection, source = key
        unexpected = sum(
            row["outcome"]
            not in (
                "completed",
                "controlled_timeout",
                "elevation_required",
                "unsupported_library_launch",
            )
            for row in group
        )
        lines.append(
            f"| {collection} / {source} | {len(group)} | "
            f"{sum(bool(row['report_valid']) for row in group)} | "
            f"{sum(bool(row['ran']) for row in group)} | "
            f"{sum(row['outcome'] == 'completed' for row in group)} | "
            f"{sum(row['outcome'] == 'controlled_timeout' for row in group)} | "
            f"{sum(row['outcome'] == 'elevation_required' for row in group)} | "
            f"{sum(row['outcome'] == 'unsupported_library_launch' for row in group)} | "
            f"{unexpected} |"
        )

    lines.extend(
        [
            "",
            "## Prepared Dynamic Scenarios",
            "",
            "| Target | Expected signal check | Events | Exceptions | VEH hits | VCH hits | UEF hits | RtlAdd | RtlInstallCallback | Trace |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in expected:
        lines.append(
            f"| `{row['path']}` | {row['expected_signal']} | {row['event_count']} | "
            f"{row['exceptions_seen']} | {row['veh_hits']} | {row['vch_hits']} | "
            f"{row['uef_hits']} | {row['rtl_add_function_table_calls']} | "
            f"{row['rtl_install_function_table_cb_calls']} | {row['trace_count']} |"
        )

    lines.extend(
        [
            "",
            "## Runtime Evidence On The Full Corpus",
            "",
            f"- Reports with exceptions or dynamic registration/hit evidence: **{len(signal_rows)}**",
            f"- Exceptions observed: **{sum(int(row['exceptions_seen']) for row in ran)}**",
            f"- Unwind handler hits: **{sum(int(row['unwind_handler_hits']) for row in ran)}**",
            f"- VEH registrations / hits: **{sum(int(row['veh_registrations']) for row in ran)} / {sum(int(row['veh_hits']) for row in ran)}**",
            f"- VCH registrations / hits: **{sum(int(row['vch_registrations']) for row in ran)} / {sum(int(row['vch_hits']) for row in ran)}**",
            f"- UEF set calls / hits: **{sum(int(row['uef_set_calls']) for row in ran)} / {sum(int(row['uef_hits']) for row in ran)}**",
            f"- RtlAddFunctionTable calls: **{sum(int(row['rtl_add_function_table_calls']) for row in ran)}**",
            f"- RtlInstallFunctionTableCallback calls: **{sum(int(row['rtl_install_function_table_cb_calls']) for row in ran)}**",
        ]
    )

    if timed_out:
        lines.extend(
            [
                "",
                "## Controlled Timeouts",
                "",
                "These targets did not exit under a no-argument invocation. The analyzer emitted a timeout event, marked the report failed, returned non-zero, and terminated the target.",
                "",
                "| Target | Elapsed ms | Events |",
                "|---|---:|---:|",
            ]
        )
        for row in timed_out:
            lines.append(
                f"| `{row['collection']}/{row['path']}` | "
                f"{row['elapsed_ms']} | {row['event_count']} |"
            )

    if libraries:
        lines.extend(
            [
                "",
                "## Unsupported Library Launches",
                "",
                "The dynamic collector uses CreateProcess and therefore cannot directly execute DLL or PYD inputs. Static reports are still valid, but dynamic_validation.ran is false.",
                "",
                "| Extension | Count |",
                "|---|---:|",
            ]
        )
        extension_counts = Counter(row["extension"] for row in libraries)
        for extension, count in sorted(extension_counts.items()):
            lines.append(f"| {extension} | {count} |")

    if elevation_required:
        lines.extend(
            [
                "",
                "## Elevation-Required Targets",
                "",
                "CreateProcess returned ERROR_ELEVATION_REQUIRED (740), so no debug session was started. These targets require a separate elevated validation run.",
                "",
                "| Target | Valid report |",
                "|---|---|",
            ]
        )
        for row in elevation_required:
            lines.append(
                f"| `{row['collection']}/{row['path']}` | "
                f"{'yes' if row['report_valid'] else 'no'} |"
            )

    if nonzero_targets:
        lines.extend(
            [
                "",
                "## Completed Targets With Non-Zero Exit Codes",
                "",
                "| Target | Exit code | Exceptions |",
                "|---|---:|---:|",
            ]
        )
        for row in nonzero_targets:
            lines.append(
                f"| `{row['collection']}/{row['path']}` | "
                f"{row['target_exit_code']} | {row['exceptions_seen']} |"
            )

    if problematic:
        lines.extend(
            [
                "",
                "## Unexpected Failures",
                "",
                "| Target | Outcome | Return code | Error |",
                "|---|---|---:|---|",
            ]
        )
        for row in problematic:
            lines.append(
                f"| `{row['collection']}/{row['path']}` | {row['outcome']} | "
                f"{row['returncode']} | {row['error']} |"
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Windows dynamic validation over synthetic and real corpora"
    )
    parser.add_argument("tool", type=Path)
    parser.add_argument("synthetic", type=Path)
    parser.add_argument("real", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    parser.add_argument("--trace-steps", type=int, default=32)
    args = parser.parse_args()

    tool = args.tool.resolve()
    synthetic = args.synthetic.resolve()
    real = args.real.resolve()
    output = args.output.resolve()
    if not tool.is_file() or not synthetic.is_dir() or not real.is_dir():
        print("tool or corpus directory is missing", file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )

    corpora = (("synthetic", synthetic), ("real", real))
    inputs = [
        (collection, root, path)
        for collection, root in corpora
        for path in sorted(root.rglob("*"))
        if (
            path.is_file()
            and not path.name.startswith("._")
            and path.suffix.lower() in PE_EXTENSIONS
        )
    ]
    rows: list[dict[str, Any]] = []
    for index, (collection, root, binary) in enumerate(inputs, 1):
        row = analyze_one(
            tool,
            collection,
            root,
            output,
            binary,
            validator,
            args.timeout_ms,
            args.trace_steps,
        )
        rows.append(row)
        print(
            f"[{index:03d}/{len(inputs):03d}] "
            f"{row['outcome']:<28} {collection}/{row['path']}",
            flush=True,
        )

    write_csv(output / "results.csv", rows)
    (output / "results.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_markdown(
        output / "REPORT.md",
        rows,
        tool,
        args.timeout_ms,
        args.trace_steps,
    )

    unexpected = sum(
        row["outcome"]
        not in (
            "completed",
            "controlled_timeout",
            "elevation_required",
            "unsupported_library_launch",
        )
        or row["expected_signal"] == "fail"
        for row in rows
    )
    print(f"Completed {len(rows)} inputs; unexpected failures: {unexpected}")
    return 1 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
