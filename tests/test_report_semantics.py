#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path

import jsonschema

from report_semantics import validate_report_semantics


ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests" / "samples" / "bin" / "benign_minimal.exe"
REPORT_SCHEMA = ROOT / "docs" / "report.schema.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        report_path = Path(temp_dir) / "report.json"
        result = subprocess.run(
            [
                str(args.tool.resolve()),
                str(SAMPLE),
                "--heuristics",
                "--json",
                str(report_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))

    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(report)
    errors = validate_report_semantics(report)
    if errors:
        raise AssertionError("valid report rejected:\n" + "\n".join(errors))

    dynamic_report = copy.deepcopy(report)
    dynamic_report["dynamic_validation"] = {
        "enabled": True,
        "ran": True,
        "ok": True,
        "timed_out": False,
        "target_exited": True,
        "target_exit_code": 0,
        "timeout_ms": 1000,
        "trace_steps": 8,
        "instrumentation_complete": True,
        "modules_observed_peak": 4,
        "module_refresh_failures": 0,
        "module_list_truncations": 0,
        "unwind_handlers_discovered": 0,
        "breakpoint_set_attempts": 5,
        "breakpoint_set_failures": 0,
        "breakpoint_capacity_drops": 0,
        "pending_rearm_failures": 0,
        "breakpoint_rearm_failures": 0,
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
        "dynamic_signal_count": 0,
        "dropped_events": 0,
        "details": "",
        "events": [],
        "trace": [],
    }
    jsonschema.Draft202012Validator(schema).validate(dynamic_report)
    dynamic_errors = validate_report_semantics(dynamic_report)
    if dynamic_errors:
        raise AssertionError(
            "valid dynamic report rejected:\n" + "\n".join(dynamic_errors)
        )

    broken = copy.deepcopy(report)
    broken["functions"][0]["size"] += 1
    broken["heuristic_analysis"]["weak_finding_count"] += 1
    broken["heuristic_analysis"]["score_weight_sum"] = 101
    broken["heuristic_analysis"]["score"] = 99
    broken["assessment"]["dynamic_signal_count"] += 1
    broken["sections"][0]["executable"] = False
    errors = validate_report_semantics(broken)
    expected_fragments = (
        "functions[0].size",
        "heuristic_analysis.weak_finding_count",
        "heuristic_analysis.score",
        "assessment.dynamic_signal_count",
        "sections[0].executable",
    )
    for fragment in expected_fragments:
        if not any(fragment in error for error in errors):
            raise AssertionError(f"semantic validator missed {fragment}: {errors}")

    print("test_report_semantics: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
