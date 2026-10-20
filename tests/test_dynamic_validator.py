#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "tests" / "validate_dynamic_reports.py"


def make_report(**updates: int) -> dict:
    dynamic = {
        "enabled": True,
        "ran": True,
        "ok": True,
        "timed_out": False,
        "target_exited": True,
        "events": [{"type": "exception"}],
        "exceptions_seen": 1,
        "veh_registrations": 0,
        "veh_hits": 0,
        "uef_set_calls": 0,
        "uef_hits": 0,
        "vch_registrations": 0,
        "vch_hits": 0,
        "rtl_add_function_table_calls": 0,
        "rtl_install_function_table_cb_calls": 0,
    }
    dynamic.update(updates)
    return {
        "report_metadata": {"input_sha256": "0" * 64},
        "dynamic_validation": dynamic,
    }


def run_validator(paths: dict[str, Path]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--veh",
            str(paths["veh"]),
            "--uef",
            str(paths["uef"]),
            "--vch",
            str(paths["vch"]),
            "--rtl",
            str(paths["rtl"]),
        ],
        capture_output=True,
        text=True,
    )


def main() -> int:
    reports = {
        "veh": make_report(veh_registrations=1, veh_hits=1),
        "uef": make_report(uef_set_calls=1, uef_hits=1),
        "vch": make_report(vch_registrations=1, vch_hits=1),
        "rtl": make_report(
            rtl_add_function_table_calls=1,
            rtl_install_function_table_cb_calls=1,
        ),
    }

    with tempfile.TemporaryDirectory() as temp_dir:
        paths: dict[str, Path] = {}
        for name, report in reports.items():
            path = Path(temp_dir) / f"{name}.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            paths[name] = path

        positive = run_validator(paths)
        if positive.returncode != 0:
            print(positive.stdout, end="")
            print(positive.stderr, end="", file=sys.stderr)
            return 1

        reports["veh"]["dynamic_validation"]["timed_out"] = True
        paths["veh"].write_text(json.dumps(reports["veh"]), encoding="utf-8")
        negative = run_validator(paths)
        if negative.returncode == 0:
            print("validator accepted a timed-out dynamic report", file=sys.stderr)
            return 1

        reports["veh"]["dynamic_validation"]["timed_out"] = False
        paths["veh"].write_text(json.dumps(reports["veh"]), encoding="utf-8")
        uef = reports["uef"]["dynamic_validation"]
        uef.update(uef_hits=0, second_chance_seen=1, target_exit_code=0xE0000003,
                   events=[{"type": "exception", "exception_code": "0xe0000003",
                            "first_chance": False}])
        paths["uef"].write_text(json.dumps(reports["uef"]), encoding="utf-8")
        if run_validator(paths).returncode != 0:
            print("validator rejected documented debugger second-chance delivery", file=sys.stderr)
            return 1

        for field, invalid in (
            ("uef_set_calls", 0),
            ("second_chance_seen", 0),
            ("target_exit_code", 0),
            ("events", [{"type": "exception", "exception_code": "0xc0000005", "first_chance": False}]),
            ("events", [{"type": "exception", "exception_code": "0xe0000003", "first_chance": True}]),
        ):
            original = uef[field]
            uef[field] = invalid
            paths["uef"].write_text(json.dumps(reports["uef"]), encoding="utf-8")
            if run_validator(paths).returncode == 0:
                print(f"validator accepted invalid UEF evidence: {field}", file=sys.stderr)
                return 1
            uef[field] = original

    print("test_dynamic_validator: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
