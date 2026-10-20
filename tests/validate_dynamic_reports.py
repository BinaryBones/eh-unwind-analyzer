#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jsonschema

from report_semantics import validate_report_semantics


def load_report(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot read valid JSON: {exc}") from exc


def require(report: dict, path: Path, field: str, predicate, expected: str) -> None:
    current = report
    try:
        for part in field.split("."):
            current = current[part]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"{path}: missing field {field}") from exc
    if not predicate(current):
        raise ValueError(f"{path}: {field} expected {expected}, got {current!r}")


def validate_common(report: dict, path: Path) -> None:
    require(report, path, "report_metadata.input_sha256", lambda v: len(v) == 64, "SHA-256")
    require(report, path, "dynamic_validation.enabled", lambda v: v is True, "true")
    require(report, path, "dynamic_validation.ran", lambda v: v is True, "true")
    require(report, path, "dynamic_validation.ok", lambda v: v is True, "true")
    require(report, path, "dynamic_validation.timed_out", lambda v: v is False, "false")
    require(report, path, "dynamic_validation.target_exited", lambda v: v is True, "true")
    require(report, path, "dynamic_validation.events", lambda v: isinstance(v, list) and v, "non-empty list")


def validate_uef_outcome(report: dict, path: Path) -> None:
    # Windows may route an unhandled exception directly to the debugger instead
    # of invoking the registered filter. MSVC and MinGW CRTs differ here.
    # https://learn.microsoft.com/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter
    dynamic = report["dynamic_validation"]
    if dynamic.get("uef_hits", 0) > 0:
        return
    require(report, path, "dynamic_validation.second_chance_seen", lambda v: v > 0, "> 0")
    require(report, path, "dynamic_validation.target_exit_code",
            lambda v: v == 0xE0000003, "UEF fixture exception code 0xE0000003")
    require(report, path, "dynamic_validation.events", lambda events: any(
        event.get("type") == "exception"
        and event.get("exception_code", "").lower() == "0xe0000003"
        and event.get("first_chance") is False
        for event in events
    ), "second-chance event for the UEF fixture exception 0xE0000003")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Windows dynamic smoke reports")
    parser.add_argument("--veh", type=Path, required=True)
    parser.add_argument("--uef", type=Path, required=True)
    parser.add_argument("--vch", type=Path, required=True)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--schema", type=Path)
    args = parser.parse_args()
    schema_validator = None
    if args.schema:
        schema = load_report(args.schema)
        jsonschema.Draft202012Validator.check_schema(schema)
        schema_validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )

    checks = {
        "veh": (
            args.veh,
            {
                "dynamic_validation.exceptions_seen": lambda v: v > 0,
                "dynamic_validation.veh_registrations": lambda v: v > 0,
                "dynamic_validation.veh_hits": lambda v: v > 0,
            },
        ),
        "uef": (
            args.uef,
            {
                "dynamic_validation.exceptions_seen": lambda v: v > 0,
                "dynamic_validation.uef_set_calls": lambda v: v > 0,
            },
        ),
        "vch": (
            args.vch,
            {
                "dynamic_validation.vch_registrations": lambda v: v > 0,
                "dynamic_validation.vch_hits": lambda v: v > 0,
            },
        ),
        "rtl": (
            args.rtl,
            {
                "dynamic_validation.rtl_add_function_table_calls": lambda v: v > 0,
                "dynamic_validation.rtl_install_function_table_cb_calls": lambda v: v > 0,
            },
        ),
    }

    failed = False
    for name, (path, fields) in checks.items():
        try:
            report = load_report(path)
            if schema_validator:
                errors = list(schema_validator.iter_errors(report))
                if errors:
                    first = errors[0]
                    location = "/".join(str(part) for part in first.absolute_path) or "<root>"
                    raise ValueError(f"schema violation at {location}: {first.message}")
                semantic_errors = validate_report_semantics(report)
                if semantic_errors:
                    raise ValueError(f"semantic violation: {semantic_errors[0]}")
            validate_common(report, path)
            for field, predicate in fields.items():
                require(report, path, field, predicate, "> 0")
            if name == "uef":
                validate_uef_outcome(report, path)
        except ValueError as exc:
            failed = True
            print(f"[FAIL] {name}: {exc}", file=sys.stderr)
        else:
            print(f"[OK] {name}: {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
