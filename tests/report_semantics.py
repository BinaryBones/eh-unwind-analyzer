#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

UA_ABI_MASK = sum(1 << bit for bit in range(12, 17))


def _hex_value(value: Any, path: str, errors: list[str]) -> int | None:
    if not isinstance(value, str):
        errors.append(f"{path}: expected hexadecimal string")
        return None
    try:
        return int(value, 16)
    except ValueError:
        errors.append(f"{path}: invalid hexadecimal value {value!r}")
        return None


def _dynamic_signal_count(dynamic: dict[str, Any] | None) -> int:
    if not dynamic:
        return 0
    return sum(
        (
            bool(dynamic.get("unwind_handler_hits")),
            bool(dynamic.get("veh_hits") or dynamic.get("veh_registrations")),
            bool(dynamic.get("vch_hits") or dynamic.get("vch_registrations")),
            bool(dynamic.get("uef_hits") or dynamic.get("uef_set_calls")),
            bool(
                dynamic.get("rtl_add_function_table_calls")
                or dynamic.get("rtl_install_function_table_cb_calls")
            ),
            bool(dynamic.get("second_chance_seen")),
        )
    )


def _dynamic_session_complete(dynamic: dict[str, Any] | None) -> bool:
    return bool(
        dynamic
        and dynamic.get("ran")
        and dynamic.get("ok")
        and not dynamic.get("timed_out")
        and dynamic.get("target_exited")
        and dynamic.get("instrumentation_complete")
    )


def _runtime_evidence_level(dynamic: dict[str, Any] | None) -> str:
    if not dynamic or not dynamic.get("ran"):
        return "none"
    strong = int(
        bool(
            dynamic.get("unwind_handler_hits")
            or dynamic.get("veh_hits")
            or dynamic.get("vch_hits")
            or dynamic.get("uef_hits")
        )
    )
    medium = int(
        bool(
            dynamic.get("rtl_add_function_table_calls")
            or dynamic.get("rtl_install_function_table_cb_calls")
        )
    ) + int(bool(dynamic.get("second_chance_seen")))
    weak = int(
        bool(
            dynamic.get("veh_registrations")
            or dynamic.get("vch_registrations")
            or dynamic.get("uef_set_calls")
            or dynamic.get("first_chance_seen")
        )
    )
    level = "none"
    if strong >= 1 and medium >= 1:
        level = "strong"
    elif strong >= 1 or medium >= 2:
        level = "medium"
    elif medium >= 1 or weak >= 1:
        level = "weak"
    if not _dynamic_session_complete(dynamic) and level != "none":
        return "weak"
    return level


def _correlated(
    heuristic: dict[str, Any] | None,
    dynamic: dict[str, Any] | None,
) -> bool:
    if not heuristic or not _dynamic_session_complete(dynamic):
        return False
    suspicious_handler = bool(
        heuristic.get("handler_nonexec_section")
        or heuristic.get("handler_writable_section")
        or "handler_dominance" in heuristic.get("evidence_families", [])
    )
    handler_hit = bool(
        dynamic.get("unwind_handler_hits")
        or dynamic.get("veh_hits")
        or dynamic.get("vch_hits")
        or dynamic.get("uef_hits")
    )
    suspicious_placement = bool(
        heuristic.get("unwind_exec_section")
        or heuristic.get("unwind_unusual_section")
        or heuristic.get("unwind_writable_section")
        or heuristic.get("handler_nonexec_section")
        or heuristic.get("handler_writable_section")
    )
    runtime_table = bool(
        dynamic.get("rtl_add_function_table_calls")
        or dynamic.get("rtl_install_function_table_cb_calls")
    )
    return (suspicious_handler and handler_hit) or (
        suspicious_placement and runtime_table
    )


def _case_strength(static_level: str, runtime_level: str, correlated: bool) -> str:
    if correlated and (static_level == "strong" or runtime_level == "strong"):
        return "strong_correlated_case"
    if correlated and (static_level == "medium" or runtime_level == "medium"):
        return "medium_correlated_case"
    if static_level == "strong" or runtime_level == "strong":
        return "strong_unconfirmed_case"
    if static_level == "medium" or runtime_level == "medium":
        return "medium_case"
    if static_level == "weak" or runtime_level == "weak":
        return "weak_case"
    return "no_case"


def validate_report_semantics(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    functions = report.get("functions", [])
    if not isinstance(functions, list):
        return ["functions: expected array"]

    exception = report.get("exception_directory", {})
    exception_size = _hex_value(exception.get("size"), "exception_directory.size", errors)
    exception_directory_oob = report.get("pe_validation", {}).get(
        "exception_directory_oob"
    )
    if (
        exception_size is not None
        and exception_directory_oob is not True
        and exception_size != len(functions) * 12
    ):
        errors.append(
            "exception_directory.size: expected "
            f"0x{len(functions) * 12:x} for {len(functions)} functions, "
            f"got 0x{exception_size:x}"
        )

    for index, function in enumerate(functions):
        prefix = f"functions[{index}]"
        if function.get("index") != index:
            errors.append(f"{prefix}.index: expected {index}, got {function.get('index')!r}")
        begin = _hex_value(function.get("begin_rva"), f"{prefix}.begin_rva", errors)
        end = _hex_value(function.get("end_rva"), f"{prefix}.end_rva", errors)
        if begin is not None and end is not None:
            expected_size = end - begin if end >= begin else 0
            if function.get("size") != expected_size:
                errors.append(
                    f"{prefix}.size: expected {expected_size}, got {function.get('size')!r}"
                )
        unwind = function.get("unwind", {})
        has_chain = unwind.get("has_chain")
        if (unwind.get("chain") is not None) != (has_chain is True):
            errors.append(f"{prefix}.unwind.chain: inconsistent with has_chain")
        if unwind.get("has_handler") is False:
            handler = _hex_value(
                unwind.get("handler_rva"), f"{prefix}.unwind.handler_rva", errors
            )
            if handler not in (None, 0):
                errors.append(f"{prefix}.unwind.handler_rva: expected zero without handler")
            if unwind.get("handler_section") != "-":
                errors.append(f"{prefix}.unwind.handler_section: expected '-' without handler")

    for index, section in enumerate(report.get("sections", [])):
        prefix = f"sections[{index}]"
        characteristics = _hex_value(
            section.get("characteristics"), f"{prefix}.characteristics", errors
        )
        if characteristics is None:
            continue
        expected = {
            "readable": bool(characteristics & 0x40000000),
            "writable": bool(characteristics & 0x80000000),
            "executable": bool(characteristics & 0x20000000),
        }
        for field, value in expected.items():
            if section.get(field) is not value:
                errors.append(
                    f"{prefix}.{field}: inconsistent with section characteristics"
                )

    heuristic = report.get("heuristic_analysis")
    if isinstance(heuristic, dict):
        score = heuristic.get("score")
        score_weight_sum = heuristic.get("score_weight_sum")
        if isinstance(score, int) and isinstance(score_weight_sum, int):
            expected_score = min(score_weight_sum, 100)
            if score != expected_score:
                errors.append(
                    "heuristic_analysis.score: expected min(score_weight_sum, 100) "
                    f"= {expected_score}, got {score!r}"
                )
        if heuristic.get("total") != len(functions):
            errors.append(
                f"heuristic_analysis.total: expected {len(functions)}, "
                f"got {heuristic.get('total')!r}"
            )
        findings = heuristic.get("findings", [])
        weak = sum(
            finding.get("severity") not in ("medium", "high", "critical")
            for finding in findings
        )
        medium = sum(finding.get("severity") == "medium" for finding in findings)
        strong = sum(
            finding.get("severity") in ("high", "critical") for finding in findings
        )
        for field, expected in (
            ("weak_finding_count", weak),
            ("medium_finding_count", medium),
            ("strong_finding_count", strong),
            ("evidence_family_count", len(heuristic.get("evidence_families", []))),
            (
                "weakening_rule_count",
                len(heuristic.get("weakening_rules_applied", [])),
            ),
        ):
            if heuristic.get(field) != expected:
                errors.append(
                    f"heuristic_analysis.{field}: expected {expected}, "
                    f"got {heuristic.get(field)!r}"
                )
        pe_validation = report.get("pe_validation", {})
        for field in (
            "section_raw_oob",
            "section_virtual_oob",
            "section_raw_overlaps",
            "section_virtual_overlaps",
            "section_misaligned",
        ):
            heuristic_field = f"pe_{field}"
            if heuristic.get(heuristic_field) != pe_validation.get(field):
                errors.append(
                    f"heuristic_analysis.{heuristic_field}: inconsistent with pe_validation"
                )
        if heuristic.get("pe_exception_directory_oob") != pe_validation.get(
            "exception_directory_oob"
        ):
            errors.append(
                "heuristic_analysis.pe_exception_directory_oob: "
                "inconsistent with pe_validation"
            )
        parse_failures = sum(not function.get("unwind_ok") for function in functions)
        anomaly_count = sum(
            bool(function.get("unwind_ok"))
            and bool(function.get("unwind", {}).get("anomalies", 0) & ~UA_ABI_MASK)
            for function in functions
        )
        abi_warning_count = sum(
            bool(function.get("unwind_ok"))
            and bool(function.get("unwind", {}).get("anomalies", 0) & UA_ABI_MASK)
            for function in functions
        )
        if heuristic.get("unwind_parse_fail") != parse_failures:
            errors.append(
                "heuristic_analysis.unwind_parse_fail: "
                f"expected {parse_failures}, got {heuristic.get('unwind_parse_fail')!r}"
            )
        if heuristic.get("unwind_anomalies") != anomaly_count:
            errors.append(
                "heuristic_analysis.unwind_anomalies: "
                f"expected {anomaly_count}, got {heuristic.get('unwind_anomalies')!r}"
            )
        if heuristic.get("unwind_abi_warnings") != abi_warning_count:
            errors.append(
                "heuristic_analysis.unwind_abi_warnings: "
                f"expected {abi_warning_count}, "
                f"got {heuristic.get('unwind_abi_warnings')!r}"
            )

    dynamic = report.get("dynamic_validation")
    if isinstance(dynamic, dict):
        expected_exceptions = dynamic.get("first_chance_seen", 0) + dynamic.get(
            "second_chance_seen", 0
        )
        if dynamic.get("exceptions_seen") != expected_exceptions:
            errors.append(
                "dynamic_validation.exceptions_seen: expected first_chance_seen + "
                f"second_chance_seen = {expected_exceptions}, "
                f"got {dynamic.get('exceptions_seen')!r}"
            )
        signals = _dynamic_signal_count(dynamic)
        if dynamic.get("dynamic_signal_count") != signals:
            errors.append(
                f"dynamic_validation.dynamic_signal_count: expected {signals}, "
                f"got {dynamic.get('dynamic_signal_count')!r}"
            )
        if len(dynamic.get("trace", [])) > dynamic.get("trace_steps", 0):
            errors.append("dynamic_validation.trace: longer than requested trace_steps")
        incomplete_counters = (
            "module_refresh_failures",
            "module_list_truncations",
            "breakpoint_set_failures",
            "breakpoint_capacity_drops",
            "pending_rearm_failures",
            "breakpoint_rearm_failures",
            "dropped_events",
        )
        if dynamic.get("instrumentation_complete") is True and any(
            dynamic.get(field, 0) for field in incomplete_counters
        ):
            errors.append(
                "dynamic_validation.instrumentation_complete: true with "
                "instrumentation loss counters"
            )

    assessment = report.get("assessment")
    if isinstance(assessment, dict):
        signals = _dynamic_signal_count(dynamic if isinstance(dynamic, dict) else None)
        static_level = (
            heuristic.get("evidence_level", "none")
            if isinstance(heuristic, dict)
            else "none"
        )
        runtime_level = _runtime_evidence_level(
            dynamic if isinstance(dynamic, dict) else None
        )
        correlated = _correlated(
            heuristic if isinstance(heuristic, dict) else None,
            dynamic if isinstance(dynamic, dict) else None,
        )
        expected_strength = _case_strength(static_level, runtime_level, correlated)
        expected_weakening = (
            heuristic.get("weakening_rule_count", 0)
            if isinstance(heuristic, dict)
            else 0
        )
        expected_confidence = (
            heuristic.get("confidence", 0.10)
            if isinstance(heuristic, dict)
            else 0.10
        )
        dynamic_complete = _dynamic_session_complete(
            dynamic if isinstance(dynamic, dict) else None
        )
        if dynamic_complete and signals:
            expected_confidence += 0.10
        if correlated:
            expected_confidence += 0.10
        expected_confidence = min(expected_confidence, 0.98)

        score = heuristic.get("score") if isinstance(heuristic, dict) else None
        expected_verdict = "no_strong_correlated_evidence"
        if score is not None:
            if score >= 70:
                expected_verdict = (
                    "high_suspicion_correlated"
                    if correlated
                    else "high_suspicion_static"
                )
            elif score >= 40:
                expected_verdict = (
                    "moderate_suspicion_correlated"
                    if correlated
                    else "moderate_suspicion_static"
                )
            elif score >= 15:
                expected_verdict = (
                    "low_suspicion_correlated"
                    if correlated
                    else "low_suspicion_static"
                )
            elif dynamic_complete and signals:
                expected_verdict = "runtime_signals_only"
        elif dynamic_complete and signals:
            expected_verdict = "runtime_signals_only"

        expected_fields = {
            "dynamic_signal_count": signals,
            "weakening_rule_count": expected_weakening,
            "static_evidence_level": static_level,
            "runtime_evidence_level": runtime_level,
            "static_dynamic_correlation": correlated,
            "case_strength": expected_strength,
            "final_verdict": expected_verdict,
        }
        for field, expected in expected_fields.items():
            if assessment.get(field) != expected:
                errors.append(
                    f"assessment.{field}: expected {expected!r}, "
                    f"got {assessment.get(field)!r}"
                )
        actual_confidence = assessment.get("final_confidence")
        if not isinstance(actual_confidence, (int, float)) or abs(
            actual_confidence - expected_confidence
        ) > 0.000001:
            errors.append(
                "assessment.final_confidence: "
                f"expected {expected_confidence:.6f}, got {actual_confidence!r}"
            )

    return errors
