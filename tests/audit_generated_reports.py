#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html as html_module
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


KNOWN_FINDINGS = {
    "pe_section_raw_oob",
    "pe_section_virtual_oob",
    "pe_section_raw_overlap",
    "pe_section_virtual_overlap",
    "pe_section_misaligned",
    "pe_exception_directory_oob",
    "no_runtime_functions",
    "invalid_ranges",
    "rf_oob",
    "unwind_rva_oob",
    "rf_unsorted",
    "rf_overlaps",
    "duplicate_begin",
    "unwind_parse_fail",
    "unwind_anomalies",
    "unwind_reuse_strong",
    "handler_dominance",
    "unwind_reuse_moderate",
    "unwind_in_exec_section",
    "unwind_unusual_section",
    "unwind_writable_section",
    "handler_nonexec_section",
    "handler_writable_section",
    "placement_exec_nonexec_handler_combo",
    "placement_integrity_combo",
    "reuse_dominance_combo",
    "writable_metadata_handler_combo",
}

GENERIC_TITLES = {"Эвристический признак"}
GENERIC_MEANING_FRAGMENTS = {
    "состояние, снижающее доверие к PE/EH/Unwind-разметке",
}
GENERIC_NEXT_FRAGMENTS = {
    "Representative RVA подлежит сопоставлению",
}


def dynamic_signal_count(dynamic: dict[str, Any] | None) -> int:
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


def dynamic_session_complete(dynamic: dict[str, Any] | None) -> bool:
    return bool(
        dynamic
        and dynamic.get("ran")
        and dynamic.get("ok")
        and not dynamic.get("timed_out")
        and dynamic.get("target_exited")
        and dynamic.get("instrumentation_complete")
    )


def runtime_evidence_level(dynamic: dict[str, Any] | None) -> str:
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
    if strong and medium:
        level = "strong"
    elif strong or medium >= 2:
        level = "medium"
    elif medium or weak:
        level = "weak"
    if level != "none" and not dynamic_session_complete(dynamic):
        return "weak"
    return level


def html_text(raw: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html_module.unescape(text)).strip()


def report_pairs(root: Path) -> list[tuple[Path, Path]]:
    pairs: list[tuple[Path, Path]] = []
    extended = root / "build" / "corpus-reports"
    for json_path in sorted((extended / "json").glob("*.json")):
        html_path = extended / "html" / (json_path.stem + ".html")
        if html_path.exists():
            pairs.append((json_path, html_path))
    showcase = root / "reports" / "showcase"
    for json_path in sorted(showcase.glob("*.json")):
        html_path = json_path.with_suffix(".html")
        if html_path.exists():
            pairs.append((json_path, html_path))
    acceptance = root / "reports" / "final_acceptance_2026-07-17"
    for json_path in sorted(acceptance.glob("*/report.json")):
        html_path = json_path.with_suffix(".html")
        if html_path.exists():
            pairs.append((json_path, html_path))
    return pairs


def add_issue(
    issues: list[tuple[str, str, str]],
    severity: str,
    report: Path,
    message: str,
) -> None:
    issues.append((severity, str(report), message))


def audit_pair(
    json_path: Path,
    html_path: Path,
    issues: list[tuple[str, str, str]],
    stats: Counter[str],
    generic_codes: Counter[str],
) -> None:
    try:
        report = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        add_issue(issues, "critical", json_path, f"JSON unreadable: {exc}")
        return
    try:
        raw_html = html_path.read_text(encoding="utf-8")
    except OSError as exc:
        add_issue(issues, "critical", html_path, f"HTML unreadable: {exc}")
        return

    text = html_text(raw_html)
    stats["pairs"] += 1
    findings = report.get("heuristic_analysis", {}).get("findings", [])
    stats["findings"] += len(findings)

    heuristic = report.get("heuristic_analysis")
    if isinstance(heuristic, dict):
        score = heuristic.get("score")
        score_weight_sum = heuristic.get("score_weight_sum")
        suspicion = heuristic.get("suspicion")
        confidence = heuristic.get("confidence")
        if not isinstance(score, int) or not 0 <= score <= 100:
            add_issue(issues, "critical", json_path, f"invalid score {score!r}")
        if not isinstance(score_weight_sum, int) or score_weight_sum < 0:
            add_issue(
                issues,
                "critical",
                json_path,
                f"invalid score_weight_sum {score_weight_sum!r}",
            )
        elif isinstance(score, int) and score != min(score_weight_sum, 100):
            add_issue(
                issues,
                "critical",
                json_path,
                f"score {score!r} is inconsistent with score_weight_sum {score_weight_sum!r}",
            )
        if not isinstance(suspicion, (int, float)) or not math.isclose(
            suspicion, (score or 0) / 100.0, abs_tol=1e-9
        ):
            add_issue(
                issues,
                "high",
                json_path,
                f"suspicion {suspicion!r} is inconsistent with score {score!r}",
            )
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            add_issue(issues, "critical", json_path, f"invalid confidence {confidence!r}")
        severities = Counter(finding.get("severity", "low") for finding in findings)
        expected_weak = sum(
            count
            for severity, count in severities.items()
            if severity not in {"medium", "high", "critical"}
        )
        expected_medium = severities["medium"]
        expected_strong = severities["high"] + severities["critical"]
        for field, expected in (
            ("weak_finding_count", expected_weak),
            ("medium_finding_count", expected_medium),
            ("strong_finding_count", expected_strong),
        ):
            if heuristic.get(field) != expected:
                add_issue(
                    issues,
                    "high",
                    json_path,
                    f"{field}={heuristic.get(field)!r}, expected {expected}",
                )

    dynamic = report.get("dynamic_validation")
    if isinstance(dynamic, dict):
        expected_signals = dynamic_signal_count(dynamic)
        if dynamic.get("dynamic_signal_count") != expected_signals:
            add_issue(
                issues,
                "high",
                json_path,
                "dynamic_signal_count is inconsistent with signal categories",
            )

    assessment = report.get("assessment")
    if isinstance(assessment, dict):
        expected_signals = dynamic_signal_count(dynamic if isinstance(dynamic, dict) else None)
        expected_runtime = runtime_evidence_level(
            dynamic if isinstance(dynamic, dict) else None
        )
        if assessment.get("dynamic_signal_count") != expected_signals:
            add_issue(
                issues,
                "high",
                json_path,
                "assessment.dynamic_signal_count is inconsistent with runtime data",
            )
        if assessment.get("runtime_evidence_level") != expected_runtime:
            add_issue(
                issues,
                "high",
                json_path,
                "assessment.runtime_evidence_level is inconsistent with completeness gate",
            )
        final_confidence = assessment.get("final_confidence")
        if not isinstance(final_confidence, (int, float)) or not 0 <= final_confidence <= 1:
            add_issue(
                issues,
                "critical",
                json_path,
                f"invalid assessment.final_confidence {final_confidence!r}",
            )

    report_name = json_path.name.lower()
    parent_name = json_path.parent.name.lower()
    is_showcase_mode = "reports_showcase_html" in json_path.parts and (
        "dynamic" in report_name or "mixed" in report_name
    )
    is_acceptance_mode = "final_acceptance_2026-07-17" in json_path.parts and (
        parent_name == "dynamic" or parent_name == "mixed"
    )
    if (is_showcase_mode or is_acceptance_mode) and not (
        isinstance(dynamic, dict) and dynamic.get("ran")
    ):
        add_issue(
            issues,
            "high",
            json_path,
            "report is presented as dynamic/mixed, but no dynamic session ran",
        )

    for finding in findings:
        code = finding.get("code", "")
        if code not in KNOWN_FINDINGS:
            add_issue(issues, "high", json_path, f"unknown finding code {code!r}")
        title = finding.get("title_ru", "")
        meaning = finding.get("meaning_ru", "")
        next_step = finding.get("what_to_check_next_ru", "")
        required = (
            "message",
            "title_ru",
            "meaning_ru",
            "why_it_matters_ru",
            "what_to_check_next_ru",
            "rule",
            "observed",
            "expected",
            "impact",
            "evidence_chain",
        )
        missing = [field for field in required if not finding.get(field)]
        if missing:
            add_issue(
                issues,
                "high",
                json_path,
                f"{code}: empty fields: {', '.join(missing)}",
            )
        if title in GENERIC_TITLES or any(
            fragment in meaning for fragment in GENERIC_MEANING_FRAGMENTS
        ) or any(fragment in next_step for fragment in GENERIC_NEXT_FRAGMENTS):
            generic_codes[code] += 1
        if code.endswith("_combo") and finding.get("affected_count") == 0:
            evidence_total = finding.get("evidence_records_total")
            if evidence_total is None:
                add_issue(
                    issues,
                    "medium",
                    json_path,
                    f"{code}: aggregate finding reports affected_count=0 and has no evidence-record count",
                )
            elif evidence_total > 0:
                add_issue(
                    issues,
                    "medium",
                    json_path,
                    f"{code}: affected_count=0 is displayed beside {evidence_total} evidence records",
                )

        if code not in text:
            add_issue(issues, "high", html_path, f"finding code {code!r} is absent from HTML")
        for value_name in ("title_ru", "rule", "expected"):
            value = finding.get(value_name)
            if isinstance(value, str) and value and value not in text:
                add_issue(
                    issues,
                    "medium",
                    html_path,
                    f"{code}: {value_name} is absent from visible HTML",
                )

    if "<table" not in raw_html.lower() or "</table>" not in raw_html.lower():
        add_issue(issues, "high", html_path, "HTML contains no complete table")
    if re.search(r"(?i)(?:\bnan\b|\bundefined\b|\(null\)|>null<)", text):
        add_issue(issues, "high", html_path, "HTML contains an unresolved null/NaN marker")
    if len(re.findall(r"<table", raw_html, re.I)) != len(
        re.findall(r"</table>", raw_html, re.I)
    ):
        add_issue(issues, "critical", html_path, "unbalanced table tags")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    issues: list[tuple[str, str, str]] = []
    stats: Counter[str] = Counter()
    generic_codes: Counter[str] = Counter()
    pairs = report_pairs(args.root)
    if not pairs:
        raise SystemExit("no JSON/HTML report pairs found")
    for json_path, html_path in pairs:
        audit_pair(json_path, html_path, issues, stats, generic_codes)

    print(f"REPORT_PAIRS={stats['pairs']}")
    print(f"FINDINGS={stats['findings']}")
    print("GENERIC_FINDING_CODES=")
    for code, count in generic_codes.most_common():
        print(f"  {code}: {count}")
    severity_counts = Counter(severity for severity, _, _ in issues)
    print("ISSUES=" + ", ".join(f"{key}:{severity_counts[key]}" for key in (
        "critical", "high", "medium", "low"
    )))
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for severity, path, message in issues:
        grouped[severity].append((path, message))
    for severity in ("critical", "high", "medium", "low"):
        print(f"\n[{severity.upper()}]")
        for path, message in grouped[severity]:
            print(f"{path}: {message}")
    return 1 if severity_counts["critical"] or severity_counts["high"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
