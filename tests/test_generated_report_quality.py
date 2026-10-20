#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

import jsonschema

from report_semantics import validate_report_semantics


ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests" / "samples" / "bin" / "suspicious_eh_unwind_tamper.exe"
SCHEMA = ROOT / "docs" / "report.schema.json"

FINDING_CODES = (
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
    "unwind_reuse_moderate",
    "handler_dominance",
    "unwind_in_exec_section",
    "unwind_unusual_section",
    "unwind_writable_section",
    "handler_nonexec_section",
    "handler_writable_section",
    "placement_exec_nonexec_handler_combo",
    "placement_integrity_combo",
    "reuse_dominance_combo",
    "writable_metadata_handler_combo",
)


def assert_table_shape(
    html: str, marker: str, expected_columns: int, *, required: bool = True
) -> None:
    start = html.find(marker)
    if start < 0:
        if not required:
            return
        raise AssertionError(f"generated HTML misses table marker {marker!r}")
    end = html.find("</table>", start)
    if end < 0:
        raise AssertionError(f"table {marker!r} has no closing tag")
    fragment = html[start : end + len("</table>")]

    thead = re.search(r"<thead>(.*?)</thead>", fragment, flags=re.DOTALL)
    if not thead:
        raise AssertionError(f"table {marker!r} has no thead")
    header_columns = len(re.findall(r"<th(?:\s|>)", thead.group(1)))
    if header_columns != expected_columns:
        raise AssertionError(
            f"table {marker!r} has {header_columns} headers, expected {expected_columns}"
        )

    tbody = re.search(r"<tbody>(.*?)</tbody>", fragment, flags=re.DOTALL)
    if not tbody:
        raise AssertionError(f"table {marker!r} has no tbody")
    for row_number, row in enumerate(
        re.findall(r"<tr>(.*?)</tr>", tbody.group(1), flags=re.DOTALL), start=1
    ):
        cells = len(re.findall(r"<td(?:\s|>)", row))
        if cells != expected_columns:
            raise AssertionError(
                f"table {marker!r} row {row_number} has {cells} cells, "
                f"expected {expected_columns}"
            )

    colgroup = re.search(r"<colgroup>(.*?)</colgroup>", fragment, flags=re.DOTALL)
    if colgroup:
        widths = [float(value) for value in re.findall(r"width:([0-9.]+)%", colgroup.group(1))]
        if len(widths) != expected_columns:
            raise AssertionError(
                f"table {marker!r} colgroup has {len(widths)} columns, "
                f"expected {expected_columns}"
            )
        if abs(sum(widths) - 100.0) > 0.01:
            raise AssertionError(
                f"table {marker!r} colgroup occupies {sum(widths):.2f}%, expected 100%"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir)
        json_path = output_dir / "report.json"
        html_path = output_dir / "report.html"
        result = subprocess.run(
            [
                str(args.tool.resolve()),
                str(SAMPLE),
                "--heuristics",
                "--strict-abi",
                "--json",
                str(json_path),
                "--html",
                str(html_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)
        report = json.loads(json_path.read_text(encoding="utf-8"))
        html = html_path.read_text(encoding="utf-8")

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(report)
    semantic_errors = validate_report_semantics(report)
    if semantic_errors:
        raise AssertionError("generated report is semantically invalid:\n" + "\n".join(semantic_errors))

    required_fragments = (
        "Результаты статического анализа",
        "Доказательные карточки",
        "Матрица покрытия 27 эвристических признаков",
        "Полная контрольная карта статического анализа",
        "Сводная оценка",
        "Базовый вес",
        "Уверенность итоговой оценки",
        "Finding (аналитическое наблюдение)",
        "<th>Индекс записи</th><th>Положение entry в .pdata</th>",
        "id=\"runtime-functions\"",
        "class=\"report-nav\"",
        "text-align:left;text-wrap:pretty;hyphens:none",
        "justify-content:space-between",
        ".code-wrap{white-space:normal;overflow-wrap:normal;word-break:normal}",
        ".runtime-table{width:100%;min-width:100%;table-layout:fixed}",
        ".diagnostics-table{width:100%;min-width:100%;table-layout:fixed}",
        ".diagnostic-field>span{display:block;color:var(--muted);font-size:12px;margin-bottom:2px}",
        ".diagnostic-field code{display:inline-block;max-width:100%;white-space:nowrap}",
        ".diagnostics-table .code-wrap{white-space:normal;overflow-wrap:anywhere;word-break:break-word}",
        ".evidence-table{width:100%;min-width:100%;table-layout:fixed}",
        ".heuristic-matrix-table{width:100%;min-width:100%;table-layout:fixed}",
        ".heuristic-matrix-table .finding-link{display:block;min-width:0}",
        ".heuristic-matrix-table .finding-link code{display:block;white-space:normal;overflow-wrap:anywhere;word-break:break-word}",
        "list-style-position:inside",
        "@media(min-width:701px){.table-wrap{overflow-x:clip}}",
        "for(const wrap of document.querySelectorAll('.table-wrap'))wrap.scrollLeft=0;",
        '<colgroup><col style="width:4%"><col style="width:20%"><col style="width:16%">',
        '<col style="width:8%"><col style="width:7%"><col style="width:12%">',
        ".heuristic-matrix-table thead th{height:58px;padding:10px 12px;text-align:left;vertical-align:middle;line-height:1.25;hyphens:none}",
        ".heuristic-matrix-table th:first-child{text-align:left;white-space:nowrap}",
        ".heuristic-matrix-table td:first-child{text-align:center;white-space:nowrap}",
        ".heuristic-matrix-table th:nth-child(5){white-space:nowrap;text-align:left}",
        ".heuristic-matrix-table td:nth-child(5){white-space:nowrap;text-align:left}",
        ".heuristic-matrix-table thead th.matrix-status-head{text-align:left;padding-left:12px;padding-right:8px}",
        ".heuristic-matrix-table td:nth-child(6){overflow-wrap:anywhere;word-break:break-word}",
        ".runtime-table .code-wrap{display:block;margin-top:4px;white-space:normal;overflow-wrap:anywhere;word-break:break-word}",
        '<colgroup><col style="width:4%"><col style="width:14%"><col style="width:11%">',
        '<col style="width:17%"><col style="width:9%"><col style="width:20%"></colgroup>',
        '<th class="matrix-status-head">Нарушение</th>',
        'В колонке «Нарушение»',
        'целостность таблиц',
        'размещение метаданных',
        ".finding-detail>summary>code{max-width:100%;white-space:normal;overflow-wrap:anywhere;word-break:break-word}",
    )
    for fragment in required_fragments:
        if fragment not in html:
            raise AssertionError(f"generated HTML misses {fragment!r}")
    assert_table_shape(html, '<table id="functions" class="runtime-table">', 9)
    assert_table_shape(html, '<table class="diagnostics-table">', 7, required=False)
    assert_table_shape(html, '<table class="evidence-table">', 6, required=False)
    assert_table_shape(html, '<table class="heuristic-matrix-table">', 9)
    evidence_start = html.find('<table class="evidence-table">')
    if evidence_start >= 0:
        evidence_end = html.index('</table>', evidence_start)
        evidence = html[evidence_start:evidence_end]
        if "section=<code>" not in evidence or "<br>rights=<code>" not in evidence:
            raise AssertionError("evidence table must label both section and rights values")
        if re.search(r'<td class="wrap">-<br>rights=', evidence):
            raise AssertionError("evidence table contains an unlabeled section placeholder")
        if "section=<code>-</code>" in evidence or "rights=<code>---</code>" in evidence:
            raise AssertionError("evidence table contains ambiguous dash placeholders")
    diagnostics_start = html.find('<table class="diagnostics-table">')
    if diagnostics_start >= 0:
        diagnostics_end = html.index('</table>', diagnostics_start)
        diagnostics = html[diagnostics_start:diagnostics_end]
        for fragment in (
            '<span>Индекс записи</span>',
            '<span>Begin RVA</span>',
            '<span>End RVA</span>',
            '<span>File offset</span>',
        ):
            if fragment not in diagnostics:
                raise AssertionError(f"structural diagnostics misses stacked field {fragment!r}")
        if re.search(r'<td><code>0x[0-9a-f]{8}\.\.0x[0-9a-f]{8}</code></td>', diagnostics):
            raise AssertionError("structural diagnostics contains an unbreakable function range")
    matrix_start = html.index('<table class="heuristic-matrix-table">')
    matrix_end = html.index('</table>', matrix_start)
    matrix = html[matrix_start:matrix_end]
    if "зафиксирован" in matrix:
        raise AssertionError("heuristic matrix still contains the obsolete status wording")
    if ">да</b>" not in matrix or ">нет</b>" not in matrix:
        raise AssertionError("heuristic matrix must use compact да/нет status values")
    if ">Да</b>" in matrix or ">Нет</b>" in matrix:
        raise AssertionError("heuristic matrix contains inconsistent capitalized status values")
    for code in FINDING_CODES:
        if code not in html:
            raise AssertionError(f"heuristic matrix misses {code}")

    forbidden_fragments = (
        "Краткий журнал findings",
        "Анализатор зафиксировал состояние, снижающее доверие",
        "Representative RVA подлежит сопоставлению",
        "Комбинация взаимно усиливающих признаков",
        "Сводная экспертная оценка",
        "Уверенность модели",
        "Методика расчёта.",
        "Методика расчёта итоговой оценки.",
        "overflow-x:hidden",
    )
    for fragment in forbidden_fragments:
        if fragment in html:
            raise AssertionError(f"generated HTML contains generic/redundant text {fragment!r}")
    if re.search(r"эксперт", html, flags=re.IGNORECASE):
        raise AssertionError("generated HTML contains an obsolete expert-role reference")
    bad_count_phrase = re.search(
        r"\b\d+\s+(?:нарушений|частных срабатываний|записей-доказательств)\b",
        html,
    )
    if bad_count_phrase:
        raise AssertionError(
            f"generated HTML contains a number-dependent Russian noun form: {bad_count_phrase.group(0)!r}"
        )

    for finding in report.get("heuristic_analysis", {}).get("findings", []):
        code = finding.get("code")
        if f'href="#finding-{code}"' not in html:
            raise AssertionError(f"finding {code!r} has no matrix-to-detail link")
        if f'id="finding-{code}"' not in html:
            raise AssertionError(f"finding {code!r} has no detail anchor")
        for field in ("code", "title_ru", "rule", "observed", "expected", "impact"):
            value = finding.get(field)
            if not isinstance(value, str) or not value:
                raise AssertionError(f"finding {finding.get('code')!r} has empty {field}")
            if value not in re.sub(r"<[^>]+>", "", html).replace("&gt;", ">").replace("&lt;", "<"):
                if field not in {"observed"}:
                    raise AssertionError(
                        f"finding {finding.get('code')!r} field {field} is absent from HTML"
                    )

    for tag in ("table", "details", "section"):
        opening = len(re.findall(fr"<{tag}(?:\s|>)", html, flags=re.IGNORECASE))
        closing = len(re.findall(fr"</{tag}>", html, flags=re.IGNORECASE))
        if opening != closing:
            raise AssertionError(f"unbalanced <{tag}> tags: {opening} != {closing}")

    print("test_generated_report_quality: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
