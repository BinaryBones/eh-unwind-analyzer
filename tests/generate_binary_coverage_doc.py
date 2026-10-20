#!/usr/bin/env python3
from __future__ import annotations

import csv
import datetime as dt
import html
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text_any(path: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1251", "cp866"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="latin-1", errors="ignore")


def read_csv_any(path: Path) -> list[dict[str, str]]:
    text = read_text_any(path)
    lines = text.splitlines()
    if not lines:
        return []

    # Normalize possible quoted or BOM-prefixed headers.
    header = lines[0].lstrip("\ufeff")
    lines[0] = header
    rows = list(csv.DictReader(lines))
    if rows and "binary" in rows[0]:
        return rows

    # Fallback: normalize keys (strip quotes/spaces/BOM).
    norm_rows: list[dict[str, str]] = []
    for r in rows:
        nr: dict[str, str] = {}
        for k, v in r.items():
            if k is None:
                continue
            nk = k.strip().strip('"').strip().lstrip("\ufeff")
            nr[nk] = v
        norm_rows.append(nr)
    return norm_rows


def find_pack_dir() -> Path:
    for static_csv in ROOT.rglob("results_static_validation.csv"):
        if (static_csv.parent / "results_dynamic_validation.csv").exists():
            return static_csv.parent
    raise FileNotFoundError("Папка с результатами тестов не найдена")


def xml_p(text: str) -> str:
    if not text:
        return "<w:p/>"
    return (
        '<w:p><w:r><w:t xml:space="preserve">'
        + html.escape(text, quote=False)
        + "</w:t></w:r></w:p>"
    )


def write_docx(path: Path, title: str, lines: list[str]) -> None:
    body = [xml_p(title), xml_p("")]
    for line in lines:
        body.append(xml_p(line))

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>"
        + "".join(body)
        + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" '
        'w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>'
        "</w:body></w:document>"
    )

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""
    timestamp = dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
    core = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>{html.escape(title)}</dc:title>
  <dc:creator>Codex</dc:creator>
  <cp:lastModifiedBy>Codex</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{timestamp}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{timestamp}</dcterms:modified>
</cp:coreProperties>
"""
    app = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Codex</Application>
</Properties>
"""
    doc_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>
"""

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("docProps/core.xml", core)
        zf.writestr("docProps/app.xml", app)
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/_rels/document.xml.rels", doc_rels)


def main() -> int:
    pack = find_pack_dir()
    static_rows = {r["binary"]: r for r in read_csv_any(pack / "results_static_validation.csv")}
    dynamic_rows = {r["binary"]: r for r in read_csv_any(pack / "results_dynamic_validation.csv")}
    matrix_file = next(p for p in pack.glob("*.csv") if p.name not in {"results_static_validation.csv", "results_dynamic_validation.csv"})
    matrix_rows = read_csv_any(matrix_file)

    interventions = {
        "01_benign_minimal.exe": "Вмешательство отсутствует (чистый baseline).",
        "02_benign_richer.exe": "Вмешательство отсутствует (чистый baseline с более богатой структурой).",
        "03_static_unwind_oob_parse_fail.exe": "Искусственно поврежден UnwindInfoRVA: выход за пределы образа + parse fail.",
        "04_static_invalid_ranges.exe": "Повреждение диапазона RUNTIME_FUNCTION: EndAddress <= BeginAddress.",
        "05_static_rf_oob.exe": "Повреждение диапазона RUNTIME_FUNCTION: Begin/End выходят за SizeOfImage.",
        "06_static_unsorted_overlap_duplicate.exe": "Нарушена целостность таблицы: unsorted + overlap + duplicate begin.",
        "07_static_unwind_bad_opcode.exe": "Порча UNWIND_INFO: внедрен недопустимый unwind opcode.",
        "08_static_unwind_bad_operands.exe": "Порча UNWIND_INFO: некорректные операнды/параметры.",
        "09_static_unwind_unusual_section.exe": "Перенос/маскировка unwind-метаданных в необычную секцию.",
        "10_static_unwind_exec_handler_nonexec.exe": "Комбо-вмешательство: unwind в executable section + handler в non-exec section.",
        "11_static_unwind_writable_only.exe": "Секция unwind-метаданных сделана writable.",
        "12_static_writable_metadata_handler_writable.exe": "Комбо-вмешательство: writable unwind metadata + writable handler target.",
        "13_static_placement_integrity_combo.exe": "Сильное комбинированное вмешательство: placement + integrity (включая unwind_oob/parse_fail).",
        "14_static_reuse_dominance_combo.exe": "Централизация: массовое reuse одного unwind и доминирование одного handler.",
        "15_dynamic_veh.exe": "Runtime-вмешательство: регистрация и срабатывание VEH.",
        "16_dynamic_vch.exe": "Runtime-вмешательство: регистрация и срабатывание VCH.",
        "17_dynamic_uef.exe": "Runtime-вмешательство: установка и срабатывание UEF (+ first/second chance flow).",
        "18_dynamic_rtl_function_table.exe": "Runtime-вмешательство: динамическая регистрация unwind-таблиц через Rtl*FunctionTable API.",
    }

    lines: list[str] = []
    lines.append("Назначение файла")
    lines.append("Это карта покрытия тестовых бинарников: что проверяется, какое покрытие эвристик/режимов и какое вмешательство реализовано.")
    lines.append("")
    lines.append(f"Папка набора: {pack}")
    lines.append(f"Источник матрицы: {matrix_file.name}")
    lines.append("")
    lines.append("Сводка")
    lines.append("- Всего бинарников: 18.")
    lines.append("- Static: 14 (структурные/метаданные вмешательства в EH/Unwind).")
    lines.append("- Dynamic: 4 (runtime-вмешательства и перехваты).")
    lines.append("")
    lines.append("Детализация по каждому бинарнику")

    for row in matrix_rows:
        b = row.get("binary", "").strip()
        target_signals = row.get("target_signals", "").strip()
        coverage = row.get("heuristic_family_or_mode", "").strip()
        is_dynamic = "dynamic" in coverage
        lines.append(f"- {b}")
        lines.append(f"  Тип: {'dynamic' if is_dynamic else 'static'}")
        lines.append(f"  Что проверяет: {target_signals}")
        lines.append(f"  Что покрывает: {coverage}")
        lines.append(f"  Вмешательство: {interventions.get(b, 'Описание вмешательства не задано.')}")
        if b in static_rows:
            s = static_rows[b]
            lines.append(
                f"  Ожидаемый результат: score={s.get('score','')}, verdict={s.get('verdict','')}, findings={s.get('findings','')}"
            )
        if b in dynamic_rows:
            d = dynamic_rows[b]
            lines.append(
                "  Ожидаемый runtime-результат: "
                f"dyn_ok={d.get('dyn_ok','')}, exceptions={d.get('exceptions','')}, "
                f"veh_hits={d.get('veh_hits','')}, vch_hits={d.get('vch_hits','')}, "
                f"uef_hits={d.get('uef_hits','')}, rtl_add={d.get('rtl_add','')}, "
                f"rtl_install={d.get('rtl_install','')}"
            )
        lines.append("")

    lines.append("Итог")
    lines.append("Набор покрывает baseline, table_integrity, unwind_integrity, metadata_placement, unwind_reuse, handler_dominance и dynamic runtime-подтверждение.")

    out = pack / "Карта_бинарников_покрытие_и_вмешательства.docx"
    write_docx(out, "Карта тестовых бинарников: покрытие и вмешательства", lines)
    print(f"[OK] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
