#!/usr/bin/env python3
from __future__ import annotations

import csv
import datetime as dt
import html
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]


def read_text_any(path: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1251", "cp866"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="latin-1", errors="ignore")


def read_csv_any(path: Path) -> list[dict[str, str]]:
    data = read_text_any(path)
    reader = csv.DictReader(data.splitlines())
    return [dict(row) for row in reader]


def find_pack_dir() -> Path:
    for static_csv in ROOT.rglob("results_static_validation.csv"):
        dynamic_csv = static_csv.parent / "results_dynamic_validation.csv"
        if dynamic_csv.exists():
            return static_csv.parent
    raise FileNotFoundError("Не найдена папка с results_static_validation.csv + results_dynamic_validation.csv")


def find_or_create_analysis_doc_path() -> Path:
    target_dir = ROOT / "обучение и анализ проекта"
    target_dir.mkdir(parents=True, exist_ok=True)
    preferred = target_dir / "Анализ_проекта_EH_Unwind_Analyzer.docx"
    if preferred.exists():
        return preferred
    candidates = sorted(ROOT.rglob("*EH_Unwind_Analyzer.docx"))
    return candidates[0] if candidates else preferred


def parse_function_map(src_dir: Path) -> dict[str, list[tuple[str, int]]]:
    func_re = re.compile(
        r"^\s*(?:static\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z0-9_\s\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{",
        re.M,
    )
    keywords = {"if", "for", "while", "switch"}
    out: dict[str, list[tuple[str, int]]] = {}

    for c_file in sorted(src_dir.glob("*.c")):
        text = read_text_any(c_file)
        found: list[tuple[str, int]] = []
        seen_names: set[str] = set()
        for m in func_re.finditer(text):
            name = m.group(1)
            if name in keywords:
                continue
            if name in seen_names:
                continue
            seen_names.add(name)
            line = text.count("\n", 0, m.start()) + 1
            found.append((name, line))
        out[c_file.name] = found
    return out


def parse_heuristic_constants(path: Path) -> dict[str, str]:
    text = read_text_any(path)
    const_re = re.compile(
        r"^static const (?:int|double)\s+(SCORE_[A-Z0-9_]+|CONFIDENCE_[A-Z0-9_]+|THRESHOLD_[A-Z0-9_]+)\s*=\s*([^;]+);",
        re.M,
    )
    out: dict[str, str] = {}
    for name, value in const_re.findall(text):
        out[name] = value.strip()
    return out


def parse_finding_codes(path: Path) -> list[tuple[str, str, str]]:
    text = read_text_any(path)
    find_re = re.compile(r'add_finding\(\s*out\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*([^,]+)\s*,')
    rows: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for code, family, sev in find_re.findall(text):
        if code in seen:
            continue
        seen.add(code)
        rows.append((code, family, sev.strip()))
    return rows


def top_level_inventory(root: Path) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        files = [x for x in d.rglob("*") if x.is_file()]
        total_bytes = sum(x.stat().st_size for x in files)
        out.append((d.name, len(files), total_bytes))
    return out


def summarize_static_results(rows: list[dict[str, str]]) -> dict[str, object]:
    verdicts = Counter(row.get("verdict", "") for row in rows)
    statuses = Counter(row.get("status", "") for row in rows)
    findings_counter: Counter[str] = Counter()
    for row in rows:
        for f in (row.get("findings", "") or "").split(","):
            f = f.strip()
            if f:
                findings_counter[f] += 1
    return {
        "total": len(rows),
        "statuses": statuses,
        "verdicts": verdicts,
        "top_findings": findings_counter.most_common(12),
    }


def summarize_dynamic_results(rows: list[dict[str, str]]) -> dict[str, object]:
    statuses = Counter(row.get("status", "") for row in rows)
    dyn_ok = Counter(row.get("dyn_ok", "") for row in rows)
    return {
        "total": len(rows),
        "statuses": statuses,
        "dyn_ok": dyn_ok,
    }


def describe_function(name: str) -> str:
    explicit = {
        "main": "точка входа CLI: парсинг аргументов, запуск стадий анализа, запись отчетов",
        "usage": "печать справки по параметрам командной строки",
        "parse_args": "валидация CLI-параметров и формирование конфигурации запуска",
        "pe_parse": "парсинг заголовков PE32+ (x64), секций и exception directory",
        "pe_rva_to_fileoff": "безопасное отображение RVA в файловый offset",
        "unwind_read_runtime_functions": "чтение таблицы RUNTIME_FUNCTION из exception directory",
        "unwind_parse": "разбор UNWIND_INFO, chain-info, handler tail и аномалий",
        "heuristics_analyze": "расчет признаков, score/confidence, findings, mitigations и verdict",
        "report_write_csv": "экспорт результатов в CSV (обычный и Ghidra-режим)",
        "report_write_json_ex": "экспорт расширенного отчета в JSON (статический+динамический+assessment)",
        "report_print_heuristics": "печать человекочитаемого итогового блока эвристик",
        "dynamic_collect_windows": "динамический сбор доказательств через Windows Debug API",
        "dynamic_report_init": "инициализация runtime-структуры отчета",
        "dynamic_report_free": "освобождение ресурсов runtime-отчета",
        "sb_init": "инициализация буфера строк StrBuf",
        "sb_appendf": "безопасное форматированное добавление текста в StrBuf",
        "buf_init_from_file": "чтение файла в память для бинарного парсинга",
    }
    if name in explicit:
        return explicit[name]
    if name.startswith("pe_"):
        return "вспомогательная функция слоя PE-парсинга"
    if name.startswith("unwind_"):
        return "вспомогательная функция слоя разбора unwind-метаданных"
    if name.startswith("heuristics_"):
        return "вспомогательная функция эвристического движка"
    if name.startswith("report_"):
        return "вспомогательная функция отчетности/экспорта"
    if name.startswith("dynamic_"):
        return "вспомогательная функция динамического модуля"
    if name.startswith("sb_"):
        return "вспомогательная функция строкового буфера"
    if name.startswith("buf_"):
        return "вспомогательная функция безопасного чтения бинарных данных"
    if name.startswith("hmap_"):
        return "внутренний мини-хеш-индекс для подсчетов в эвристиках"
    if name.startswith("bp_"):
        return "внутренняя функция управления breakpoint в динамическом анализе"
    if name.startswith("mods_"):
        return "внутренняя функция инвентаризации модулей процесса в Debug API"
    return "внутренняя сервисная функция модуля"


def folder_content_lines(root: Path) -> list[str]:
    lines: list[str] = []
    top_dirs = [d for d in sorted(root.iterdir()) if d.is_dir()]
    for d in top_dirs:
        files = [p for p in d.rglob("*") if p.is_file()]
        lines.append(f"- Папка `{d.name}`: {len(files)} файлов.")
        for p in sorted(files):
            rel = p.relative_to(root).as_posix()
            lines.append(f"  {rel}")
    return lines


def xml_p(text: str) -> str:
    if text == "":
        return "<w:p/>"
    escaped = html.escape(text, quote=False)
    return (
        '<w:p><w:r><w:t xml:space="preserve">'
        + escaped
        + "</w:t></w:r></w:p>"
    )


def write_docx(path: Path, lines: Iterable[str], title: str) -> None:
    body = [xml_p(title), xml_p("")]
    for line in lines:
        body.append(xml_p(line))

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:o="urn:schemas-microsoft-com:office:office" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" '
        'xmlns:v="urn:schemas-microsoft-com:vml" '
        'xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:w10="urn:schemas-microsoft-com:office:word" '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
        'xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml" '
        'xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" '
        'xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" '
        'xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" '
        'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 w15 wp14">'
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


def build_instruction_lines(
    pack_dir: Path,
    static_rows: list[dict[str, str]],
    dynamic_rows: list[dict[str, str]],
    matrix_rows: list[dict[str, str]],
) -> list[str]:
    lines: list[str] = []
    lines.append("Назначение документа")
    lines.append("Этот документ описывает полный практический запуск проекта и проверку всех тестовых бинарников из набора.")
    lines.append("")
    lines.append("Что уже находится в папке")
    lines.append(f"- Папка набора: {pack_dir}")
    lines.append("- Подпапка `бинарники/static`: 14 сценариев статического анализа.")
    lines.append("- Подпапка `бинарники/dynamic`: 4 сценария динамического анализа.")
    lines.append("- CSV-файлы с результатами валидации и матрицей покрытия.")
    lines.append("")
    lines.append("Предварительные требования")
    lines.append("- ОС: Windows x64.")
    lines.append("- В проекте должен быть собран `eh_unwind_analyzer.exe`.")
    lines.append("- Для регенерации набора нужен `gcc` (для dynamic) и `clang+lld-link` или `gcc` (для static).")
    lines.append("")
    lines.append("Шаг 1. Перейти в корень проекта")
    lines.append("Команда: `cd <корень_проекта>`")
    lines.append("")
    lines.append("Шаг 2. Сборка анализатора")
    lines.append("Вариант MinGW: `build_mingw.bat`")
    lines.append("Вариант MSVC: `build_msvc.bat`")
    lines.append("Проверка: файл `eh_unwind_analyzer.exe` появился в корне проекта.")
    lines.append("")
    lines.append("Шаг 3. (Опционально) Пересоздать набор бинарников")
    lines.append("Команда: `python tests/samples/build_full_test_pack.py`")
    lines.append("Результат: обновятся папки static/dynamic и матрица покрытия.")
    lines.append("")
    lines.append("Шаг 4. Проверить статические кейсы (14 файлов)")
    lines.append("Запуск вручную на одном файле (пример):")
    lines.append("`eh_unwind_analyzer.exe \"бинарники на тестирование\\бинарники\\static\\10_static_unwind_exec_handler_nonexec.exe\" --heuristics --json out_10.json`")
    lines.append("Массовый прогон можно делать циклом PowerShell по всем `*.exe` в `...\\static`.")
    lines.append("")
    lines.append("Шаг 5. Проверить динамические кейсы (4 файла)")
    lines.append("Общий шаблон:")
    lines.append("`eh_unwind_analyzer.exe <путь_к_dynamic_exe> --heuristics --dynamic --timeout-ms 15000 --trace-steps 64 --json <report.json>`")
    lines.append("Для динамики обязателен запуск на Windows, так как используется Debug API.")
    lines.append("")
    lines.append("Шаг 6. Сверить результаты с эталонными CSV")
    lines.append("- `results_static_validation.csv` содержит ожидаемые score/verdict/findings для 14 static бинарников.")
    lines.append("- `results_dynamic_validation.csv` содержит ожидаемые runtime-сигналы для 4 dynamic бинарников.")
    lines.append("- `матрица_покрытия_бинарников.csv` связывает каждый бинарник с целевыми эвристиками/признаками.")
    lines.append("")
    lines.append("Какие признаки должен активировать каждый бинарник")
    for row in matrix_rows:
        b = row.get("binary", "").strip()
        sig = row.get("target_signals", "").strip()
        fam = row.get("heuristic_family_or_mode", "").strip()
        lines.append(f"- {b}: сигнал `{sig}`; семейство/режим `{fam}`.")
    lines.append("")
    lines.append("Критерии успешного тестирования")
    lines.append(f"- Статических кейсов: {len(static_rows)}; статус `OK` должен быть у каждого.")
    lines.append(f"- Динамических кейсов: {len(dynamic_rows)}; `dyn_ok=True` должен быть у каждого.")
    lines.append("- Для dynamic-бинарников должны появляться ожидаемые runtime-счетчики (veh/vch/uef/rtl_*).")
    lines.append("")
    lines.append("Типовые проблемы и решение")
    lines.append("- Если dynamic режим не запускается: проверить, что анализ выполняется на Windows и процесс разрешен к отладке.")
    lines.append("- Если нет `gcc/clang`: установить компилятор или использовать уже сгенерированный набор бинарников.")
    lines.append("- Если путь содержит пробелы/кириллицу: обязательно брать путь в кавычки.")
    lines.append("")
    lines.append("Рекомендуемый порядок демонстрации на защите")
    lines.append("1. Показать clean baseline: 01 и 02 (score=0).")
    lines.append("2. Показать по одному кейсу на каждое семейство эвристик.")
    lines.append("3. Показать комбинированный кейс 13 (максимальный score).")
    lines.append("4. Показать runtime-кейсы 15-18 и что динамика подтверждает перехваты.")
    return lines


def build_analysis_lines(
    pack_dir: Path,
    analysis_doc_path: Path,
    function_map: dict[str, list[tuple[str, int]]],
    constants: dict[str, str],
    findings: list[tuple[str, str, str]],
    static_rows: list[dict[str, str]],
    dynamic_rows: list[dict[str, str]],
    matrix_rows: list[dict[str, str]],
) -> list[str]:
    static_summary = summarize_static_results(static_rows)
    dynamic_summary = summarize_dynamic_results(dynamic_rows)
    inventory = top_level_inventory(ROOT)

    lines: list[str] = []
    lines.append("1. Введение и назначение проекта")
    lines.append("Проект EH/Unwind Analyzer предназначен для выявления аномалий и признаков перехвата обработки исключений в PE x64.")
    lines.append("Инструмент объединяет три технических уровня: парсинг бинарного формата, статический эвристический анализ и динамическую валидацию под Debug API.")
    lines.append("Результат работы пригоден для практики реверс-инжиниринга и для ВКР как инженерная методика детекта вмешательства в EH/unwind-поток.")
    lines.append("")
    lines.append("2. Формулировка темы ВКР")
    lines.append("Рекомендуемая тема:")
    lines.append("«Метод и программное средство статического и динамического анализа EH/Unwind-метаданных PE x64 для выявления аномалий обработки исключений».")
    lines.append("")
    lines.append("3. Что делает проект простыми словами")
    lines.append("- Считывает из PE-файла таблицу функций исключений (`.pdata`) и unwind-описания (`UNWIND_INFO`).")
    lines.append("- Проверяет целостность и правдоподобность этих структур (границы, сортировка, перекрытия, опкоды, chain-info, handler targets).")
    lines.append("- Назначает риск-оценку (score 0..100), уровень доказательности и confidence.")
    lines.append("- При запуске в dynamic-режиме наблюдает, куда реально уходит обработка исключений во время выполнения.")
    lines.append("- Сохраняет отчеты в JSON/CSV и подготавливает CSV для аннотаций в Ghidra.")
    lines.append("")
    lines.append("4. Архитектура по блокам")
    lines.append("Блок A. Парсинг и нормализация PE")
    lines.append("Ответственность: безопасно извлечь exception directory, секции и преобразования RVA->file offset.")
    lines.append("Файлы: `src/pe.c`, `include/pe.h`, `src/util.c`, `include/util.h`.")
    lines.append("Блок B. Разбор UNWIND")
    lines.append("Ответственность: декодировать `UNWIND_INFO`, unwind-операции, handler/chain, аномалии формата.")
    lines.append("Файлы: `src/unwind.c`, `include/unwind.h`.")
    lines.append("Блок C. Статические эвристики")
    lines.append("Ответственность: расчет признаков, score, findings, mitigations, verdict, confidence.")
    lines.append("Файлы: `src/heuristics.c`, `include/heuristics.h`.")
    lines.append("Блок D. Динамическая валидация")
    lines.append("Ответственность: runtime-наблюдение exception flow через breakpoints и Debug API.")
    lines.append("Файлы: `src/dynamic_win.c`, `include/dynamic.h`.")
    lines.append("Блок E. Отчетность и интеграция")
    lines.append("Ответственность: текстовый вывод, JSON/CSV, Ghidra CSV, сводный assessment.")
    lines.append("Файлы: `src/report.c`, `include/report.h`, `ghidra/import_unwind_csv.py`.")
    lines.append("Блок F. Точка входа и orchestration")
    lines.append("Ответственность: CLI, последовательность стадий, вызовы модулей, управление режимами.")
    lines.append("Файл: `src/main.c`.")
    lines.append("")
    lines.append("5. Полная карта папок (содержимое и объем)")
    for name, file_count, total_bytes in inventory:
        lines.append(f"- `{name}`: файлов {file_count}, суммарный размер {total_bytes} байт.")
    lines.append("")
    lines.append("6. Карта кода по файлам и функциям (ядро проекта)")
    total_functions = 0
    for file_name, funcs in sorted(function_map.items()):
        total_functions += len(funcs)
        lines.append(f"- `src/{file_name}`: функций {len(funcs)}.")
        for fname, line in funcs:
            lines.append(f"  `{fname}` (строка {line}): {describe_function(fname)}.")
    lines.append(f"Итого в ядре `src/*.c` обнаружено функций: {total_functions}.")
    lines.append("")
    lines.append("7. Эвристики: какие признаки учитываются и зачем")
    lines.append("7.1 Семейства доказательств")
    lines.append("- table_integrity: проблемы структуры таблицы `RUNTIME_FUNCTION`.")
    lines.append("- unwind_integrity: проблемы разбора/формата `UNWIND_INFO`.")
    lines.append("- metadata_placement: подозрительное размещение unwind/handler в секциях.")
    lines.append("- unwind_reuse: аномально сильное переиспользование одного `UnwindInfoRVA`.")
    lines.append("- handler_dominance: доминирование одного обработчика на множестве функций.")
    lines.append("")
    lines.append("7.2 Список finding-codes (из реализации)")
    for code, family, severity_expr in findings:
        lines.append(f"- `{code}`: family=`{family}`, severity-expression=`{severity_expr}`.")
    lines.append("")
    lines.append("7.3 Весовые коэффициенты и пороги (фрагмент калибровки)")
    const_keys = [
        "SCORE_EMPTY_PDATA",
        "SCORE_RF_OOB_HIGH",
        "SCORE_UNWIND_RVA_OOB_HIGH",
        "SCORE_UNWIND_PARSE_FAIL_HIGH",
        "SCORE_UNWIND_EXEC_SECTION",
        "SCORE_HANDLER_NONEXEC",
        "SCORE_COMBO_PLACEMENT_EXEC_AND_HANDLER",
        "SCORE_COMBO_WRITABLE_METADATA_AND_HANDLER",
        "THRESHOLD_HIGH_PERCENT",
        "THRESHOLD_UNWIND_ANOM_HIGH",
        "THRESHOLD_UNWIND_REUSE_MEDIUM",
        "THRESHOLD_UNWIND_REUSE_HIGH",
        "THRESHOLD_HANDLER_DOMINANCE",
        "CONFIDENCE_BASE",
        "CONFIDENCE_PER_FAMILY",
        "CONFIDENCE_PENALTY_SINGLE_SIGNAL",
        "CONFIDENCE_PENALTY_SMALL_SAMPLE",
        "CONFIDENCE_PENALTY_PLACEMENT_ONLY",
    ]
    for key in const_keys:
        if key in constants:
            lines.append(f"- {key} = {constants[key]}")
    lines.append("")
    lines.append("7.4 Что означают score/verdict/confidence")
    lines.append("- score (0..100): интегральная подозрительность, растет от суммы сработавших признаков.")
    lines.append("- verdict: категориальная интерпретация (`no_strong_static_anomalies`, `low`, `moderate`, `high`).")
    lines.append("- confidence: уверенность в интерпретации (понижается mitigation-правилами при слабых/изолированных сигналах).")
    lines.append("")
    lines.append("8. Динамический анализ: как подтверждается вмешательство")
    lines.append("- Инструмент запускает цель под отладчиком (Debug API) и ловит debug-события.")
    lines.append("- Ставит breakpoints на:")
    lines.append("  1) handler targets из статически разобранных `UNWIND_INFO`.")
    lines.append("  2) API регистрации обработчиков (`AddVectoredExceptionHandler`, `AddVectoredContinueHandler`, `SetUnhandledExceptionFilter`).")
    lines.append("  3) API динамических function tables (`RtlAddFunctionTable`, `RtlInstallFunctionTableCallback`).")
    lines.append("- Считает first-chance / second-chance исключения и снимает RIP-trace после handler-hit.")
    lines.append("- Это дает runtime-доказательство, что exception-flow реально перехватывается.")
    lines.append("")
    lines.append("9. Интеграция в Ghidra (простое объяснение)")
    lines.append("Инструмент формирует CSV с диапазонами функций и комментариями unwind.")
    lines.append("Скрипт `ghidra/import_unwind_csv.py` в Ghidra создает/обновляет функции и переносит комментарии,")
    lines.append("чтобы исследователь сразу видел, какие участки кода связаны с подозрительными unwind/handler-признаками.")
    lines.append("")
    lines.append("10. Тестовое покрытие: созданный набор бинарников")
    lines.append(f"Папка набора: {pack_dir}")
    lines.append(f"Static кейсов: {len([r for r in matrix_rows if 'dynamic' not in (r.get('heuristic_family_or_mode',''))])}")
    lines.append(f"Dynamic кейсов: {len([r for r in matrix_rows if 'dynamic' in (r.get('heuristic_family_or_mode',''))])}")
    lines.append("Каждый бинарник целенаправленно активирует конкретный признак/комбинацию признаков.")
    for row in matrix_rows:
        lines.append(
            f"- {row.get('binary','')}: сигнал `{row.get('target_signals','')}`, покрытие `{row.get('heuristic_family_or_mode','')}`."
        )
    lines.append("")
    lines.append("11. Фактические результаты тестирования (из CSV)")
    lines.append(f"- Статический прогон: {static_summary['total']} образцов.")
    lines.append(f"- Статусы static: {dict(static_summary['statuses'])}.")
    lines.append(f"- Verdict static: {dict(static_summary['verdicts'])}.")
    lines.append("- Наиболее частые finding-codes:")
    for code, count in static_summary["top_findings"]:
        lines.append(f"  {code}: {count}")
    lines.append("Подробно по static-бинарникам:")
    for row in static_rows:
        lines.append(
            f"- {row.get('binary','')}: status={row.get('status','')}, score={row.get('score','')}, "
            f"verdict={row.get('verdict','')}, evidence_level={row.get('evidence_level','')}, findings={row.get('findings','')}"
        )
    lines.append("")
    lines.append(f"- Динамический прогон: {dynamic_summary['total']} образцов.")
    lines.append(f"- Статусы dynamic: {dict(dynamic_summary['statuses'])}.")
    lines.append(f"- dyn_ok: {dict(dynamic_summary['dyn_ok'])}.")
    lines.append("Подробно по dynamic-бинарникам:")
    for row in dynamic_rows:
        lines.append(
            f"- {row.get('binary','')}: dyn_ok={row.get('dyn_ok','')}, exceptions={row.get('exceptions','')}, "
            f"veh_hits={row.get('veh_hits','')}, vch_hits={row.get('vch_hits','')}, "
            f"uef_hits={row.get('uef_hits','')}, rtl_add={row.get('rtl_add','')}, "
            f"rtl_install={row.get('rtl_install','')}, case_strength={row.get('case_strength','')}"
        )
    lines.append("")
    lines.append("12. Сильные стороны проекта")
    lines.append("- Комбинация static + dynamic, а не только один слой проверки.")
    lines.append("- Явная evidence-модель: findings, families, score, confidence, mitigations.")
    lines.append("- Репродуцируемый тестовый набор из 18 бинарников с матрицей покрытия.")
    lines.append("- Интеграция в Ghidra ускоряет анализ и снижает ручную рутину.")
    lines.append("- JSON assessment уже содержит manual validation steps для практической проверки гипотез.")
    lines.append("")
    lines.append("13. Ограничения и риски интерпретации")
    lines.append("- Эвристики не являются математически идеальным классификатором; это инженерный triage.")
    lines.append("- Для финальной статистической калибровки нужна расширенная корпусная выборка (см. `docs/threshold_calibration.md`).")
    lines.append("- Некоторые runtime-паттерны могут иметь легитимные причины (JIT/рантайм/инструментация), поэтому важна ручная верификация.")
    lines.append("- Текущий regression-набор в основном синтетический; для оценки false positive/false negative нужен корпус реальных benign/protected PE.")
    lines.append("- Windows dynamic-результаты сохранены в сводном CSV, но raw console/JSON артефакты нужно повторно получить для финальной сборки.")
    lines.append("- Dynamic collector использует программные breakpoints и фиксированные внутренние лимиты, поэтому на крупных/многопоточных целях возможны пропуски.")
    lines.append("")
    lines.append("14. Ответ на вопрос о детекте вмешательства в EH/Unwind")
    lines.append("Проект обнаруживает подготовленные признаки вмешательства в EH/unwind:")
    lines.append("- статически: по структурным, размещенческим и комбинированным аномалиям;")
    lines.append("- динамически: по фактическим hit/registration-событиям обработчиков и function tables.")
    lines.append("Это подтверждено синтетическими бинарниками 03-14 и сохраненными CSV-результатами Windows-прогона 15-18; универсальная детектирующая способность пока не доказана.")
    lines.append("")
    lines.append("15. Что можно развивать дальше")
    lines.append("- Добавить corpus-level калибровку порогов на большом наборе benign/protected приложений.")
    lines.append("- Добавить richer correlation (пер-функциональный граф static<->dynamic).")
    lines.append("- Добавить экспорт в SIEM/правила SOC (формат событий по findings/families).")
    lines.append("- Добавить автоматическую пакетную валидацию нескольких целей в одном запуске.")
    lines.append("")
    lines.append("16. Итоговое заключение")
    lines.append("Проект готов как содержательный инженерный прототип ВКР-уровня:")
    lines.append("- код модульный и покрывает полный цикл от парсинга до отчета;")
    lines.append("- признаки и эвристики формализованы и документированы;")
    lines.append("- статическая часть воспроизводимо проверена unit/regression-наборами и специально собранными бинарниками;")
    lines.append("- перед финальной защитой требуется пересобрать Windows EXE из актуальных исходников и сохранить raw JSON/console динамических прогонов;")
    lines.append("- для заявления о готовом детекторе, а не triage-прототипе, нужна расширенная калибровка на реальном корпусе.")
    lines.append("")
    lines.append("Приложение A. Подробная карта содержимого папок")
    lines.extend(folder_content_lines(ROOT))
    lines.append("")
    lines.append("Приложение B. Где хранится этот отчет")
    lines.append(f"- Основной файл анализа: {analysis_doc_path}")
    return lines


def main() -> int:
    pack_dir = find_pack_dir()
    static_csv = pack_dir / "results_static_validation.csv"
    dynamic_csv = pack_dir / "results_dynamic_validation.csv"
    matrix_csv_candidates = [p for p in pack_dir.glob("*.csv") if p.name not in {static_csv.name, dynamic_csv.name}]
    if not matrix_csv_candidates:
        raise FileNotFoundError("Не найдена матрица покрытия CSV в папке набора.")
    matrix_csv = matrix_csv_candidates[0]

    static_rows = read_csv_any(static_csv)
    dynamic_rows = read_csv_any(dynamic_csv)
    matrix_rows = read_csv_any(matrix_csv)

    function_map = parse_function_map(ROOT / "src")
    constants = parse_heuristic_constants(ROOT / "src" / "heuristics.c")
    findings = parse_finding_codes(ROOT / "src" / "heuristics.c")

    analysis_doc = find_or_create_analysis_doc_path()
    instruction_doc = pack_dir / "Инструкция_по_запуску_и_проверке_бинарников.docx"

    analysis_lines = build_analysis_lines(
        pack_dir=pack_dir,
        analysis_doc_path=analysis_doc,
        function_map=function_map,
        constants=constants,
        findings=findings,
        static_rows=static_rows,
        dynamic_rows=dynamic_rows,
        matrix_rows=matrix_rows,
    )
    instruction_lines = build_instruction_lines(
        pack_dir=pack_dir,
        static_rows=static_rows,
        dynamic_rows=dynamic_rows,
        matrix_rows=matrix_rows,
    )

    write_docx(
        analysis_doc,
        analysis_lines,
        "Глубокий аналитический отчет по проекту EH/Unwind Analyzer",
    )
    write_docx(
        instruction_doc,
        instruction_lines,
        "Подробная пошаговая инструкция: запуск проекта и проверка тестовых бинарников",
    )

    analysis_copy = pack_dir / analysis_doc.name
    analysis_copy.write_bytes(analysis_doc.read_bytes())

    print(f"[OK] analysis report: {analysis_doc}")
    print(f"[OK] instruction report: {instruction_doc}")
    print(f"[OK] analysis copy: {analysis_copy}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
