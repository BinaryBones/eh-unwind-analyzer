#!/usr/bin/env python3
from __future__ import annotations

import datetime as _dt
import html
import os
import re
import textwrap
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "ru"
OUT_PDF = OUT_DIR / "МОЕ ПОВТОРЕНИЕ ПРОЕКТА.pdf"
SOURCE_SNAPSHOT = OUT_DIR / "МОЕ ПОВТОРЕНИЕ ПРОЕКТА - источник.txt"

FONT = Path(
    r"C:\Users\Templar\.cache\codex-runtimes\codex-primary-runtime"
    r"\dependencies\native\poppler\Library\share\fonts\DejaVuSans.ttf"
)


def register_fonts() -> None:
    if not FONT.exists():
        raise FileNotFoundError(f"Font not found: {FONT}")
    pdfmetrics.registerFont(TTFont("DejaVu", str(FONT)))


def styles():
    base = getSampleStyleSheet()
    for name in base.byName:
        base[name].fontName = "DejaVu"
    base.add(
        ParagraphStyle(
            "BookTitle",
            parent=base["Title"],
            fontName="DejaVu",
            fontSize=28,
            leading=34,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#1d3557"),
            spaceAfter=10,
        )
    )
    base.add(
        ParagraphStyle(
            "BookSubtitle",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=12,
            leading=17,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#4b5563"),
            spaceAfter=18,
        )
    )
    base.add(
        ParagraphStyle(
            "Chapter",
            parent=base["Heading1"],
            fontName="DejaVu",
            fontSize=20,
            leading=26,
            textColor=colors.HexColor("#1d3557"),
            spaceBefore=8,
            spaceAfter=12,
            keepWithNext=True,
        )
    )
    base.add(
        ParagraphStyle(
            "Section",
            parent=base["Heading2"],
            fontName="DejaVu",
            fontSize=15,
            leading=20,
            textColor=colors.HexColor("#263238"),
            spaceBefore=10,
            spaceAfter=7,
            keepWithNext=True,
        )
    )
    base.add(
        ParagraphStyle(
            "Subsection",
            parent=base["Heading3"],
            fontName="DejaVu",
            fontSize=12.5,
            leading=17,
            textColor=colors.HexColor("#374151"),
            spaceBefore=8,
            spaceAfter=5,
            keepWithNext=True,
        )
    )
    base.add(
        ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=9.6,
            leading=14.2,
            alignment=TA_LEFT,
            spaceAfter=5,
        )
    )
    base.add(
        ParagraphStyle(
            "Small",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=8.1,
            leading=11.4,
            spaceAfter=3,
        )
    )
    base.add(
        ParagraphStyle(
            "BookBullet",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=9.1,
            leading=13.2,
            leftIndent=12,
            firstLineIndent=-8,
            spaceAfter=2.5,
        )
    )
    base.add(
        ParagraphStyle(
            "Callout",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=9.1,
            leading=13.5,
            leftIndent=7,
            rightIndent=7,
            textColor=colors.HexColor("#111827"),
            spaceAfter=6,
        )
    )
    base.add(
        ParagraphStyle(
            "BookCode",
            parent=base["Code"],
            fontName="DejaVu",
            fontSize=7.4,
            leading=9.4,
            leftIndent=0,
            spaceAfter=0,
        )
    )
    return base


ST = None
STORY: list = []
TEXT_SNAPSHOT: list[str] = []


def esc(text: object) -> str:
    return html.escape(str(text), quote=False)


def raw_text(text: str) -> None:
    TEXT_SNAPSHOT.append(text.rstrip() + "\n")


def p(text: str, style: str = "Body") -> None:
    raw_text(text)
    STORY.append(Paragraph(esc(text), ST[style]))


def h1(text: str) -> None:
    raw_text("\n# " + text)
    STORY.append(Paragraph(esc(text), ST["Chapter"]))


def h2(text: str) -> None:
    raw_text("\n## " + text)
    STORY.append(Paragraph(esc(text), ST["Section"]))


def h3(text: str) -> None:
    raw_text("\n### " + text)
    STORY.append(Paragraph(esc(text), ST["Subsection"]))


def spacer(height: float = 5) -> None:
    STORY.append(Spacer(1, height))


def pagebreak() -> None:
    STORY.append(PageBreak())
    raw_text("\n--- page break ---\n")


def bullets(items: list[str]) -> None:
    for item in items:
        raw_text("- " + item)
        STORY.append(Paragraph("- " + esc(item), ST["BookBullet"]))
    spacer(3)


def numbered(items: list[str]) -> None:
    for i, item in enumerate(items, 1):
        raw_text(f"{i}. {item}")
        STORY.append(Paragraph(f"{i}. {esc(item)}", ST["BookBullet"]))
    spacer(3)


def code(text: str, width: int = 96) -> None:
    lines: list[str] = []
    for line in text.strip("\n").splitlines():
        if not line:
            lines.append("")
            continue
        chunks = textwrap.wrap(
            line,
            width=width,
            replace_whitespace=False,
            drop_whitespace=False,
            break_long_words=True,
            break_on_hyphens=False,
        )
        lines.extend(chunks or [""])
    wrapped = "\n".join(lines)
    raw_text("\n```text\n" + wrapped + "\n```")
    tbl = Table(
            [[Preformatted(wrapped, ST["BookCode"])]],
        colWidths=[170 * mm],
        style=TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
                ("BOX", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d5db")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        ),
    )
    STORY.append(tbl)
    spacer(6)


def table(headers: list[str], rows: list[list[object]], widths: list[float] | None = None) -> None:
    raw_text("\n" + " | ".join(headers))
    for row in rows:
        raw_text(" | ".join(str(x) for x in row))
    data = [[Paragraph(esc(h), ST["Small"]) for h in headers]]
    for row in rows:
        data.append([Paragraph(esc(cell), ST["Small"]) for cell in row])
    col_widths = [w * mm for w in widths] if widths else None
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, -1), "DejaVu"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    STORY.append(tbl)
    spacer(8)


def callout(title: str, body: str) -> None:
    raw_text(f"\n[{title}] {body}")
    tbl = Table(
        [[Paragraph(esc(title), ST["Subsection"])], [Paragraph(esc(body), ST["Callout"])]],
        colWidths=[170 * mm],
        style=TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#34d399")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        ),
    )
    STORY.append(tbl)
    spacer(8)


def source_info() -> dict[str, dict[str, object]]:
    files = [
        "CMakeLists.txt",
        "CMakePresets.json",
        "include/util.h",
        "include/pe.h",
        "include/unwind.h",
        "include/heuristics.h",
        "include/report.h",
        "include/dynamic.h",
        "include/app_info.h",
        "src/util.c",
        "src/pe.c",
        "src/unwind.c",
        "src/heuristics.c",
        "src/report.c",
        "src/dynamic_win.c",
        "src/app_info.c",
        "src/main.c",
        "tests/unit/unit_unwind.c",
        "tests/unit/unit_heuristics.c",
        "tests/unit/unit_core_edges.c",
        "tests/test_cli_contract.py",
    ]
    info: dict[str, dict[str, object]] = {}
    rx = re.compile(
        r"^(?:static\s+)?(?:const\s+)?(?:[A-Za-z_][\w_]*\s+)+[*\s]*([A-Za-z_]\w*)\s*\([^;]*\)\s*\{",
        re.MULTILINE,
    )
    for rel in files:
        path = ROOT / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        funcs = [m.group(1) for m in rx.finditer(text)]
        info[rel] = {
            "lines": text.count("\n") + 1,
            "bytes": path.stat().st_size,
            "functions": funcs[:24],
        }
    return info


MODULES = [
    {
        "name": "util.h / util.c",
        "role": "Фундамент: чтение файла в память, безопасное чтение байтов, little-endian числа, растущая строка, атомарная запись файла, SHA-256.",
        "concepts": [
            "указатели и `NULL`",
            "`size_t`, `uint8_t`, `uint32_t`, `uint64_t`",
            "`malloc`, `calloc`, `realloc`, `free`",
            "проверка выхода за границы буфера",
            "маленький endian",
            "вариадические функции через `va_list`",
            "переполнение целых чисел",
            "владение памятью",
        ],
        "structures": ["Buf", "StrBuf", "Sha256Ctx"],
        "functions": [
            "buf_init_from_file",
            "buf_read",
            "buf_read_u16/u32/u64",
            "sb_init",
            "sb_appendn",
            "sb_appendf",
            "file_write_atomic",
            "sha256_hex",
        ],
        "steps": [
            "Создай `Buf`: два поля, `const uint8_t* data` и `size_t size`. Пока не пиши PE.",
            "Напиши `buf_read`: сначала проверки аргументов, потом проверка `off > size`, потом `len > size - off`, затем `memcpy`.",
            "Напиши `le16`, `le32`, `le64`. Научись видеть, что байты файла не обязаны совпадать с порядком байтов CPU.",
            "Добавь `buf_read_u16/u32/u64`: читаешь временный массив байтов и переводишь в число.",
            "Напиши чтение файла: `fopen`, `fseek`, `ftell`, выделение памяти, `fread`, закрытие файла.",
            "Сделай `StrBuf`: `s`, `len`, `cap`, `failed`. Не добавляй строку без места под завершающий ноль.",
            "Реализуй `sb_reserve` через `realloc`. Проверь, что рост емкости не переполняет `SIZE_MAX`.",
            "Реализуй `sb_appendn`, потом `sb_append`, потом `sb_appendf`.",
            "Сделай `file_write_atomic`: сначала `.tmp.<pid>`, потом замена итогового файла.",
            "SHA-256 можно написать последним: это самостоятельный алгоритм, он нужен для идентичности входного файла в отчетах.",
        ],
        "checks": [
            "Пустой файл читается без падения, размер равен 0, но память все равно не `NULL`.",
            "`buf_read` возвращает `false`, если просишь байты за концом.",
            "`sb_appendf` после нескольких добавлений оставляет строку с `\\0` в конце.",
            "После ошибки выделения `StrBuf.failed` остается `true`, а вызывающий код может остановиться.",
        ],
    },
    {
        "name": "pe.h / pe.c",
        "role": "Строит минимальную модель PE32+ AMD64: заголовки, секции, exception directory, проверки диапазонов и перевод RVA в file offset.",
        "concepts": [
            "бинарный формат как контракт",
            "структура как модель предметной области",
            "магические числа и именованные константы",
            "границы массива секций",
            "виртуальный адрес против смещения в файле",
            "валидация до доверия",
        ],
        "structures": ["PeSection", "PeImage"],
        "functions": ["pe_parse", "pe_free", "pe_find_section_for_rva", "pe_rva_to_fileoff"],
        "steps": [
            "Начни с констант `MZ`, `PE\\0\\0`, `AMD64`, `PE32+`, индекса exception directory.",
            "Опиши `PeSection`: имя, virtual address, virtual size, raw pointer, raw size, characteristics.",
            "Опиши `PeImage`: глобальные поля образа, массив секций, счетчики проблем.",
            "В `pe_parse` первым делом зануляй `out`, чтобы при ошибке не осталось мусора.",
            "Прочитай `e_lfanew` из DOS header: это смещение до NT headers.",
            "Проверь сигнатуру PE и COFF Machine. Проект сознательно принимает только AMD64.",
            "Прочитай optional header PE32+: image base, alignment, image/header size, число data directories.",
            "Найди exception directory по индексу 3. Сохрани RVA и размер.",
            "Прочитай секции циклом по 40 байт на заголовок.",
            "Посчитай структурные проблемы: выход raw за файл, virtual за SizeOfImage, overlaps, alignment.",
            "Реализуй `pe_find_section_for_rva` и `pe_rva_to_fileoff`: это карта, без которой unwind parser слепой.",
        ],
        "checks": [
            "Файл не с `MZ` отвергается с понятной ошибкой.",
            "PE32/x86 отвергается, потому что проект про PE32+ AMD64.",
            "RVA внутри заголовков мапится напрямую.",
            "RVA в виртуальном хвосте секции не мапится в файл.",
        ],
    },
    {
        "name": "unwind.h / unwind.c",
        "role": "Читает `.pdata` как массив `RUNTIME_FUNCTION` и декодирует `UNWIND_INFO` V1/V2, операции пролога, handler и chain.",
        "concepts": [
            "битовые поля",
            "маски флагов",
            "переменный размер записи",
            "`switch` по opcode",
            "цикл с шагом, зависящим от данных",
            "строгие и совместимые проверки ABI",
            "bounded recursion через chain",
        ],
        "structures": ["RuntimeFunction", "UnwindSummary", "UnwindParseOpts"],
        "functions": [
            "unwind_read_runtime_functions_ex",
            "unwind_parse",
            "slots_for_code",
            "unwind_parse_fail",
            "unwind_reg_name",
            "unwind_flags_to_string",
        ],
        "steps": [
            "Сначала реализуй только чтение `RUNTIME_FUNCTION`: каждая запись 12 байт, три `uint32_t` RVA.",
            "В `UnwindSummary` добавь только базовые поля: version, flags, prolog, count, frame.",
            "Реализуй чтение header `UNWIND_INFO`: первый байт делится на version и flags.",
            "Сделай `slots_for_code`: для каждого unwind opcode верни, сколько 2-байтовых slots он занимает.",
            "Напиши цикл `for (i = 0; i < count;)`: читаешь slot, выделяешь CodeOffset, Op, OpInfo, увеличиваешь `i += slots`.",
            "Для каждого opcode сначала добавь распознавание и текст, потом вычисление stack/register effects.",
            "Добавь anomaly flags: unsupported version, truncated, bad opcode, bad operand, code offset, alignment.",
            "Добавь handler tail: если флаги EHANDLER/UHANDLER, после slots лежит handler RVA.",
            "Добавь chain tail: если CHAININFO, после slots лежит еще один `RUNTIME_FUNCTION`.",
            "Включи follow-chain только после того, как одиночный record работает. Ограничение depth защищает от циклов.",
        ],
        "checks": [
            "V3 не парсится как V1/V2: это отдельный формат.",
            "Если opcode требует 3 slots, а `CountOfCodes` заканчивается раньше, парсер возвращает ошибку.",
            "Невыровненный `UNWIND_INFO` отмечается anomaly, но не обязательно делает запись фатальной.",
            "Parse error сохраняется в `UnwindSummary.parse_error`, чтобы отчет знал точную причину.",
        ],
    },
    {
        "name": "heuristics.h / heuristics.c",
        "role": "Превращает наблюдения в findings, score, confidence, evidence level, verdict и weakening rules.",
        "concepts": [
            "инженерная эвристика против статистической вероятности",
            "массивы структур фиксированного размера",
            "`qsort` и компаратор",
            "простая hash map с open addressing",
            "отношения и проценты",
            "семейства доказательств",
            "снижение уверенности при слабом контексте",
        ],
        "structures": ["HeuristicFinding", "HeuristicMitigation", "HeuristicReport", "HMap"],
        "functions": [
            "heuristics_analyze",
            "add_finding",
            "add_mitigation",
            "finalize_verdict",
            "hmap_inc",
            "heuristics_free",
        ],
        "steps": [
            "Сначала перенеси счетчики из `PeImage`: section problems и exception directory problems.",
            "Пройди все `RuntimeFunction`: invalid ranges, out-of-bounds begin/end, out-of-bounds unwind RVA, unsorted.",
            "Параллельно считай reuse `UnwindInfoRVA` через маленькую hash map.",
            "Если unwind parse failed или `anomalies` содержит не только ABI warnings, увеличивай счетчики integrity.",
            "Проверь placement: где лежит unwind info и где лежит handler target.",
            "Отсортируй копию begin/end, чтобы найти overlaps и duplicate begins.",
            "Добавь findings: code, family, severity, message, representative RVA, affected count.",
            "Собери score по матрице весов. Важно: score это triage, не доказательство.",
            "Посчитай confidence: базовое значение, бонусы за семейства/сильные сигналы, затем weakening rules.",
            "Сформируй `verdict`, `evidence_level` и `requires_manual_review`.",
        ],
        "checks": [
            "Одиночный необычный section name не должен превращать файл в `high_suspicion`.",
            "Writable metadata и handler writable вместе усиливают case.",
            "Strict ABI warnings не повышают score сами по себе.",
            "Все findings влезают в `HEURISTICS_MAX_FINDINGS`, а переполнение не ломает details.",
        ],
    },
    {
        "name": "report.h / report.c",
        "role": "Сериализует модель в console, CSV, Ghidra CSV, JSON и HTML. Отчеты являются внешним контрактом проекта.",
        "concepts": [
            "serialization",
            "CSV escaping",
            "JSON escaping и UTF-8",
            "HTML escaping и Content Security Policy",
            "модель отчета и schema",
            "атомарная запись результата",
            "ручной план валидации",
        ],
        "structures": ["ReportMetadata", "AssessmentSummary", "ManualValidationSteps"],
        "functions": [
            "report_print_brief",
            "report_write_csv",
            "report_write_json_ex",
            "report_write_html",
            "report_print_heuristics",
        ],
        "steps": [
            "Начни с console: вывести path, Machine, ImageBase, SizeOfImage, Exception Directory, count.",
            "Добавь CSV без Ghidra mode: одна строка на function, явные колонки.",
            "Добавь Ghidra CSV: begin, end, generated name, comment.",
            "Сделай escape функций для CSV, JSON и HTML. Не доверяй строкам из входа.",
            "Опиши `ReportMetadata`: версия, schema, timestamp, sha256, размер, command line, build.",
            "Добавь model validation: report writer должен отказаться от невозможных указателей/границ.",
            "Собери JSON по schema, затем добавь HTML dashboard.",
            "В отчете отдели static evidence, dynamic evidence, final assessment и manual validation steps.",
        ],
        "checks": [
            "Кавычки, переносы строк и запятые в CSV не ломают файл.",
            "Невалидный UTF-8 не проходит в JSON как сырые байты.",
            "HTML не грузит внешние скрипты, стили, шрифты или картинки.",
            "Временные `.tmp.<pid>` файлы не остаются после успешной записи.",
        ],
    },
    {
        "name": "dynamic.h / dynamic_win.c",
        "role": "Windows-only сбор runtime evidence через Debug API: exceptions, VEH/VCH/UEF, unwind handler breakpoints, dynamic function tables.",
        "concepts": [
            "условная компиляция `#ifdef _WIN32`",
            "Windows HANDLE и cleanup",
            "CreateProcess под debugger",
            "debug events",
            "INT3 breakpoint и re-arm",
            "GetThreadContext / SetThreadContext",
            "модульные базы и offsets",
            "граница безопасности execution",
        ],
        "structures": ["DynamicEvent", "DynamicReport", "ModList", "Breakpoint", "PendingRearmList"],
        "functions": [
            "dynamic_report_init",
            "dynamic_collect_windows",
            "mods_refresh_toolhelp",
            "bp_add_and_arm_selfcheck",
            "add_api_bps_if_ready",
            "dynamic_event_add",
        ],
        "steps": [
            "Сначала реализуй non-Windows stub: dynamic mode сообщает, что поддержан только Windows.",
            "Опиши `DynamicReport`: счетчики, events, trace, details.",
            "На Windows собери command line с правильным quoting.",
            "Запусти target через `CreateProcess` с debug flags.",
            "Обновляй список модулей через Toolhelp, чтобы переводить адреса в module+offset.",
            "Поставь API breakpoints на VEH/VCH/UEF и RtlAddFunctionTable/RtlInstallFunctionTableCallback.",
            "Поставь breakpoints на handlers, найденные static stage.",
            "В debug loop различай CREATE_PROCESS, LOAD_DLL, EXCEPTION, EXIT_PROCESS.",
            "При INT3 сними breakpoint, откати RIP, включи trap flag, затем re-arm на single-step.",
            "Всегда чисти breakpoints и handles, даже если timeout или ошибка.",
        ],
        "checks": [
            "На Linux/macOS сборка статического режима проходит без Windows headers.",
            "Timeout завершает dynamic session и не оставляет зависший процесс.",
            "Instrumentation completeness показывает, где сбор evidence был неполным.",
            "Dynamic mode не заменяет sandbox: файл реально выполняется.",
        ],
    },
    {
        "name": "app_info.h / app_info.c",
        "role": "Единая точка версий, build metadata и UTC timestamp для отчетов.",
        "concepts": [
            "макросы версии",
            "условная компиляция по compiler/platform",
            "время UTC",
            "маленький модуль как стабильный источник правды",
        ],
        "structures": ["EHUA_VERSION", "EHUA_REPORT_SCHEMA_VERSION"],
        "functions": [
            "app_version",
            "app_report_schema_version",
            "app_build_compiler",
            "app_build_platform",
            "app_build_mode",
            "app_utc_timestamp",
        ],
        "steps": [
            "Вынеси версии в header, чтобы main/report/tests видели одно значение.",
            "Определи compiler через `_MSC_VER`, `__clang__`, `__GNUC__`.",
            "Определи platform через `_WIN64`, `__linux__`, `__APPLE__`.",
            "Сделай `app_build_mode`: `NDEBUG` означает release.",
            "Сделай timestamp строго RFC 3339: `YYYY-MM-DDTHH:MM:SSZ`.",
        ],
        "checks": [
            "`--version` печатает tool version и report schema.",
            "JSON metadata содержит ту же schema version, что и `app_info.h`.",
        ],
    },
    {
        "name": "main.c",
        "role": "CLI, жизненный цикл программы, оркестрация модулей, владение памятью и exit codes.",
        "concepts": [
            "структура Args",
            "разбор аргументов",
            "коды выхода",
            "последовательность pipeline",
            "ранний выход и cleanup",
            "передача указателей между модулями",
            "redaction target arguments",
        ],
        "structures": ["Args", "ParseResult"],
        "functions": [
            "parse_args",
            "build_invocation",
            "print_one",
            "main",
        ],
        "steps": [
            "Начни с `usage` и `--version`: программу можно проверить еще до парсера PE.",
            "Опиши `Args` с дефолтами: follow_chain true, max depth 8, timeout 15000, trace 64.",
            "Напиши `parse_args`: каждую опцию проверяй отдельно, диапазоны чисел валидируй.",
            "В `main` сначала прочитай файл, затем `pe_parse`, затем `unwind_read_runtime_functions_ex`.",
            "Выдели массивы `UnwindSummary` и `bool us_ok` размером `rf_count ? rf_count : 1`.",
            "Для каждой `RuntimeFunction` вызови `unwind_parse` и сохрани результат.",
            "Если попросили `--dump`, выведи краткую строку по каждой функции.",
            "Если попросили `--heuristics`, вызови `heuristics_analyze` и запомни `hr_ptr`.",
            "Если попросили `--dynamic`, вызови collector и запомни `dr_ptr`.",
            "Отчеты пиши после анализа, когда есть metadata, SHA-256 и command line.",
            "В конце освободи все: reports, buffers, arrays, PE sections, input bytes.",
        ],
        "checks": [
            "Без аргументов exit code 2 и usage.",
            "Отсутствующий файл дает exit code 1.",
            "Неверный `--max-chain-depth 17` дает exit code 2.",
            "После `--` аргументы target не попадают в JSON metadata.",
        ],
    },
]


BOOTCAMP = [
    (
        "Компилятор, linker и единица трансляции",
        "C-файл компилируется отдельно. Header не является отдельной программой: он вставляется препроцессором в `.c`, который его `#include`-ит. "
        "Linker потом соединяет объектные файлы и проверяет, что объявленные функции действительно где-то определены. "
        "Поэтому в этом проекте `.h` описывает контракт, `.c` реализует контракт, а `CMakeLists.txt` говорит, какие `.c` участвуют в сборке.",
    ),
    (
        "Типы фиксированной ширины",
        "`uint8_t`, `uint16_t`, `uint32_t`, `uint64_t` нужны, потому что PE и UNWIND_INFO задают поля в конкретных размерах. "
        "`int` может быть удобен для счетчиков, но для поля из файла лучше брать тип с точной шириной. "
        "Если спецификация говорит 'DWORD', обычно это 32 бита, значит в коде нужен `uint32_t`.",
    ),
    (
        "Указатель",
        "Указатель хранит адрес. В проекте указатели часто означают 'я даю функции доступ к уже существующему объекту'. "
        "`PeImage* out` значит: функция заполнит объект, который создал вызывающий код. "
        "`const Buf* b` значит: функция читает буфер, но не должна менять сам `Buf` и его bytes.",
    ),
    (
        "Проверка `NULL`",
        "В C нет автоматической защиты от обращения по нулевому указателю. Поэтому почти каждая публичная функция начинает с guard: "
        "`if (!out || !b || !err) return false;`. Это не формальность, а страховка границы API.",
    ),
    (
        "Массив и размер",
        "В C массив не носит с собой длину. Если функция получает pointer на bytes, она обязана получать и `size`. "
        "Именно поэтому `Buf` содержит `data` и `size` вместе. Это маленькая структура, но она предотвращает целый класс ошибок.",
    ),
    (
        "Владение памятью",
        "Вопрос 'кто делает `free`?' важнее синтаксиса. `buf_init_from_file` выделяет память и возвращает ее через `owned_mem`; "
        "освобождает ее вызывающий код через `buf_free_owned`. `pe_parse` выделяет `sections`, а `pe_free` освобождает. "
        "Такой договор надо видеть у каждого модуля.",
    ),
    (
        "Строка в C",
        "C-строка заканчивается нулевым байтом. Если забыть место под `\\0`, строковые функции уйдут читать чужую память. "
        "`StrBuf` всегда хранит `len`, `cap` и дописывает ноль после каждого append.",
    ),
    (
        "Переполнение",
        "В парсере недоверенного файла нельзя писать `off + len <= size`, если `off + len` может переполниться. "
        "Проект часто пишет безопаснее: сначала `if (off > size)`, потом `if (len > size - off)`. "
        "Так сложение заменяется вычитанием уже проверенного диапазона.",
    ),
    (
        "Endian",
        "PE хранит числа little-endian. Даже если твой процессор тоже little-endian, проект вручную собирает числа из байтов. "
        "Это делает код явным и независимым от неочевидного поведения платформы.",
    ),
    (
        "Флаги и битовые маски",
        "Флаг - это один бит внутри числа. `flags & UNW_FLAG_EHANDLER` отвечает на вопрос: установлен ли этот бит. "
        "`anomalies |= UA_TRUNCATED` добавляет признак проблемы, не стирая остальные признаки.",
    ),
    (
        "Ранний выход",
        "В C часто проще остановиться сразу после ошибки. Но ранний выход требует освобождать уже выделенные ресурсы. "
        "`main.c` поэтому выглядит длинным: он не только запускает этапы, но и аккуратно чистит память на каждом пути.",
    ),
    (
        "Тесты как учебник",
        "Unit tests в этом проекте не просто проверяют код. Они показывают минимальные искусственные bytes, из которых рождается `UNWIND_INFO`. "
        "Когда непонятно, как работает формат, открой `tests/unit/unit_unwind.c` и разбери один тест как лабораторную работу.",
    ),
]


GLOSSARY = [
    ("ABI", "Application Binary Interface: правила вызовов, регистров, stack alignment и unwind metadata для бинарного кода."),
    ("Address", "Число, указывающее место в памяти или файле. В PE важно различать virtual address, RVA и file offset."),
    ("Alignment", "Требование, чтобы адрес или размер был кратен некоторому числу, например 4, 8, 0x200 или 0x1000."),
    ("Anomaly", "Структурное отклонение, которое проект фиксирует как бит в `UnwindSummary.anomalies`."),
    ("Atomic write", "Запись через временный файл и последующую замену, чтобы не оставить наполовину записанный отчет."),
    ("Breakpoint", "Остановка выполнения. В dynamic collector часто ставится INT3 byte `0xCC`."),
    ("Buf", "Пара `data + size`, безопасная обертка над bytes входного файла."),
    ("CHAININFO", "Флаг `UNWIND_INFO`, означающий, что хвост записи содержит chained `RUNTIME_FUNCTION`."),
    ("CLI", "Command Line Interface: способ управлять программой через аргументы командной строки."),
    ("COFF header", "Часть PE header, где лежат machine type, число секций и размер optional header."),
    ("Compiler", "Программа, превращающая C-код в object files."),
    ("Confidence", "Уверенность в интерпретации evidence. В проекте это rule-based число, не статистическая вероятность."),
    ("CountOfCodes", "Поле `UNWIND_INFO`, показывающее число 2-байтовых slots unwind code array."),
    ("CSV", "Табличный текстовый формат. В проекте есть обычный CSV и Ghidra CSV."),
    ("Data directory", "Массив записей optional header PE. Exception directory имеет индекс 3."),
    ("Debug API", "Windows API для запуска процесса под debugger и получения debug events."),
    ("Dynamic mode", "Режим, который запускает target и собирает runtime evidence. Требует изоляции для недоверенных файлов."),
    ("EHANDLER", "Флаг `UNWIND_INFO`, означающий наличие exception handler RVA в tail."),
    ("Evidence family", "Группа родственных findings: table integrity, unwind integrity, placement, reuse, handler dominance."),
    ("File offset", "Смещение в файле от начала bytes. Не равно RVA в общем случае."),
    ("Finding", "Структурированное наблюдение: code, family, severity, message, affected count, representative RVA."),
    ("Frame register", "Регистр, используемый как frame pointer в unwind metadata."),
    ("Ghidra CSV", "CSV, который importer использует для создания функций, комментариев и bookmarks в Ghidra."),
    ("Handler", "Адрес обработчика исключения, связанный с unwind metadata или runtime exception API."),
    ("Hash map", "Таблица key -> value. В heuristics нужна для подсчета reuse одинаковых RVA."),
    ("Header", "Файл `.h`, где описываются структуры, константы и прототипы функций."),
    ("Heap", "Область памяти для `malloc/calloc/realloc`, которую надо освобождать через `free`."),
    ("ImageBase", "Базовый виртуальный адрес, по которому PE предпочитает быть загруженным."),
    ("INT3", "Однобайтовая x86/x64 инструкция breakpoint, значение `0xCC`."),
    ("JSON Schema", "Формальный контракт JSON report, по которому валидируются поля и типы."),
    ("Leaf function", "Функция, которой может не требоваться unwind entry, если она не меняет stack опасным образом."),
    ("Linker", "Собирает объектные файлы в executable и связывает вызовы функций с их реализациями."),
    ("Little-endian", "Порядок байтов, где младший байт числа лежит раньше старшего."),
    ("Machine", "Поле COFF header. Для проекта допустимо только `IMAGE_FILE_MACHINE_AMD64`."),
    ("Metadata placement", "Где именно лежит unwind или handler metadata: `.xdata`, `.rdata`, `.pdata`, `.text`, writable section и т.д."),
    ("Mitigation", "В коде эвристик - weakening rule, которая снижает confidence при слабом или изолированном evidence."),
    ("MZ", "DOS signature в начале PE-файла."),
    ("Optional header", "PE header с ImageBase, alignment, SizeOfImage, data directories. Для PE32+ вовсе не optional для загрузчика."),
    ("Out of bounds", "Ссылка или диапазон выходит за допустимые размеры файла или image."),
    ("PE32+", "64-битный вариант PE optional header, magic `0x20b`."),
    ("RUNTIME_FUNCTION", "12-байтовая запись `.pdata`: BeginAddress, EndAddress, UnwindInfoAddress."),
    ("RVA", "Relative Virtual Address: адрес относительно ImageBase."),
    ("Section", "Область PE с virtual range, raw file range и permissions."),
    ("SizeOfImage", "Размер виртуального образа PE в памяти."),
    ("StrBuf", "Растущая строка проекта: pointer, length, capacity, failed flag."),
    ("Strict ABI", "Дополнительный режим диагностики формальных правил Microsoft x64 unwind ABI."),
    ("Suspicion score", "Оценка подозрительности 0..100. Это triage, а не доказательство."),
    ("UHANDLER", "Флаг `UNWIND_INFO`, связанный с unwind/termination handler."),
    ("UNWIND_INFO", "Структура Windows x64, описывающая prolog, stack effects, saved registers, handlers и chain."),
    ("UWOP_ALLOC_SMALL", "Unwind opcode, кодирующий небольшое выделение stack frame."),
    ("UWOP_PUSH_NONVOL", "Unwind opcode, описывающий push nonvolatile register."),
    ("Validation", "Проверка инвариантов и границ перед тем, как доверять данным."),
    ("VEH", "Vectored Exception Handler, runtime exception mechanism Windows."),
    ("VCH", "Vectored Continue Handler."),
    ("UEF", "Unhandled Exception Filter."),
]


def add_title() -> None:
    STORY.append(Spacer(1, 28 * mm))
    STORY.append(Paragraph("МОЕ ПОВТОРЕНИЕ ПРОЕКТА", ST["BookTitle"]))
    STORY.append(
        Paragraph(
            esc(
                "Учебник для переписывания EH/Unwind Analyzer руками: архитектура, язык C, план файлов, проверки и упражнения."
            ),
            ST["BookSubtitle"],
        )
    )
    today = _dt.date.today().strftime("%Y-%m-%d")
    p(f"Версия учебника: {today}. Проект: EH/Unwind Analyzer 1.0.0, report schema 1.1.0.", "BookSubtitle")
    spacer(12)
    callout(
        "Договор с учеником",
        "Эта книга написана для человека, который честно начинает почти с нуля. "
        "Твоя цель - не перепечатать код механически, а каждый раз понимать: какие bytes мы читаем, "
        "какой объект строим, кто владеет памятью, что проверяем и почему следующий модуль может доверять результату.",
    )
    code(
        """
Главный маршрут проекта:

untrusted PE bytes
  -> util: безопасные bytes и строки
  -> pe: модель PE32+ AMD64 и перевод RVA в file offset
  -> unwind: .pdata / RUNTIME_FUNCTION / UNWIND_INFO
  -> heuristics: findings, score, confidence, verdict
  -> optional dynamic: Windows Debug API evidence
  -> report: console, CSV, JSON, HTML, Ghidra CSV
  -> main: CLI, владение ресурсами, exit codes
        """
    )
    pagebreak()


def add_toc() -> None:
    h1("Как читать эту книгу")
    p(
        "Не читай ее как роман. Читай как маршрут сборки. В каждом большом разделе есть три слоя: "
        "что понять, что написать руками, как проверить себя. Если ты пока не знаешь C, не перескакивай сразу к `unwind.c`: "
        "этот файл станет понятным только после `Buf`, integer widths, `struct`, pointer ownership и PE sections."
    )
    h2("Содержание")
    numbered(
        [
            "Нулевая карта проекта и смысл задачи.",
            "Мини-курс C ровно под этот проект.",
            "Предметная область: PE, RVA, `.pdata`, `UNWIND_INFO`, отчеты.",
            "Архитектура: файлы, модули, ownership, data flow.",
            "Подробная архитектура блоков: ответственность, входы, выходы, взаимодействия.",
            "Пошаговый план написания проекта руками.",
            "Объясняющая карта файлов: зачем файл нужен, что в нем писать и как он работает.",
            "Версионный маршрут: как собрать проект маленькими рабочими состояниями.",
            "Подробный маршрут по каждому файлу.",
            "Как проверять себя тестами и маленькими лабораторными.",
            "Глоссарий и карта ошибок.",
        ]
    )
    h2("Правило одного маленького шага")
    p(
        "Пиши маленькими кусками. В C очень легко получить ошибку, которая выглядит мистически, если ты изменил сразу 200 строк. "
        "Правильный учебный ритм: написать 10-30 строк, собрать, запустить маленький тест, только потом идти дальше. "
        "Проект большой, но он состоит из простых инженерных кирпичей."
    )
    h2("Что значит 'разобраться в каждой строчке'")
    bullets(
        [
            "Ты можешь назвать типы всех переменных в строке.",
            "Ты понимаешь, кто владеет памятью, на которую указывает pointer.",
            "Ты знаешь, какая проверка защищает от выхода за границы.",
            "Ты можешь объяснить, что случится при ошибочном input.",
            "Ты понимаешь, какая следующая функция использует результат этой строки.",
        ]
    )
    pagebreak()


def add_project_map(info: dict[str, dict[str, object]]) -> None:
    h1("1. Что это за проект")
    p(
        "EH/Unwind Analyzer - защитный анализатор Windows PE32+ AMD64 exception/unwind metadata. "
        "Он не пытается запускать статический input и не делает дизассемблирование `.text` в static mode. "
        "Он читает bytes PE-файла, извлекает exception directory, строит таблицу функций, декодирует `UNWIND_INFO`, "
        "фиксирует структурные отклонения и пишет отчеты. Dynamic mode существует отдельно и на Windows действительно запускает target под debugger."
    )
    h2("Главная идея")
    p(
        "В Windows x64 stack unwinding и exception handling завязаны не только на инструкции CPU, но и на metadata. "
        "Эта metadata говорит системе, где начинается и заканчивается функция, как prolog менял stack pointer, какие регистры сохранялись, "
        "есть ли exception handler и есть ли chained unwind record. Если metadata повреждена или необычно размещена, reverse engineer получает сигнал: "
        "здесь нужно ручное внимание."
    )
    h2("Дерево основных файлов")
    rows = []
    for rel, meta in info.items():
        if rel.startswith("reports") or rel.startswith("docs/ru"):
            continue
        rows.append([rel, meta["lines"], ", ".join(meta["functions"][:5]) if meta["functions"] else "-"])
    table(["Файл", "Строк", "Первые функции/точки интереса"], rows[:28], [52, 16, 92])
    h2("Архитектурный конвейер")
    code(
        """
main.c
  parse_args()
  buf_init_from_file()
  pe_parse()
  unwind_read_runtime_functions_ex()
  for each RuntimeFunction:
      unwind_parse()
  optional:
      heuristics_analyze()
      dynamic_collect_windows()
  optional outputs:
      report_write_csv()
      report_write_json_ex()
      report_write_html()
  cleanup and return exit code
        """
    )
    h2("Модули и ответственность")
    table(
        ["Модуль", "За что отвечает", "Что отдает следующему слою"],
        [
            ["util", "Bytes, строки, file I/O, SHA-256", "`Buf`, `StrBuf`, безопасные read helpers"],
            ["pe", "PE32+ AMD64 headers, sections, exception directory", "`PeImage`, sections, RVA mapping"],
            ["unwind", "`.pdata`, `RUNTIME_FUNCTION`, `UNWIND_INFO`", "`RuntimeFunction[]`, `UnwindSummary[]`"],
            ["heuristics", "Findings, score, confidence, verdict", "`HeuristicReport`"],
            ["dynamic", "Runtime evidence через Windows Debug API", "`DynamicReport`"],
            ["report", "CSV, JSON, HTML, console, Ghidra CSV", "Файлы отчетов"],
            ["app_info", "Версии, compiler/platform/build mode, UTC", "`ReportMetadata` поля"],
            ["main", "CLI и orchestration", "Exit code и выбранные outputs"],
        ],
        [28, 70, 70],
    )
    callout(
        "Самое важное архитектурное решение",
        "Модули не должны читать мысли друг друга. `pe.c` не знает, как считать score. `heuristics.c` не читает файл напрямую. "
        "`report.c` не парсит PE. Такой дизайн позволяет учить проект блоками: каждый блок строит одну модель и передает ее дальше.",
    )
    pagebreak()


def add_c_bootcamp() -> None:
    h1("2. C с нуля, но без лишней воды")
    p(
        "Этот раздел не заменяет полный учебник по C. Он дает ровно те понятия, которые будут встречаться в проекте. "
        "Если ты понимаешь этот раздел, исходники перестают быть стеной символов и превращаются в набор повторяющихся инженерных приемов."
    )
    for title, body in BOOTCAMP:
        h2(title)
        p(body)
        if title == "Указатель":
            code(
                """
bool pe_parse(PeImage* out, const Buf* b, StrBuf* err)
{
    // out: куда функция запишет результат
    // b: откуда функция читает bytes
    // err: куда функция добавит текст ошибки
}
                """
            )
        elif title == "Переполнение":
            code(
                """
// Опаснее:
if (off + len > b->size) return false;

// Надежнее:
if (off > b->size) return false;
if (len > b->size - off) return false;
                """
            )
        elif title == "Флаги и битовые маски":
            code(
                """
if (flags & UNW_FLAG_CHAININFO) {
    out->has_chain = true;
}

out->anomalies |= UA_TRUNCATED;
out->anomalies |= UA_BAD_OPERAND;
                """
            )
    h2("Мини-лабораторные перед проектом")
    numbered(
        [
            "Напиши программу, которая принимает path и печатает размер файла.",
            "Добавь функцию `read_u32_le(bytes, offset)` и проверь ее на массиве `{0x78,0x56,0x34,0x12}`.",
            "Сделай структуру `StrBuf`, добавь `append`, напечатай результат.",
            "Сделай структуру `Section` и функцию `rva_to_off` для одного искусственного section.",
            "Собери эти упражнения через CMake или обычный gcc, не переходи к PE, пока они не работают.",
        ]
    )
    pagebreak()


def add_domain_theory() -> None:
    h1("3. Предметная область проекта")
    h2("PE как карта для загрузчика")
    p(
        "PE-файл - это не просто байты программы. Это договор с Windows loader: где заголовки, какие секции есть, "
        "какие диапазоны файла превращаются в какие диапазоны виртуальной памяти, где лежат таблицы импорта, экспорта, ресурсов и exception metadata. "
        "Analyzer читает только нужную часть этого договора, но обязан проверять базовую целостность всей карты."
    )
    code(
        """
File offset:  смещение от начала файла на диске.
RVA:          relative virtual address, адрес относительно ImageBase.
VA:           ImageBase + RVA, адрес в памяти процесса.

Пример:
  ImageBase          = 0x140000000
  section .xdata RVA = 0x3000
  поле указывает RVA = 0x3040
  virtual address    = 0x140003040
        """
    )
    h2("`.pdata` и `RUNTIME_FUNCTION`")
    p(
        "На Windows x64 exception directory обычно указывает на `.pdata`. Эта область содержит массив `RUNTIME_FUNCTION`. "
        "Каждая запись занимает 12 байт: begin RVA, end RVA и RVA структуры `UNWIND_INFO`. Диапазон функции читается как half-open interval: "
        "`[BeginAddress, EndAddress)`. Это значит: begin включен, end уже не включен."
    )
    code(
        """
typedef struct RuntimeFunction {
    uint32_t begin_rva;
    uint32_t end_rva;
    uint32_t unwind_rva;
} RuntimeFunction;
        """
    )
    h2("`UNWIND_INFO`")
    p(
        "`UNWIND_INFO` описывает, что prolog функции сделал со stack и регистрами. Это не машинный код, а compact metadata. "
        "Первый байт содержит version и flags. Затем идут prolog size, count of unwind codes, frame register/offset. "
        "После массива unwind slots может идти handler RVA или chained runtime function."
    )
    table(
        ["Поле", "Смысл для ученика"],
        [
            ["Version", "Проект поддерживает V1 и V2. V3 отклоняется как другой формат."],
            ["Flags", "EHANDLER, UHANDLER, CHAININFO. Определяют хвост структуры."],
            ["Prolog size", "Размер prolog в bytes, нужен для sanity checks code offsets."],
            ["CountOfCodes", "Сколько 2-байтовых slots занимает массив операций."],
            ["Frame register/off", "Опциональный frame pointer и смещение."],
            ["Unwind codes", "Кодированные операции push/save/alloc/set frame/epilog."],
            ["Tail", "Handler RVA или chained `RUNTIME_FUNCTION`, если флаги требуют."],
        ],
        [42, 120],
    )
    h2("Что такое эвристика")
    p(
        "Эвристика - это инженерное правило для приоритизации внимания. Она не доказывает, что файл вредоносный, "
        "и не является обученной статистической моделью. В проекте каждая эвристика видна: есть finding code, family, severity, score weight и weakening rules."
    )
    h2("Static и dynamic")
    bullets(
        [
            "Static mode читает bytes и не выполняет target. Его можно безопаснее гонять в CI и на больших corpus.",
            "Dynamic mode запускает target под Windows Debug API. Это пересечение execution boundary, нужен изолированный VM/lab.",
            "Static отвечает на вопрос: что записано в PE-файле.",
            "Dynamic отвечает на вопрос: что произошло в конкретном запуске.",
            "Final assessment сильнее, когда static и dynamic evidence коррелируют.",
        ]
    )
    pagebreak()


def add_architecture_deep() -> None:
    h1("4. Архитектура и ownership")
    h2("Data flow")
    code(
        """
input path
  -> buf_init_from_file
       owns: input bytes through owned_mem
  -> pe_parse
       owns: img.sections
  -> unwind_read_runtime_functions_ex
       owns: RuntimeFunction* rf
  -> calloc UnwindSummary[] and bool us_ok[]
  -> unwind_parse for each rf[i]
  -> heuristics_analyze
       owns: hr.details StrBuf
  -> dynamic_collect_windows
       owns: dr.details StrBuf, process/debug resources during run
  -> report writers borrow all model objects
  -> cleanup in reverse-ish order
        """
    )
    h2("Карта владения памятью")
    table(
        ["Кто создает", "Что создает", "Кто освобождает", "Функция освобождения"],
        [
            ["`buf_init_from_file`", "input bytes", "`main`", "`buf_free_owned`"],
            ["`pe_parse`", "`PeImage.sections`", "`main`", "`pe_free`"],
            ["`unwind_read_runtime_functions_ex`", "`RuntimeFunction*`", "`main`", "`free`"],
            ["`calloc` in `main`", "`UnwindSummary*`, `bool*`", "`main`", "`free`"],
            ["`heuristics_analyze`", "`HeuristicReport.details`", "`main`", "`heuristics_free`"],
            ["`dynamic_report_init`", "`DynamicReport.details`", "`main`", "`dynamic_report_free`"],
            ["`report_write_*`", "temporary `StrBuf`", "same function", "`sb_free`"],
        ],
        [38, 52, 38, 40],
    )
    h2("Почему проект не смешивает слои")
    p(
        "Если `pe.c` начал бы сразу считать suspicious score, его стало бы сложно тестировать: PE parser должен быть проверяемым сам по себе. "
        "Если `report.c` начал бы перепарсивать файл, JSON мог бы расходиться с console. Если `dynamic_win.c` был бы обязательным для сборки, "
        "static mode перестал бы быть cross-platform. Разделение ответственности - не украшение, а способ удержать проект в голове."
    )
    h2("Exit codes")
    table(
        ["Код", "Смысл"],
        [
            ["0", "Запрошенный анализ и outputs завершены."],
            ["1", "Ошибка input, анализа, dynamic session или записи output."],
            ["2", "Неверная командная строка."],
        ],
        [20, 140],
    )
    pagebreak()


def add_architecture_blocks_deep() -> None:
    h1("5. Подробный разбор блоков и взаимодействий")
    p(
        "Архитектуру этого проекта надо понимать не как список файлов, а как цепочку превращений. На вход приходит путь к PE-файлу. "
        "Дальше проект превращает путь в bytes, bytes в модель PE, модель PE в таблицу runtime functions, runtime functions в summaries unwind metadata, "
        "summaries в findings и score, а затем все это в отчеты для человека и инструментов. Каждый блок имеет узкую ответственность. "
        "Если блок начинает делать чужую работу, проект становится непонятным и его сложно повторить руками."
    )
    callout(
        "Главное правило архитектуры",
        "У каждого блока есть вопрос, на который он отвечает. `util` отвечает: как безопасно читать bytes и строить строки? "
        "`pe` отвечает: как устроен PE и где лежат секции? `unwind` отвечает: что записано в `.pdata` и `UNWIND_INFO`? "
        "`heuristics` отвечает: насколько эти наблюдения подозрительны? `report` отвечает: как показать результат наружу? "
        "`main` отвечает: в каком порядке все это вызвать и что освободить."
    )

    h2("Схема потока данных")
    code(
        """
CLI arguments
  -> main.c parses options
  -> util.c reads input file into Buf
  -> pe.c builds PeImage
  -> unwind.c reads RuntimeFunction[] from exception directory
  -> unwind.c parses each UNWIND_INFO into UnwindSummary[]
  -> heuristics.c builds HeuristicReport
  -> dynamic_win.c optionally adds runtime DynamicReport
  -> report.c serializes everything to console / JSON / CSV / HTML
  -> main.c frees every owned object and returns exit code
        """
    )
    p(
        "Эта схема важна потому, что данные идут в одну сторону. `report.c` не должен заново читать PE. `heuristics.c` не должен открывать файл. "
        "`pe.c` не должен решать, вредоносный файл или нет. Чем строже это разделение, тем легче тебе писать проект по частям: сначала bytes, потом PE, потом unwind, потом смысл."
    )

    h2("Карта блоков")
    table(
        ["Блок", "За что отвечает", "Что принимает", "Что отдает"],
        [
            [
                "`main.c`",
                "Оркестрация: аргументы, порядок вызовов, обработка ошибок, cleanup, exit codes.",
                "`argc/argv`, пути, flags пользователя.",
                "Запущенный pipeline, файлы отчетов, код завершения 0/1/2.",
            ],
            [
                "`util.h/c`",
                "Безопасные базовые операции: bytes, endian, строки, запись файлов, hash.",
                "Путь к файлу, `Buf`, offset/length, куски текста.",
                "`Buf`, числа `u16/u32/u64`, `StrBuf`, записанный файл, SHA-256.",
            ],
            [
                "`pe.h/c`",
                "Модель PE32+ AMD64: headers, sections, exception directory, RVA mapping.",
                "`Buf` с bytes файла.",
                "`PeImage`: секции, размеры, directories, structural counters.",
            ],
            [
                "`unwind.h/c`",
                "Чтение `.pdata` и расшифровка `UNWIND_INFO`.",
                "`Buf`, `PeImage`, exception directory, unwind RVA.",
                "`RuntimeFunction[]`, `UnwindSummary[]`, anomaly flags.",
            ],
            [
                "`heuristics.h/c`",
                "Интерпретация наблюдений: findings, score, confidence, verdict.",
                "`PeImage`, runtime functions, unwind summaries, optional dynamic report.",
                "`HeuristicReport` с evidence families, score и объяснениями.",
            ],
            [
                "`report.h/c`",
                "Внешний контракт: console, CSV, Ghidra CSV, JSON, HTML.",
                "Готовые модели: metadata, PE, unwind, heuristics, dynamic.",
                "Текстовые отчеты, которые можно читать и проверять.",
            ],
            [
                "`dynamic.h` / `dynamic_win.c`",
                "Опциональное runtime evidence через Windows Debug API.",
                "Путь к target, dynamic options, static context.",
                "`DynamicReport`: события VEH/VCH/UEF, runtime function table, hits.",
            ],
            [
                "`tests/`",
                "Доказательство контрактов каждого блока и всего CLI.",
                "Искусственные bytes, sample PE, CLI commands.",
                "Понимание, что поведение не сломалось после изменения.",
            ],
        ],
        [28, 55, 43, 43],
    )

    h2("Блок `main.c`: дирижер, а не рабочий цех")
    p(
        "`main.c` не должен знать, как именно устроен PE header или как экранировать JSON. Его работа - принять команду пользователя и провести данные по маршруту. "
        "Сначала он разбирает аргументы: где input, какие outputs нужны, включен ли strict ABI, нужен ли dynamic mode. Потом он вызывает `buf_init_from_file`, "
        "`pe_parse`, `unwind_read_runtime_functions_ex`, `unwind_parse`, `heuristics_analyze`, writers отчетов и cleanup."
    )
    p(
        "Почему это важно: если ты напишешь парсинг PE прямо в `main.c`, проект станет большой простыней. Ты не сможешь отдельно проверить PE parser, отдельно report writer, "
        "отдельно heuristics. `main.c` должен быть длинным только из-за обработки ошибок и освобождения ресурсов, а не из-за предметной логики."
    )
    bullets(
        [
            "Что `main.c` может делать: читать CLI options, вызывать модули, хранить pointers на созданные объекты, решать exit code.",
            "Что `main.c` не должен делать: вручную читать PE headers, считать score, экранировать JSON, декодировать unwind opcodes.",
            "Главный учебный вопрос: если любой шаг упал, какие уже созданные ресурсы надо освободить?",
        ]
    )

    h2("Блок `util`: фундамент безопасности")
    p(
        "`util` существует потому, что C сам не хранит размер массива рядом с pointer. Для парсера бинарного файла это опасно: один неправильный offset - и программа читает чужую память. "
        "`Buf` делает договор явным: есть pointer `data` и есть `size`, дальше читать можно только через функции, которые проверяют границы."
    )
    p(
        "`StrBuf` решает другую базовую проблему C: обычная строка `char*` не знает свою емкость. Отчеты могут быть маленькими или огромными, поэтому writer-ам нужна строка, "
        "которая растет через `realloc`, всегда оставляет место под `\\0` и запоминает ошибку выделения через `failed`."
    )
    table(
        ["Объект", "Кто создает", "Кто использует", "Зачем нужен"],
        [
            ["`Buf`", "`buf_init_from_file` или тест", "`pe.c`, `unwind.c`, tests", "Безопасно читать bytes по offset."],
            ["`StrBuf`", "report writers, helper functions", "`report.c`, иногда error builders", "Собирать текст неизвестной длины."],
            ["`owned_mem`", "`buf_init_from_file`", "`main.c` освобождает", "Хранить реальные bytes файла в heap."],
            ["SHA-256 hex", "`sha256_hex`", "metadata reports", "Идентифицировать точный input file."],
        ],
        [28, 43, 43, 55],
    )

    h2("Блок `pe`: карта PE-файла")
    p(
        "`pe.c` берет `Buf` и строит `PeImage`. Это не отчет и не подозрение. Это карта местности: какие секции есть, какие у них raw ranges, какие virtual ranges, "
        "где exception directory, какой SizeOfImage, какие structural проблемы уже видны. После этого другие блоки перестают гадать, где лежат bytes."
    )
    p(
        "Самая важная функция взаимодействия - `pe_rva_to_fileoff`. Unwind metadata хранит адреса как RVA, а файл читается по file offset. "
        "Когда `unwind.c` хочет прочитать `UNWIND_INFO` по RVA, он не должен сам искать секцию. Он спрашивает `pe.c`: переведи мне этот RVA в offset, если это вообще возможно."
    )
    code(
        """
unwind.c has:  unwind_info_rva = 0x1234
unwind.c asks: pe_rva_to_fileoff(pe, 0x1234, &off)
pe.c checks:   which section owns this RVA?
pe.c checks:   is this RVA backed by bytes in the file?
pe.c returns:  off, or false if reading would be unsafe
        """
    )
    p(
        "Почему `pe.c` не считает score: поврежденная секция - это наблюдение, а не verdict. Решение о подозрительности принимает `heuristics.c`, потому что только он видит все семейства признаков вместе."
    )

    h2("Блок `unwind`: предметная область проекта")
    p(
        "`unwind.c` делает две разные работы. Первая - прочитать `.pdata` как массив `RUNTIME_FUNCTION`. Вторая - по каждому `UnwindInfoAddress` прочитать `UNWIND_INFO`. "
        "Это надо держать отдельно в голове: `.pdata` говорит, какие функции описаны, а `UNWIND_INFO` говорит, как раскрутить stack frame и где могут быть handlers."
    )
    table(
        ["Часть", "Что читает", "Что получается", "Кому нужно дальше"],
        [
            ["`.pdata`", "Записи по 12 bytes: begin, end, unwind RVA.", "`RuntimeFunction[]`.", "`heuristics.c`, `report.c`, цикл parse в `main.c`."],
            ["`UNWIND_INFO` header", "Version, flags, prolog, count, frame byte.", "Базовый `UnwindSummary`.", "`heuristics.c`, HTML/JSON report."],
            ["Unwind codes", "2-byte slots переменной длины.", "Stack/register effects, anomaly flags.", "`heuristics.c`, человек в отчете."],
            ["Tail", "Handler RVA или chained runtime function.", "Handler/chain context.", "Placement checks, manual review."],
        ],
        [28, 48, 43, 50],
    )
    p(
        "Почему `unwind.c` не должен сам решать, подозрительно ли это: parser обязан быть максимально нейтральным. Он говорит 'запись обрезана', 'opcode неизвестен', "
        "'handler RVA такой-то'. А уже `heuristics.c` решает, насколько это важно с учетом секций, количества записей, других признаков и weakening rules."
    )

    h2("Блок `heuristics`: слой смысла")
    p(
        "`heuristics.c` - это место, где технические наблюдения превращаются в объяснимые признаки. Он получает уже готовые модели от `pe.c` и `unwind.c`. "
        "Он не читает bytes и не пишет JSON. Его работа - собрать counters, создать findings, посчитать score, confidence, evidence level и verdict."
    )
    bullets(
        [
            "Из `PeImage` он берет structural counters: section out-of-bounds, overlaps, exception directory problems.",
            "Из `RuntimeFunction[]` он берет invalid ranges, overlaps, duplicate begins, unsorted entries, unwind RVA problems.",
            "Из `UnwindSummary[]` он берет parse failures, anomaly flags, handlers, placement context.",
            "Из `DynamicReport` он может взять runtime signals, если dynamic mode был включен.",
            "На выходе он дает не приговор, а triage: насколько случай требует внимания и почему.",
        ]
    )
    p(
        "Здесь важно различать `score` и `confidence`. Score отвечает: сколько подозрительных признаков набралось по весам. Confidence отвечает: насколько надежна такая интерпретация. "
        "Один слабый признак может дать небольшой score и низкую confidence. Несколько независимых семейств evidence дают более сильную картину."
    )

    h2("Блок `report`: перевод внутренней модели наружу")
    p(
        "`report.c` не анализирует файл. Он берет готовые структуры и превращает их в форматы. Это похоже на переводчика: смысл уже создан, теперь его надо безопасно записать в console, CSV, JSON или HTML. "
        "Поэтому `report.c` обязан заниматься escaping, schema version, порядком полей, atomic write, но не обязан знать, почему конкретный finding получил такой score."
    )
    table(
        ["Формат", "Для чего нужен", "Что важно не сломать"],
        [
            ["Console", "Быстро понять результат после запуска.", "Короткий verdict, score, главные findings."],
            ["JSON", "Автотесты, интеграция, защита schema.", "Валидный JSON, стабильные имена полей, escaping."],
            ["CSV", "Таблицы, фильтрация, простая обработка.", "Кавычки, запятые, переносы строк."],
            ["Ghidra CSV", "Перенос результатов в reverse engineering workflow.", "RVA, comments/bookmarks, ожидаемые колонки importer-а."],
            ["HTML", "Человекочитаемый отчет.", "HTML escaping, CSP, понятная структура evidence."],
        ],
        [28, 68, 70],
    )

    h2("Блок `dynamic`: отдельная граница опасности")
    p(
        "Static pipeline просто читает bytes. Dynamic mode запускает target. Это принципиально другая граница риска. Поэтому dynamic mode отделен в `dynamic_win.c`, включается явно и является Windows-specific. "
        "Его результат не заменяет static analysis, а добавляет runtime evidence: были ли регистрации VEH/VCH/UEF, сработали ли handlers, вызывались ли runtime function table APIs."
    )
    p(
        "Взаимодействие такое: `main.c` после static analysis смотрит, просил ли пользователь dynamic mode. Если да - запускает collector, получает `DynamicReport`, передает его в `heuristics` или report layer. "
        "Если dynamic mode не удался, static result не исчезает. В отчете должна быть причина, почему runtime evidence неполное."
    )

    h2("Как блоки взаимодействуют на одном примере")
    numbered(
        [
            "Пользователь передает `sample.exe --json out.json`.",
            "`main.c` разбирает аргументы и вызывает `buf_init_from_file`.",
            "`util.c` возвращает `Buf`: bytes файла и размер.",
            "`pe.c` проверяет `MZ`, `PE`, AMD64, PE32+, читает секции и exception directory.",
            "`unwind.c` берет exception directory из `PeImage` и читает `RuntimeFunction[]`.",
            "`unwind.c` для каждой записи переводит unwind RVA через `pe_rva_to_fileoff` и читает `UNWIND_INFO`.",
            "`heuristics.c` смотрит на PE problems, runtime function problems, unwind anomalies и создает findings.",
            "`report.c` сериализует metadata, PE summary, unwind summaries и heuristic report в JSON.",
            "`main.c` вызывает cleanup: `heuristics_free`, `free`, `pe_free`, `buf_free_owned`.",
        ]
    )

    h2("Запрещенные смешивания ответственности")
    table(
        ["Если хочется сделать так", "Почему это плохо", "Как правильно"],
        [
            [
                "В `pe.c` сразу увеличивать suspicious score.",
                "PE parser станет невозможно тестировать как нейтральный parser.",
                "В `pe.c` только counters, score - в `heuristics.c`.",
            ],
            [
                "В `report.c` заново искать секции и RVA.",
                "Разные отчеты могут начать расходиться в логике.",
                "Report получает готовый `PeImage` и только выводит его.",
            ],
            [
                "В `unwind.c` открывать файл по path.",
                "Появится второй способ чтения input и риск разных ошибок.",
                "Все bytes идут через `Buf` из `util.c`.",
            ],
            [
                "В `main.c` руками формировать JSON.",
                "Оркестратор станет смесью CLI, анализа и сериализации.",
                "Вызвать `report_write_json`.",
            ],
            [
                "Всегда запускать dynamic mode.",
                "Это опасно для недоверенных файлов и ломает cross-platform static mode.",
                "Dynamic mode только по явному флагу и в изоляции.",
            ],
        ],
        [48, 60, 58],
    )

    h2("Что надо уметь объяснить на защите")
    bullets(
        [
            "Почему `Buf` стоит раньше PE parser и почему голый pointer недостаточен.",
            "Почему `PeImage` является картой адресов, а не результатом подозрительности.",
            "Почему `unwind.c` зависит от `pe_rva_to_fileoff`, а не переводит RVA сам.",
            "Почему `heuristics.c` отделен от parser-ов и от report writer-ов.",
            "Почему score - это triage, а не вероятность вредоносности.",
            "Почему dynamic mode optional и требует изоляции.",
            "Почему cleanup находится в `main.c`, хотя память создают разные модули.",
        ]
    )
    pagebreak()


def add_build_plan() -> None:
    h1("6. Сборка как часть обучения")
    p(
        "Сборка в C - это не кнопка 'магия'. Это отдельная модель проекта: какие `.c` входят в library, какой executable их использует, "
        "какие предупреждения включены, какие тесты запускаются. Начинать повторение проекта лучше с минимальной сборки, а не с полного `unwind.c`."
    )
    h2("Минимальный порядок")
    numbered(
        [
            "Создай `include/` и `src/`.",
            "Создай пустые `util.h`, `util.c`, `main.c`.",
            "Сделай `CMakeLists.txt` с library `ehua_core` и executable `eh_unwind_analyzer`.",
            "Включи C17.",
            "Добавь warnings: `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2`.",
            "Собери пустую программу с `--help`.",
            "Только потом добавляй PE parser.",
        ]
    )
    code(
        """
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

cmake --preset release
cmake --build --preset release
ctest --preset release
        """
    )
    h2("Как относиться к warnings")
    p(
        "В этом проекте warnings-as-errors включены не для жесткости ради жесткости. В C warning часто означает 'здесь компилятор увидел место, "
        "где человек мог ошибиться с типом, размером или format string'. Когда ты учишься, warning - это бесплатный преподаватель."
    )
    pagebreak()


def add_deep_file_manual() -> None:
    h1("7. Файл за файлом: что, зачем и как должно работать")
    p(
        "Этот раздел добавлен специально как обучающая версия маршрута. Здесь каждый файл рассматривается не как пункт 'создай и напиши', "
        "а как деталь системы. Для каждого блока сначала объясняется, зачем файл вообще нужен, какую проблему он закрывает, какие сущности должны появиться "
        "в заголовке `.h`, какая логика должна жить в `.c`, как данные проходят через модуль и почему следующий модуль сможет на него опереться."
    )
    callout(
        "Как пользоваться этой главой",
        "Не переписывай сразу полный файл из готового проекта. Сначала сделай минимальный скелет, собери проект, потом добавь одну функцию, опять собери, "
        "потом напиши маленькую проверку. Если ты можешь словами объяснить, какой input у функции, какой output, кто владеет памятью и что будет при ошибке, "
        "значит кусок действительно начал становиться твоим."
    )

    def guide(
        title: str,
        why: str,
        problem: str,
        header_items: list[str],
        source_items: list[str],
        flow: list[str],
        skeleton: str,
        checks: list[str],
        c_focus: list[str],
    ) -> None:
        h2(title)
        h3("Зачем этот файл существует")
        p(why)
        h3("Какую проблему он решает")
        p(problem)
        h3("Что должно быть в заголовке или конфигурации")
        bullets(header_items)
        h3("Что должно быть в реализации")
        bullets(source_items)
        h3("Как это будет работать в проекте")
        numbered(flow)
        h3("Минимальный скелет, с которого можно начать")
        code(skeleton, width=92)
        h3("Как понять, что блок готов")
        bullets(checks)
        h3("Что ты здесь учишь в C")
        bullets(c_focus)
        pagebreak()

    guide(
        "CMakeLists.txt и CMakePresets.json",
        "Эти файлы нужны не для анализа PE, а для управления всей стройкой проекта. В C один `.c` файл сам по себе не превращается в программу: "
        "его надо скомпилировать, связать с другими объектными файлами, дать include-пути, включить предупреждения и отдельно собрать тесты.",
        "Главная проблема новичка в C - непонятно, почему код написан, но программа не собирается. CMake фиксирует контракт сборки: какие исходники входят "
        "в ядро, какой исполняемый файл является CLI, какие тесты должны линковаться с ядром, какие предупреждения считаются ошибками.",
        [
            "`CMakeLists.txt` должен объявить проект, стандарт C17 и опции сборки.",
            "В нем должна быть библиотека ядра, например `ehua_core`, куда входят `util.c`, `pe.c`, `unwind.c`, `heuristics.c`, `report.c`, `app_info.c`.",
            "Отдельно должен быть executable `eh_unwind_analyzer`, который добавляет `src/main.c` и линкуется с `ehua_core`.",
            "`include/` должен быть публичным include-каталогом, потому что `.c` файлы и тесты подключают заголовки оттуда.",
            "`CMakePresets.json` нужен для повторяемых команд `debug`, `release`, `mingw` без ручного ввода длинных параметров.",
        ],
        [
            "Здесь нет `.c` реализации, но есть логика зависимостей: кто от кого зависит и что должно пересобираться при изменении файла.",
            "Добавь warnings: они будут твоим ранним преподавателем по типам, форматным строкам, неиспользуемым переменным и опасным преобразованиям.",
            "Добавь CTest, чтобы после каждого маленького шага можно было запускать не весь проект руками, а автоматические проверки.",
        ],
        [
            "Ты пишешь `src/util.c`, компилятор превращает его в объектный файл.",
            "CMake собирает несколько объектных файлов в библиотеку `ehua_core`.",
            "`main.c` вызывает функции из ядра, а linker соединяет вызовы с реализациями.",
            "Unit tests тоже линкуются с `ehua_core`, поэтому можно проверять `pe.c` или `unwind.c` без запуска полного CLI.",
        ],
        """
cmake_minimum_required(VERSION 3.20)
project(eh_unwind_analyzer C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(ehua_core
    src/util.c
    src/pe.c
    src/unwind.c
    src/heuristics.c
    src/report.c
    src/app_info.c
)
target_include_directories(ehua_core PUBLIC include)

add_executable(eh_unwind_analyzer src/main.c)
target_link_libraries(eh_unwind_analyzer PRIVATE ehua_core)

enable_testing()
        """,
        [
            "`cmake --preset debug` создает build-каталог без ручной настройки.",
            "`cmake --build --preset debug` собирает хотя бы пустой CLI.",
            "`ctest --preset debug` запускается, даже если сначала тестов мало.",
            "Если добавил новый `.c`, он явно появился в списке источников, а не потерялся.",
        ],
        [
            "Что такое translation unit: каждый `.c` компилируется отдельно.",
            "Что такое header include path.",
            "Что такое linker и почему прототип функции в `.h` не равен реализации.",
            "Почему warnings важны для C, где язык часто разрешает опасные вещи.",
        ],
    )

    guide(
        "include/util.h и src/util.c",
        "`util` - фундамент. Он не знает про PE, unwind и подозрительность. Его задача - дать безопасные кирпичи: прочитать файл в память, читать байты "
        "по смещению без выхода за границы, собирать растущую строку отчета, писать файл атомарно и считать hash входного файла.",
        "Все остальные модули работают с недоверенным бинарным файлом. Если каждый модуль сам будет писать `fread`, `off + len`, `realloc` и форматирование строк, "
        "ошибки размножатся. `util` собирает опасные низкоуровневые операции в одном месте и делает их проверяемыми.",
        [
            "`typedef struct Buf { const uint8_t* data; size_t size; } Buf;` - представление массива байтов с длиной.",
            "Прототипы `buf_init_from_file`, `buf_free_owned`, `buf_read`, `buf_read_u16`, `buf_read_u32`, `buf_read_u64`.",
            "`typedef struct StrBuf { char* s; size_t len; size_t cap; bool failed; } StrBuf;` - растущая строка для отчетов.",
            "Прототипы `sb_init`, `sb_appendn`, `sb_append`, `sb_appendf`, `sb_free`, `sb_ok`.",
            "Прототипы `file_write_atomic` и `sha256_hex`, потому что отчетам нужны надежная запись и идентичность входного файла.",
        ],
        [
            "`buf_read` должен сначала проверять аргументы, потом `off > size`, потом `len > size - off`, и только после этого делать `memcpy`.",
            "`buf_read_u32` должен читать 4 байта и вручную собирать little-endian число, а не делать опасное приведение указателя.",
            "`buf_init_from_file` открывает файл, узнает размер, выделяет память, читает bytes и возвращает владение вызывающему коду.",
            "`StrBuf` должен всегда оставлять строку с завершающим `\\0` и не терять старую строку при неудачном `realloc`.",
            "`file_write_atomic` пишет во временный файл, а затем заменяет итоговый, чтобы не оставить битый отчет при сбое.",
        ],
        [
            "`main.c` просит `buf_init_from_file` загрузить target.exe.",
            "`pe.c` получает `Buf` и читает из него заголовки через `buf_read_u32`, не касаясь `FILE*`.",
            "`report.c` создает `StrBuf`, добавляет JSON/HTML/CSV текст, проверяет `sb_ok` и пишет результат через `file_write_atomic`.",
            "В конце `main.c` вызывает `buf_free_owned`, потому что именно он владеет выделенной памятью входного файла.",
        ],
        """
typedef struct Buf {
    const uint8_t* data;
    size_t size;
} Buf;

bool buf_read(const Buf* b, size_t off, void* out, size_t len) {
    if (!b || !out) return false;
    if (off > b->size) return false;
    if (len > b->size - off) return false;
    memcpy(out, b->data + off, len);
    return true;
}

bool buf_read_u32(const Buf* b, size_t off, uint32_t* out) {
    uint8_t x[4];
    if (!out || !buf_read(b, off, x, sizeof x)) return false;
    *out = ((uint32_t)x[0]) |
           ((uint32_t)x[1] << 8) |
           ((uint32_t)x[2] << 16) |
           ((uint32_t)x[3] << 24);
    return true;
}
        """,
        [
            "Попытка прочитать 4 байта из 2-байтового буфера возвращает `false`, а не падает.",
            "Число bytes `01 00 00 00` читается как `1`.",
            "После нескольких `sb_append` строка имеет правильный `len` и завершающий ноль.",
            "Каждая функция ясно отвечает на вопрос: кто выделил память и кто ее освобождает.",
        ],
        [
            "Указатели и `NULL`.",
            "`size_t` против `uint32_t`.",
            "Проверка границ без integer overflow.",
            "`malloc`, `realloc`, `free` и владение памятью.",
            "Почему C-строка требует завершающий нулевой байт.",
        ],
    )

    guide(
        "include/pe.h и src/pe.c",
        "`pe` превращает сырой файл из набора bytes в понятную модель PE32+ AMD64: заголовки, секции, exception directory, размеры образа и карту RVA -> file offset. "
        "Без этого `unwind.c` не знает, где в файле лежит `.pdata`, а `heuristics.c` не знает, какие диапазоны подозрительны.",
        "PE использует разные координаты: file offset - место в файле, RVA - адрес относительно ImageBase в памяти, section raw range - bytes на диске, virtual range - область в памяти. "
        "Ошибка в этой карте ломает весь анализ. Поэтому `pe.c` не просто читает поля, а проверяет границы, пересечения и выравнивание.",
        [
            "Константы: `MZ`, `PE\\0\\0`, `IMAGE_FILE_MACHINE_AMD64`, `PE32+`, индекс exception directory.",
            "`PeSection`: имя секции, RVA, virtual size, raw pointer, raw size, characteristics.",
            "`PeImage`: image base, size of image, alignments, массив секций, exception directory RVA/size, счетчики проблем.",
            "Прототипы `pe_parse`, `pe_free`, `pe_find_section_for_rva`, `pe_rva_to_fileoff`.",
        ],
        [
            "`pe_parse` должен занулять `out`, читать DOS header, брать `e_lfanew`, проверять PE signature.",
            "Дальше читается COFF header: machine, число секций, размер optional header.",
            "Optional header PE32+ дает ImageBase, SectionAlignment, FileAlignment, SizeOfImage, DataDirectory.",
            "Цикл по section headers создает массив `PeSection`.",
            "После чтения надо посчитать structural counters: raw out-of-bounds, virtual out-of-bounds, overlaps, misalignment.",
            "`pe_rva_to_fileoff` должен возвращать `false`, если RVA попал в virtual tail, которого нет на диске.",
        ],
        [
            "`main.c` передает `Buf` в `pe_parse`.",
            "`pe_parse` заполняет `PeImage`, но не копирует весь файл: он только строит карту и метаданные.",
            "`unwind.c` спрашивает у `PeImage`, где exception directory и как перевести RVA unwind info в file offset.",
            "`heuristics.c` берет из `PeImage` счетчики поврежденных секций и использует их как признаки.",
            "В конце `main.c` вызывает `pe_free`, потому что `PeImage` владеет массивом секций.",
        ],
        """
typedef struct PeSection {
    char name[9];
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_ptr;
    uint32_t raw_size;
    uint32_t characteristics;
} PeSection;

bool pe_rva_to_fileoff(const PeImage* pe, uint32_t rva, size_t* out) {
    const PeSection* s = pe_find_section_for_rva(pe, rva);
    if (!s || !out) return false;
    uint32_t delta = rva - s->virtual_address;
    if (delta >= s->raw_size) return false;
    *out = (size_t)s->raw_ptr + delta;
    return true;
}
        """,
        [
            "Не-PE файл отвергается понятной ошибкой.",
            "PE32/x86 отвергается, потому что проект анализирует PE32+ AMD64 unwind.",
            "RVA внутри секции переводится в file offset.",
            "RVA в виртуальном хвосте секции не считается доступным байтом файла.",
            "Секция, чей raw range выходит за размер файла, увеличивает счетчик проблемы.",
        ],
        [
            "`struct` как модель предметной области.",
            "Чтение бинарного формата по фиксированным offset.",
            "Разница между `uint32_t` RVA и `size_t` file offset.",
            "Циклы по массиву структур.",
            "Ошибки формата как нормальный результат функции, а не авария.",
        ],
    )

    guide(
        "include/unwind.h и src/unwind.c",
        "`unwind` читает именно ту часть Windows x64, ради которой создан проект: `.pdata` как массив `RUNTIME_FUNCTION` и `UNWIND_INFO` как описание пролога, stack frame, saved registers, handlers и chains.",
        "`.pdata` не хранит красивые структуры C. Это компактные bytes с битовыми полями, переменной длиной записей и хвостами, которые появляются только при определенных flags. "
        "Если читать это без строгого алгоритма, легко перепутать opcode, выйти за границы или принять мусор за handler.",
        [
            "`RuntimeFunction`: `begin_rva`, `end_rva`, `unwind_info_rva`.",
            "`UnwindSummary`: version, flags, prolog size, count of codes, frame register, stack allocation, saved registers, handler RVA, anomalies, parse error.",
            "`UnwindParseOpts`: режимы strict ABI, follow chain, ограничения глубины.",
            "Константы flags: EHANDLER, UHANDLER, CHAININFO.",
            "Константы anomalies: truncated, unsupported version, bad opcode, bad operand, alignment, handler out-of-bounds.",
        ],
        [
            "`unwind_read_runtime_functions_ex` берет exception directory из `PeImage`, переводит RVA в file offset и читает записи по 12 байт.",
            "`unwind_parse` читает первый byte как version+flags, затем prolog, count, frame byte.",
            "`slots_for_code` должен знать, сколько 2-байтовых slots занимает каждый UWOP.",
            "Главный цикл идет `for (i = 0; i < count;)`, потому что шаг зависит от opcode.",
            "После slots надо учитывать padding до четного количества slots, затем optional handler tail или chain tail.",
            "Follow-chain включается осторожно и с ограничением глубины, чтобы поврежденный файл не загнал анализатор в бесконечность.",
        ],
        [
            "`main.c` получает массив `RuntimeFunction`.",
            "Для каждой записи `main.c` вызывает `unwind_parse` и кладет результат в массив `UnwindSummary`.",
            "`heuristics.c` потом сравнивает begin/end/unwind RVA и смотрит anomalies из каждого summary.",
            "`report.c` показывает человеку не сырые bytes, а расшифровку: flags, handler, ошибки, stack effect.",
        ],
        """
bool unwind_parse(const Buf* b, const PeImage* pe,
                  uint32_t unwind_rva, UnwindSummary* out) {
    size_t off = 0;
    uint8_t header[4];
    if (!pe_rva_to_fileoff(pe, unwind_rva, &off)) return false;
    if (!buf_read(b, off, header, sizeof header)) return false;

    out->version = header[0] & 0x7u;
    out->flags = header[0] >> 3;
    out->prolog_size = header[1];
    out->code_count = header[2];
    out->frame_register = header[3] & 0x0fu;
    out->frame_offset = header[3] >> 4;

    for (uint32_t i = 0; i < out->code_count;) {
        /* read slot, decode op, validate operand slots, then i += slots */
    }
    return true;
}
        """,
        [
            "Запись `.pdata` размером не кратным 12 отмечается как проблема.",
            "`UNWIND_INFO` с unsupported version не парсится как обычная версия.",
            "Opcode, которому нужны дополнительные slots, проверяет наличие этих slots.",
            "EHANDLER/UHANDLER читают handler RVA из хвоста только после правильного выравнивания.",
            "Ошибку парсинга видно в `UnwindSummary`, а не только в общем сообщении CLI.",
        ],
        [
            "Битовые поля: mask, shift, flags.",
            "`switch` по opcode.",
            "Цикл с переменным шагом.",
            "Байтовый формат переменной длины.",
            "Защитное программирование при недоверенном input.",
        ],
    )

    guide(
        "include/heuristics.h и src/heuristics.c",
        "`heuristics` превращает технические наблюдения в человеческий вывод: findings, severity, score, suspicion, confidence, evidence level и verdict. "
        "Это слой интерпретации, а не слой чтения файла.",
        "PE parser и unwind parser говорят 'видел overlap', 'handler лежит в writable section', 'unwind info не читается'. Для защиты и отчета этого мало: "
        "нужно сгруппировать признаки, объяснить серьезность, не завысить вывод по одному слабому сигналу и показать, где требуется ручная проверка.",
        [
            "`HeuristicFinding`: code, family, severity, message, representative RVA, affected count.",
            "`HeuristicMitigation`: причина, почему confidence снижен.",
            "`HeuristicReport`: score 0..100, suspicion, confidence, evidence level, verdict, arrays findings/mitigations.",
            "Константы максимального числа findings и mitigation entries.",
            "Прототипы `heuristics_analyze`, `heuristics_free`, функции получения текстовых имен severity/evidence.",
        ],
        [
            "Сначала собрать counters из `PeImage`: section oob, overlaps, exception directory oob.",
            "Потом пройти массив `RuntimeFunction`: invalid ranges, begin/end outside image, unwind RVA outside file/image, unsorted, overlaps, duplicates.",
            "Потом посмотреть `UnwindSummary`: parse errors, anomalies, handler placement, writable/executable metadata.",
            "Reuse одинаковых unwind RVA удобно считать маленькой hash map с open addressing.",
            "После counters добавить findings с понятными codes и messages.",
            "Score считать по весам, confidence - отдельно по силе и разнообразию evidence, затем применить weakening rules.",
        ],
        [
            "`heuristics_analyze` получает уже готовые `PeImage`, `RuntimeFunction[]`, `UnwindSummary[]`.",
            "Он не читает файл сам: его вход - результаты предыдущих слоев.",
            "Он создает `HeuristicReport`, который потом используют console/JSON/HTML writers.",
            "Если finding один и слабый, confidence должен снижаться: проект не должен притворяться статистической моделью.",
        ],
        """
typedef struct HeuristicFinding {
    const char* code;
    const char* family;
    const char* severity;
    uint32_t representative_rva;
    size_t affected_count;
    char message[256];
} HeuristicFinding;

static void add_finding(HeuristicReport* r,
                        const char* code,
                        const char* family,
                        const char* severity,
                        uint32_t rva,
                        size_t count,
                        const char* message) {
    if (r->finding_count >= HEURISTICS_MAX_FINDINGS) return;
    /* fill next slot, then increment finding_count */
}
        """,
        [
            "Benign sample с нормальной таблицей получает score 0 или низкий score без high verdict.",
            "Два сильных независимых признака дают strong evidence.",
            "Один placement-only признак не превращается автоматически в уверенное обвинение.",
            "Все findings имеют code, severity и объяснимый affected count.",
            "`heuristics_free` освобождает все, что было выделено внутри report.",
        ],
        [
            "Массивы структур фиксированного размера.",
            "`qsort` и компараторы.",
            "Простая hash map.",
            "Разделение score и confidence.",
            "Почему инженерная эвристика не равна вероятности.",
        ],
    )

    guide(
        "include/report.h и src/report.c",
        "`report` отвечает за внешний контракт проекта. Пользователь и защита видят не внутренние структуры C, а console summary, CSV, Ghidra CSV, JSON и HTML. "
        "Этот слой должен быть скучным и надежным: правильно экранировать текст, не ломать формат и писать файлы атомарно.",
        "Даже хороший анализ бесполезен, если JSON невалиден, CSV ломается на запятой, HTML допускает неэкранированный текст, а файл отчета остается наполовину записанным. "
        "`report.c` отделяет вычисление evidence от представления evidence.",
        [
            "`ReportMetadata`: версия приложения, версия schema, путь входного файла, размер, sha256, время.",
            "`AssessmentSummary`: verdict, score, suspicion, confidence, requires manual review.",
            "Прототипы `report_write_console`, `report_write_json`, `report_write_csv`, `report_write_ghidra_csv`, `report_write_html`.",
            "Функции escaping: JSON string, CSV cell, HTML text.",
        ],
        [
            "Каждый writer должен сначала проверить аргументы.",
            "Текст собирается в `StrBuf`, а не печатается кусками прямо в файл.",
            "JSON writer обязан следить за запятыми между элементами массива.",
            "CSV writer обязан заключать поле в кавычки, если внутри есть запятая, кавычка или newline.",
            "HTML writer обязан экранировать пользовательские данные и добавлять CSP.",
            "Запись на диск идет через `file_write_atomic`.",
        ],
        [
            "`main.c` собирает metadata, `PeImage`, unwind summaries и heuristic report.",
            "В зависимости от CLI options он вызывает один или несколько report writers.",
            "Writer не пересчитывает score и не перечитывает PE: он только сериализует готовую модель.",
            "Python tests читают JSON/CSV/HTML и проверяют, что внешний контракт не изменился случайно.",
        ],
        """
bool report_write_json(const char* path,
                       const ReportMetadata* meta,
                       const PeImage* pe,
                       const HeuristicReport* hr) {
    StrBuf sb;
    sb_init(&sb);
    sb_append(&sb, "{\\n");
    sb_appendf(&sb, "  \\"schema_version\\": \\"%s\\",\\n", meta->schema_version);
    sb_appendf(&sb, "  \\"score\\": %u,\\n", hr->score);
    sb_append(&sb, "  \\"findings\\": [\\n");
    /* append escaped findings */
    sb_append(&sb, "  ]\\n}\\n");
    if (!sb_ok(&sb)) { sb_free(&sb); return false; }
    bool ok = file_write_atomic(path, sb.s, sb.len);
    sb_free(&sb);
    return ok;
}
        """,
        [
            "JSON открывается парсером без ошибок.",
            "Строка с кавычкой в message корректно экранируется.",
            "CSV не ломает колонку, если в тексте есть запятая.",
            "HTML показывает кириллицу и специальные символы без поломанной верстки.",
            "При ошибке записи функция возвращает `false`, а `main.c` может вернуть exit code 1.",
        ],
        [
            "Сериализация данных.",
            "Форматные строки и `printf`-семейство.",
            "Экранирование специальных символов.",
            "Работа с динамической строкой.",
            "Контракт между программой и внешними тестами.",
        ],
    )

    guide(
        "include/dynamic.h и src/dynamic_win.c",
        "`dynamic` - необязательный Windows-слой, который не просто смотрит на файл, а запускает target под debugger и собирает runtime evidence: VEH/VCH/UEF, RtlAddFunctionTable, "
        "срабатывания handler и другие события исключений.",
        "Статический анализ показывает, что в файле есть подозрительная структура. Динамический режим может дать дополнительное основание: код действительно регистрирует runtime function table "
        "или обработчик исключений срабатывает во время выполнения. Но запускать чужой код опасно, поэтому этот режим должен быть изолированным и отделенным от обычного static pipeline.",
        [
            "`DynamicOptions`: путь к target, аргументы, timeout, flags включения наблюдений.",
            "`DynamicEvent`: тип события, адрес/RVA, текстовое описание.",
            "`DynamicReport`: массив событий, counters, флаг completed, error message.",
            "Прототипы `dynamic_report_init`, `dynamic_report_free`, `dynamic_collect`.",
            "В заголовке должен быть portable контракт, а Windows API детали остаются в `dynamic_win.c`.",
        ],
        [
            "На не-Windows сборке должен быть stub, который честно сообщает, что dynamic mode недоступен.",
            "На Windows `CreateProcess` запускает процесс как debuggee.",
            "Debug loop читает события, ставит breakpoints, восстанавливает оригинальный byte, откатывает RIP и ставит trap flag.",
            "INT3 event добавляет `DynamicEvent`; single-step переустанавливает breakpoint.",
            "Timeout и cleanup обязательны: debuggee нельзя оставлять зависшим.",
        ],
        [
            "`main.c` запускает dynamic mode только если пользователь явно попросил соответствующую опцию.",
            "Dynamic report добавляется к итоговому report рядом со static evidence.",
            "Финальная confidence может увеличиться, если dynamic evidence коррелирует со static findings.",
            "Если dynamic mode не завершился, static report все равно остается полезным, но в отчете будет причина неполноты.",
        ],
        """
bool dynamic_collect(const DynamicOptions* opt, DynamicReport* out) {
#ifndef _WIN32
    dynamic_report_add_error(out, "dynamic mode is available only on Windows");
    return false;
#else
    /* create debuggee, set breakpoints, process debug events, cleanup */
    return true;
#endif
}
        """,
        [
            "Обычный static анализ собирается и работает без Windows debugger.",
            "На неподдерживаемой платформе dynamic mode дает понятную ошибку, а не undefined behavior.",
            "При timeout процесс завершается или отсоединяется предсказуемо.",
            "События dynamic report сериализуются в JSON/HTML и не смешиваются с static counters.",
        ],
        [
            "Условная компиляция `#ifdef _WIN32`.",
            "Разделение portable API и platform-specific реализации.",
            "Работа с ресурсами ОС.",
            "Состояние debug loop.",
            "Почему небезопасный runtime режим должен быть отдельным от парсинга файла.",
        ],
    )

    guide(
        "include/app_info.h и src/app_info.c",
        "`app_info` кажется маленьким, но он нужен для воспроизводимости. Отчет должен говорить, какой версией анализатора и какой версией схемы он создан. "
        "Иначе через месяц невозможно понять, почему старый JSON отличается от нового.",
        "Версия приложения, schema version и build metadata часто размазываются по коду строковыми литералами. Тогда один writer пишет одно, CLI `--version` другое, а тесты третье. "
        "`app_info` делает единый источник правды.",
        [
            "Константы или функции: `app_name`, `app_version`, `report_schema_version`, `build_compiler`.",
            "Прототип функции, которая заполняет `ReportMetadata` базовыми версиями.",
            "Никакой логики PE или эвристик в этом заголовке быть не должно.",
        ],
        [
            "Вернуть строковые константы через функции или экспортировать `const char*`.",
            "При наличии макросов сборки аккуратно подставить compiler/build info.",
            "`main.c` и `report.c` должны брать версии отсюда, а не хранить свои копии.",
        ],
        [
            "Пользователь вызывает `--version`, и `main.c` печатает данные из `app_info`.",
            "JSON writer берет `schema_version` из той же точки.",
            "Release tests проверяют, что версия и schema согласованы.",
        ],
        """
const char* app_name(void) {
    return "EH/Unwind Analyzer";
}

const char* app_version(void) {
    return "1.0.0";
}

const char* report_schema_version(void) {
    return "1.1.0";
}
        """,
        [
            "`--version` и JSON metadata показывают одну и ту же версию.",
            "При смене schema обновляется одно место и тесты видят новое значение.",
            "В модуле нет зависимостей на PE/unwind/heuristics.",
        ],
        [
            "Строковые литералы и время их жизни.",
            "Глобальные константы против функций доступа.",
            "Минимальный модуль без владения памятью.",
            "Зачем проекту единый источник метаданных.",
        ],
    )

    guide(
        "src/main.c",
        "`main.c` - дирижер, а не место для всей логики. Он читает аргументы командной строки, запускает этапы в правильном порядке, обрабатывает ошибки, вызывает writers и освобождает все ресурсы.",
        "Новичку часто хочется писать весь проект в `main`, потому что так сначала проще. Но тогда невозможно отдельно тестировать PE parser, отдельно unwind parser и отдельно reports. "
        "`main.c` должен соединять готовые модули, а не становиться вторым проектом внутри проекта.",
        [
            "У `main.c` обычно нет своего `.h`, потому что он не предоставляет API другим модулям.",
            "В начале должны быть include нужных публичных заголовков: `util.h`, `pe.h`, `unwind.h`, `heuristics.h`, `report.h`, `dynamic.h`, `app_info.h`.",
            "Полезно иметь локальную структуру `CliOptions`, но она остается `static` внутри `main.c`.",
        ],
        [
            "Функция `parse_args` разбирает input path, output paths, flags `--json`, `--html`, `--strict-abi`, `--dynamic`, `--help`, `--version`.",
            "Главный pipeline: read file -> parse PE -> read runtime functions -> parse unwind for each -> heuristics -> optional dynamic -> reports.",
            "Каждый failure path должен выставлять сообщение, переходить к cleanup и возвращать правильный exit code.",
            "Cleanup должен освобождать `Buf`, `PeImage`, arrays runtime/unwind, heuristic report, dynamic report независимо от того, где случилась ошибка.",
        ],
        [
            "Пользователь запускает CLI с путем к PE.",
            "`main.c` проверяет аргументы и загружает файл.",
            "Дальше он по одному вызывает независимые модули и передает результаты вперед.",
            "Если выбран JSON/HTML/CSV, он вызывает соответствующие writers.",
            "Перед выходом он освобождает все ресурсы и возвращает 0, 1 или 2.",
        ],
        """
int main(int argc, char** argv) {
    CliOptions opt;
    Buf input = {0};
    uint8_t* owned = NULL;
    PeImage pe = {0};
    RuntimeFunction* rf = NULL;
    UnwindSummary* summaries = NULL;
    HeuristicReport hr = {0};
    int exit_code = 1;

    if (!parse_args(argc, argv, &opt)) return 2;
    if (!buf_init_from_file(opt.input_path, &input, &owned)) goto cleanup;
    if (!pe_parse(&input, &pe, opt.err, sizeof opt.err)) goto cleanup;
    /* read runtime functions, parse unwind, analyze, write reports */
    exit_code = 0;

cleanup:
    heuristics_free(&hr);
    free(summaries);
    free(rf);
    pe_free(&pe);
    buf_free_owned(owned);
    return exit_code;
}
        """,
        [
            "`--help` работает без input file.",
            "Неверные аргументы дают exit code 2.",
            "Ошибки анализа или записи дают exit code 1.",
            "Нормальный анализ и успешная запись reports дают exit code 0.",
            "Sanitizer или внимательная проверка показывает, что на failure path память не течет.",
        ],
        [
            "`argc/argv`.",
            "Локальные структуры состояния.",
            "`goto cleanup` как честный способ не дублировать освобождение ресурсов в C.",
            "Разница между ошибкой пользователя и ошибкой анализа.",
            "Почему orchestration отличается от бизнес-логики.",
        ],
    )

    guide(
        "tests/unit и Python CLI tests",
        "Тесты в этом проекте - не только защита от регрессий, но и учебные лабораторные. Они позволяют проверить маленький кусок без ожидания, пока весь анализатор станет полным.",
        "Когда ты учишь C, самая тяжелая ошибка - написать много кода и не понимать, где он сломался. Unit tests уменьшают зону поиска: `buf_read` проверяется на 8 bytes, "
        "`unwind_parse` - на искусственном массиве bytes, report JSON - на маленькой модели данных.",
        [
            "`tests/unit/unit_core_edges.c`: границы `Buf`, PE edge cases, маленькие искусственные inputs.",
            "`tests/unit/unit_unwind.c`: байты `UNWIND_INFO`, opcodes, truncated records.",
            "`tests/unit/unit_heuristics.c`: counters -> findings -> score/confidence.",
            "`tests/unit/unit_report_json.c` и HTML/CSV tests: внешний контракт writers.",
            "Python tests проверяют CLI как черный ящик: exit codes, schema, файлы отчетов.",
        ],
        [
            "Для C unit tests удобно писать маленькие helper asserts и явно создавать byte arrays.",
            "Каждый test должен проверять одну идею, а не весь проект сразу.",
            "Python tests запускают собранный executable и читают output files стандартными парсерами.",
            "Regression samples нужны позже, когда базовые функции уже работают.",
        ],
        [
            "Ты написал `buf_read` - сразу создал тест на нормальное чтение и выход за границы.",
            "Ты написал один unwind opcode - сразу создал bytes, где этот opcode встречается.",
            "Ты добавил finding - сразу проверил, что JSON содержит его code и severity.",
            "Перед переходом к следующему модулю запускаешь CTest.",
        ],
        """
static void test_buf_read_bounds(void) {
    const uint8_t bytes[] = {1, 2, 3};
    Buf b = { bytes, sizeof bytes };
    uint32_t value = 0;

    assert(!buf_read_u32(&b, 0, &value));
    assert(buf_read(&b, 1, &value, 2));
}

int main(void) {
    test_buf_read_bounds();
    return 0;
}
        """,
        [
            "Один test падает - ты понимаешь, какой контракт нарушен.",
            "После каждого учебного шага есть команда сборки и теста.",
            "Тесты не требуют настоящего malware, потому что многие форматы можно собрать из bytes руками.",
            "CLI tests проверяют то, что увидит пользователь, а unit tests - внутренние детали.",
        ],
        [
            "`assert` и минимальные test runners.",
            "Искусственные byte arrays.",
            "Разница между white-box и black-box тестом.",
            "Почему тест - это письменное объяснение ожидаемого поведения.",
        ],
    )


def add_incremental_versions() -> None:
    h1("8. Как писать проект версиями, чтобы он всегда оставался живым")
    p(
        "Большой проект нельзя учить как один гигантский файл. Его лучше собирать версиями. Каждая версия должна компилироваться, запускаться и чему-то учить. "
        "Так ты не тонешь в синтаксисе C и одновременно видишь, как из маленьких функций рождается полный анализатор."
    )
    versions = [
        [
            "0",
            "Пустой CLI",
            "`CMakeLists.txt`, `main.c`, `app_info`",
            "Программа отвечает на `--help` и `--version`.",
            "Ты учишь, что такое сборка, executable, exit code и аргументы командной строки.",
        ],
        [
            "1",
            "Безопасные bytes",
            "`util.h/c`: `Buf`, `buf_read`, little-endian helpers",
            "Можно читать искусственный byte array и файл без выхода за границы.",
            "Ты учишь указатели, размеры, `memcpy`, integer overflow.",
        ],
        [
            "2",
            "Растущие строки",
            "`StrBuf`, `sb_append`, `sb_appendf`",
            "Можно собрать строку отчета в памяти.",
            "Ты учишь heap, capacity, `realloc`, C-строку с `\\0`.",
        ],
        [
            "3",
            "Минимальный PE parser",
            "`pe_parse`: MZ, PE signature, AMD64, PE32+",
            "Программа отличает нужный PE32+ AMD64 от неподходящего файла.",
            "Ты учишь binary format, offsets, magic constants.",
        ],
        [
            "4",
            "Секции и RVA",
            "`PeSection`, section loop, `pe_rva_to_fileoff`",
            "Можно объяснить, где RVA находится в файле.",
            "Ты учишь массив структур и разницу virtual/raw координат.",
        ],
        [
            "5",
            ".pdata",
            "`RuntimeFunction[]` из exception directory",
            "Можно вывести begin/end/unwind RVA каждой функции.",
            "Ты учишь чтение таблиц фиксированной записи по 12 bytes.",
        ],
        [
            "6",
            "UNWIND_INFO header и slots",
            "`unwind_parse`, flags, CountOfCodes, opcodes",
            "Можно расшифровать один unwind record и увидеть anomalies.",
            "Ты учишь bit masks, switch, переменный размер записи.",
        ],
        [
            "7",
            "Эвристики",
            "`heuristics_analyze`, findings, score, confidence",
            "Технические counters превращаются в объяснимый verdict.",
            "Ты учишь агрегацию, сортировку, hash map, rule-based decision.",
        ],
        [
            "8",
            "Отчеты",
            "`report.c`: console, JSON, CSV, HTML",
            "Результат анализа можно сохранить и проверить внешними инструментами.",
            "Ты учишь serialization, escaping, внешний контракт.",
        ],
        [
            "9",
            "Полный main pipeline",
            "`main.c`: args, orchestration, cleanup",
            "CLI соединяет все модули и корректно освобождает ресурсы.",
            "Ты учишь lifecycle ресурсов и failure paths.",
        ],
        [
            "10",
            "Dynamic mode",
            "`dynamic_win.c` и интеграция report",
            "Runtime evidence добавляется как отдельный слой, не ломая static analysis.",
            "Ты учишь conditional compilation, Windows API и почему запуск чужого кода отделен.",
        ],
    ]
    table(["Версия", "Цель", "Что писать", "Что должно работать", "Что ты учишь"], versions, [12, 27, 42, 45, 48])
    h2("Почему такой порядок лучше для новичка")
    bullets(
        [
            "Сначала ты учишь безопасно обращаться с bytes, потому что PE и unwind - это просто bytes с правилами.",
            "PE parser идет раньше unwind parser, потому что unwind RVA невозможно читать без карты секций.",
            "Heuristics идут после парсеров, потому что они не должны сами лазить в файл.",
            "Reports идут после модели результата, потому что сериализация должна выводить готовые данные, а не вычислять их.",
            "`main.c` удобнее доводить в конце: когда модули уже умеют работать отдельно, orchestration становится понятной.",
            "Dynamic mode последний, потому что он сложнее, Windows-specific и потенциально опаснее обычного чтения файла.",
        ]
    )
    h2("Формула одного учебного шага")
    numbered(
        [
            "Сформулируй один маленький контракт: например, `buf_read` возвращает `false`, если чтение выходит за конец.",
            "Запиши прототип в `.h`, чтобы стало ясно, какие input и output у функции.",
            "Напиши минимальную реализацию в `.c`.",
            "Собери проект. Исправь warnings до перехода дальше.",
            "Напиши один тест или ручную команду, которая доказывает контракт.",
            "Объясни себе вслух: кто владеет памятью, какие границы проверены, какой следующий модуль использует результат.",
        ]
    )
    callout(
        "Главная мысль",
        "Ты не обязан понимать весь EH/Unwind Analyzer в первый день. Но каждая версия должна быть маленькой, рабочей и объяснимой. "
        "Если версия 4 понятна, то версия 5 - это не новый монстр, а просто таблица `.pdata`, которая пользуется уже понятной картой RVA."
    )
    pagebreak()


STEP_TEACHING_NOTES = {
    "util.h / util.c": [
        (
            "`Buf` нужен как самый первый договор проекта: любые bytes всегда идут вместе с длиной. Один `uint8_t*` в C не знает, сколько памяти за ним лежит.",
            "Он решает проблему слепого указателя. Без `size` любая функция может случайно читать дальше конца файла, а для парсера недоверенного PE это критическая ошибка.",
            "`data` указывает на первый байт, `size` говорит, сколько байтов разрешено читать. Сам `Buf` памятью не владеет: он только описывает область. Владение остается у того, кто выделил массив.",
            "В `util.h` подключи `<stdint.h>` и `<stddef.h>`, объяви `typedef struct Buf { const uint8_t* data; size_t size; } Buf;`. Пока никаких PE-полей, только универсальная обертка над bytes.",
            "Создай маленький массив `{1,2,3}` и `Buf b = {bytes, 3}`. Ты должен уметь словами сказать: pointer указывает на byte 1, читать можно ровно 3 bytes.",
        ),
        (
            "`buf_read` - сторож всех последующих парсеров. Через него `pe.c` и `unwind.c` будут брать bytes из файла, не рискуя выйти за границу.",
            "Он решает две проблемы: неверные аргументы (`NULL`) и опасные диапазоны (`off + len` может выйти за конец или переполниться). Поэтому проверка пишется через `len > size - off`.",
            "Функция сначала доказывает, что чтение безопасно, и только потом делает `memcpy`. Если доказать безопасность нельзя, она возвращает `false`, а вызывающий код обязан остановиться или записать ошибку.",
            "В `util.c` напиши `bool buf_read(const Buf* b, size_t off, void* out, size_t len)`. Внутри: `if (!b || !out)`, затем `if (off > b->size)`, затем `if (len > b->size - off)`, затем `memcpy(out, b->data + off, len)`.",
            "Проверь три случая: чтение внутри буфера возвращает `true`; чтение с `off == size` и `len == 0` допустимо; чтение `len == 1` при `off == size` возвращает `false`.",
        ),
        (
            "`le16`, `le32`, `le64` нужны, потому что файл хранит числа как последовательность bytes, а не как готовые переменные C.",
            "Это решает проблему неявного доверия CPU и выравниванию. Если просто привести `uint8_t*` к `uint32_t*`, можно получить undefined behavior или зависимость от платформы.",
            "Little-endian означает: младший байт числа лежит первым. Число `0x12345678` в файле будет bytes `78 56 34 12`. Функция собирает число сдвигами и `|`.",
            "Напиши `static uint16_t le16(const uint8_t x[2])`, `static uint32_t le32(const uint8_t x[4])`, `static uint64_t le64(const uint8_t x[8])`. Делай cast перед shift: `((uint32_t)x[3] << 24)`.",
            "Проверь на bytes `{0x78,0x56,0x34,0x12}`: `le32` должен вернуть `0x12345678`. Если ты можешь нарисовать это на бумаге, шаг понят.",
        ),
        (
            "`buf_read_u16/u32/u64` соединяют безопасное чтение диапазона и перевод little-endian bytes в число.",
            "Это решает проблему повторения. PE parser будет десятки раз читать `uint16_t` и `uint32_t`; если каждый раз писать `buf_read` и `le32` вручную, легко ошибиться.",
            "Функция создает временный массив bytes на stack, вызывает `buf_read`, а потом передает bytes в `le16/le32/le64`. Наружу выходит уже нормальное число C.",
            "Напиши три функции с одинаковой формой: проверить `out`, объявить `uint8_t tmp[N]`, вызвать `buf_read(b, off, tmp, sizeof tmp)`, если не вышло - `false`, иначе `*out = leN(tmp)`.",
            "Проверь, что `buf_read_u32` не меняет `*out`, если чтение не удалось, либо хотя бы возвращает `false` и вызывающий код не использует старое значение.",
        ),
        (
            "Чтение файла нужно, чтобы превратить путь от пользователя в `Buf`, с которым уже могут работать PE parser и остальные модули.",
            "Это решает проблему границы между операционной системой и анализатором. Дальше весь проект хочет работать с bytes в памяти, а не таскать везде `FILE*`.",
            "`fopen` открывает файл, `fseek/ftell` узнают размер, `malloc` выделяет массив, `fread` заполняет его, затем файл закрывается. Важно закрывать файл и при успехе, и при ошибке.",
            "Напиши `bool buf_init_from_file(const char* path, Buf* out, uint8_t** owned_mem)`. `out->data` должен указывать на выделенную память, `out->size` на размер, а `*owned_mem` вернуть владельцу для будущего `free`.",
            "Проверь пустой файл: размер 0, функция не падает, `data` можно сделать не `NULL` через выделение хотя бы 1 byte или аккуратно обработать нулевой размер по единому договору проекта.",
        ),
        (
            "`StrBuf` нужен, потому что отчеты неизвестной длины: JSON, HTML и CSV растут по мере добавления секций, функций и findings.",
            "Он решает проблему обычных C-строк: у `char*` нет длины и емкости. Без `len/cap` легко перезаписать память или забыть место под завершающий `\\0`.",
            "`s` указывает на выделенную строку, `len` - сколько полезных символов уже записано, `cap` - сколько всего выделено, `failed` - флаг, что дальнейшие append больше нельзя считать надежными.",
            "В `util.h` объяви `typedef struct StrBuf { char* s; size_t len; size_t cap; bool failed; } StrBuf;` и функции `sb_init`, `sb_free`, `sb_appendn`, `sb_append`, `sb_appendf`, `sb_ok`.",
            "После `sb_init` строка должна быть валидной C-строкой: `s[0] == '\\0'`, `len == 0`, `cap >= 1`, `failed == false`.",
        ),
        (
            "`sb_reserve` - механизм роста памяти для `StrBuf`. Все append зависят от него.",
            "Он решает проблему нехватки места и переполнения размера. Если нужно `len + n + 1`, надо заранее проверить, что сложение не перешло через `SIZE_MAX`.",
            "Функция сравнивает нужный размер с `cap`. Если места хватает - ничего не делает. Если не хватает - увеличивает емкость, обычно удваивая, но каждый шаг проверяет overflow.",
            "Напиши `static bool sb_reserve(StrBuf* sb, size_t need)`. Используй временный pointer: `char* p = realloc(sb->s, new_cap)`. Старый `sb->s` меняй только если `p != NULL`.",
            "Искусственно попроси большой размер или смоделируй ошибку: после неудачи `failed` должен стать `true`, а старый buffer не должен быть потерян.",
        ),
        (
            "`sb_appendn`, `sb_append`, `sb_appendf` - это три уровня добавления текста: bytes с длиной, обычная C-строка и форматированный текст.",
            "Они решают проблему безопасной сборки отчетов. Writer не должен думать о `realloc` и `\\0`; он должен сказать: добавь такой текст.",
            "`sb_appendn` резервирует `len + n + 1`, копирует bytes в `s + len`, увеличивает `len`, ставит `s[len] = '\\0'`. `sb_append` вызывает `strlen`. `sb_appendf` сначала узнает нужную длину через `vsnprintf`.",
            "Пиши именно в таком порядке: сначала `appendn`, потому что он базовый; потом `append`, потому что это thin wrapper; потом `appendf`, потому что там появятся `va_list`, `va_start`, `va_end`.",
            "Проверь строку после трех добавлений: содержимое правильное, `len == strlen(s)`, последний byte после текста равен `\\0`.",
        ),
        (
            "`file_write_atomic` нужен для отчетов: лучше не создать файл вообще, чем оставить битый JSON или HTML, если запись оборвалась посередине.",
            "Он решает проблему частично записанного результата. Пользователь может открыть отчет после сбоя и подумать, что анализатор выдал валидный вывод, хотя файл оборвался.",
            "Функция пишет во временный путь рядом с итоговым файлом, закрывает его, проверяет ошибки, затем заменяет итоговый файл через rename/MoveFileEx. Если что-то сломалось, временный файл удаляется.",
            "Сначала собери имя `target + .tmp.<pid>`, открой временный файл, запиши все bytes, закрой, затем сделай замену. На Windows учти, что заменить существующий файл может потребовать отдельной функции.",
            "Проверь, что после успешной записи итоговый файл содержит ровно переданные bytes, а временный файл не остался рядом.",
        ),
        (
            "SHA-256 нужен не для поиска признаков, а для идентичности входного файла в отчете.",
            "Он решает проблему доказуемости: если на защите или в тестах обсуждается отчет, hash показывает, к какому именно бинарнику он относится. Имя файла может совпадать, содержимое - нет.",
            "Алгоритм читает bytes блоками, обновляет внутреннее состояние и в конце выдает 32 bytes digest, который печатается как 64 hex-символа.",
            "Пиши SHA-256 последним, потому что это отдельный алгоритм. Сначала можно временно вернуть placeholder, но в финале нужны `sha256_init`, `sha256_update`, `sha256_final`, `sha256_hex`.",
            "Проверь на известном тест-векторе: SHA-256 пустой строки должен быть `e3b0c44298fc1c149afbf4c8996fb924...`.",
        ),
    ],
    "pe.h / pe.c": [
        (
            "Константы `MZ`, `PE\\0\\0`, AMD64 и PE32+ нужны, чтобы код говорил языком формата, а не магическими числами.",
            "Они решают проблему непонятного кода: `0x5A4D` без имени ничего не объясняет, а `PE_MAGIC_MZ` сразу говорит, какую сигнатуру проверяем.",
            "PE parser будет читать числа из файла и сравнивать с этими константами. Если сигнатура не совпала, это не наш формат или файл поврежден.",
            "В `pe.c` или `pe.h` объяви именованные `#define`/`enum` для сигнатур, machine type, magic PE32+ и индекса exception directory.",
            "Проверь, что файл без `MZ` отвергается до чтения NT headers.",
        ),
        (
            "`PeSection` нужен как модель одной секции PE: где она лежит в памяти, где ее bytes лежат в файле и какие у нее права.",
            "Он решает проблему смешивания координат. Без отдельной структуры ты будешь путать RVA, raw pointer, virtual size и raw size.",
            "Каждый section header из PE превращается в один `PeSection`; дальше RVA mapping и heuristics будут работать уже с этим массивом.",
            "Опиши поля `name[9]`, `virtual_address`, `virtual_size`, `raw_ptr`, `raw_size`, `characteristics`.",
            "Проверь на одном section header: имя завершается нулем, а числовые поля совпадают с bytes файла.",
        ),
        (
            "`PeImage` нужен как общий результат PE parsing: не просто секции, а весь контекст образа.",
            "Он решает проблему передачи десятка отдельных переменных между функциями. Следующим модулям нужен один объект, который описывает разобранный PE.",
            "`PeImage` владеет массивом секций, хранит image size, alignments, exception directory и счетчики structural problems.",
            "В `pe.h` объяви `PeImage` и сразу рядом прототип `pe_free`, чтобы договор владения памятью был виден рядом со структурой.",
            "После `pe_parse` можно вывести `section_count` и exception directory RVA/size без повторного чтения файла.",
        ),
        (
            "Зануление `out` в начале `pe_parse` нужно, чтобы ошибка на середине не оставила мусорные указатели.",
            "Это решает проблему cleanup: если `pe_free` вызовут после частичной ошибки, он должен видеть либо валидную память, либо нули.",
            "Функция ставит `*out` в известное состояние, затем постепенно заполняет поля. Любой failure path остается безопасным.",
            "Начни `pe_parse` с проверки аргументов и `memset(out, 0, sizeof *out)`.",
            "Смоделируй ошибку после начала парсинга и убедись, что `pe_free` не падает.",
        ),
        (
            "`e_lfanew` - мост от DOS header к настоящим NT headers PE.",
            "Он решает проблему расположения PE header: он не обязан начинаться сразу после первых bytes файла.",
            "Parser читает 32-битное смещение из DOS header, проверяет, что оно внутри файла, и от него читает `PE\\0\\0`.",
            "Через `buf_read_u32(b, 0x3c, &lfanew)` получи offset, затем проверяй диапазон перед чтением signature.",
            "Проверь файл, где `e_lfanew` указывает за конец: parser должен вернуть ошибку, а не читать мусор.",
        ),
        (
            "Проверка PE signature и Machine нужна, чтобы не применять x64 unwind rules к чужому формату.",
            "Она решает проблему ложного анализа. x86 PE или не-PE файл могут иметь похожие bytes, но правила `.pdata` и `UNWIND_INFO` будут другими.",
            "После `PE\\0\\0` идет COFF header. Из него читается Machine и NumberOfSections; Machine должен быть AMD64.",
            "Прочитай signature, затем `Machine`, затем `NumberOfSections`. Если Machine не AMD64 - верни понятную ошибку.",
            "Проверь, что x86 PE отвергается сообщением про unsupported machine.",
        ),
        (
            "Optional header PE32+ хранит размеры и таблицу data directories, без которых нельзя найти exception directory.",
            "Он решает проблему контекста: section headers сами по себе не говорят ImageBase, SizeOfImage и directories.",
            "Parser читает magic PE32+, image base, alignment, size of image, number of directories и проверяет, что optional header достаточно большой.",
            "Добавь чтение полей только после проверки `SizeOfOptionalHeader`; не читай directory, если его индекс отсутствует.",
            "Проверь PE с малым optional header: parser должен отказать аккуратно.",
        ),
        (
            "Exception directory - точка входа в `.pdata`, то есть в главную предметную область проекта.",
            "Она решает вопрос: где находится таблица `RUNTIME_FUNCTION` и сколько bytes она занимает.",
            "В PE data directories entry 3 хранит RVA и size. Эти значения сохраняются в `PeImage`, но сами записи читает уже `unwind.c`.",
            "Прочитай directory RVA/size по индексу 3 и сохрани в `pe->exception_rva`, `pe->exception_size`.",
            "Проверь PE без exception directory: проект не падает, а дальше heuristics понимает, что runtime functions нет.",
        ),
        (
            "Цикл по секциям нужен, чтобы построить карту файла.",
            "Он решает проблему адресации: почти все дальнейшие RVA придется искать внутри section table.",
            "Каждая секция занимает 40 bytes header. Parser читает имя, virtual size/address, raw size/pointer и characteristics.",
            "Выдели массив `PeSection* sections = calloc(section_count, sizeof *sections)` и заполни его в цикле.",
            "Проверь, что `section_count == 0` или слишком большой count обрабатывается без переполнения выделения.",
        ),
        (
            "Structural counters нужны, чтобы parser не только строил карту, но и фиксировал странности самой PE-структуры.",
            "Они решают проблему потери evidence. Если секция выходит за файл или пересекается с другой, это важно для heuristics и отчета.",
            "После чтения секций отдельным проходом проверь raw bounds, virtual bounds, overlaps и alignment. Не смешивай это с чтением полей.",
            "Добавь счетчики в `PeImage` и увеличивай их при каждом нарушении.",
            "Создай искусственную секцию с raw range за концом файла и проверь, что счетчик стал больше нуля.",
        ),
        (
            "`pe_find_section_for_rva` и `pe_rva_to_fileoff` нужны, чтобы все последующие модули могли перейти от адреса в памяти к bytes на диске.",
            "Они решают главную координатную проблему PE: RVA не равен file offset.",
            "Сначала ищется секция, чей virtual range содержит RVA. Затем `delta = rva - section.virtual_address`; если `delta < raw_size`, file offset равен `raw_ptr + delta`.",
            "Напиши функцию поиска секции отдельно от функции перевода RVA, чтобы их можно было тестировать независимо.",
            "Проверь RVA в начале секции, внутри секции и в virtual tail за `raw_size`: последний случай должен вернуть `false`.",
        ),
    ],
    "unwind.h / unwind.c": [
        (
            "Чтение `RUNTIME_FUNCTION` сначала нужно потому, что `.pdata` - это список входов в `UNWIND_INFO`.",
            "Оно решает проблему навигации: без begin/end/unwind RVA непонятно, какие функции вообще описаны в таблице.",
            "Каждая запись ровно 12 bytes: BeginAddress, EndAddress, UnwindInfoAddress, все как little-endian `uint32_t` RVA.",
            "Напиши цикл по exception directory size / 12, через `buf_read_u32` считывай три поля в `RuntimeFunction`.",
            "Проверь directory size не кратный 12: лишние bytes должны стать anomaly или ошибкой, а не отдельной записью.",
        ),
        (
            "`UnwindSummary` сначала должен содержать только базовые поля, чтобы ты не пытался понять весь ABI за один раз.",
            "Он решает проблему сложности: parser может начать с header, а stack effects, handlers и chains добавить позже.",
            "Summary - это сжатая расшифровка `UNWIND_INFO`, которую потом читает heuristics и report.",
            "Добавь поля version, flags, prolog size, count of codes, frame register/offset, parse_error, anomalies.",
            "Проверь один минимальный `UNWIND_INFO`: header читается, даже если codes пока не интерпретируются полностью.",
        ),
        (
            "Header `UNWIND_INFO` нужен как оглавление записи: он говорит версию, flags и сколько slots читать дальше.",
            "Он решает проблему переменного размера: без CountOfCodes ты не знаешь, где заканчивается массив unwind codes.",
            "Первый byte делится на version и flags, четвертый byte - на frame register и frame offset.",
            "Прочитай 4 bytes header, выдели bits через `&`, `>>`, сохрани в summary.",
            "Проверь version 3: parser должен отметить unsupported version, если проект поддерживает только V1/V2.",
        ),
        (
            "`slots_for_code` нужен, потому что разные UWOP занимают разное количество 2-байтовых slots.",
            "Он решает проблему правильного шага цикла. Если всегда делать `i++`, parser быстро потеряет границы записи.",
            "Функция смотрит opcode и opinfo и возвращает 1, 2 или 3 slots. Для неизвестного opcode возвращает ошибку.",
            "Напиши `switch (op)` и явно перечисли поддерживаемые UWOP.",
            "Проверь opcode, которому нужны 3 slots, при `CountOfCodes == 1`: parser должен увидеть truncation.",
        ),
        (
            "Цикл `for (i = 0; i < count;)` нужен, потому что шаг зависит от содержимого записи.",
            "Он решает проблему чтения массива переменной структуры внутри формально одинаковых slots.",
            "На каждой итерации parser читает slot, выделяет CodeOffset, UnwindOp, OpInfo, вычисляет slots и проверяет `i + slots <= count`.",
            "Не увеличивай `i` в заголовке цикла; увеличивай его после успешной интерпретации opcode.",
            "Проверь два opcodes подряд: второй должен читаться с правильного индекса.",
        ),
        (
            "Интерпретация opcode нужна, чтобы отчет показывал не просто bytes, а смысл: push register, allocate stack, save register.",
            "Она решает проблему человеческого чтения. Реверс-инженер должен видеть, что описывает unwind metadata.",
            "Для каждого UWOP summary обновляет счетчики stack allocation, saved registers, frame usage или textual details.",
            "Сначала добавь распознавание и текст, потом математические эффекты stack/register, чтобы не смешивать две сложности.",
            "Проверь `UWOP_ALLOC_SMALL`: по opinfo должен получиться ожидаемый размер stack allocation.",
        ),
        (
            "Anomaly flags нужны, чтобы parser не терял причину странности.",
            "Они решают проблему одного общего `false`: отчету важно различать truncation, bad opcode, bad operand и alignment.",
            "Флаги накапливаются через `anomalies |= FLAG`, поэтому одна запись может иметь несколько проблем.",
            "Определи bit masks и ставь их в конкретных местах проверки.",
            "Проверь запись с bad opcode и truncation: обе причины должны сохраниться, если обе обнаружены.",
        ),
        (
            "Handler tail нужен, потому что EHANDLER/UHANDLER flags означают, что после unwind codes лежит RVA обработчика.",
            "Он решает проблему связи metadata с exception handling: именно handler часто важен для подозрительных кейсов.",
            "После массива codes есть выравнивание до четного количества slots, затем 4-byte handler RVA.",
            "Вычисли offset tail аккуратно: `code_slots_rounded = (count + 1) & ~1`, затем читай handler RVA.",
            "Проверь EHANDLER запись: handler RVA должен попасть в summary и потом в отчет.",
        ),
        (
            "Chain tail нужен для `UNW_FLAG_CHAININFO`: запись может ссылаться на другой `RUNTIME_FUNCTION`.",
            "Он решает проблему составных unwind records. Без chain parser будет считать хвост handler-ом или мусором.",
            "При CHAININFO после codes лежат три `uint32_t`, то есть embedded `RUNTIME_FUNCTION`.",
            "Добавь отдельную ветку: если CHAININFO, не читай handler RVA, а читай chained begin/end/unwind.",
            "Проверь запись с CHAININFO: parser не должен одновременно считать ее EHANDLER.",
        ),
        (
            "Follow-chain надо включать только после одиночной записи, потому что это рекурсивная логика.",
            "Он решает проблему полноты анализа, но добавляет риск циклов и глубоких цепочек.",
            "Parser идет по chained unwind RVA с ограничением depth и набором sanity checks.",
            "Добавь `max_chain_depth` в options и уменьши его при каждом переходе.",
            "Проверь искусственную self-chain: parser должен остановиться по лимиту, а не зависнуть.",
        ),
    ],
    "heuristics.h / heuristics.c": [
        (
            "Счетчики из `PeImage` надо перенести первыми, потому что структурные проблемы секций - базовый слой evidence.",
            "Это решает проблему потери контекста: unwind может быть странным именно потому, что секции уже повреждены.",
            "Heuristics читает готовые counters и превращает их в внутренние признаки, не перечитывая PE.",
            "В начале `heuristics_analyze` скопируй или учти raw_oob, virtual_oob, overlaps, exception directory problems.",
            "Проверь PE с одной raw-oob секцией: должен появиться соответствующий finding или счетчик.",
        ),
        (
            "Проход по `RuntimeFunction` нужен, чтобы проверить саму `.pdata`: begin/end ranges, unwind RVA, сортировку.",
            "Он решает проблему таблицы, которая формально есть, но указывает за пределы образа или противоречит себе.",
            "Для каждой записи проверяются `begin < end`, оба адреса внутри image, unwind RVA доступен, порядок не убывает.",
            "Напиши цикл по `rf_count` и отдельные counters для каждого класса нарушения.",
            "Проверь запись `begin >= end`: она должна повышать invalid range counter.",
        ),
        (
            "Reuse `UnwindInfoRVA` нужно считать, потому что много функций, указывающих на один unwind info, может быть нормой или признаком упаковки.",
            "Это решает проблему частотного признака: одиночное совпадение неинтересно, массовое совпадение уже требует внимания.",
            "Маленькая hash map считает, сколько раз встречается каждый unwind RVA, и потом ищется максимум/доля.",
            "Реализуй `HMap` с open addressing: key - RVA, value - count.",
            "Проверь три одинаковых RVA: max reuse должен стать 3.",
        ),
        (
            "Parse failures и anomalies из `UnwindSummary` надо учитывать отдельно от structural PE problems.",
            "Это решает проблему смешивания семей evidence: поврежденная секция и плохой unwind opcode - разные причины.",
            "Heuristics смотрит `summary.parse_error` и `summary.anomalies`, но strict ABI warnings может учитывать мягче, чем hard truncation.",
            "Добавь counters: parse_fail_count, hard_anomaly_count, abi_warning_count.",
            "Проверь, что один strict ABI warning сам по себе не делает high score.",
        ),
        (
            "Placement checks нужны, чтобы понять, где лежит unwind info и handler: в read-only metadata, executable, writable section.",
            "Это решает проблему контекста. Один и тот же handler RVA выглядит по-разному, если он указывает в `.text` или writable data.",
            "Через `pe_find_section_for_rva` определяется секция для unwind info и handler target, затем смотрятся characteristics.",
            "Добавь counters для writable metadata, executable metadata, writable handler, non-executable handler.",
            "Проверь handler в writable секции: finding должен объяснять именно placement.",
        ),
        (
            "Сортировка копии begin/end нужна, чтобы найти overlaps и duplicate begins независимо от исходного порядка.",
            "Она решает проблему анализа отношений между записями `.pdata`.",
            "Копия массива сортируется по begin, потом соседние записи сравниваются на overlap и duplicate begin.",
            "Сделай отдельную структуру range и `qsort` comparator.",
            "Проверь две пересекающиеся функции: overlap counter должен увеличиться.",
        ),
        (
            "Findings нужны, чтобы заменить набор counters человеческими сообщениями.",
            "Они решают проблему отчета: пользователю нужен code, severity, family, affected count и representative RVA, а не только `score=40`.",
            "Каждый finding добавляется через одну функцию, которая контролирует лимит массива и формат message.",
            "Напиши `add_finding(report, code, family, severity, rva, count, message)`.",
            "Проверь переполнение лимита findings: программа не должна писать за пределы массива.",
        ),
        (
            "Score нужен как triage-оценка, но не как доказательство вредоносности.",
            "Он решает проблему сортировки случаев: что смотреть первым, что слабее, где нужно ручное внимание.",
            "Weights добавляются за разные findings, затем итог ограничивается 0..100.",
            "Опиши веса константами и собирай score после того, как counters и findings уже известны.",
            "Проверь, что score никогда не становится больше 100.",
        ),
        (
            "Confidence нужно считать отдельно, потому что высокий score по одному шаткому признаку не равен надежному выводу.",
            "Это решает проблему честности интерпретации. Confidence отвечает не 'насколько плохо', а 'насколько уверенно мы читаем evidence'.",
            "Бонусы идут за разные семейства и сильные признаки, штрафы - за single signal, small sample, placement-only.",
            "После score добавь расчет confidence и список mitigations, которые объясняют снижение.",
            "Проверь один слабый finding: confidence должен быть ниже, чем при нескольких независимых семействах.",
        ),
        (
            "Verdict и manual review нужны как финальная формулировка для человека.",
            "Они решают проблему последнего шага: отчет должен сказать, что делать с результатом, а не только показать числа.",
            "Verdict берется по thresholds score, evidence level - по количеству сильных/средних признаков, manual review включается для неоднозначных или сильных случаев.",
            "Сделай отдельную `finalize_verdict`, чтобы thresholds были в одном месте.",
            "Проверь границы 15, 40, 70: verdict должен меняться предсказуемо.",
        ),
    ],
    "report.h / report.c": [
        (
            "Сначала нужна модель отчета, потому что writers должны получать один и тот же набор данных.",
            "Это решает проблему расхождения output formats: console, JSON и HTML не должны считать разные verdict.",
            "Metadata и summary собираются один раз, а writer только превращает их в текст.",
            "В `report.h` опиши структуры metadata/summary или прототипы writer functions с одинаковыми входами.",
            "Проверь, что JSON и console показывают один score.",
        ),
        (
            "Console output нужен для быстрого запуска без файлов.",
            "Он решает проблему первого контакта пользователя с программой: команда должна сразу показать verdict и главные findings.",
            "Writer печатает короткий summary, затем список findings в порядке важности.",
            "Напиши функцию, которая принимает готовый report и `FILE*` или путь, не перечитывая PE.",
            "Проверь запуск без `--json`: пользователь все равно видит результат.",
        ),
        (
            "CSV нужен для таблиц, фильтрации и импорта в другие инструменты.",
            "Он решает проблему плоского представления findings: одна строка - один finding или одна runtime function.",
            "CSV cell должен экранировать кавычки, запятые и переносы строк.",
            "Напиши helper `csv_escape_cell` и используй его в каждом поле.",
            "Проверь message с запятой и кавычкой: CSV должен открываться корректно.",
        ),
        (
            "Ghidra CSV нужен отдельно, потому что это не просто таблица, а формат для работы в reverse engineering инструменте.",
            "Он решает проблему переноса findings в Ghidra как bookmarks/comments/function hints.",
            "Writer выбирает поля, которые нужны importer-у: RVA, тип события, текст комментария.",
            "Не смешивай обычный CSV и Ghidra CSV в одной функции; у них разный внешний контракт.",
            "Проверь, что строка содержит RVA в ожидаемом формате.",
        ),
        (
            "JSON нужен как главный машинно-читаемый отчет.",
            "Он решает проблему автоматической проверки, интеграции и защиты: можно показать schema, fields, evidence.",
            "JSON writer строит объект с metadata, PE summary, unwind entries, heuristic report и optional dynamic evidence.",
            "Следи за запятыми между элементами массива и экранируй строки.",
            "Проверь отчет через JSON parser, а не глазами.",
        ),
        (
            "HTML нужен как человекочитаемая страница отчета.",
            "Он решает проблему просмотра без специальных инструментов: открыл файл и видишь verdict, sections, findings.",
            "HTML writer должен экранировать все данные из файла и отчета, чтобы текст не стал HTML-кодом.",
            "Добавь `html_escape` и Content Security Policy, не вставляй внешние скрипты.",
            "Проверь message с `<` и `&`: на странице должны быть символы, а не сломанная разметка.",
        ),
        (
            "Atomic write в report layer нужен, чтобы любой формат либо записался полностью, либо не считался готовым.",
            "Это решает проблему битых отчетов после ошибки диска или прерывания.",
            "Writer сначала собирает весь текст в `StrBuf`, проверяет `sb_ok`, потом вызывает `file_write_atomic`.",
            "Не пиши отчет прямо по частям в итоговый файл.",
            "Проверь, что при ошибке writer возвращает `false`, а `main.c` дает exit code 1.",
        ),
        (
            "Manual validation steps нужны, чтобы проект честно говорил: это основание для подозрения, а не автоматический приговор.",
            "Это решает проблему защиты: можно объяснить, что именно должен проверить реверс-инженер после finding.",
            "Report добавляет к findings список ручных действий: проверить секцию, handler target, unwind bytes, dynamic correlation.",
            "Сформируй эти steps рядом с heuristic report, чтобы JSON/HTML показывали одинаковую логику.",
            "Проверь high suspicion case: в отчете есть не только score, но и что делать дальше.",
        ),
    ],
    "dynamic.h / dynamic_win.c": [
        (
            "Сначала нужен portable header, чтобы остальной проект мог знать о dynamic mode без подключения Windows API.",
            "Это решает проблему зависимости: static analyzer должен собираться и без Windows debugger.",
            "`dynamic.h` описывает options/report/events, но не тянет тяжелую platform-specific реализацию в другие модули.",
            "Опиши `DynamicOptions`, `DynamicEvent`, `DynamicReport` и функции init/free/collect.",
            "Проверь, что `main.c` компилируется с include `dynamic.h` на non-Windows.",
        ),
        (
            "Non-Windows stub нужен, потому что dynamic mode Windows-only, но проект целиком не должен из-за этого ломаться.",
            "Он решает проблему переносимости static mode.",
            "Stub возвращает `false` и понятное сообщение, если пользователь запросил dynamic mode на неподдерживаемой платформе.",
            "Добавь `#ifndef _WIN32` ветку с честной ошибкой.",
            "Проверь сборку без Windows headers.",
        ),
        (
            "Запуск debuggee нужен, чтобы наблюдать runtime exception behavior, а не только bytes на диске.",
            "Он решает проблему статической неопределенности: некоторые признаки подтверждаются только во время выполнения.",
            "Windows Debug API запускает процесс под отладчиком, после чего analyzer получает debug events.",
            "Используй `CreateProcess` с debug flags и сохрани handles для cleanup.",
            "Проверь, что несуществующий target дает понятную ошибку.",
        ),
        (
            "Debug loop нужен как центральный цикл сбора dynamic evidence.",
            "Он решает проблему асинхронных событий: exceptions, load dll, breakpoints приходят не линейно.",
            "Цикл ждет событие, определяет тип, обновляет report, продолжает выполнение debuggee.",
            "Напиши loop вокруг `WaitForDebugEvent` и `ContinueDebugEvent`.",
            "Проверь timeout: цикл должен завершиться, а не ждать бесконечно.",
        ),
        (
            "Breakpoints на API/handlers нужны, чтобы поймать регистрации и срабатывания exception mechanisms.",
            "Они решают проблему невидимых runtime действий: статически вызов может быть косвенным или спрятанным.",
            "Analyzer заменяет первый byte инструкции на `0xCC`, сохраняет оригинальный byte и адрес.",
            "Сделай таблицу breakpoints: address, original byte, enabled, event kind.",
            "Проверь, что breakpoint не ставится дважды на один адрес.",
        ),
        (
            "INT3 handling нужен, потому что breakpoint меняет поток исполнения.",
            "Он решает проблему корректного продолжения: после `0xCC` надо вернуть original byte и откатить RIP.",
            "При breakpoint event analyzer записывает evidence, восстанавливает byte, ставит RIP на адрес инструкции и включает trap flag.",
            "Добавь функцию обработки breakpoint hit отдельно от общего debug loop.",
            "Проверь, что после hit процесс продолжает выполнение, а не застревает на том же INT3.",
        ),
        (
            "Single-step handling нужен, чтобы снова поставить breakpoint после выполнения оригинальной инструкции.",
            "Он решает проблему одноразового breakpoint: если его не вернуть, следующий вызов API не будет замечен.",
            "После single-step analyzer снова записывает `0xCC` на адрес и снимает режим single-step.",
            "Храни pending breakpoint, который надо переустановить.",
            "Проверь два вызова одной API: должно быть два события.",
        ),
        (
            "VEH/VCH/UEF события нужны, потому что проект исследует exception handling, а не просто факт запуска процесса.",
            "Они решают проблему связи runtime поведения с темой EH/unwind.",
            "Dynamic collector отмечает регистрации обработчиков и фактические exception hits.",
            "Добавь event kinds и counters для VEH, VCH, UEF.",
            "Проверь тестовый sample с VEH: отчет должен содержать registration или hit.",
        ),
        (
            "Runtime function table events нужны, чтобы увидеть `RtlAddFunctionTable` и похожие механизмы.",
            "Они решают проблему динамически создаваемой unwind metadata, которой может не быть в статической `.pdata`.",
            "Breakpoint на API фиксирует адрес таблицы, размер и caller context насколько это доступно.",
            "Добавь отдельный event kind для RtlAddFunctionTable/RtlInstallFunctionTableCallback.",
            "Проверь sample с runtime table: dynamic signal count должен увеличиться.",
        ),
        (
            "Cleanup нужен, потому что dynamic mode владеет handles, breakpoints и потенциально живым процессом.",
            "Он решает проблему оставленных процессов и поврежденного debuggee state.",
            "На любом выходе нужно восстановить breakpoints, закрыть handles, остановить или отсоединить debuggee по правилам режима.",
            "Сделай единый cleanup path, как в `main.c`, и вызывай его при ошибке и timeout.",
            "Проверь ошибку в середине: handles закрыты, процесс не остался висеть.",
        ),
    ],
    "app_info.h / app_info.c": [
        (
            "Единые строковые константы нужны, чтобы версия приложения не была размазана по разным файлам.",
            "Это решает проблему расхождения: CLI может печатать одно, JSON другое, документация третье.",
            "`app_info.c` становится единственным местом, откуда берутся app name/version/schema version.",
            "В `app_info.h` объяви функции `app_name`, `app_version`, `report_schema_version`.",
            "Проверь, что `--version` и JSON metadata используют одну и ту же функцию.",
        ),
        (
            "`app_info.c` должен быть маленьким и независимым.",
            "Это решает проблему лишних зависимостей: версия не должна зависеть от PE parser или report writer.",
            "Функции возвращают строковые литералы со статическим временем жизни.",
            "Реализуй функции как `return \"1.0.0\";`, без выделения памяти.",
            "Проверь, что вызывающий код не пытается `free` эти строки.",
        ),
        (
            "Build metadata полезна для воспроизводимости.",
            "Она решает проблему вопроса 'каким компилятором и какой сборкой это получено'.",
            "Если доступны макросы сборки, функция возвращает строку compiler/build mode; если нет - stable fallback.",
            "Добавь compile-time macros аккуратно, чтобы отсутствие макроса не ломало сборку.",
            "Проверь debug и release: output остается валидным.",
        ),
        (
            "Schema version нужна отдельно от app version.",
            "Она решает проблему совместимости отчетов: приложение может обновиться без изменения JSON schema, и наоборот.",
            "Report writer записывает schema version, а tests валидируют ожидаемый контракт.",
            "Не используй app version как schema version.",
            "Проверь тест release metadata: schema не пустая и совпадает с ожидаемой.",
        ),
        (
            "Интеграция с `main.c` и `report.c` завершает модуль.",
            "Она решает проблему мертвого кода: если версии объявлены, но никто их не использует, контракт не работает.",
            "`main.c` печатает version, report metadata берет schema/name из `app_info`.",
            "Замени строковые литералы в других местах вызовами `app_info`.",
            "Проверь поиском по проекту, что версия не продублирована в нескольких `.c` без причины.",
        ),
    ],
    "main.c": [
        (
            "Структура CLI options нужна, чтобы не таскать десятки локальных переменных по `main`.",
            "Она решает проблему хаоса аргументов: input path, output paths, flags и режимы должны жить в одном объекте.",
            "`parse_args` заполняет `CliOptions`, дальше pipeline читает уже готовые поля.",
            "Создай `typedef struct CliOptions` внутри `main.c`, если она не нужна другим файлам.",
            "Проверь `--help`: он не требует input file.",
        ),
        (
            "Разбор `--help` и `--version` нужен до анализа файла.",
            "Он решает проблему лишних требований: пользователь должен увидеть справку даже без PE.",
            "Если найден help/version, программа печатает текст и выходит с code 0.",
            "Сделай эти флаги ранними ветками в `parse_args` или сразу после него.",
            "Проверь запуск без аргументов и с `--help`: exit code должен быть предсказуемым.",
        ),
        (
            "Валидация аргументов нужна, чтобы отличать ошибку командной строки от ошибки анализа.",
            "Она решает проблему exit codes: неверная команда - это code 2, а не failed analysis.",
            "Parser проверяет обязательный input, конфликтующие опции и корректность путей output.",
            "После parse_args верни отдельный статус: ok/help/error.",
            "Проверь неизвестную опцию: программа возвращает 2.",
        ),
        (
            "Загрузка файла через `Buf` запускает pipeline.",
            "Она решает проблему перехода от CLI path к универсальным bytes.",
            "`main.c` вызывает `buf_init_from_file`, хранит `owned_mem`, и передает `Buf` дальше как read-only input.",
            "Не открывай файл повторно в `pe.c` или `unwind.c`.",
            "Проверь несуществующий файл: ошибка понятная, память не освобождается дважды.",
        ),
        (
            "PE parse должен идти раньше unwind parse.",
            "Он решает проблему карты адресов: `.pdata` и `UNWIND_INFO` задаются RVA, а читать надо file offsets.",
            "`pe_parse` создает `PeImage`, который дальше используют все слои.",
            "После `pe_parse` при ошибке переходи в cleanup.",
            "Проверь non-PE input: до unwind parser дело не доходит.",
        ),
        (
            "Чтение runtime functions - первый unwind этап.",
            "Оно решает проблему списка функций: дальше нужно знать, сколько записей парсить и какие unwind RVA посещать.",
            "`unwind_read_runtime_functions_ex` возвращает массив и count, которыми владеет `main.c`.",
            "Храни pointer и count рядом; освобождай pointer в cleanup.",
            "Проверь PE без `.pdata`: pipeline завершает анализ с пустым списком, а не падает.",
        ),
        (
            "Парсинг каждого `UNWIND_INFO` нужен до heuristics.",
            "Он решает проблему evidence: heuristics должны видеть summaries и anomalies, а не сырые RVA.",
            "`main.c` выделяет массив summaries по `rf_count` и заполняет его в цикле.",
            "Если одна запись не парсится, сохрани parse error в summary и продолжай, если политика проекта это допускает.",
            "Проверь один плохой unwind record: отчет должен показать ошибку этой записи.",
        ),
        (
            "Heuristics идут после всех static данных.",
            "Они решают проблему финальной интерпретации: только теперь есть PE context, runtime functions и unwind summaries.",
            "`heuristics_analyze` создает report, который потом передается writers.",
            "Не считай score в `main.c`; вызови отдельный модуль.",
            "Проверь, что один и тот же input дает одинаковый score в console и JSON.",
        ),
        (
            "Dynamic mode должен быть optional.",
            "Он решает проблему безопасности и переносимости: static analysis не обязан запускать чужой код.",
            "`main.c` вызывает dynamic collector только при явном флаге и добавляет результат в общий отчет.",
            "Если dynamic mode failed, не уничтожай static result; запиши причину.",
            "Проверь запуск без dynamic flag: Windows API не требуется.",
        ),
        (
            "Запись reports должна быть последним этапом после анализа.",
            "Она решает проблему целостности output: writers должны видеть полностью готовые данные.",
            "`main.c` смотрит CLI options и вызывает нужные writer functions.",
            "Если writer вернул `false`, выставь exit code 1.",
            "Проверь `--json out.json`: файл появился и парсится.",
        ),
        (
            "Единый cleanup path нужен, потому что в C нет автоматического освобождения heap-памяти.",
            "Он решает проблему утечек и двойных освобождений при ранних ошибках.",
            "Все ресурсы инициализируются нулями, каждый failure path идет в один блок cleanup, где вызываются free-функции.",
            "Используй `goto cleanup` осознанно: это не грязный трюк, а нормальный C-паттерн для функции с несколькими ресурсами.",
            "Проверь ошибку на каждом этапе: программа выходит без падения и освобождает уже созданные объекты.",
        ),
    ],
}


def add_teaching_steps(module: dict[str, object]) -> None:
    steps = module["steps"]
    notes = STEP_TEACHING_NOTES.get(module["name"], [])
    if not notes:
        numbered(steps)
        return
    p(
        "Ниже каждый пункт раскрыт как учебный шаг. Сначала смотри не на синтаксис, а на смысл: зачем этот объект появляется, "
        "какую опасность он убирает, как данные пойдут дальше и чем доказать, что шаг действительно работает."
    )
    for i, step in enumerate(steps, 1):
        h3(f"Шаг {i}. {step}")
        if i - 1 < len(notes):
            why, solves, how, write, check = notes[i - 1]
        else:
            why = "Этот шаг нужен, чтобы продвинуть модуль к его роли в общем pipeline проекта."
            solves = "Он закрывает одну маленькую проблему модуля и создает контракт для следующего шага."
            how = "Сначала опиши входные данные и выходной результат, потом реализуй минимальную проверяемую функцию."
            write = step
            check = "Собери проект и проверь один нормальный и один ошибочный сценарий."
        p("Зачем: " + why)
        p("Какую проблему решает: " + solves)
        p("Как работает: " + how)
        p("Что писать руками: " + write)
        p("Как проверить: " + check)
        spacer(3)


def add_module_chapters() -> None:
    h1("9. Подробный план написания каждого файла")
    p(
        "Ниже - маршрут переписывания проекта руками. Не начинай с полного файла. Каждый модуль разбит на смысл, новые C-понятия, структуры, функции, порядок написания и проверки. "
        "Когда написан один шаг, собирай проект. Если сборка сломалась, не иди дальше: вернись к последнему маленькому изменению."
    )
    for module in MODULES:
        h2(module["name"])
        p(module["role"])
        h3("Что выучить в C на этом модуле")
        bullets(module["concepts"])
        h3("Главные структуры и функции")
        table(
            ["Структуры/константы", "Функции"],
            [[", ".join(module["structures"]), ", ".join(module["functions"])]],
            [72, 96],
        )
        h3("Порядок написания")
        add_teaching_steps(module)
        h3("Проверки перед переходом дальше")
        bullets(module["checks"])
        h3("Как объяснять себе каждую строку")
        p(
            "Для каждой строки задавай четыре вопроса: какой объект она читает, какой объект меняет, какой failure path возможен, "
            "какой следующий слой будет использовать результат. Если строка только украшает код и не проходит эти вопросы, скорее всего ты пока ее не понял."
        )
        if module["name"].startswith("util"):
            code(
                """
bool buf_read(const Buf* b, size_t off, void* out, size_t len) {
    if (!b || !out) return false;
    if (off > b->size) return false;
    if (len > b->size - off) return false;
    memcpy(out, b->data + off, len);
    return true;
}
                """
            )
        elif module["name"].startswith("pe"):
            code(
                """
RVA -> file offset:
  1. Найти section, где virtual_address <= RVA < virtual_address + span.
  2. delta = RVA - section.virtual_address.
  3. Если delta >= raw_size, bytes нет в файле: это virtual tail.
  4. file_offset = raw_ptr + delta.
                """
            )
        elif module["name"].startswith("unwind"):
            code(
                """
slot:
  low byte  = CodeOffset
  high byte = (OpInfo << 4) | UnwindOp

while i < CountOfCodes:
  read slot i
  determine slots_for_code(op, opinfo)
  validate i + slots <= CountOfCodes
  interpret operands
  i += slots
                """
            )
        elif module["name"].startswith("heuristics"):
            code(
                """
observation counters -> finding -> score -> evidence level -> confidence -> verdict

score answers: "насколько это подозрительно по весам?"
confidence answers: "насколько надежна эта интерпретация с учетом контекста?"
                """
            )
        elif module["name"].startswith("report"):
            code(
                """
Любой output writer:
  1. Проверить аргументы.
  2. Собрать текст в StrBuf.
  3. Экранировать специальные символы формата.
  4. Проверить sb_ok().
  5. Записать через file_write_atomic().
                """
            )
        elif module["name"].startswith("dynamic"):
            code(
                """
Dynamic mode:
  create process as debuggee
  receive debug events
  set API/handler breakpoints
  on INT3:
      restore original byte
      rewind RIP
      set trap flag
      record event
  on single-step:
      re-arm breakpoint
                """
            )
        pagebreak()


def add_rebuild_schedule() -> None:
    h1("10. Большой маршрут переписывания руками")
    p(
        "Это не календарь по датам, а учебная последовательность. Один 'день' может занять вечер или неделю. "
        "Главное - завершать день работающим маленьким состоянием проекта."
    )
    days = [
        ("Сборка-скелет", "CMake, `main.c`, `--help`, `--version` stub", "единица трансляции, linker"),
        ("Первые типы", "`util.h`: `Buf`, `StrBuf`, прототипы", "header guards / `#pragma once`, typedef struct"),
        ("Чтение bytes", "`buf_read`, `buf_read_u16/u32/u64`", "указатели, границы, endian"),
        ("Чтение файла", "`buf_init_from_file`, `buf_free_owned`", "FILE*, malloc, ownership"),
        ("Растущая строка", "`sb_init`, `sb_reserve`, `sb_appendn`", "capacity, realloc"),
        ("Format append", "`sb_appendf`", "variadic functions, vsnprintf"),
        ("Atomic write", "`file_write_atomic`", "temporary files, cleanup"),
        ("SHA-256", "`sha256_hex` или временный stub с тестом", "алгоритм и state"),
        ("PE структуры", "`pe.h`: constants, `PeSection`, `PeImage`", "domain structs"),
        ("DOS/PE header", "`read_dos_lfanew`, signature checks", "magic numbers, offsets"),
        ("COFF/optional", "Machine, PE32+ magic, ImageBase, alignments", "binary layout"),
        ("Data directory", "exception RVA/size", "таблица directories"),
        ("Section headers", "чтение секций", "цикл, массив структур"),
        ("PE validation", "oob, overlaps, misalignment", "инварианты"),
        ("RVA mapping", "`pe_find_section_for_rva`, `pe_rva_to_fileoff`", "virtual vs raw"),
        ("Runtime functions", "`unwind_read_runtime_functions_ex`", "массив 12-байтовых записей"),
        ("Unwind header", "version, flags, prolog, count, frame", "bit fields"),
        ("Slots table", "`slots_for_code`", "switch, variable record length"),
        ("Unwind loop", "parse slots, stack effects", "loop with manual increment"),
        ("Anomalies", "bad opcode, truncated, handler oob, alignment", "bit masks"),
        ("Handler tail", "EHANDLER/UHANDLER tail", "условный layout"),
        ("Chain tail", "CHAININFO and follow-chain", "bounded recursion"),
        ("Heuristic counters", "rf ranges, parse fail, placement", "aggregation"),
        ("Hash map reuse", "`HMap`, max counts", "open addressing"),
        ("Findings", "`add_finding`, representative RVA", "structured evidence"),
        ("Score/confidence", "weights, mitigations, verdict", "policy code"),
        ("CSV reports", "normal CSV and Ghidra CSV", "escaping"),
        ("JSON report", "metadata, sections, functions, heuristics", "serialization contract"),
        ("HTML report", "offline dashboard", "HTML escaping, CSP"),
        ("Dynamic stub", "non-Windows path", "conditional compilation"),
        ("Dynamic Windows", "debug loop and breakpoints", "Windows API"),
        ("Main orchestration", "full pipeline and cleanup", "resource lifecycle"),
        ("Unit tests", "`unit_unwind`, `unit_core_edges`", "fake input bytes"),
        ("CLI contract", "`test_cli_contract.py`", "black-box tests"),
        ("Regression/fuzz", "sample corpus and mutation fuzz", "robustness"),
        ("Release hygiene", "version, schema, packaging", "product discipline"),
    ]
    rows = []
    for i, (goal, write, learn) in enumerate(days, 1):
        rows.append([i, goal, write, learn])
    table(["Шаг", "Цель", "Что писать", "Что учить"], rows, [12, 36, 64, 54])
    h2("Контрольные ворота")
    bullets(
        [
            "После `util`: можешь безопасно прочитать arbitrary bytes и собрать строку отчета.",
            "После `pe`: можешь открыть PE32+ AMD64 и объяснить каждую секцию.",
            "После `unwind`: можешь взять одну `.pdata` entry и найти ее `UNWIND_INFO`.",
            "После `heuristics`: можешь объяснить любой finding без слов 'магия' и 'мне кажется'.",
            "После `report`: можешь сохранить результат и проверить JSON schema/CSV/HTML.",
            "После `main`: можешь провести полный анализ sample и освободить все ресурсы.",
        ]
    )
    pagebreak()


def add_practice_workbook() -> None:
    h1("11. Практикум: как руками пройти каждый модуль")
    p(
        "Этот раздел нужен не для чтения, а для работы рядом с редактором. Открываешь модуль, выполняешь лабораторную, "
        "пишешь короткий ответ в тетрадь или комментарий рядом с кодом, собираешь проект. Если лабораторная не получается, "
        "значит еще рано переписывать следующий файл."
    )
    for module in MODULES:
        h2(f"Практикум: {module['name']}")
        p(f"Цель практикума: {module['role']}")
        h3("Лабораторная A: словарь модуля")
        numbered(
            [
                "Выпиши названия всех структур и функций модуля.",
                "Напротив каждой структуры напиши, кто ее создает и кто освобождает.",
                "Напротив каждой функции напиши одно предложение: какой input она принимает и какой output производит.",
                "Отдельно отметь функции, которые могут вернуть `false` или код ошибки.",
                "Собери проект после того, как добавишь только объявления в `.h`.",
            ]
        )
        h3("Лабораторная B: минимальный работающий кусок")
        p(
            "Сделай самую маленькую версию модуля, которая компилируется и выполняет один честный сценарий. "
            "Не пытайся сразу покрыть все edge cases. Сначала нужен живой скелет, потом защита границ."
        )
        numbered(
            [
                f"Выбери первую функцию из списка: `{module['functions'][0]}`.",
                "Напиши happy path без сложных веток.",
                "Добавь guard checks на `NULL` и неверные размеры.",
                "Добавь один негативный тест.",
                "Проверь, что ошибка не портит уже созданные объекты.",
            ]
        )
        h3("Лабораторная C: плохой input")
        p(
            "Большая часть ценности проекта - в спокойном отношении к сломанному input. Поэтому для каждого модуля обязательно придумай "
            "три плохих входа: пустой, обрезанный, противоречивый. Программа должна вернуть ошибку или finding, но не падать."
        )
        bullets(
            [
                "Пустой input: размер 0, нулевой count, отсутствующая секция или отсутствие events.",
                "Обрезанный input: header есть, но tail не помещается.",
                "Противоречивый input: begin больше end, RVA вне image, флаги несовместимы.",
                "Проверка: после плохого input вызывается cleanup и процесс завершается предсказуемым кодом.",
            ]
        )
        h3("Вопросы для устного объяснения")
        bullets(
            [
                f"Почему этот модуль не должен делать работу соседнего модуля?",
                f"Какая структура здесь является главным результатом?",
                f"Какая строка в модуле самая опасная с точки зрения выхода за границы?",
                f"Какая ошибка новичка здесь наиболее вероятна?",
                f"Какой тест докажет, что модуль можно передать следующему слою?",
            ]
        )
        h3("Микро-итерации")
        for idx, step in enumerate(module["steps"], 1):
            p(
                f"Итерация {idx}. {step} После этой итерации собери проект. "
                "Если это header-only шаг, проверь, что все `.c` видят объявления. "
                "Если это реализация, добавь хотя бы один минимальный вызов из теста или временного `main`."
            )
        pagebreak()


def add_daily_deep_plan() -> None:
    h1("12. Детальный дневник обучения")
    p(
        "Ниже тот же маршрут, но в формате дневника. У каждого дня есть цель, результат, тема C и вопрос, на который ты должен ответить без подсказки. "
        "Не обязательно проходить по одному пункту в календарный день. Можно растянуть. Важно, чтобы каждый пункт заканчивался проверяемым состоянием."
    )
    days = [
        ("Скелет проекта", "Программа собирается и печатает help", "translation unit, `main`, CMake target", "Почему `.h` сам по себе не компилируется как программа?"),
        ("Контракты util", "Есть `util.h` с `Buf` и `StrBuf`", "struct, prototypes, include guards", "Чем объявление функции отличается от определения?"),
        ("Безопасное чтение", "`buf_read` не читает за пределами bytes", "pointer arithmetic, `size_t`", "Почему проверка `len > size - off` безопаснее сложения?"),
        ("Endian helpers", "Работают `le16/le32/le64`", "битовые сдвиги", "Почему `0x12 0x34` не всегда число `0x1234`?"),
        ("Файл в память", "`buf_init_from_file` читает path", "`FILE*`, heap", "Кто освобождает память файла?"),
        ("Растущая строка", "`StrBuf` добавляет текст", "`realloc`, capacity", "Почему нужен отдельный `failed` flag?"),
        ("Форматирование", "`sb_appendf` работает", "`va_list`, `vsnprintf`", "Почему format string надо проверять warnings?"),
        ("Атомарная запись", "Временный файл заменяет итоговый", "filesystem failure paths", "Что будет, если запись прервется посередине?"),
        ("PE constants", "Создан `pe.h`", "macros, fixed-width types", "Почему `IMAGE_FILE_MACHINE_AMD64` лучше числа без имени?"),
        ("DOS header", "`e_lfanew` читается из 0x3c", "offsets", "Что означает `MZ`?"),
        ("PE signature", "Проверяется `PE\\0\\0`", "magic values", "Почему нельзя продолжать после неверной сигнатуры?"),
        ("COFF header", "Читаются machine, sections, optional size", "binary structure layout", "Почему проект отвергает x86?"),
        ("Optional header", "Читаются ImageBase, alignments, sizes", "PE32+ offsets", "Почему optional header здесь не optional?"),
        ("Data directory", "Exception directory найден", "таблицы", "Почему exception directory index равен 3?"),
        ("Sections", "Секции читаются в массив", "heap array", "Почему имя секции хранится как 8 bytes плюс `\\0`?"),
        ("PE validation", "Счетчики проблем заполняются", "invariants", "Чем raw overlap отличается от virtual overlap?"),
        ("RVA mapping", "RVA переводится в file offset", "range mapping", "Почему virtual tail не имеет bytes в файле?"),
        ("Runtime table", "`.pdata` превращается в `RuntimeFunction[]`", "array of records", "Почему запись 12 bytes?"),
        ("Unwind header", "Читаются version/flags/count/frame", "bit fields", "Как из одного byte получить version и flags?"),
        ("Slots", "Определяется длина opcode", "`switch`", "Почему цикл идет `i += slots`, а не `i++`?"),
        ("Stack effects", "Считается fixed stack", "overflow-safe addition", "Почему `PUSH_MACHFRAME` добавляет 40 или 48 bytes?"),
        ("Anomalies", "Флаги проблем выставляются", "bitmask", "Почему можно хранить несколько anomalies в одном числе?"),
        ("Handler tail", "Читается handler RVA", "conditional layout", "Почему tail зависит от flags?"),
        ("Chain tail", "Читается chained runtime function", "bounded following", "Как проект защищается от chain loop?"),
        ("Heuristic counters", "Считаются invalid/oob/parse fail", "aggregation", "Почему сначала observation, потом finding?"),
        ("Reuse maps", "Считается reuse unwind/handler", "hash map", "Почему ratio без count опасен?"),
        ("Findings", "Появляются structured findings", "arrays of structs", "Что должен содержать хороший finding?"),
        ("Confidence", "Score отделен от confidence", "policy code", "Почему score не probability?"),
        ("CSV", "Пишется обычный CSV", "escaping", "Почему кавычки в CSV удваиваются?"),
        ("Ghidra CSV", "Пишется импортируемый CSV", "tool integration", "Почему имя функции `sub_<RVA>` полезно?"),
        ("JSON", "Пишется schema-friendly report", "JSON escaping", "Почему report metadata важна?"),
        ("HTML", "Пишется offline dashboard", "HTML escaping/CSP", "Почему нельзя вставлять сырой input в HTML?"),
        ("Dynamic stub", "Non-Windows path собирается", "`#ifdef`", "Почему Windows headers нельзя требовать в static mode?"),
        ("Windows dynamic", "Понятен debug event loop", "handles, breakpoints", "Почему dynamic mode нужен только в VM/lab?"),
        ("Main cleanup", "Полный pipeline освобождает ресурсы", "lifetime", "В каком порядке освобождаются объекты?"),
        ("Тесты", "Запускаются unit/CLI tests", "assertions", "Как тест превращает bytes в понятный пример?"),
    ]
    for i, (title, result, topic, question) in enumerate(days, 1):
        h2(f"День {i}. {title}")
        p(f"Ожидаемый результат: {result}.")
        p(f"Тема C: {topic}.")
        p(f"Вопрос дня: {question}")
        p(
            "Рабочий ритуал: сначала перечитай соответствующий header, затем напиши минимальную реализацию, затем добавь проверку плохого input, "
            "затем собери проект. В конце дня оставь короткую заметку: что понял, где ошибся, какой invariant теперь держит код."
        )
    pagebreak()


def add_error_atlas() -> None:
    h1("13. Атлас типичных ошибок")
    p(
        "Когда учишь C на реальном парсере, ошибки неизбежны. Важно не пугаться, а уметь распознать класс проблемы. "
        "Этот атлас помогает понять, куда смотреть."
    )
    rows = [
        ["Segmentation fault", "Обращение по плохому pointer", "Проверить `NULL`, lifetime, выход за массив."],
        ["Use after free", "Объект освобожден, но pointer еще используется", "После `free` не трогать объект; занулять owner при необходимости."],
        ["Double free", "Один heap pointer освобожден дважды", "Назначить одного owner; не освобождать borrowed pointer."],
        ["Heap overflow", "Запись за выделенную память", "Проверить capacity, место под `\\0`, индексы loops."],
        ["Integer overflow", "Сумма/умножение перешло границу типа", "Использовать проверки вида `a > max - b`."],
        ["Wrong endian", "Bytes собраны в неправильном порядке", "Проверить `le16/le32/le64` на ручном примере."],
        ["Off-by-one", "На один byte/element больше или меньше", "Проверить half-open ranges `[begin, end)`."],
        ["Uninitialized field", "Структура не занулена", "Добавить `memset` или явную инициализацию."],
        ["Leaked allocation", "Нет `free` на error path", "Пройти все `return` в функции и отметить ownership."],
        ["Dangling pointer", "Pointer указывает на stack object, который уже исчез", "Не возвращать адрес локальной переменной."],
        ["Bad format specifier", "`printf` тип не совпал с `%`", "Включить `-Wformat=2`, приводить типы явно."],
        ["CSV broken", "Не экранированы запятые/кавычки/переносы", "Использовать `csv_cell` для каждого cell."],
        ["JSON broken", "Сырая строка содержит кавычку или control char", "Всегда идти через `json_escape`."],
        ["HTML injection", "Сырая строка попала в HTML", "Всегда идти через `html_escape`."],
        ["RVA not mapped", "RVA попал в virtual tail или вне sections", "Проверить section span и raw_size."],
        ["Wrong section span", "Использован только virtual_size или raw_size", "В проекте часто нужен `max(virtual_size, raw_size)`."],
        ["Malformed `.pdata`", "Размер exception directory не кратен 12", "Вернуть malformed result, не читать partial entry."],
        ["Unsupported unwind version", "Version не 1 и не 2", "Не парсить V3 старым layout."],
        ["Opcode spans beyond count", "Slots opcode выходят за CountOfCodes", "Проверить `i + slots > count`."],
        ["Handler tail truncated", "Флаг требует tail, но bytes нет", "Вернуть parse fail и сохранить parse_error."],
        ["Chain loop", "Chained records ссылаются по кругу", "Хранить seen array и max depth."],
        ["False high suspicion", "Одна слабая эвристика дала слишком сильный вывод", "Проверить weakening rules и context."],
        ["Dynamic timeout", "Target не вышел до deadline", "Ставить timeout, чистить процесс и report state."],
        ["Breakpoint not rearmed", "INT3 снят, но не поставлен обратно", "Проверить single-step path и pending rearm per thread."],
        ["Command line leak", "Target args попали в report metadata", "После `--` писать redaction marker."],
    ]
    table(["Симптом", "Вероятная причина", "Что проверить"], rows, [42, 58, 66])
    pagebreak()


def add_function_question_cards(info: dict[str, dict[str, object]]) -> None:
    h1("14. Карточки вопросов по функциям")
    p(
        "Эти карточки нужны для самопроверки. Берешь функцию из списка, открываешь исходник и отвечаешь на пять вопросов. "
        "Если не можешь ответить, не переписывай ее пока механически."
    )
    for rel, meta in info.items():
        funcs = list(meta.get("functions") or [])
        if not funcs:
            continue
        h2(rel)
        for name in funcs[:18]:
            h3(name)
            bullets(
                [
                    f"Какой главный input у `{name}` и считается ли он trusted?",
                    f"Какой объект `{name}` изменяет или возвращает?",
                    f"Какая первая проверка должна защитить функцию от плохих аргументов?",
                    f"Какой ресурс может потребовать cleanup внутри `{name}`?",
                    f"Какой тест или assert докажет, что `{name}` работает хотя бы на одном плохом input?",
                ]
            )
    pagebreak()


def add_testing_chapter() -> None:
    h1("15. Тестирование как способ понять проект")
    p(
        "Тесты здесь особенно ценны для новичка: они уменьшают формат PE/UNWIND_INFO до маленьких искусственных массивов bytes. "
        "Если настоящий EXE кажется огромным, тест показывает минимальную ситуацию: вот bytes, вот section mapping, вот ожидаемый stack size."
    )
    h2("Типы тестов")
    table(
        ["Тип", "Что проверяет", "Как использовать при обучении"],
        [
            ["unit_unwind", "slots, opcodes, chain, V2 epilog, parse errors", "Разбирать один тест перед написанием соответствующего opcode."],
            ["unit_heuristics", "score, placement, verdict", "Проверять, что finding появляется только при нужном контексте."],
            ["unit_core_edges", "empty tables, overflow, mapping, SHA-256", "Учиться думать о границах и пустых входах."],
            ["unit_report_json/html", "serialization, escaping, schema-ish invariants", "Проверять output как контракт."],
            ["cli_contract", "exit codes, options, redaction, partial reports", "Смотреть на программу глазами пользователя."],
            ["mutation_fuzz", "устойчивость к поломанным bytes", "Понять, что parser не должен падать на мусоре."],
        ],
        [34, 58, 76],
    )
    h2("Как писать свой первый тест")
    numbered(
        [
            "Создай маленький `uint8_t file[0x600]` и занули его.",
            "Опиши одну fake section: `.xdata`, virtual address `0x1000`, raw ptr `0x200`, raw size `0x200`.",
            "Положи 4 bytes `UNWIND_INFO` header по raw offset `0x200`.",
            "Положи один unwind slot.",
            "Создай `Buf` и `PeImage` вручную.",
            "Вызови `unwind_parse`.",
            "Проверь `assert(ok)`, `assert(us.fixed_stack_bytes == ...)`, `assert(us.anomalies == 0)`.",
        ]
    )
    code(
        """
Мини-идея теста:
  RVA 0x1000 -> file offset 0x200
  UNWIND_INFO at 0x200:
    version=1, flags=0
    count=1
    one slot: UWOP_ALLOC_SMALL, opinfo=0
  Ожидаем fixed_stack_bytes = 8
        """
    )
    h2("Как отлаживать")
    bullets(
        [
            "Если parser вернул false, сначала распечатай `err.s` и `us.parse_error`.",
            "Если mapping не работает, вручную посчитай `delta = rva - section.virtual_address`.",
            "Если JSON сломан, проверь escaping до записи файла.",
            "Если test падает на Windows-only dynamic, отдели static tests от dynamic smoke.",
            "Если warning стал error, сначала пойми предупреждение, не глуши его флагами.",
        ]
    )
    pagebreak()


def add_line_by_line_methods() -> None:
    h1("16. Как читать реальные строки проекта")
    h2("Шаблон guard")
    p("Почти каждая публичная функция защищает свои входы. Для новичка это первый признак серьезного C-кода.")
    code(
        """
if (!out || !b || !err) return false;

Перевод:
  если вызывающий код не дал место для результата,
  или не дал буфер,
  или не дал буфер ошибок,
  функция не имеет права продолжать.
        """
    )
    h2("Шаблон zero-init")
    code(
        """
memset(out, 0, sizeof(*out));

Перевод:
  перед заполнением результата делаем все поля предсказуемыми.
  bool станут false, указатели NULL, числа 0.
        """
    )
    h2("Шаблон checked read")
    code(
        """
uint32_t lfanew = 0;
if (!buf_read_u32(b, 0x3c, &lfanew)) return false;

Перевод:
  хотим прочитать 4 bytes из offset 0x3c;
  если bytes нет, не продолжаем;
  если есть, little-endian число попадет в lfanew.
        """
    )
    h2("Шаблон enum flags")
    code(
        """
enum UnwindAnom {
    UA_TRUNCATED = 1u << 1,
    UA_BAD_OPCODE = 1u << 2
};

out->anomalies |= UA_TRUNCATED;

Перевод:
  anomalies - это набор битов.
  Можно хранить несколько проблем в одном uint32_t.
        """
    )
    h2("Шаблон cleanup")
    code(
        """
free(us_ok);
free(us);
free(rf);
pe_free(&img);
sb_free(&err);
buf_free_owned(owned);

Перевод:
  main завершает владение всеми объектами,
  которые создавались на этапах pipeline.
        """
    )
    h2("Главная мыслительная привычка")
    p(
        "В C строка кода почти всегда делает одно из пяти: проверяет, читает, преобразует, сохраняет, освобождает. "
        "Если ты не можешь отнести строку к одной из этих ролей, остановись и подпиши ее на бумаге."
    )
    pagebreak()


def add_appendix(info: dict[str, dict[str, object]]) -> None:
    h1("17. Приложение: карта функций")
    p(
        "Эта карта автоматически извлечена из текущих исходников. Используй ее как навигатор: сначала пойми публичные функции из headers, "
        "затем переходи к static helpers внутри `.c`."
    )
    for rel, meta in info.items():
        funcs = meta.get("functions") or []
        h2(rel)
        p(f"Размер: {meta['lines']} строк, {meta['bytes']} bytes.")
        if funcs:
            bullets([", ".join(funcs[i : i + 6]) for i in range(0, len(funcs), 6)])
        else:
            p("Функции не извлечены или файл является конфигурацией/данными.")
    pagebreak()


def add_glossary() -> None:
    h1("18. Глоссарий")
    p(
        "Глоссарий лучше читать дважды: первый раз до реализации, чтобы не пугаться терминов, второй раз после `unwind.c`, "
        "когда слова начнут цепляться за конкретные строки кода."
    )
    rows = [[term, definition] for term, definition in GLOSSARY]
    table(["Термин", "Определение"], rows, [42, 126])
    pagebreak()


def add_final_checklists() -> None:
    h1("19. Финальные чеклисты")
    h2("Перед тем как считать свой повтор проекта завершенным")
    bullets(
        [
            "Ты можешь собрать debug и release.",
            "Ты можешь объяснить, почему `Buf` хранит size рядом с pointer.",
            "Ты можешь вручную перевести хотя бы один RVA в file offset.",
            "Ты можешь прочитать одну `RUNTIME_FUNCTION` entry из hex bytes.",
            "Ты можешь объяснить, почему `CountOfCodes` округляется до even slots для tail.",
            "Ты можешь назвать хотя бы пять anomaly flags и условия их установки.",
            "Ты можешь объяснить разницу score и confidence.",
            "Ты можешь показать, где JSON escaping защищает report.",
            "Ты можешь объяснить, почему dynamic mode нельзя запускать на недоверенном файле без изоляции.",
            "Ты можешь пройти один unit test от bytes до assertions.",
        ]
    )
    h2("Вопросы для самозащиты проекта")
    numbered(
        [
            "Почему проект ограничен PE32+ AMD64?",
            "Почему static mode cross-platform, а dynamic mode Windows-only?",
            "Почему `UNWIND_INFO` V3 не парсится как V1/V2?",
            "Почему output JSON имеет schema version?",
            "Почему score не является вероятностью?",
            "Какие false positives возможны у placement heuristics?",
            "Что делает `--strict-abi` и почему он не повышает score сам по себе?",
            "Как проект защищается от out-of-bounds чтения?",
            "Как dynamic collector ставит и перевзводит breakpoints?",
            "Что будет, если exception directory unreadable, но пользователь запросил JSON?",
        ]
    )
    h2("Последнее напутствие")
    p(
        "Самый полезный способ учить C на этом проекте - каждый день оставлять после себя работающий маленький инвариант. "
        "Сегодня безопасно читаются bytes. Завтра мапится RVA. Потом декодируется один unwind slot. Потом появляется один finding. "
        "Так большой системный проект перестает быть монолитом и становится цепочкой понятных побед."
    )


def footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("DejaVu", 7.2)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    width, height = A4
    canvas.drawString(18 * mm, 10 * mm, "МОЕ ПОВТОРЕНИЕ ПРОЕКТА - EH/Unwind Analyzer")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"стр. {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
    canvas.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
    canvas.restoreState()


def build() -> None:
    global ST
    register_fonts()
    ST = styles()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    info = source_info()
    add_title()
    add_toc()
    add_project_map(info)
    add_c_bootcamp()
    add_domain_theory()
    add_architecture_deep()
    add_architecture_blocks_deep()
    add_build_plan()
    add_deep_file_manual()
    add_incremental_versions()
    add_module_chapters()
    add_rebuild_schedule()
    add_practice_workbook()
    add_daily_deep_plan()
    add_error_atlas()
    add_function_question_cards(info)
    add_testing_chapter()
    add_line_by_line_methods()
    add_appendix(info)
    add_glossary()
    add_final_checklists()

    doc = SimpleDocTemplate(
        str(OUT_PDF),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="МОЕ ПОВТОРЕНИЕ ПРОЕКТА",
        author="Codex",
        subject="Учебник для повторения EH/Unwind Analyzer руками",
    )
    doc.build(STORY, onFirstPage=footer, onLaterPages=footer)
    SOURCE_SNAPSHOT.write_text("\n".join(TEXT_SNAPSHOT), encoding="utf-8")
    print(OUT_PDF)
    print(SOURCE_SNAPSHOT)


if __name__ == "__main__":
    os.chdir(ROOT)
    build()
