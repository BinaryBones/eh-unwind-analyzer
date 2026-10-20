#!/usr/bin/env python3
"""Append a sourced competitor study to the Russian defense Q&A PDF."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
BASE_SOURCE = ROOT / "docs/ru/EH_Unwind_Analyzer_Банк_вопросов_и_ответов_для_защиты.pdf"
TARGET = ROOT / "docs/ru/EH_Unwind_Analyzer_Защита_проекта.pdf"
WORK = Path("/tmp/ehua-competition-work")
FRONT = WORK / "defense_front_matter.pdf"
APPENDIX = WORK / "competition_appendix.pdf"
MERGED = WORK / "defense_qa_with_competition.pdf"

FONT_DIR = Path("/System/Library/Fonts/Supplemental")
pdfmetrics.registerFont(TTFont("Arial", str(FONT_DIR / "Arial.ttf")))
pdfmetrics.registerFont(TTFont("Arial-Bold", str(FONT_DIR / "Arial Bold.ttf")))
pdfmetrics.registerFont(TTFont("Arial-Italic", str(FONT_DIR / "Arial Italic.ttf")))
pdfmetrics.registerFontFamily(
    "Arial",
    normal="Arial",
    bold="Arial-Bold",
    italic="Arial-Italic",
    boldItalic="Arial-Bold",
)

NAVY = colors.HexColor("#14243F")
BLUE = colors.HexColor("#1769D2")
CYAN = colors.HexColor("#16ACC1")
PALE_BLUE = colors.HexColor("#EAF2FE")
PALE_CYAN = colors.HexColor("#EAF8FB")
PALE_GREEN = colors.HexColor("#EAF7F1")
GREEN = colors.HexColor("#16845B")
PALE_AMBER = colors.HexColor("#FFF4DF")
AMBER = colors.HexColor("#A46711")
PALE_RED = colors.HexColor("#FDECEC")
RED = colors.HexColor("#BE3535")
PURPLE = colors.HexColor("#6548C8")
GRID = colors.HexColor("#B8C7D9")
TEXT = colors.HexColor("#182235")
MUTED = colors.HexColor("#58687E")
WHITE = colors.white

PAGE_W, PAGE_H = A4
LEFT = 18 * mm
RIGHT = 18 * mm
TOP = 19 * mm
BOTTOM = 17 * mm
CONTENT_W = PAGE_W - LEFT - RIGHT

styles = getSampleStyleSheet()
BODY = ParagraphStyle(
    "BodyRU",
    parent=styles["BodyText"],
    fontName="Arial",
    fontSize=9.2,
    leading=13.0,
    textColor=TEXT,
    spaceAfter=5,
)
SMALL = ParagraphStyle(
    "SmallRU",
    parent=BODY,
    fontSize=8.1,
    leading=10.7,
    spaceAfter=3,
)
TINY = ParagraphStyle(
    "TinyRU",
    parent=BODY,
    fontSize=7.2,
    leading=9.1,
    spaceAfter=1,
)
H1 = ParagraphStyle(
    "H1RU",
    parent=styles["Heading1"],
    fontName="Arial-Bold",
    fontSize=17,
    leading=20,
    textColor=BLUE,
    spaceBefore=0,
    spaceAfter=8,
)
H2 = ParagraphStyle(
    "H2RU",
    parent=styles["Heading2"],
    fontName="Arial-Bold",
    fontSize=12.2,
    leading=15,
    textColor=NAVY,
    spaceBefore=8,
    spaceAfter=5,
)
H3 = ParagraphStyle(
    "H3RU",
    parent=styles["Heading3"],
    fontName="Arial-Bold",
    fontSize=10.2,
    leading=12.4,
    textColor=NAVY,
    spaceBefore=5,
    spaceAfter=3,
)
LEAD = ParagraphStyle(
    "LeadRU",
    parent=BODY,
    fontName="Arial-Bold",
    fontSize=10,
    leading=14,
    alignment=TA_LEFT,
)
TABLE_HEAD = ParagraphStyle(
    "TableHeadRU",
    parent=SMALL,
    fontName="Arial-Bold",
    fontSize=7.3,
    leading=8.7,
    textColor=WHITE,
    alignment=TA_CENTER,
)
TABLE_CELL = ParagraphStyle(
    "TableCellRU",
    parent=SMALL,
    fontSize=7.2,
    leading=8.8,
    spaceAfter=0,
)
TABLE_CENTER = ParagraphStyle(
    "TableCenterRU",
    parent=TABLE_CELL,
    alignment=TA_CENTER,
)
SOURCE = ParagraphStyle(
    "SourceRU",
    parent=SMALL,
    fontSize=7.8,
    leading=10.2,
    wordWrap="CJK",
    textColor=TEXT,
)
QUESTION = ParagraphStyle(
    "QuestionRU",
    parent=BODY,
    fontName="Arial-Bold",
    fontSize=9.1,
    leading=12,
    textColor=NAVY,
    spaceAfter=3,
)
ANSWER = ParagraphStyle(
    "AnswerRU",
    parent=BODY,
    fontSize=8.7,
    leading=12,
    spaceAfter=0,
)


def p(text: str, style: ParagraphStyle = BODY) -> Paragraph:
    return Paragraph(text, style)


def bullets(items: Iterable[str], style: ParagraphStyle = BODY) -> list[Paragraph]:
    return [p(f"•&nbsp;&nbsp;{item}", style) for item in items]


def callout(title: str, text: str, kind: str = "blue") -> Table:
    palette = {
        "blue": (PALE_BLUE, BLUE),
        "green": (PALE_GREEN, GREEN),
        "amber": (PALE_AMBER, AMBER),
        "red": (PALE_RED, RED),
        "cyan": (PALE_CYAN, CYAN),
    }
    bg, border = palette[kind]
    table = Table(
        [[p(f"<b>{title}</b>", SMALL)], [p(text, SMALL)]],
        colWidths=[CONTENT_W],
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("TEXTCOLOR", (0, 0), (-1, 0), border),
                ("BOX", (0, 0), (-1, -1), 0.9, border),
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def comparison_table(headers: list[str], rows: list[list[str]], widths: list[float]) -> Table:
    data = [[p(h, TABLE_HEAD) for h in headers]]
    for row in rows:
        data.append([p(cell, TABLE_CELL) for cell in row])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for idx in range(1, len(data)):
        if idx % 2 == 0:
            commands.append(("BACKGROUND", (0, idx), (-1, idx), colors.HexColor("#F3F6FA")))
    table.setStyle(TableStyle(commands))
    return table


def competitor_card(
    name: str,
    category: str,
    facts: str,
    stronger: str,
    weaker: str,
    conclusion: str,
    sources: str,
) -> KeepTogether:
    rows = [
        [p(f"<b>{name}</b>", LEAD)],
        [p(f"<b>Класс:</b> {category}", SMALL)],
        [p(f"<b>Что подтверждено источниками.</b> {facts}", SMALL)],
        [p(f"<b>Где аналог сильнее.</b> {stronger}", SMALL)],
        [p(f"<b>Где EH/Unwind Analyzer сильнее или удобнее.</b> {weaker}", SMALL)],
        [p(f"<b>Итог.</b> {conclusion}", SMALL)],
        [p(f"<b>Источники:</b> {sources}", TINY)],
    ]
    table = Table(rows, colWidths=[CONTENT_W], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PALE_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), NAVY),
                ("BOX", (0, 0), (-1, -1), 0.75, GRID),
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, GRID),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return KeepTogether([table, Spacer(1, 7)])


def qa(number: int, question: str, answer: str, caution: str | None = None) -> KeepTogether:
    data = [
        [p(f"Вопрос {number}. {question}", QUESTION)],
        [p(f"<font color='#16845B'><b>Ответ.</b></font> {answer}", ANSWER)],
    ]
    if caution:
        data.append([p(f"<font color='#BE3535'><b>Осторожно.</b></font> {caution}", ANSWER)])
    table = Table(data, colWidths=[CONTENT_W], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PALE_BLUE),
                ("BACKGROUND", (0, 1), (-1, -1), WHITE),
                ("BOX", (0, 0), (-1, -1), 0.65, GRID),
                ("LINEBELOW", (0, 0), (-1, 0), 0.45, GRID),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return KeepTogether([table, Spacer(1, 6)])


SOURCES = [
    (
        "S1",
        "Microsoft Learn — x64 exception handling",
        "https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64",
        "Нормативная модель RUNTIME_FUNCTION, UNWIND_INFO и раскрутки x64.",
    ),
    (
        "S2",
        "Microsoft Learn — x64 exception handling: UNWIND_INFO version 3",
        "https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#version-3",
        "Опубликованное 26 мая 2026 года расширение UNWIND_INFO v3.",
    ),
    (
        "S3",
        "Microsoft Learn — PE format",
        "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
        "Официальное описание PE/COFF, секций и exception directory.",
    ),
    (
        "S4",
        "Microsoft Learn — WinDbg .fnent",
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-fnent--display-function-table-entry-",
        "Штатный просмотр function table entry и unwind information.",
    ),
    (
        "S5",
        "LIEF documentation — PE exceptions",
        "https://lief.re/doc/latest/formats/pe/exceptions.html",
        "API-модель исключений PE и RuntimeFunctionX64.",
    ),
    (
        "S6",
        "LIEF 0.17.0 changelog",
        "https://lief.re/doc/stable/changelog.html#version-0-17-0",
        "Добавленная расширенная поддержка PE exception information.",
    ),
    (
        "S7",
        "LLVM Command Guide — llvm-readobj",
        "https://llvm.org/docs/CommandGuide/llvm-readobj.html",
        "Опция --unwind и машинно-ориентированный просмотр объектных структур.",
    ),
    (
        "S8",
        "PE-bear official repository",
        "https://github.com/hasherezade/pe-bear",
        "Кроссплатформенный визуальный инструмент исследования PE.",
    ),
    (
        "S9",
        "pestudio official product page",
        "https://www.winitor.com/tools/pestudio/current/pestudio.html",
        "Широкая статическая PE-malware triage без выполнения файла.",
    ),
    (
        "S10",
        "pestudio features",
        "https://www.winitor.com/tools/pestudio/current/pestudio-features.pdf",
        "Заявленные возможности, indicators и интеграции продукта.",
    ),
    (
        "S11",
        "4n4lDetector official repository",
        "https://github.com/4n4lDetector/4n4lDetector",
        "Широкий PE-анализатор аномалий, packer/anti-debug и подозрительных свойств.",
    ),
    (
        "S12",
        "Hex-Rays — exception handlers",
        "https://docs.hex-rays.com/user-guide/user-interface/menu-bar/edit/functions",
        "Работа IDA с exception-handler metadata и границами функций.",
    ),
    (
        "S13",
        "Hex-Rays IDA 9.2 release notes",
        "https://docs.hex-rays.com/release-notes/9_2",
        "Текущее развитие широкого коммерческого reverse-engineering комплекса.",
    ),
    (
        "S14",
        "Ghidra official repository",
        "https://github.com/NationalSecurityAgency/ghidra",
        "Полноценная платформа software reverse engineering с анализом кода.",
    ),
    (
        "S15",
        "Binary Ninja documentation",
        "https://docs.binary.ninja/",
        "Интерактивный анализ, API, промежуточные представления и автоматизация.",
    ),
    (
        "S16",
        "radare2 official repository",
        "https://github.com/radareorg/radare2",
        "Кроссплатформенный CLI/framework для disassembly, debugging и binary analysis.",
    ),
    (
        "S17",
        "x64dbg official site",
        "https://x64dbg.com/",
        "Windows user-mode debugger с plugin/script ecosystem.",
    ),
    (
        "S18",
        "Microsoft BinSkim official repository",
        "https://github.com/microsoft/binskim",
        "Static binary scanner для security/compiler settings и SARIF.",
    ),
    (
        "S19",
        "Mandiant capa official repository",
        "https://github.com/mandiant/capa",
        "Rule-based определение возможностей исполняемого кода.",
    ),
    (
        "S20",
        "Detect It Easy official repository",
        "https://github.com/horsicq/Detect-It-Easy",
        "Определение типов, packer/compiler и сигнатурно-эвристическое исследование файлов.",
    ),
    (
        "S21",
        "pefile official repository",
        "https://github.com/erocarrera/pefile",
        "Python-библиотека чтения и исследования PE.",
    ),
    (
        "S22",
        "readpe official repository",
        "https://github.com/mentebinaria/readpe",
        "Набор CLI-инструментов и библиотека для PE.",
    ),
    (
        "S23",
        "PE Tree official repository",
        "https://github.com/blackberry/pe_tree",
        "Визуализатор PE на базе pefile, доступный отдельно и в IDA/Ghidra.",
    ),
    (
        "S24",
        "XPEViewer official repository",
        "https://github.com/horsicq/XPEViewer",
        "Кроссплатформенный viewer/editor PE.",
    ),
    (
        "S25",
        "Dissect documentation — PE exception directory",
        "https://docs.dissect.tools/en/stable/api/dissect/executable/pe/exception.html",
        "Программный доступ к AMD64 exception directory и unwind records.",
    ),
    (
        "S26",
        "DFRWS — Stack Trace Analysis of Large Scale Android Applications",
        "https://dfrws.org/presentation/stack-trace-analysis-of-large-scale-android-applications/",
        "Исследовательский пример криминалистического использования unwind/stack metadata.",
    ),
]


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 9 * mm, PAGE_W, 9 * mm, stroke=0, fill=1)
    canvas.setFillColor(CYAN)
    canvas.rect(0, PAGE_H - 9 * mm, 43 * mm, 1.4 * mm, stroke=0, fill=1)
    canvas.setFont("Arial", 6.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(LEFT, 7.2 * mm, "EH/Unwind Analyzer · подготовка к защите")
    canvas.drawRightString(
        PAGE_W - RIGHT,
        7.2 * mm,
        f"Страница {30 + doc.page}",
    )
    canvas.restoreState()


def front_header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 9 * mm, PAGE_W, 9 * mm, stroke=0, fill=1)
    canvas.setFillColor(CYAN)
    canvas.rect(0, PAGE_H - 9 * mm, 43 * mm, 1.4 * mm, stroke=0, fill=1)
    canvas.setFont("Arial", 6.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(LEFT, 7.2 * mm, "EH/Unwind Analyzer · полная защита проекта")
    canvas.drawRightString(PAGE_W - RIGHT, 7.2 * mm, f"Страница {doc.page}")
    canvas.restoreState()


def build_front_matter() -> None:
    story = [
        Spacer(1, 24 * mm),
        p("EH/UNWIND ANALYZER", ParagraphStyle(
            "CoverTitle",
            parent=H1,
            fontSize=25,
            leading=29,
            alignment=TA_CENTER,
            textColor=NAVY,
            spaceAfter=8,
        )),
        p("ПОЛНАЯ ЗАЩИТА ПРОЕКТА", ParagraphStyle(
            "CoverSubtitle",
            parent=LEAD,
            fontSize=15,
            leading=19,
            alignment=TA_CENTER,
            textColor=BLUE,
            spaceAfter=15,
        )),
        callout(
            "От технической основы до ответов жёсткой комиссии",
            "Теория и устройство проекта, 27 признаков и 12 внутренних аномалий, точность и "
            "ограничения модели, динамический анализ, архитектура, тестирование, аналоги, рынок, "
            "актуальность, новизна, самостоятельность реализации, сценарий выступления, демонстрация "
            "и 332 подготовленных вопроса с ответами.",
            "cyan",
        ),
        Spacer(1, 15 * mm),
        p(
            "<b>Версия проекта:</b> 1.0.0<br/>"
            "<b>Дата актуализации:</b> 9 июня 2026 года<br/>"
            "<b>Область:</b> PE32+ AMD64, UNWIND_INFO v1/v2; Windows-only dynamic collector",
            ParagraphStyle(
                "CoverMeta",
                parent=BODY,
                fontSize=9.5,
                leading=14,
                alignment=TA_CENTER,
                textColor=MUTED,
            ),
        ),
        Spacer(1, 12 * mm),
        callout(
            "Главный принцип защиты",
            "Не преувеличивать возможности. Сильная позиция строится на конкретных invariants, "
            "воспроизводимых результатах, честном разграничении фактов и эвристик и готовности "
            "показать, как проверяется каждое утверждение.",
            "green",
        ),
        PageBreak(),
        p("Содержание полной защиты", H1),
        comparison_table(
            ["Раздел", "Содержание"],
            [
                ["1–5", "Постановка, термины, PE32+, RUNTIME_FUNCTION/UNWIND_INFO, parser."],
                ["6–8", "27 признаков, score/confidence, динамика, reports и Ghidra."],
                ["9–12", "Архитектура, тестирование, платформы, базовые провокационные вопросы."],
                ["13", "Аналоги, конкуренты, SWOT, источники и 36 вопросов."],
                ["14", "Актуальность, новизна, значимость и 30 вопросов."],
                ["15", "Рынок, собственное ядро, open source, AI/ML и 42 враждебных вопроса."],
                ["16", "Обоснование 27 findings, coverage, точность модели и 42 вопроса."],
                ["17", "Слайды, текст выступления, тактика ответа и финальная памятка."],
                ["18–22", "Демонстрация, fallback, карта доказательств, чек-листы и итоговая позиция."],
            ],
            [27 * mm, CONTENT_W - 27 * mm],
        ),
        Spacer(1, 8),
        p("Ключевые проверенные показатели", H2),
        comparison_table(
            ["Показатель", "Значение", "Правильная интерпретация"],
            [
                ["Итоговые findings", "27", "Независимые аналитические classes, не все low-level checks."],
                ["Внутренние UA_* reasons", "12", "Детали декодирования UNWIND_INFO."],
                ["Вопросы и ответы", "332", "От основ до hostile defense."],
                ["Benign corpus", "106/106", "Наблюдаемая specificity 100% только на выбранном corpus."],
                ["Runtime functions", "174 795", "Разобраны без parse failures/structural anomalies на corpus."],
                ["Extended mutations", "1 000", "Robustness, не statistical detection accuracy."],
                ["Windows reports", "124/124", "Schema/semantic-valid в выполненной validation."],
            ],
            [39 * mm, 25 * mm, CONTENT_W - 64 * mm],
        ),
        Spacer(1, 8),
        callout(
            "Как пользоваться документом",
            "Сначала изучите разделы 1–17. Перед защитой повторите 17.3, 19, 20 и 21. На прямой "
            "вопрос отвечайте первым предложением соответствующего ответа; подробность добавляйте "
            "только после уточнения комиссии.",
            "blue",
        ),
    ]
    doc = SimpleDocTemplate(
        str(FRONT),
        pagesize=A4,
        leftMargin=LEFT,
        rightMargin=RIGHT,
        topMargin=TOP,
        bottomMargin=BOTTOM,
        title="EH/Unwind Analyzer: полная защита проекта",
        author="EH/Unwind Analyzer project",
    )
    doc.build(story, onFirstPage=front_header_footer, onLaterPages=front_header_footer)


def build_story() -> list:
    story: list = []

    story.extend(
        [
            Spacer(1, 15 * mm),
            p("13. Аналоги, конкуренты и рыночное позиционирование", H1),
            p(
                "Исследование публично доступных зарубежных и российских инструментов, "
                "которые пересекаются с EH/Unwind Analyzer по разбору PE, x64 exception/unwind, "
                "поиску аномалий, reverse engineering или динамической проверке.",
                LEAD,
            ),
            Spacer(1, 5 * mm),
            callout(
                "Главный вывод",
                "В исследованном наборе официальных документов и первичных репозиториев не найден "
                "готовый инструмент, который повторяет всю комбинацию проекта: строгий разбор "
                "RUNTIME_FUNCTION/UNWIND_INFO, объяснимые cross-record эвристики, score и confidence, "
                "ослабляющие правила, автономные JSON/HTML/CSV-отчёты и корреляцию с Windows runtime "
                "events. Однако отдельные части этой комбинации реализованы у более зрелых и гораздо "
                "более широких продуктов. Поэтому корректное позиционирование — специализированный "
                "аналитический модуль, а не замена IDA, Ghidra, LIEF или WinDbg.",
                "cyan",
            ),
            Spacer(1, 5 * mm),
            p("<b>Дата среза:</b> 9 июня 2026 года.", BODY),
            p(
                "<b>Версия сравниваемого проекта:</b> 1.0.0. Состояние функций сверено с "
                "README.md, docs/ARCHITECTURE.md, docs/PRODUCT_READINESS.md, "
                "docs/evidence_matrix.md и исходным кодом.",
                BODY,
            ),
            p(
                "<b>Ограничение:</b> фраза «весь интернет» не может означать буквально все "
                "существующие закрытые продукты и внутренние разработки. Исследование охватывает "
                "репрезентативный набор публично документированных решений и не утверждает, что "
                "неизвестных или непубличных аналогов не существует.",
                BODY,
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.1. Методика поиска и правила честного сравнения", H1),
            p(
                "Поиск выполнен по официальной документации Microsoft, страницам производителей, "
                "официальным репозиториям и документации проектов. Блоги-агрегаторы, рекламные "
                "пересказы и случайные списки «лучших PE tools» не использовались как основание для "
                "функциональных утверждений.",
                BODY,
            ),
            p("Сравнение проводилось в четыре шага:", H2),
            *bullets(
                [
                    "<b>Функциональное пересечение:</b> умеет ли продукт читать PE exception "
                    "directory, RUNTIME_FUNCTION и UNWIND_INFO.",
                    "<b>Аналитическая глубина:</b> только показывает поля или выявляет нарушения "
                    "между записями, секциями, правами памяти и обработчиками.",
                    "<b>Эксплуатационная форма:</b> GUI, CLI, библиотека, API, форматы отчётов, "
                    "автоматизация, работа без облака.",
                    "<b>Доказательность:</b> объясняются ли причины вывода, есть ли score, "
                    "confidence, provenance и ручные шаги проверки.",
                ]
            ),
            callout(
                "Что считается фактом",
                "Фактом считается только возможность, явно заявленная в официальной документации "
                "или видимая в первичном репозитории. Формулировки «не найдено», «не заявлено» и "
                "«проект выглядит сильнее» являются аналитическими выводами, а не доказательством "
                "полного отсутствия функции в любом плагине или закрытой редакции.",
                "blue",
            ),
            p("Критерии сравнения", H2),
            comparison_table(
                ["Критерий", "Что именно оценивается"],
                [
                    ["Фокус EH/Unwind", "Насколько предметная область является центральной, а не побочной."],
                    ["Глубина структуры", "Границы, сортировка, overlaps, chains, handlers, opcodes, placement."],
                    ["Объяснимость", "Коды findings, причины, affected count, representative RVA, manual steps."],
                    ["Автоматизация", "CLI/API, стабильная schema, пакетная обработка, CI/БД-интеграция."],
                    ["Динамика", "Фактические exceptions, handler hits, registrations, dynamic function tables."],
                    ["Анализ кода", "Disassembly, decompilation, CFG, data flow, сопоставление с прологом."],
                    ["Зрелость", "История проекта, ecosystem, plugins, поддержка форматов и архитектур."],
                ],
                [42 * mm, CONTENT_W - 42 * mm],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.2. Карта конкурентного поля", H1),
            p(
                "Один общий список конкурентов вводит в заблуждение. Ниже инструменты разделены по "
                "тому, какую часть рабочего процесса они действительно перекрывают.",
                BODY,
            ),
            comparison_table(
                ["Уровень", "Инструменты", "Конкурируют за"],
                [
                    [
                        "Ближайшие технические аналоги",
                        "LIEF, llvm-readobj, Dissect PE",
                        "Декодирование exception/unwind structures и программный доступ к ним.",
                    ],
                    [
                        "Широкие PE triage/viewers",
                        "pestudio, PE-bear, 4n4lDetector, pefile, readpe, PE Tree, XPEViewer",
                        "Первичный осмотр PE, indicators, секции, imports, packer и структурные свойства.",
                    ],
                    [
                        "Reverse-engineering platforms",
                        "IDA, Ghidra, Binary Ninja, radare2",
                        "Время аналитика, интерактивное исследование кода, функций и control flow.",
                    ],
                    [
                        "Dynamic/debugging",
                        "WinDbg, x64dbg, встроенные debuggers IDA/Binary Ninja",
                        "Наблюдение реального выполнения, exceptions, breakpoints и stack unwinding.",
                    ],
                    [
                        "Смежная security-аналитика",
                        "BinSkim, capa, Detect It Easy",
                        "Security posture, capabilities, compiler/packer identification и triage.",
                    ],
                ],
                [36 * mm, 58 * mm, CONTENT_W - 94 * mm],
            ),
            Spacer(1, 7),
            callout(
                "Кто является самым близким конкурентом",
                "<b>LIEF</b> ближе всего по глубине программного представления PE x64 exceptions. "
                "<b>pestudio и 4n4lDetector</b> ближе по идее автоматического PE triage и indicators. "
                "<b>IDA/Ghidra</b> ближе по конечной аудитории. <b>WinDbg/x64dbg</b> ближе по "
                "динамическому подтверждению. Но ни один из них нельзя честно назвать полным прямым "
                "аналогом всей системы.",
                "green",
            ),
            p("Корректная рыночная формулировка", H2),
            p(
                "EH/Unwind Analyzer — узкоспециализированный explainable triage-инструмент для "
                "Windows PE32+ AMD64 exception/unwind metadata. Он располагается между библиотекой "
                "форматного разбора, PE anomaly scanner и reverse-engineering workflow: автоматически "
                "выделяет подозрительные места и передаёт их человеку или внешней платформе.",
                LEAD,
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.3. Сводная функциональная матрица", H1),
            p(
                "Обозначения: <b>++</b> — центральная и развитая возможность; <b>+</b> — имеется или "
                "достигается штатными средствами; <b>±</b> — частично, косвенно или требует "
                "дополнительной настройки; <b>—</b> — в исследованной официальной документации не "
                "заявлено как готовая функция.",
                SMALL,
            ),
            comparison_table(
                ["Инструмент", "EH/UW parse", "Аномалии", "Code RE", "Dynamic", "Schema/CLI", "Фокус"],
                [
                    ["EH/Unwind Analyzer", "++", "++", "—", "+", "++", "Узкий"],
                    ["LIEF", "++", "±", "—", "—", "++", "Библиотека"],
                    ["llvm-readobj", "+", "—", "—", "—", "+", "Инспекция"],
                    ["Dissect PE", "+", "—", "—", "—", "++", "Библиотека"],
                    ["pestudio", "±", "+", "—", "—", "±", "PE triage"],
                    ["PE-bear", "±", "±", "±", "—", "—", "PE viewer"],
                    ["4n4lDetector", "±", "+", "±", "—", "±", "PE anomalies"],
                    ["IDA Pro", "+", "±", "++", "+", "+", "Полный RE"],
                    ["Ghidra", "+", "±", "++", "+", "+", "Полный RE"],
                    ["Binary Ninja", "+", "±", "++", "+", "++", "Полный RE/API"],
                    ["radare2", "±", "±", "++", "+", "++", "RE framework"],
                    ["WinDbg", "+", "—", "++", "++", "+", "Debugger"],
                    ["x64dbg", "±", "—", "++", "++", "+", "Debugger"],
                    ["BinSkim", "—", "+", "—", "—", "++", "Security lint"],
                    ["capa", "—", "+", "++", "—", "++", "Capabilities"],
                    ["Detect It Easy", "—", "+", "±", "—", "+", "Packer/type"],
                ],
                [38 * mm, 18 * mm, 19 * mm, 18 * mm, 18 * mm, 21 * mm, CONTENT_W - 132 * mm],
            ),
            Spacer(1, 7),
            callout(
                "Как читать таблицу",
                "Матрица сравнивает готовые функции «из коробки», а не теоретическую возможность "
                "написать plugin. IDA, Ghidra, Binary Ninja и radare2 программируемы, поэтому почти "
                "любой узкий анализ можно реализовать расширением. Это не отменяет ценность отдельного "
                "готового инструмента, но снижает технологический барьер для копирования идеи.",
                "amber",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.4. Ближайшие технические аналоги", H1),
            competitor_card(
                "LIEF",
                "кроссплатформенная библиотека C++ с Python/Rust bindings",
                "Документация описывает PE exception information, RuntimeFunctionX64, unwind "
                "opcodes, chained entries и связанные структуры. В версии 0.17.0 поддержка PE "
                "exceptions была существенно расширена.",
                "Гораздо шире поддержка форматов, архитектур и операций чтения/изменения; зрелая API-"
                "экосистема; удобна как фундамент собственного продукта.",
                "Проект выдаёт готовые findings, evidence families, score, confidence, mitigations, "
                "manual validation steps, автономный HTML и Windows runtime evidence. Для LIEF такой "
                "предметный аналитический слой требуется писать отдельно.",
                "Самый близкий конкурент на уровне parser/model, но скорее потенциальный backend или "
                "зависимость, чем законченный конкурент аналитического workflow.",
                "[S5], [S6]",
            ),
            competitor_card(
                "llvm-readobj --unwind",
                "официальная CLI-утилита LLVM для низкоуровневого отображения object-file structures",
                "Command Guide документирует опцию --unwind для показа unwind information.",
                "Надёжная часть LLVM toolchain, удобна для компиляторной диагностики и проверки "
                "сгенерированных объектов; узнаваемый стандартный CLI.",
                "Не формирует специализированную модель аномалий по всему образу, score/confidence, "
                "placement/reuse/dominance findings, динамическую корреляцию и analyst report.",
                "Сильный baseline: комиссия может спросить, почему недостаточно llvm-readobj. Ответ — "
                "он показывает данные, а проект интерпретирует взаимосвязи и приоритизирует проверку.",
                "[S7]",
            ),
            competitor_card(
                "Dissect PE",
                "Python-библиотека forensic tooling",
                "Документация предоставляет программный доступ к AMD64 exception directory и "
                "runtime/unwind records.",
                "Удобна для Python forensic pipelines, быстро интегрируется с другими компонентами "
                "экосистемы Dissect.",
                "Нет заявленного готового набора EH/Unwind findings, engineering score, confidence, "
                "HTML dashboard и Windows runtime collector.",
                "Близкий программный аналог чтения данных, но не самостоятельный explainable detector.",
                "[S25]",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.5. PE viewers и anomaly scanners", H1),
            competitor_card(
                "pestudio",
                "зрелый статический PE malware triage продукт",
                "Официальные материалы описывают inspection PE без запуска, indicators, VirusTotal "
                "интеграцию, сведения о sections/imports/resources/certificates и другие malware-"
                "ориентированные признаки.",
                "Шире охват PE и malware triage, готовый GUI, зрелая пользовательская база, больше "
                "общеизвестных indicators и внешних интеграций.",
                "Проект глубже объясняет именно x64 unwind records, chains, cross-record integrity, "
                "reuse/dominance и выдаёт открыто документированную evidence matrix.",
                "Сильный workflow-конкурент для первичного triage, но не подтверждён как столь же "
                "глубокий специализированный анализатор UNWIND_INFO.",
                "[S9], [S10]",
            ),
            competitor_card(
                "PE-bear",
                "open-source cross-platform PE reversing tool",
                "Репозиторий позиционирует продукт как быстрый и гибкий инструмент исследования и "
                "изменения PE-файлов с визуальным интерфейсом.",
                "Лучше интерактивный просмотр структуры и байтов, удобнее ручная навигация и "
                "визуальное исследование; может использоваться аналитиком ежедневно.",
                "Проект лучше для batch/CI, воспроизводимых JSON reports и автоматического ранжирования "
                "EH/Unwind нарушений по явным правилам.",
                "Не замена, а естественная парная связка: EH/Unwind Analyzer находит адрес и причину, "
                "PE-bear помогает вручную посмотреть файл.",
                "[S8]",
            ),
            competitor_card(
                "4n4lDetector",
                "широкий open-source PE anomaly and malware triage tool",
                "Официальный репозиторий заявляет поиск PE anomalies, packer/anti-debug techniques, "
                "entropy, suspicious imports/sections и другие признаки.",
                "Шире malware-oriented surface и больше типов общих PE сигналов; удобнее для общего "
                "первичного расследования подозрительного файла.",
                "Проект имеет более узкую, формализованную и документированную модель x64 unwind, "
                "отдельные families/mitigations и статико-динамическую корреляцию.",
                "Один из наиболее близких конкурентов по идее anomaly detector, но предметные модели "
                "разные: общий PE/malware triage против EH/Unwind integrity.",
                "[S11]",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.6. Reverse-engineering платформы", H1),
            competitor_card(
                "IDA Pro / Hex-Rays",
                "коммерческая профессиональная reverse-engineering platform",
                "Официальная документация описывает работу с exception handlers, функциями, "
                "disassembly/decompilation и широким набором процессоров и форматов.",
                "Несопоставимо глубже анализ кода: disassembly, decompiler, CFG, types, xrefs, plugins, "
                "debugging и зрелый analyst workflow.",
                "Проект дешевле по вычислительной и организационной сложности, полностью "
                "детерминирован для своей задачи, подходит для пакетного сканирования и сразу выдаёт "
                "формальный JSON/HTML с объяснением каждого сигнала.",
                "IDA — не прямой detector-конкурент, а основная среда ручной верификации. Риск для "
                "проекта: аналогичный анализ можно реализовать IDAPython plugin.",
                "[S12], [S13]",
            ),
            competitor_card(
                "Ghidra",
                "бесплатная open-source software reverse-engineering platform",
                "Официальный репозиторий описывает disassembly, decompilation, graphing, scripting и "
                "совместную работу с широким набором архитектур и форматов.",
                "Глубже восстанавливает функции и контекст кода; имеет большую plugin/script "
                "экосистему; бесплатно решает значительную часть ручного RE.",
                "Проект запускается как компактный CLI, выдаёт готовый explainable assessment и "
                "импортирует найденные функции/комментарии в Ghidra через собственный CSV importer.",
                "Стратегически проект должен позиционироваться как preprocessor и evidence provider "
                "для Ghidra, а не как её замена.",
                "[S14]",
            ),
            competitor_card(
                "Binary Ninja",
                "коммерческая RE platform с сильным API и intermediate languages",
                "Официальная документация описывает интерактивный анализ, API, automation, "
                "intermediate representations и debugger.",
                "Сильнее по program analysis, data flow, scripting ergonomics, UI и возможности "
                "строить собственные анализаторы поверх IL.",
                "Проект проще развернуть как независимый scanner, не требует коммерческой лицензии "
                "для просмотра отчёта и имеет предметно зафиксированные эвристики.",
                "Конкурент за автоматизацию рабочего процесса, но также потенциальный потребитель "
                "JSON/API результатов проекта.",
                "[S15]",
            ),
            competitor_card(
                "radare2",
                "open-source CLI/framework для reverse engineering",
                "Репозиторий заявляет disassembly, debugging, binary analysis, patching и scripting "
                "на множестве платформ.",
                "Шире по форматам и архитектурам, сильнее как интерактивный CLI и программируемая "
                "платформа анализа кода.",
                "Проект даёт более предметный и предсказуемый EH/Unwind report без необходимости "
                "собирать команды и scripts вручную.",
                "Конкурирует за CLI-аудиторию. Главный риск — опытный пользователь может собрать "
                "часть проверок скриптами radare2, но это будет отдельная реализация.",
                "[S16]",
            ),
        ]
    )

    story.extend(
        [
            p("13.7. Debuggers и динамическая проверка", H1),
            competitor_card(
                "WinDbg",
                "официальный Windows debugger",
                "Команда .fnent показывает function table entry и unwind information; debugger "
                "имеет прямой доступ к Windows runtime state, stack и exception events.",
                "Глубже и точнее исследует конкретный процесс, нативно понимает Windows debugging, "
                "символы, memory, stack, exceptions и kernel/user contexts.",
                "Проект автоматизирует массовый статический разбор до запуска, связывает его с "
                "ограниченным runtime collector и выпускает единый переносимый отчёт.",
                "WinDbg сильнее для ручного доказательства конкретного поведения. Проект сильнее как "
                "повторяемый triage pipeline. Они дополняют друг друга.",
                "[S4]",
            ),
            competitor_card(
                "x64dbg",
                "open-source Windows user-mode debugger",
                "Официальный сайт описывает debugger для x64/x32 applications, scripting и plugins.",
                "Значительно удобнее для интерактивного unpacking, stepping, memory inspection, "
                "breakpoints и plugins.",
                "Проект автоматически расставляет предметные точки наблюдения по статически "
                "извлечённым handlers и function-table APIs и формирует schema-validated report.",
                "x64dbg — ручная лаборатория, EH/Unwind Analyzer — узкий автоматизированный sensor. "
                "Для вредоносных файлов обоим нужна изолированная Windows VM.",
                "[S17]",
            ),
            callout(
                "Ограничение собственной динамики",
                "Dynamic collector проекта не заменяет debugger: он фиксирует только заранее "
                "определённые events, handler/API hits и ограниченный RIP trace. Он не выполняет "
                "полное instruction tracing, symbolic execution, unpacking, taint/data-flow analysis "
                "или восстановление всех runtime-generated function tables.",
                "red",
            ),
            p("Практическая конкурентная связка", H2),
            p(
                "Наиболее реалистичный рабочий процесс: проект выполняет быстрый статический triage → "
                "аналитик открывает representative RVA в Ghidra/IDA/PE-bear → при необходимости "
                "подтверждает поведение в WinDbg/x64dbg → JSON сохраняется в БД и связывает артефакты.",
                BODY,
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.8. Смежные security-инструменты", H1),
            competitor_card(
                "Microsoft BinSkim",
                "static binary security scanner",
                "Репозиторий описывает проверку security properties и compiler/linker settings, "
                "масштабируемый анализ и SARIF output.",
                "Зрелая security engineering модель, стандартный SARIF, применение в build pipelines "
                "и проверка защитных свойств binaries.",
                "Проект глубже именно в x64 unwind integrity и runtime evidence; находит те классы "
                "метаданных, которые не являются основной задачей BinSkim.",
                "Смежный CI-конкурент. Полезное направление развития проекта — дополнительный SARIF "
                "export и совместный запуск в security pipeline.",
                "[S18]",
            ),
            competitor_card(
                "Mandiant capa",
                "rule-based capability identification",
                "capa определяет возможности программы по features/rules и работает с executable "
                "code и результатами анализа.",
                "Сильнее отвечает на вопрос «что код умеет делать», имеет развитую rule ecosystem и "
                "malware-analysis recognition.",
                "Проект отвечает на другой вопрос: «корректны ли EH/Unwind structures и насколько "
                "необычно они организованы». Он работает даже до полноценного disassembly.",
                "Не прямой конкурент. Совместный отчёт был бы сильнее: structural metadata evidence "
                "плюс semantic code capabilities.",
                "[S19]",
            ),
            competitor_card(
                "Detect It Easy",
                "file type/compiler/packer identification",
                "Официальный репозиторий описывает signature и heuristic analysis для определения "
                "типов, packers, compilers и других file properties.",
                "Шире и лучше для быстрого определения toolchain/packer и общего file triage.",
                "Проект глубже проверяет внутреннюю согласованность exception/unwind metadata и "
                "формирует адресные findings для ручного анализа.",
                "Смежный front-door tool. Результаты DiE могли бы использоваться как контекст, "
                "смягчающий или усиливающий отдельные эвристики проекта.",
                "[S20]",
            ),
            competitor_card(
                "pefile / readpe / PE Tree / XPEViewer",
                "generic PE libraries and viewers",
                "Первичные проекты предоставляют чтение, отображение или редактирование PE "
                "structures; PE Tree использует pefile и интегрируется с IDA/Ghidra.",
                "Шире базовый PE surface, удобнее как reusable library или visual inspector.",
                "Проект содержит готовую предметную evidence model и dynamic correlation вместо "
                "простого представления полей.",
                "Это инфраструктурные и workflow-аналоги, но не полный detector. Они снижают стоимость "
                "разработки конкурирующего parser frontend.",
                "[S21], [S22], [S23], [S24]",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.9. В чём проект объективно сильнее", H1),
            p(
                "Слово «сильнее» здесь означает преимущество в конкретной узкой задаче, а не общую "
                "победу над более крупным продуктом.",
                BODY,
            ),
            *bullets(
                [
                    "<b>Предметная специализация.</b> Проверяются не только отдельные поля, но и "
                    "отношения между section map, exception directory, RUNTIME_FUNCTION, UNWIND_INFO, "
                    "handler targets, chains, permissions, reuse и dominance.",
                    "<b>Объяснимость.</b> Каждый finding имеет стабильный code, family, severity, "
                    "weight, affected count, representative RVA/section и понятное объяснение.",
                    "<b>Разделение подозрительности и уверенности.</b> Score не выдаётся за вероятность; "
                    "confidence снижается mitigations при слабом, одиночном или маломасштабном сигнале.",
                    "<b>Готовый analyst output.</b> Один запуск создаёт strict JSON, автономный HTML, "
                    "CSV и Ghidra CSV; отчёт содержит SHA-256 и build provenance.",
                    "<b>Static/dynamic bridge.</b> Статические handler/placement findings могут быть "
                    "сопоставлены с handler hits, VEH/VCH/UEF и function-table API activity.",
                    "<b>Кроссплатформенная безопасная статика.</b> Windows binaries можно разбирать на "
                    "Linux/macOS без исполнения; динамика изолирована Windows-only модулем.",
                    "<b>Малый deployment footprint.</b> Компактный C17 CLI легче встроить в backend, "
                    "очередь задач или offline lab, чем полноценную RE platform.",
                    "<b>Прозрачные правила.</b> Evidence matrix и пороги доступны для аудита, "
                    "обсуждения на защите и последующей калибровки.",
                    "<b>Robustness engineering.</b> Bounds checks, atomic reports, schema/semantic "
                    "validation, sanitizer/mutation/fuzz gates уменьшают риск падений на malformed PE.",
                    "<b>Privacy.</b> Анализ не требует загрузки файла в облако; HTML не использует "
                    "сетевые assets.",
                ]
            ),
            callout(
                "Самое защищаемое преимущество",
                "Главное отличие — не сам факт чтения UNWIND_INFO. Его умеют другие библиотеки и "
                "debuggers. Отличие состоит в объединении форматных инвариантов, cross-record "
                "эвристик, понятной evidence model, weakening rules и воспроизводимого отчёта.",
                "green",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.10. В чём проект слабее конкурентов", H1),
            *bullets(
                [
                    "<b>Нет disassembly и decompilation.</b> Инструмент не сравнивает unwind codes с "
                    "реальным прологом/эпилогом и не понимает семантику функции.",
                    "<b>Узкая платформа.</b> Предметная модель ограничена PE32+ AMD64; нет ARM64, "
                    "ARM64EC, x86 SEH, ELF/DWARF CFI, Mach-O compact unwind и kernel-specific models.",
                    "<b>Нет UNWIND_INFO v3.</b> На 9 июня 2026 года parser принимает только версии 1 и "
                    "2; официальный Microsoft v3 будет помечен unsupported/parse failure.",
                    "<b>Эвристики не статистически откалиброваны.</b> Пороги являются engineering "
                    "defaults; нет ROC/precision/recall на большом репрезентативном corpus.",
                    "<b>Недостаточно malicious/protected corpus evidence.</b> Benign compatibility "
                    "подтверждена лучше, чем detection effectiveness на реальных protectors/malware.",
                    "<b>Динамика ограничена.</b> Нет полного trace, emulation, symbolic execution, "
                    "anti-anti-debug, DLL host orchestration и реконструкции всех runtime tables.",
                    "<b>Нет полноценного GUI, project database и collaboration.</b> Крупные платформы "
                    "лучше для длительной ручной работы нескольких аналитиков.",
                    "<b>Нет plugin ecosystem.</b> IDA/Ghidra/Binary Ninja/radare2 расширяются "
                    "сообществом и уже встроены в рабочие процессы.",
                    "<b>Release ещё rc1.</b> Документация проекта сама требует независимый MSVC gate "
                    "перед формальным тегом 1.0.0.",
                    "<b>Низкий network effect.</b> Новый специализированный инструмент должен отдельно "
                    "доказывать качество, поддерживать документацию и завоёвывать доверие.",
                ]
            ),
            callout(
                "Самое опасное слабое место на защите",
                "Нельзя утверждать, что проект «правильно ловит все аномалии» или превосходит "
                "конкурентов по точности. Для такого вывода нужен размеченный comparative benchmark. "
                "Корректно утверждать: реализованные правила детерминированы, объяснимы и проверены на "
                "заявленных наборах; полнота обнаружения не доказана.",
                "red",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.11. Критическое обновление стандарта: UNWIND_INFO v3", H1),
            callout(
                "Факт",
                "Microsoft Learn указывает, что начиная с Windows SDK 10.0.26100.0 определена версия "
                "3 UNWIND_INFO. Страница обновлена 26 мая 2026 года. V3 вводит дополнительные "
                "возможности описания эпилогов через epilog descriptors и расширенный header layout. "
                "Это не гипотетическая будущая идея, а опубликованная текущая спецификация. [S2]",
                "red",
            ),
            p("Что делает текущий parser", H2),
            p(
                "В src/unwind.c явно разрешены только <b>ver == 1 || ver == 2</b>. Любая другая версия "
                "получает UA_VERSION_UNKNOWN и завершает разбор как «Unsupported UNWIND_INFO version». "
                "Следовательно, корректный V3-файл способен получить parse failures и повышенный "
                "heuristic score.",
                BODY,
            ),
            p("Почему это важно для конкурентоспособности", H2),
            *bullets(
                [
                    "Новые MSVC/Windows SDK binaries со временем могут сделать V3 нормальным случаем.",
                    "Без поддержки V3 появится систематический false positive, а не редкая edge case.",
                    "LIEF и крупные RE platforms обновляются независимо; узкий инструмент должен "
                    "оперативно следить за нормативной моделью.",
                    "Документация и книга должны явно фиксировать, какую версию Microsoft spec "
                    "поддерживает конкретный release.",
                ]
            ),
            p("Что требуется сделать", H2),
            comparison_table(
                ["Приоритет", "Работа"],
                [
                    ["P0", "Добавить V3 model/header parsing и отдельные unit fixtures по официальной спецификации."],
                    ["P0", "Не считать V3 повреждением, если структура корректна, даже до полной семантической поддержки."],
                    ["P0", "Добавить binaries, собранные актуальным SDK, в benign compatibility corpus."],
                    ["P1", "Сравнить декодирование V3 с MSVC/WinDbg/LIEF или другим независимым oracle."],
                    ["P1", "Обновить evidence matrix, docs, JSON semantics и defense materials."],
                ],
                [25 * mm, CONTENT_W - 25 * mm],
            ),
            callout(
                "Вывод для релиза",
                "До реализации V3 проект можно выпускать только с явно указанной областью поддержки "
                "«UNWIND_INFO v1/v2». Для заявления «поддерживает современные Windows x64 unwind "
                "metadata» V3 должен стать release gate.",
                "amber",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.12. SWOT-анализ", H1),
            comparison_table(
                ["Сильные стороны", "Слабые стороны"],
                [
                    [
                        "Узкий экспертный фокус; объяснимые findings; cross-record checks; "
                        "JSON/HTML/CSV; статико-динамическая корреляция; offline и cross-platform static.",
                        "Нет V3, disassembly, GUI/DB, статистической калибровки, широкого malicious "
                        "corpus, множества архитектур и зрелой ecosystem.",
                    ],
                ],
                [CONTENT_W / 2, CONTENT_W / 2],
            ),
            Spacer(1, 7),
            comparison_table(
                ["Возможности", "Угрозы"],
                [
                    [
                        "Plugin/API для Ghidra/IDA; SARIF; backend service; V3/ARM64EC; comparison "
                        "with prolog; corpus/ROC; team reports; YARA/capa/DiE context.",
                        "Крупная платформа реализует такой же plugin; новые SDK меняют формат; "
                        "heuristics дают false positives; недостаток corpus подрывает заявления о "
                        "точности; narrow niche ограничивает рынок.",
                    ],
                ],
                [CONTENT_W / 2, CONTENT_W / 2],
            ),
            p("Защитимая конкурентная стратегия", H2),
            *bullets(
                [
                    "<b>Не конкурировать лоб в лоб с RE platforms.</b> Быть scanner/preprocessor, "
                    "который сокращает время до первого содержательного адреса.",
                    "<b>Сделать результат переносимым.</b> JSON Schema, SARIF, REST wrapper, stable "
                    "finding codes и database-friendly metadata.",
                    "<b>Усилить доказательность.</b> Публичный labeled corpus, differential tests, "
                    "benchmark против LIEF/LLVM/WinDbg и статистическая калибровка.",
                    "<b>Поддерживать стандарт.</b> V3 и новые architectures должны отслеживаться как "
                    "release gates, а не случайные будущие улучшения.",
                    "<b>Сохранить прозрачность.</b> Не превращать score в непрозрачную «AI-оценку» без "
                    "проверяемой причины.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("13.13. Приоритетный план усиления продукта", H1),
            comparison_table(
                ["Приоритет", "Улучшение", "Конкурентный эффект"],
                [
                    ["P0", "UNWIND_INFO v3 + regression corpus", "Убирает текущий нормативный пробел и false positives."],
                    ["P0", "Независимый MSVC release gate", "Переводит rc1 в формально подтверждённый 1.0.0."],
                    ["P0", "Differential parser tests с LIEF/LLVM/WinDbg", "Даёт внешний oracle и повышает доверие."],
                    ["P1", "Disassembly-проверка unwind codes против prolog/epilog", "Закрывает главный разрыв с IDA/Ghidra."],
                    ["P1", "Размеченный benign/protector/malware corpus", "Позволяет измерять precision/recall и калибровать thresholds."],
                    ["P1", "SARIF export и стабильный library/API facade", "Упрощает CI, backend и security platform integration."],
                    ["P1", "DLL/PYD host dynamic runner и Unicode Win32 paths", "Расширяет реальную динамическую применимость."],
                    ["P2", "Ghidra/IDA/Binary Ninja plugins", "Встраивает findings в привычный analyst workflow."],
                    ["P2", "ARM64/ARM64EC и x86 SEH models", "Расширяет рынок без смешивания архитектурных инвариантов."],
                    ["P2", "Web UI/БД как отдельный слой", "Даёт collaboration, history, comparison и multi-sample analytics."],
                ],
                [18 * mm, 67 * mm, CONTENT_W - 85 * mm],
            ),
            Spacer(1, 7),
            callout(
                "Что не следует делать первым",
                "Красивый frontend не исправит parser gap, отсутствие benchmark и V3. Сначала нужны "
                "корректность, external oracles и corpus evidence; затем UI и коммерческая упаковка.",
                "amber",
            ),
            p("Минимальный критерий сильной версии 1.0", H2),
            p(
                "Поддержка актуальной Microsoft specification, чистый MSVC/MinGW/Linux/macOS gate, "
                "differential tests, воспроизводимый corpus report, документированные ограничения и "
                "стабильный JSON contract. Это важнее заявления «аналогов нет».",
                LEAD,
            ),
            PageBreak(),
        ]
    )

    questions = [
        (
            183,
            "Есть ли у проекта прямые аналоги?",
            "Полного публично документированного аналога всей комбинации функций в исследованном "
            "наборе не найдено. Ближайшие части реализуют LIEF и LLVM на уровне parsing, pestudio и "
            "4n4lDetector на уровне PE triage, IDA/Ghidra на уровне ручного RE, WinDbg/x64dbg на "
            "уровне динамической проверки.",
            "Не говорить «аналогов в мире нет»: непубличные продукты и плагины невозможно исключить.",
        ),
        (
            184,
            "Кто является главным конкурентом?",
            "Для parser/API — LIEF; для рабочего места реверс-инженера — IDA и Ghidra; для PE triage — "
            "pestudio и 4n4lDetector; для runtime verification — WinDbg и x64dbg. Главный конкурент "
            "зависит от того, какой слой системы сравнивается.",
            None,
        ),
        (
            185,
            "Почему нельзя просто использовать LIEF?",
            "LIEF уже предоставляет сильную объектную модель PE exceptions и может стать основой "
            "аналогичного продукта. Но готовые project-specific findings, evidence families, "
            "confidence mitigations, analyst reports и Windows runtime correlation поверх неё всё "
            "равно требуется реализовать.",
            None,
        ),
        (
            186,
            "Почему нельзя просто использовать llvm-readobj --unwind?",
            "llvm-readobj отображает unwind information как низкоуровневые данные. Проект дополнительно "
            "проверяет взаимные инварианты всего файла, агрегирует нарушения, ранжирует их и выдаёт "
            "машиночитаемый отчёт с шагами ручной проверки.",
            None,
        ),
        (
            187,
            "Чем проект лучше IDA или Ghidra?",
            "Он не лучше в общем reverse engineering. Он быстрее и формальнее решает одну узкую задачу: "
            "пакетно находит EH/Unwind anomalies и выдаёт объяснимый report. IDA/Ghidra намного сильнее "
            "для глубокого анализа кода и ручного подтверждения.",
            "Нельзя называть проект заменой IDA/Ghidra.",
        ),
        (
            188,
            "Чем проект лучше PE-bear или pestudio?",
            "Он глубже специализируется на x64 RUNTIME_FUNCTION/UNWIND_INFO, chains, handlers, reuse, "
            "dominance и placement, а также документирует веса и ослабляющие правила. PE-bear удобнее "
            "для визуального просмотра, pestudio шире для общего malware triage.",
            None,
        ),
        (
            189,
            "В чём уникальное торговое предложение?",
            "Explainable EH/Unwind triage: от bounds-safe parser до адресных findings, score/confidence, "
            "mitigations, JSON/HTML и статико-динамической correlation в одном компактном offline tool.",
            None,
        ),
        (
            190,
            "Можно ли доказать, что проект точнее конкурентов?",
            "Нет, текущих данных для такого утверждения недостаточно. Нужен одинаковый размеченный "
            "corpus, единые критерии, измерение precision/recall, false positives и coverage каждого "
            "инструмента.",
            "Сравнение функций не является сравнением точности.",
        ),
        (
            191,
            "Почему отсутствие полного аналога не доказывает новизну?",
            "Потому что новизна требует анализа научных публикаций, патентов, продуктов и постановки "
            "задачи, а не только поиска похожего executable. Кроме того, всю функциональность можно "
            "теоретически воспроизвести plugin поверх зрелой RE platform.",
            None,
        ),
        (
            192,
            "Какой аналог наиболее опасен как будущий конкурент?",
            "LIEF плюс небольшой аналитический слой — самый реалистичный путь быстро повторить parser "
            "и часть эвристик. Ghidra/IDA/Binary Ninja plugins опасны тем, что сразу попадают в "
            "существующий workflow и используют готовый disassembly context.",
            None,
        ),
        (
            193,
            "Почему крупные платформы ещё не делают то же самое из коробки?",
            "EH/Unwind anomaly triage является узкой задачей относительно общего reverse engineering. "
            "Платформы обычно предоставляют parser, functions, scripts и UI, оставляя предметные "
            "политики detection плагинам и исследователям.",
            None,
        ),
        (
            194,
            "Можно ли встроить проект в Ghidra, IDA или Binary Ninja?",
            "Да. Уже существует консервативный Ghidra CSV importer. Следующий уровень — plugins, "
            "которые запускают core/CLI, проверяют JSON Schema и создают bookmarks/comments/types в "
            "адресном пространстве платформы.",
            None,
        ),
        (
            195,
            "Зачем собственный parser, если есть pefile и LIEF?",
            "Собственный parser уменьшает dependency surface, позволяет точно контролировать bounds "
            "и diagnostics и демонстрирует предметную реализацию. Но для product quality полезны "
            "differential tests против независимых parsers.",
            None,
        ),
        (
            196,
            "Собственный parser — преимущество или риск?",
            "Оба. Преимущество — компактность и полный контроль. Риск — самостоятельная ответственность "
            "за каждый edge case и обновление specification. Поэтому нужны fuzzing, corpus tests и "
            "external oracles.",
            None,
        ),
        (
            197,
            "Что такое differential testing?",
            "Один и тот же corpus разбирается несколькими независимыми реализациями. Расхождения по "
            "ranges, unwind opcodes, handlers и parse status автоматически выделяются и исследуются. "
            "Это не доказывает правоту большинства, но быстро находит несовместимости.",
            None,
        ),
        (
            198,
            "Почему SARIF важен в сравнении с BinSkim?",
            "SARIF является стандартным форматом результатов static analysis и поддерживается "
            "security/developer tooling. JSON проекта богаче для предметной модели, но SARIF export "
            "упростит CI и агрегирование вместе с BinSkim и другими scanners.",
            None,
        ),
        (
            199,
            "Почему проект не использует машинное обучение?",
            "Текущая задача требует объяснимых структурных причин и работает при ограниченном "
            "размеченном corpus. Непрозрачная модель без качественных данных ухудшила бы "
            "доказательность. ML можно добавлять позже как дополнительный ranking layer.",
            None,
        ),
        (
            200,
            "Можно ли назвать score конкурентным преимуществом?",
            "Да, как прозрачную инженерную приоритизацию. Нет, если представлять его вероятностью "
            "атаки или статистически оптимальной оценкой: такой калибровки пока нет.",
            None,
        ),
        (
            201,
            "Как новый UNWIND_INFO v3 влияет на проект?",
            "Это текущий compatibility gap. Parser поддерживает v1/v2 и считает v3 unsupported, поэтому "
            "правильные новые binaries могут получить parse failure и ложный высокий score. Поддержка "
            "v3 должна стать P0 release work.",
            None,
        ),
        (
            202,
            "Почему V3 не был учтён раньше?",
            "Сравниваемая реализация была зафиксирована до публикации обновлённой Microsoft "
            "документации от 26 мая 2026 года. Это нормальный пример того, почему форматный анализатор "
            "нуждается в постоянном specification monitoring.",
            "Не отрицать проблему и не называть V3 несущественной.",
        ),
        (
            203,
            "Можно ли выпускать продукт без V3?",
            "Можно только с чёткой областью поддержки «UNWIND_INFO v1/v2» и известным ограничением. "
            "Для широкого заявления о современных Windows x64 binaries V3 должен быть реализован и "
            "проверен на реальном SDK corpus.",
            None,
        ),
        (
            204,
            "Как проверить реализацию V3?",
            "Нужны unit fixtures по спецификации, binaries актуального MSVC/SDK, negative mutations и "
            "differential comparison с независимым инструментом или WinDbg. Затем повторяются schema, "
            "semantic, sanitizer и corpus gates.",
            None,
        ),
        (
            205,
            "Какое главное преимущество проекта для заказчика?",
            "Он превращает трудоёмкий ручной осмотр EH/Unwind metadata в повторяемый первый проход: "
            "локализует адреса, объясняет причины, сохраняет результаты и передаёт их analyst/backend.",
            None,
        ),
        (
            206,
            "Какое главное ограничение для заказчика?",
            "Инструмент не определяет вредоносность и не заменяет reverse engineer. Для неизвестных "
            "toolchains, protectors и новых format versions findings требуют ручного подтверждения.",
            None,
        ),
        (
            207,
            "Кто целевой пользователь?",
            "Reverse engineers, malware analysts, DFIR specialists, исследователи protectors, "
            "разработчики binary-analysis pipelines и команды, которым нужен batch/offline PE "
            "metadata triage.",
            None,
        ),
        (
            208,
            "Нужен ли проекту GUI для конкуренции?",
            "Для specialist CLI-аудитории не обязательно. Для массового product adoption нужны "
            "удобная навигация, history, comparison и collaboration, но их разумнее реализовать "
            "отдельным frontend/backend слоем поверх стабильного core JSON contract.",
            None,
        ),
        (
            209,
            "Что важнее: GUI или повышение точности?",
            "Сначала корректность parser, V3, differential tests и corpus-based validation. GUI "
            "улучшает удобство, но не исправляет false positives и coverage gaps.",
            None,
        ),
        (
            210,
            "Как защитить проект от копирования?",
            "Сами форматные правила не являются сильным барьером. Защита создаётся качеством corpus, "
            "регрессиями, интеграциями, стабильной schema, скоростью обновления specification и "
            "доверием пользователей.",
            None,
        ),
        (
            211,
            "Можно ли коммерциализировать такой узкий инструмент?",
            "Да как часть larger platform, enterprise scanner, forensic pipeline или expert toolkit. "
            "Отдельный массовый продукт имеет ограниченный рынок, поэтому особенно важны API, "
            "integrations и доказуемое сокращение analyst time.",
            None,
        ),
        (
            212,
            "Как измерить экономический эффект?",
            "На контролируемом наборе дел измерить время до обнаружения relevant RVA, долю файлов без "
            "ручного полного просмотра, число корректно приоритизированных случаев и время подготовки "
            "воспроизводимого отчёта.",
            None,
        ),
        (
            213,
            "Какой benchmark нужен против конкурентов?",
            "Общий corpus из benign, malformed, protected и malicious PE; ground truth на уровне "
            "records; одинаковые категории сигналов; runtime scenarios; метрики parser agreement, "
            "precision/recall, crashes, throughput и analyst time.",
            None,
        ),
        (
            214,
            "Можно ли сравнить проект с антивирусом?",
            "Нет. Антивирус решает задачу обнаружения угроз на множестве signal layers. Проект "
            "исследует одну область metadata и выдаёт forensic/triage evidence, не malware verdict.",
            None,
        ),
        (
            215,
            "Можно ли сравнить проект с capa?",
            "Только как смежные уровни. capa определяет capabilities кода, а проект проверяет "
            "структуру EH/Unwind metadata. Их совместное использование даёт более полный контекст.",
            None,
        ),
        (
            216,
            "Как сформулировать конкурентное преимущество одним предложением?",
            "Это компактный explainable scanner, который превращает сложные Windows x64 EH/Unwind "
            "structures в адресные, проверяемые findings и переносимый отчёт, готовый для ручного RE "
            "и автоматизации.",
            None,
        ),
        (
            217,
            "Какой ответ будет слишком рекламным?",
            "«У проекта нет аналогов, он точнее IDA и обнаруживает скрытые атаки». Эти утверждения не "
            "подтверждены benchmark и смешивают разные классы инструментов.",
            None,
        ),
        (
            218,
            "Какой итоговый вывод о конкурентоспособности?",
            "Проект занимает реальную узкую нишу и имеет сильную explainability/integration model, но "
            "пока уступает зрелым платформам по breadth, code semantics, ecosystem и доказательности "
            "accuracy. После V3, differential tests и corpus benchmark его можно уверенно представлять "
            "как законченный specialist component.",
            None,
        ),
    ]

    story.extend(
        [
            p("13.14. Вопросы комиссии: аналоги и конкуренция", H1),
            p(
                "В этом разделе: 36 вопросов. Отвечайте сравнительно: сначала класс инструмента, затем "
                "конкретное преимущество и обязательное ограничение.",
                SMALL,
            ),
        ]
    )
    for idx, item in enumerate(questions):
        if idx and idx % 6 == 0:
            story.append(PageBreak())
            story.append(p("13.14. Вопросы комиссии: продолжение", H1))
        story.append(qa(*item))

    story.extend(
        [
            PageBreak(),
            p("13.15. Источники и дата проверки", H1),
            p(
                "Все ссылки проверены при подготовке исследования 9 июня 2026 года. Номер [S…] "
                "используется в тексте раздела. Для продуктов с plugin ecosystem отсутствие функции "
                "в документации не доказывает её отсутствия во всех сторонних расширениях.",
                BODY,
            ),
        ]
    )
    split = 14
    for idx, (sid, title, url, purpose) in enumerate(SOURCES):
        if idx == split:
            story.append(PageBreak())
            story.append(p("13.15. Источники: продолжение", H1))
        story.append(
            KeepTogether(
                [
                    p(
                        f"<b>[{sid}] <link href='{url}' color='#1769D2'>{title}</link></b><br/>"
                        f"{purpose}<br/><font color='#58687E'>{url}</font>",
                        SOURCE,
                    ),
                    Spacer(1, 5),
                ]
            )
        )

    story.extend(
        [
            Spacer(1, 8),
            callout(
                "Финальная формула позиционирования",
                "Не «замена профессиональным reverse-engineering платформам» и не «детектор "
                "вредоносности», а специализированный, объяснимый и автоматизируемый слой контроля "
                "Windows x64 EH/Unwind metadata, который сокращает ручной поиск и передаёт "
                "воспроизводимые evidence в Ghidra/IDA/debugger/backend workflow.",
                "cyan",
            ),
        ]
    )

    story.extend(
        [
            PageBreak(),
            p("14. Актуальность, новизна и значимость проекта", H1),
            p(
                "Этот раздел нужен для защиты постановки работы. Он отделяет доказуемую прикладную "
                "новизну конкретной реализации от чрезмерных утверждений о мировой научной новизне.",
                LEAD,
            ),
            callout(
                "Краткая формула актуальности",
                "Windows x64 использует exception/unwind metadata как часть штатного механизма "
                "восстановления стека и обработки исключений. Эти structures одновременно полезны "
                "загрузчику, debugger и reverse engineer, но могут быть повреждены, нестандартно "
                "сформированы, изменены protector/runtime или использоваться как источник "
                "неоднозначности. Ручная проверка большого числа взаимосвязанных записей трудоёмка; "
                "специализированная автоматизация сокращает время анализа и делает выводы "
                "воспроизводимыми.",
                "cyan",
            ),
            p("Почему тема актуальна технически", H2),
            *bullets(
                [
                    "<b>Metadata участвует в выполнении системы.</b> RUNTIME_FUNCTION и UNWIND_INFO "
                    "нужны Windows для table-based exception handling и virtual unwind nonleaf "
                    "functions; это не декоративные поля PE. [S1], [S3]",
                    "<b>Metadata является источником восстановленных функций.</b> Диапазоны, stack "
                    "actions и handler addresses полезны для debugging, crash analysis, forensics и "
                    "reverse engineering.",
                    "<b>Ошибки взаимосвязаны.</b> Отдельно корректное поле ещё не гарантирует "
                    "корректность section mapping, range ordering, chain target, handler placement "
                    "или общей таблицы.",
                    "<b>Объём превышает удобство ручной проверки.</b> Реальные binaries содержат "
                    "сотни и тысячи runtime-function records; проверка overlaps, reuse и dominance "
                    "требует агрегации всего image.",
                    "<b>Формат развивается.</b> Появление официальной UNWIND_INFO v3 в актуальном SDK "
                    "показывает, что проблема совместимости не застыла и требует постоянного "
                    "specification monitoring. [S2]",
                    "<b>Динамические tables дополняют файл.</b> JIT и runtime code могут регистрировать "
                    "function tables через Windows API, поэтому только статическое представление не "
                    "всегда описывает фактическое состояние процесса.",
                ]
            ),
            p("Почему тема актуальна для reverse engineer", H2),
            *bullets(
                [
                    "Повреждённые ranges и chains затрудняют корректное восстановление границ функций.",
                    "Handler targets и registrations помогают найти управляющую логику runtime, "
                    "protector или exception-driven control flow.",
                    "Необычное placement/reuse само по себе не доказывает атаку, но задаёт конкретные "
                    "адреса и гипотезы для ручного исследования.",
                    "Структурированный report позволяет повторить вывод другому аналитику и связать "
                    "его с исходным SHA-256, версией инструмента и конкретным finding.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("14.1. Виды новизны: что можно утверждать", H1),
            comparison_table(
                ["Уровень", "Корректная формулировка", "Что нельзя утверждать без доказательств"],
                [
                    [
                        "Научная",
                        "Предложена формализованная интерпретируемая модель совокупной оценки "
                        "EH/Unwind anomalies с разделением suspiciousness, confidence, evidence "
                        "families и weakening rules.",
                        "«Открыт новый закон», «впервые в мире найден способ разбирать UNWIND_INFO».",
                    ],
                    [
                        "Методическая",
                        "В одном workflow объединены formal invariants, contextual heuristics, "
                        "cross-record combinations, manual validation policy и static/dynamic "
                        "correlation.",
                        "«До проекта никто не проверял exception metadata».",
                    ],
                    [
                        "Программно-техническая",
                        "Создан самостоятельный bounds-safe C17 analyzer с reproducible reports, "
                        "schema, provenance, Ghidra bridge, Windows collector и release tests.",
                        "«У проекта нет ни одного аналога» или «он лучше всех RE tools».",
                    ],
                    [
                        "Прикладная",
                        "Сложные low-level structures преобразуются в адресные объяснимые findings, "
                        "которые сокращают ручной triage и пригодны для backend/БД.",
                        "«По score автоматически устанавливается вредоносность».",
                    ],
                ],
                [24 * mm, 73 * mm, CONTENT_W - 97 * mm],
            ),
            Spacer(1, 7),
            callout(
                "Наиболее безопасная формула новизны для ВКР",
                "Новизна работы состоит не в изобретении формата PE или алгоритма virtual unwind, а в "
                "разработке и реализации целостной объяснимой методики контроля Windows x64 "
                "EH/Unwind metadata: от безопасного разбора и cross-record checks до evidence model, "
                "ослабления неоднозначных эвристик, воспроизводимых отчётов и ограниченной "
                "статико-динамической корреляции.",
                "green",
            ),
            p("Из каких конкретных элементов складывается новизна", H2),
            *bullets(
                [
                    "Пять evidence families вместо плоского списка предупреждений.",
                    "Раздельные score, severity, confidence, evidence level и case strength.",
                    "Mitigations, явно понижающие уверенность при одиночном, малом или placement-only "
                    "сигнале.",
                    "Combined findings для взаимного подтверждения placement, integrity, reuse и "
                    "handler evidence.",
                    "Переход от агрегата к representative RVA/section и manual validation steps.",
                    "Один report contract для static structures и Windows runtime observations.",
                    "Консервативный Ghidra importer, который не разрушает существующие analyst names "
                    "и overlapping functions.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("14.2. Теоретическая и практическая значимость", H1),
            p("Теоретическая и методическая значимость", H2),
            *bullets(
                [
                    "Формализованы проверяемые invariants и отдельно выделены контекстные heuristics.",
                    "Показано, почему suspiciousness нельзя отождествлять с вероятностью атаки.",
                    "Предложена явная схема ослабления вывода при правдоподобном benign explanation.",
                    "Определена traceable цепочка: input bytes → parsed model → finding → assessment → "
                    "manual verification.",
                    "Зафиксирована граница между format validation, anomaly detection и malware "
                    "classification.",
                ]
            ),
            p("Практическая значимость", H2),
            *bullets(
                [
                    "<b>Для реверс-инженера:</b> сокращение пространства ручного поиска до конкретных "
                    "ranges, UNWIND_INFO blobs, handlers и suspicious sections.",
                    "<b>Для DFIR:</b> воспроизводимый offline report с SHA-256 и provenance, который "
                    "можно приложить к исследованию.",
                    "<b>Для разработчика:</b> диагностика malformed compiler/linker output, custom "
                    "runtime tables и несовместимости metadata.",
                    "<b>Для backend:</b> стабильный JSON Schema и deterministic codes позволяют "
                    "сохранять, сравнивать и агрегировать результаты.",
                    "<b>Для образования:</b> проект демонстрирует связь PE layout, ABI, exception "
                    "handling, defensive parsing, heuristics и dynamic validation в одной системе.",
                ]
            ),
            p("Общественная и экономическая значимость", H2),
            p(
                "Проект потенциально снижает стоимость экспертного анализа Windows binaries: "
                "автоматизирует повторяющиеся проверки и сохраняет экспертное время для тех участков, "
                "где действительно требуется disassembly и контекст. Экономический эффект пока не "
                "измерен; его следует доказывать controlled study по analyst time, а не объявлять "
                "заранее.",
                BODY,
            ),
            callout(
                "Критерий полезности",
                "Полезность проекта не зависит от того, классифицирует ли он malware. Даже обнаружение "
                "malformed metadata, локализация broken ranges и подготовка корректного Ghidra import "
                "имеют самостоятельную инженерную ценность.",
                "blue",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("14.3. Логика обоснования ВКР", H1),
            comparison_table(
                ["Элемент", "Формулировка применительно к проекту"],
                [
                    ["Проблема", "Ручной анализ большого массива связанных x64 EH/Unwind records трудоёмок и плохо воспроизводим."],
                    ["Объект", "PE32+ AMD64 images и их metadata обработки исключений/раскрутки стека."],
                    ["Предмет", "Структурные invariants, anomaly signs и методы static/dynamic проверки."],
                    ["Цель", "Создать инструмент безопасного анализа, локализации аномалий и формирования объяснимого отчёта."],
                    ["Методы", "Format parsing, invariant checking, heuristic aggregation, fuzz/testing, Windows debugging."],
                    ["Результат", "C17 core/CLI, reports, schema, evidence model, dynamic collector, Ghidra integration."],
                    ["Новизна", "Целостное explainable объединение указанных методов для узкой предметной области."],
                    ["Практическая ценность", "Сокращение triage и интеграция результатов в ручной и серверный workflow."],
                    ["Ограничение", "Не malware classifier; нет code semantics, V3 и статистически доказанной accuracy."],
                ],
                [34 * mm, CONTENT_W - 34 * mm],
            ),
            Spacer(1, 8),
            p("Причинная цепочка, которую нужно уметь произнести", H2),
            callout(
                "От проблемы к результату",
                "Метаданные необходимы Windows и полезны аналитику → записей много и они связаны → "
                "ручная проверка неполна и занимает время → generic viewers в основном показывают "
                "данные, а full RE platforms требуют ручной работы → поэтому нужен узкий automated "
                "triage → проект реализует parser, invariants, explainable heuristics и reports → "
                "аналитик получает проверяемые адреса и причины, но окончательный вывод делает с "
                "учётом disassembly и runtime context.",
                "cyan",
            ),
            p("Критерии достижения цели", H2),
            *bullets(
                [
                    "Поддерживаемый PE разбирается без выхода за границы и с детальными diagnostics.",
                    "Известные структурные нарушения дают ожидаемые findings.",
                    "Benign corpus не получает необъяснимых structural findings в заявленной модели.",
                    "Каждый отчёт проходит JSON Schema и semantic validation.",
                    "Dynamic evidence не смешивается со static hypothesis и явно ограничено запуском.",
                    "Результат можно передать другому специалисту и воспроизвести по hash/version.",
                ]
            ),
            PageBreak(),
        ]
    )

    relevance_questions = [
        (
            219,
            "В чём актуальность темы?",
            "Windows x64 exception/unwind metadata является рабочей частью ABI и используется для "
            "восстановления стека. Она содержит множество взаимосвязанных записей, вручную проверять "
            "которые долго. Автоматическая локализация структурных противоречий и необычных patterns "
            "сокращает reverse-engineering triage и делает его воспроизводимым.",
            None,
        ),
        (
            220,
            "Почему тема актуальна именно сейчас?",
            "Windows x64 остаётся массовой платформой, JIT/protectors/custom runtimes используют "
            "exception infrastructure, а Microsoft продолжает развивать формат: в SDK 10.0.26100.0 "
            "появилась UNWIND_INFO v3. Это показывает живую, меняющуюся предметную область.",
            None,
        ),
        (
            221,
            "В чём научная новизна?",
            "Корректнее говорить о методической и прикладной новизне: разработана explainable model, "
            "которая объединяет formal invariants, contextual heuristics, evidence families, "
            "mitigations и static/dynamic correlation. Мировая научная новизна требует отдельного "
            "литературного и патентного обзора.",
            "Не утверждать, что проект впервые научился читать UNWIND_INFO.",
        ),
        (
            222,
            "В чём программно-техническая новизна?",
            "В самостоятельной bounds-safe реализации единого workflow: PE/unwind parser, cross-record "
            "analysis, объяснимый assessment, versioned reports, Ghidra bridge, Windows runtime "
            "collector и проверяемые release gates.",
            None,
        ),
        (
            223,
            "В чём практическая значимость?",
            "Проект указывает конкретные ranges, blobs и handlers, которые нужно исследовать, "
            "сохраняет причины и provenance и может передавать JSON в backend/БД. Это уменьшает "
            "объём повторяющейся ручной работы.",
            None,
        ),
        (
            224,
            "В чём теоретическая значимость?",
            "Формализована граница между строгим нарушением, контекстной эвристикой и "
            "комбинированным evidence; отдельно определены suspiciousness, confidence и условия "
            "ослабления вывода.",
            None,
        ),
        (
            225,
            "Почему обычного PE-viewer недостаточно?",
            "Viewer удобен для просмотра полей, но сам по себе не обязан проверять отношения всего "
            "набора records, вычислять ratios/reuse/dominance, применять mitigations и выпускать "
            "стабильный machine-readable assessment.",
            None,
        ),
        (
            226,
            "Почему не ограничиться скриптом?",
            "Скрипт может реализовать отдельную проверку, но законченный инструмент требует общей "
            "модели ошибок, безопасной обработки malformed input, reports, schema, tests, packaging "
            "и воспроизводимого поведения.",
            None,
        ),
        (
            227,
            "Какая проблема решается?",
            "Разрыв между низкоуровневыми raw structures и потребностью аналитика быстро понять, "
            "какие места противоречат формату или выглядят статистически необычно и почему их нужно "
            "проверить.",
            None,
        ),
        (
            228,
            "Как доказано, что проблема существует?",
            "Сама сложность модели следует из Microsoft PE/x64 exception specification: ranges, "
            "unwind codes, tails, handlers и chains взаимозависимы. Практическая трудоёмкость "
            "подтверждается объёмом runtime functions в реальном corpus и необходимостью ручных "
            "инструментов для проверки.",
            None,
        ),
        (
            229,
            "Почему это не искусственно узкая задача?",
            "Узкая задача оправдана высокой глубиной и самостоятельной ценностью metadata для OS, "
            "debugging и reverse engineering. Специализация позволяет сделать проверки объяснимыми "
            "и строгими, не смешивая их с общей malware classification.",
            None,
        ),
        (
            230,
            "Что является объектом и предметом?",
            "Объект — PE32+ AMD64 images и их exception/unwind metadata. Предмет — invariants, "
            "признаки повреждения или необычной организации и методы их статической и динамической "
            "проверки.",
            None,
        ),
        (
            231,
            "Какова цель работы?",
            "Разработать инструмент, который безопасно разбирает Windows x64 EH/Unwind metadata, "
            "выявляет объяснимые anomalies, приоритизирует ручной анализ и выпускает "
            "воспроизводимый отчёт.",
            None,
        ),
        (
            232,
            "Какие задачи были решены для достижения цели?",
            "Изучена нормативная модель, реализованы PE/unwind parsers, evidence matrix, reports, "
            "dynamic collector, Ghidra importer, tests, fuzz/mutation validation и release packaging.",
            None,
        ),
        (
            233,
            "Как понять, что цель достигнута?",
            "Поддерживаемые inputs разбираются безопасно, test anomalies дают ожидаемые findings, "
            "reports валидируются, benign corpus обрабатывается совместимо, а результат содержит "
            "адреса и шаги ручной проверки.",
            None,
        ),
        (
            234,
            "В чём отличие результата от исходной идеи?",
            "Результат вышел за рамки parser prototype: появились evidence families, confidence и "
            "mitigations, JSON Schema, HTML/CSV, Ghidra integration, Windows runtime evidence, "
            "robustness tests и release workflow.",
            None,
        ),
        (
            235,
            "Что нового в системе признаков?",
            "Признаки разделены по происхождению и силе; hard structural defects не смешиваются с "
            "placement/reuse patterns; неоднозначные случаи ослабляются mitigations, а совпадающие "
            "семейства усиливаются combined findings.",
            None,
        ),
        (
            236,
            "Почему объяснимость важна?",
            "Reverse engineer должен проверить вывод в bytes, PE viewer, disassembler или debugger. "
            "Число без finding code, affected count, location и причины невозможно качественно "
            "защитить или воспроизвести.",
            None,
        ),
        (
            237,
            "В чём значимость динамической части?",
            "Она позволяет отличить записанную в файле гипотезу от наблюдения конкретного запуска: "
            "увидеть handler hits, exception events, registrations и dynamic function-table API "
            "activity.",
            None,
        ),
        (
            238,
            "Почему динамика не доказывает всё поведение?",
            "Покрытие зависит от input, environment и времени запуска; anti-debug может изменить "
            "исполнение. Collector наблюдает ограниченные events, а не все возможные пути.",
            None,
        ),
        (
            239,
            "Какова значимость для заказчика?",
            "Заказчик получает repeatable component, который можно встроить в pipeline, хранить "
            "результаты по schema и сравнивать samples, не превращая low-level parser в ручную "
            "экспертную процедуру каждый раз.",
            None,
        ),
        (
            240,
            "Есть ли экономическая эффективность?",
            "Она ожидается за счёт сокращения analyst time, но ещё должна быть измерена. Корректный "
            "эксперимент сравнит время и качество triage с инструментом и без него на одном corpus.",
            None,
        ),
        (
            241,
            "Почему появление V3 подтверждает актуальность, а не провал проекта?",
            "Оно показывает, что стандарт развивается и нужен поддерживаемый analyzer. Одновременно "
            "это честно выявляет текущий gap реализации, который необходимо закрыть до широкого "
            "релиза.",
            None,
        ),
        (
            242,
            "Можно ли считать проект завершённой научной работой при наличии V3 gap?",
            "Да, если цель и область реализации явно ограничены v1/v2, результаты и ограничения "
            "зафиксированы, а V3 представлен как выявленное направление развития. Для заявления о "
            "полной современной product support gap нужно устранить.",
            None,
        ),
        (
            243,
            "Как не преувеличить новизну?",
            "Не заявлять первенство без systematic literature/patent review, не называть parsing "
            "новым алгоритмом и не путать уникальную комбинацию engineering features с абсолютным "
            "отсутствием аналогов.",
            None,
        ),
        (
            244,
            "Какая самая сильная формулировка вклада автора?",
            "Автор формализовал предметную модель EH/Unwind evidence, реализовал её end-to-end в "
            "безопасном кроссплатформенном core, связал с Windows runtime observations и обеспечил "
            "проверяемость результата через tests и reports.",
            None,
        ),
        (
            245,
            "Что в работе можно повторить независимо?",
            "Сборку, regression/unit tests, mutation runs, schema/semantic validation, анализ corpus "
            "и проверку каждого finding по representative RVA и документированному правилу.",
            None,
        ),
        (
            246,
            "Почему воспроизводимость является вкладом?",
            "В binary analysis вывод часто зависит от версии инструмента и ручных действий. Hash, "
            "schema version, build provenance, deterministic rules и automated tests делают "
            "результат проверяемым другим исследователем.",
            None,
        ),
        (
            247,
            "Как проект связан с информационной безопасностью?",
            "Он поддерживает defensive reverse engineering и forensic triage: выявляет malformed или "
            "необычные служебные structures и помогает исследовать exception-driven mechanisms. Он "
            "не является средством эксплуатации.",
            None,
        ),
        (
            248,
            "Какой главный научно-практический результат?",
            "Не отдельный parser и не одна эвристика, а воспроизводимая цепочка от недоверенных bytes "
            "до ограниченного экспертного вывода с явными evidence, uncertainty и дальнейшими "
            "действиями аналитика.",
            None,
        ),
    ]

    story.extend(
        [
            p("14.4. Вопросы комиссии: актуальность и новизна", H1),
            p(
                "В этом разделе: 30 вопросов. Главный принцип ответа — доказывать конкретный вклад, "
                "не подменяя прикладную новизну недоказанным мировым первенством.",
                SMALL,
            ),
        ]
    )
    for idx, item in enumerate(relevance_questions):
        if idx and idx % 6 == 0:
            story.append(PageBreak())
            story.append(p("14.4. Вопросы комиссии: продолжение", H1))
        story.append(qa(*item))

    story.extend(
        [
            PageBreak(),
            p("15. Рыночная нужность и защита инженерных решений", H1),
            p(
                "Здесь проект рассматривается как потенциальный продукт и как инженерная система. "
                "Цель раздела — ответить на вопросы build-vs-buy, открытых компонентов, нейросетей, "
                "лицензирования, стоимости владения и реальной ценности для узкой аудитории.",
                LEAD,
            ),
            callout(
                "Кому и зачем нужен именно такой продукт",
                "Продукт нужен не массовому пользователю, а специалисту или backend pipeline, "
                "которому требуется быстро, одинаково и без облака проверить Windows x64 "
                "EH/Unwind metadata во множестве файлов, получить адресные причины и сохранить "
                "результат по стабильной schema. Полные RE platforms могут выполнить более глубокий "
                "анализ, но требуют больше ручной работы, лицензий, ресурсов и настройки.",
                "cyan",
            ),
            p("Рыночная проблема", H2),
            *bullets(
                [
                    "Generic PE tools распыляют внимание на сотни свойств и не обязаны глубоко "
                    "интерпретировать EH/Unwind consistency.",
                    "Full RE platforms дороги по времени аналитика и избыточны для массового "
                    "предварительного сканирования.",
                    "Библиотеки вроде LIEF дают building blocks, но заказчику всё равно нужно "
                    "разработать policy, reports, validation, deployment и поддержку.",
                    "Облачные scanners не всегда допустимы для закрытых binaries, malware samples и "
                    "материалов расследования.",
                    "Результаты ручного просмотра плохо сравниваются между файлами и экспертами без "
                    "стабильных finding codes и provenance.",
                ]
            ),
            p("Реалистичные продуктовые сегменты", H2),
            comparison_table(
                ["Сегмент", "Потребность", "Форма поставки"],
                [
                    ["Reverse engineering labs", "Batch triage до Ghidra/IDA и адресные handoff notes.", "CLI + HTML + plugins"],
                    ["DFIR / malware analysis", "Offline repeatable evidence и связь с hash/case.", "CLI + JSON + case DB"],
                    ["Software vendors", "Проверка compiler/linker/runtime metadata regressions.", "CI scanner + SARIF"],
                    ["Security platforms", "Дополнительный structural signal в общей системе.", "Library/service + schema"],
                    ["Education/research", "Наблюдаемая связь ABI, PE, parser, heuristics и dynamics.", "Source + corpus + book"],
                ],
                [39 * mm, 71 * mm, CONTENT_W - 110 * mm],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("15.1. Почему сделано собственное ядро", H1),
            callout(
                "Короткий ответ",
                "Не потому, что открытые проекты плохие, а потому что цель работы включает "
                "контролируемый defensive parser, точную предметную модель и доказуемую цепочку "
                "от bytes до finding. Сторонняя библиотека решила бы часть чтения формата, но не "
                "основную исследовательскую задачу.",
                "green",
            ),
            p("Причины build, а не простой сборки из GitHub-компонентов", H2),
            *bullets(
                [
                    "<b>Контроль trust boundary.</b> Parser обрабатывает недоверенные bytes; владение "
                    "bounds checks, integer arithmetic и diagnostics является частью качества.",
                    "<b>Трассируемость решения.</b> Для каждого finding можно показать конкретный "
                    "участок собственной модели и тест, а не непрозрачное поведение dependency.",
                    "<b>Минимальная поверхность.</b> Узкий C17 core имеет меньше зависимостей, проще "
                    "собирается offline и легче поставляется в изолированную лабораторию.",
                    "<b>Стабильность контракта.</b> Внешняя API/ABI и representation стороннего parser "
                    "могут меняться; project schema контролируется самим продуктом.",
                    "<b>Образовательная и квалификационная цель.</b> ВКР должна демонстрировать "
                    "понимание формата, defensive parsing и алгоритмов, а не только orchestration.",
                    "<b>Предметные diagnostics.</b> Проект сохраняет точную parse_error и anomaly mask "
                    "в форме, согласованной с heuristics и reports.",
                ]
            ),
            p("Почему всё же нужно использовать open source", H2),
            *bullets(
                [
                    "Как независимый oracle для differential testing, а не единственную истину.",
                    "Для неключевых задач: JSON Schema validation, build system, test tooling.",
                    "Как optional backend/adapter, если это уменьшит стоимость поддержки без потери "
                    "контроля над evidence model.",
                    "Для изучения edge cases и совместимости, соблюдая лицензии и attribution.",
                ]
            ),
            callout(
                "Честный недостаток собственного parser",
                "Он повышает стоимость сопровождения и риск пропустить новый вариант формата, что "
                "уже видно на UNWIND_INFO v3. Поэтому правильная стратегия — сохранить собственную "
                "модель, но регулярно сравнивать её с LIEF/LLVM/WinDbg и актуальной Microsoft spec.",
                "amber",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("15.2. Почему не используется нейросеть", H1),
            comparison_table(
                ["Фактор", "Детерминированные правила", "Нейросетевая модель"],
                [
                    ["Ground truth", "Формальные invariants выводятся из specification.", "Нужен большой качественно размеченный corpus."],
                    ["Объяснимость", "Причина, адрес, threshold и weight видны.", "Нужны дополнительные методы интерпретации."],
                    ["Воспроизводимость", "Одинаковый input и version дают одинаковый result.", "Зависит от model/version/preprocessing."],
                    ["Новые форматы", "Нужно явно обновить parser/rules.", "Без новых данных также возможен distribution shift."],
                    ["False positives", "Причина видна и может быть ослаблена mitigation.", "Ошибку сложнее технически опровергнуть."],
                    ["Deployment", "Компактный offline C17 binary.", "Weights/runtime/GPU или крупная CPU dependency."],
                    ["Лучшее применение", "Integrity validation и explainable triage.", "Ranking слабых patterns при наличии большого corpus."],
                ],
                [34 * mm, 67 * mm, CONTENT_W - 101 * mm],
            ),
            Spacer(1, 7),
            p("Почему ML сейчас методологически слабее", H2),
            *bullets(
                [
                    "Нет достаточно большого и репрезентативного labeled corpus EH/Unwind anomalies.",
                    "Многие важнейшие проверки являются точными invariants; обучать модель тому, что "
                    "EndAddress должен быть больше BeginAddress, бессмысленно.",
                    "На защите и в forensic workflow нужно объяснить, какие bytes и правило вызвали "
                    "вывод.",
                    "Редкие toolchains и новые SDK создают distribution shift; модель может уверенно "
                    "ошибаться без понятной причины.",
                    "Score проекта не претендует на probability, поэтому правила не маскируются под "
                    "псевдостатистическую модель.",
                ]
            ),
            p("Где ML может быть полезен позже", H2),
            *bullets(
                [
                    "Ранжирование weak/contextual patterns после обязательной formal validation.",
                    "Поиск кластеров необычного reuse/handler behavior в большом corpus.",
                    "Оценка similarity между toolchains/protectors при наличии labels.",
                    "Предложение analyst priority, но не замена findings и raw evidence.",
                ]
            ),
            callout(
                "Правильная архитектура возможного ML",
                "Rules остаются первым обязательным слоем и источником объяснимых features. ML "
                "добавляется отдельным необязательным ranking-компонентом с версией модели, "
                "calibration dataset и возможностью полностью отключить его.",
                "blue",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("15.3. Build-vs-buy, лицензии и supply chain", H1),
            comparison_table(
                ["Вариант", "Плюсы", "Риски"],
                [
                    [
                        "Собственное ядро",
                        "Контроль, компактность, обучение, stable evidence model.",
                        "Стоимость поддержки, новые specs, ответственность за parser bugs.",
                    ],
                    [
                        "LIEF/pefile/Dissect как core",
                        "Зрелый parsing surface, меньше собственного format code.",
                        "Dependency/API/license lifecycle; всё равно нужны heuristics/reports/dynamics.",
                    ],
                    [
                        "Plugin для Ghidra/IDA",
                        "Готовый code context и analyst workflow.",
                        "Зависимость от platform/version/license; хуже standalone batch deployment.",
                    ],
                    [
                        "Облачный сервис",
                        "Центральное обновление, collaboration, analytics.",
                        "Privacy, sample upload, network isolation и эксплуатационные затраты.",
                    ],
                ],
                [35 * mm, 61 * mm, CONTENT_W - 96 * mm],
            ),
            p("Почему нельзя просто скопировать код с GitHub", H2),
            *bullets(
                [
                    "Открытая публикация не означает отсутствие лицензии и условий использования.",
                    "Нужно проверить license compatibility, notices, attribution и возможность "
                    "коммерческого распространения.",
                    "Чужой код увеличивает supply-chain surface: CVE, malicious update, abandoned "
                    "dependency, transitive packages.",
                    "Копирование без понимания не даёт доказательства correctness и не освобождает от "
                    "собственных tests.",
                    "Для ВКР необходимо явно отделять авторский вклад от reused components.",
                ]
            ),
            p("Как доказать самостоятельность проекта", H2),
            *bullets(
                [
                    "Показать architecture, commits/историю разработки, собственные models и tests.",
                    "Привести список dependencies и лицензий.",
                    "Сопоставить evidence matrix с конкретными functions исходного кода.",
                    "Провести differential comparison: совпадение результатов не означает копирование, "
                    "а расхождения становятся предметом анализа.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("15.4. Рыночная жизнеспособность без рекламных обещаний", H1),
            p("Почему узкий рынок не означает ненужный продукт", H2),
            *bullets(
                [
                    "В профессиональном security tooling ценность часто определяется стоимостью часа "
                    "эксперта, а не числом массовых пользователей.",
                    "Компонент может продаваться не отдельно, а как engine/API внутри larger platform.",
                    "Узкая специализация облегчает доказательство качества и интеграцию в pipeline.",
                    "Один предотвращённый длительный ручной разбор или обнаруженная compiler/runtime "
                    "regression может оправдать использование инструмента.",
                ]
            ),
            p("Что должен доказать пилот", H2),
            comparison_table(
                ["Метрика", "Как измерять"],
                [
                    ["Time-to-first-relevant-RVA", "Одинаковые analysts и samples с инструментом и без него."],
                    ["False-positive burden", "Сколько findings требуют проверки и сколько получают benign explanation."],
                    ["Parser coverage", "Доля corpus, полностью декодированная без unsupported structures."],
                    ["Analyst agreement", "Насколько разные специалисты одинаково трактуют structured report."],
                    ["Pipeline value", "Скорость batch, размер отчёта, стабильность schema, стоимость хранения."],
                    ["Detection utility", "Ground-truth anomalies, precision/recall по категориям, не общий malware verdict."],
                ],
                [48 * mm, CONTENT_W - 48 * mm],
            ),
            Spacer(1, 7),
            p("Модель распространения", H2),
            *bullets(
                [
                    "Open-core или полностью open-source engine для доверия и исследований.",
                    "Платный enterprise layer: orchestration, БД, access control, collaboration, support.",
                    "Интеграционный SDK/API и plugins для существующих RE platforms.",
                    "Экспертные услуги: corpus calibration, custom rules, закрытая лабораторная поставка.",
                ]
            ),
            callout(
                "Что является настоящим рыночным риском",
                "Не отсутствие красивого frontend, а отсутствие измеренного преимущества по analyst "
                "time и отсутствие поддержки актуального формата. Рынок принимает узкий инструмент, "
                "если он надёжно экономит дорогую экспертную работу.",
                "red",
            ),
            PageBreak(),
        ]
    )

    hostile_questions = [
        (
            249,
            "Кому вообще нужен такой узкий продукт?",
            "Reverse-engineering, DFIR и malware-analysis teams, software vendors с custom runtimes и "
            "binary-analysis platforms. Их потребность — batch/offline проверка EH/Unwind metadata и "
            "быстрый переход к конкретным адресам, а не массовый пользовательский GUI.",
            None,
        ),
        (
            250,
            "Есть ли у проекта реальный рынок?",
            "Есть нишевой B2B/экспертный рынок, но его объём пока не измерен. Правильная следующая "
            "работа — interviews и pilot с метрикой analyst time. Без этого нельзя называть TAM или "
            "обещать коммерческий успех.",
            None,
        ),
        (
            251,
            "Почему заказчик не купит IDA и не решит всё?",
            "IDA нужна для глубокого ручного анализа, но не заменяет дешёвый batch scanner и "
            "database-friendly evidence contract. Проект может предварительно отбирать адреса и "
            "передавать их в IDA, экономя analyst time.",
            None,
        ),
        (
            252,
            "Почему не использовать бесплатную Ghidra?",
            "Ghidra сильнее анализирует код, но для одинакового automated EH/Unwind assessment всё "
            "равно нужен script/plugin, rules, reports и tests. Проект может быть таким внешним "
            "preprocessor и уже имеет Ghidra import.",
            None,
        ),
        (
            253,
            "Почему вы не собрали решение из LIEF и готовых библиотек?",
            "Потому что parser safety, exact diagnostics и предметная model входят в цель и авторский "
            "вклад. LIEF мог бы заменить часть parsing, но не evidence matrix, mitigations, reports, "
            "dynamic collector и validation. При этом LIEF полезен как independent oracle.",
            None,
        ),
        (
            254,
            "Разве писать свой parser не изобретение велосипеда?",
            "Было бы изобретением велосипеда без новой цели. Здесь собственный parser обеспечивает "
            "контроль trust boundary и интеграцию с уникальной evidence model. Риск дублирования "
            "компенсируется differential tests; если библиотека окажется надёжнее и дешевле, backend "
            "можно заменить без отказа от аналитического слоя.",
            None,
        ),
        (
            255,
            "Почему вашему parser можно доверять больше, чем LIEF?",
            "Нельзя априори. Доверие строится на tests, fuzzing, corpus и сравнении с независимыми "
            "реализациями. Собственный parser даёт контроль и объяснимость, но не автоматическое "
            "превосходство.",
            "Не заявлять, что собственный код по определению лучше зрелой библиотеки.",
        ),
        (
            256,
            "Вы копировали открытый код?",
            "Авторский вклад должен подтверждаться исходниками, architecture, tests и dependency/"
            "license inventory. Использование спецификаций и инструментов сравнения не является "
            "копированием. Любой reused code должен быть явно указан с лицензией и attribution.",
            None,
        ),
        (
            257,
            "Почему GitHub-код нельзя просто взять бесплатно?",
            "Публичный доступ не отменяет copyright и license terms. Кроме того, dependency нужно "
            "аудировать по безопасности, поддержке, API stability и transitive supply-chain risk.",
            None,
        ),
        (
            258,
            "Что если окажется, что аналогичный plugin уже есть?",
            "Это изменит утверждение об уникальности, но не уничтожит работу. Тогда нужно честно "
            "сравнить функции, correctness, reports и workflow. Самостоятельно реализованная и "
            "проверенная система остаётся инженерным результатом.",
            None,
        ),
        (
            259,
            "Почему не использована нейросеть?",
            "Для formal invariants нейросеть не нужна, а для слабых patterns нет достаточного "
            "размеченного corpus. Rules объяснимы, воспроизводимы и подходят forensic workflow. ML "
            "можно добавить позже только как дополнительный ranking layer.",
            None,
        ),
        (
            260,
            "Разве правила не примитивнее искусственного интеллекта?",
            "Простота не является недостатком, когда правило следует из спецификации. Нейросеть не "
            "делает проверку границ более правильной. Сложная модель оправдана только там, где она "
            "измеримо улучшает результат на независимом benchmark.",
            None,
        ),
        (
            261,
            "Может ли нейросеть найти неизвестную аномалию?",
            "Потенциально да через outlier detection, но без ground truth она также будет выделять "
            "редкие нормальные toolchains. Такой сигнал полезен как гипотеза, а не доказательство; "
            "его нужно связывать с объяснимыми features.",
            None,
        ),
        (
            262,
            "Почему score не обучен на данных?",
            "Нет corpus достаточного качества для честной statistical calibration. Поэтому score "
            "прямо назван engineering triage scale, веса документированы, а проект не выдаёт его за "
            "вероятность.",
            None,
        ),
        (
            263,
            "Тогда веса взяты с потолка?",
            "Это экспертные engineering defaults, ранжирующие formal damage выше contextual patterns. "
            "Они не скрыты и могут быть проверены threshold sweep. Следующий этап — corpus-based "
            "calibration без изменения значения самих invariants.",
            None,
        ),
        (
            264,
            "Почему продукт нужен, если он не определяет malware?",
            "Reverse engineering включает восстановление структуры, диагностику malformed metadata и "
            "локализацию механизмов, а не только malware verdict. Инструмент экономит ручную работу и "
            "поставляет evidence другим detection layers.",
            None,
        ),
        (
            265,
            "Что покупает заказчик: parser или отчёт?",
            "Заказчик покупает повторяемый workflow: безопасное чтение, policy, приоритизацию, "
            "адресные доказательства, integration contract и поддержку формата. Parser является "
            "необходимой, но не достаточной частью.",
            None,
        ),
        (
            266,
            "Почему нельзя сделать всё одним Python-скриптом?",
            "Можно сделать prototype. Product требует контролируемой памяти, cross-platform binary, "
            "atomic reports, strict schema, tests, packaging и стабильного поведения на malformed "
            "inputs. Python adapter при этом может удобно оборачивать C core.",
            None,
        ),
        (
            267,
            "Почему C, если он опасен для parser?",
            "C даёт переносимый компактный binary и прямой контроль bytes, но действительно повышает "
            "риск memory errors. Поэтому проект использует explicit bounds helpers, warnings-as-errors, "
            "ASan/UBSan, mutations и fuzzing.",
            None,
        ),
        (
            268,
            "Почему не Rust?",
            "Rust был бы сильным вариантом для memory safety. C выбран ради ABI, минимального runtime, "
            "Windows/Linux/macOS toolchains и учебной цели. Выбор не объявляется универсально лучшим; "
            "качество C реализации нужно доказывать тестами.",
            None,
        ),
        (
            269,
            "Почему нет frontend, если это продукт?",
            "Для specialist CLI и backend integration frontend не является обязательным. Core должен "
            "оставаться независимым, а GUI/БД строятся поверх JSON contract. Это снижает связность и "
            "не блокирует дальнейшую разработку.",
            None,
        ),
        (
            270,
            "Почему нет базы данных?",
            "БД отвечает за хранение, поиск и сравнение, а не за анализ bytes. Её правильнее добавить "
            "в backend layer, сохранив deterministic core и versioned JSON как границу.",
            None,
        ),
        (
            271,
            "Как продукт будет зарабатывать без GUI?",
            "Через enterprise engine/API, support, integration, private deployment и expert rules. "
            "GUI может повысить adoption, но monetization профессионального компонента не обязана "
            "зависеть от standalone desktop interface.",
            None,
        ),
        (
            272,
            "Что мешает крупному вендору скопировать проект?",
            "Форматные правила скопировать можно. Защитой являются corpus, regression history, "
            "интеграции, скорость поддержки новых specs и доверие. Поэтому moat нужно строить вокруг "
            "quality and workflow, а не секретности алгоритма.",
            None,
        ),
        (
            273,
            "Почему проект не SaaS?",
            "Закрытые binaries и malware samples часто нельзя отправлять в облако. Offline-first "
            "engine является преимуществом. SaaS/on-prem orchestration можно добавить отдельно для "
            "организаций, где это допустимо.",
            None,
        ),
        (
            274,
            "Кто несёт ответственность за ложное срабатывание?",
            "Инструмент выдаёт triage finding и требует manual review, а не автоматический приговор. "
            "Ответственность продукта — корректно показать evidence и uncertainty; решение принимает "
            "уполномоченный аналитик.",
            None,
        ),
        (
            275,
            "Что будет при ложном отрицании?",
            "Файл может сохранить полностью корректную metadata или использовать неподдерживаемую "
            "технику. Поэтому нулевой score означает только отсутствие findings в модели и не "
            "исключает вредоносность.",
            None,
        ),
        (
            276,
            "Не слишком ли много ограничений для продукта?",
            "Ограничения неизбежны у любого analyzer. Сильный продукт не скрывает их, а делает "
            "machine-readable, тестируемыми и учитывает в workflow. Опаснее обещать универсальность, "
            "которой нет.",
            None,
        ),
        (
            277,
            "Почему комиссия должна считать работу самостоятельной?",
            "Потому что можно проследить авторскую предметную модель от требований и evidence matrix "
            "до C modules, tests, reports и dynamic correlation. Готовые tools используются для "
            "сравнения и проверки, а не заменяют основную реализацию.",
            None,
        ),
        (
            278,
            "Что является минимально продаваемой версией?",
            "Core с актуальным V3, подтверждёнными Windows gates, stable JSON, differential tests, "
            "documented deployment и пилотом, показывающим экономию analyst time. GUI может быть "
            "следующим слоем.",
            None,
        ),
        (
            279,
            "Как доказать нужность рынку, а не словами?",
            "Провести 10–20 problem interviews, затем pilot на реальных задачах и измерить "
            "time-to-relevant-RVA, false-positive burden, repeatability и willingness to integrate "
            "или pay.",
            None,
        ),
        (
            280,
            "Что если интервью покажут, что отдельный продукт не нужен?",
            "Тогда ценность переносится в plugin, library или feature larger platform. Это не "
            "технический провал, а уточнение product form по данным рынка.",
            None,
        ),
        (
            281,
            "Почему рынок не решил задачу раньше?",
            "Части задачи решены parsers, viewers и RE platforms. Ниша остаётся в готовом "
            "explainable workflow именно для EH/Unwind anomalies. Её размер нужно подтвердить, а не "
            "объяснять отсутствием компетенции у рынка.",
            None,
        ),
        (
            282,
            "Какова стоимость владения?",
            "Низкая для standalone static CLI, но включает обновление specs, Windows validation, "
            "corpus maintenance и поддержку integrations. Именно эти постоянные работы определяют "
            "реальную стоимость, а не только размер executable.",
            None,
        ),
        (
            283,
            "Почему проект не поддерживает все архитектуры?",
            "Инварианты unwind architecture-specific. Попытка сразу охватить AMD64, ARM64, x86, "
            "DWARF и Mach-O ухудшила бы correctness. Правильное расширение — отдельные models за "
            "общим report contract.",
            None,
        ),
        (
            284,
            "Почему динамика Windows-only — это не архитектурный провал?",
            "Исследуемое runtime поведение реализуется Windows Debug API. Static core остаётся "
            "portable, а platform-specific collector изолирован модулем. Это сознательное разделение "
            "responsibilities.",
            None,
        ),
        (
            285,
            "Можно ли использовать проект в CI?",
            "Да для static analysis: deterministic exit/report, JSON Schema и batch CLI подходят для "
            "pipeline. Для зрелой CI-интеграции полезно добавить policy exit modes и SARIF.",
            None,
        ),
        (
            286,
            "Что если third-party dependency найдёт аномалию иначе?",
            "Расхождение нужно сохранить как differential finding, проверить по Microsoft spec и "
            "реальному loader/debugger behavior. Ни одна реализация не объявляется безусловным oracle.",
            None,
        ),
        (
            287,
            "Почему продукт не использует VirusTotal?",
            "Это другой слой, требующий передачи hash/sample третьей стороне и не объясняющий "
            "EH/Unwind integrity. Интеграция может быть optional context, но core должен работать "
            "offline и без внешнего verdict.",
            None,
        ),
        (
            288,
            "Где граница авторского вклада?",
            "В предметной модели, parser/heuristics/report/dynamic integration, tests и release "
            "workflow. CMake, compiler, OS API и стандарты являются инфраструктурой; их использование "
            "не выдаётся за авторское изобретение.",
            None,
        ),
        (
            289,
            "Самый разрушительный вопрос: а что если проект никому не нужен?",
            "Это проверяемая product hypothesis, а не вопрос веры. Технический результат уже полезен "
            "как research/education component. Коммерческая форма должна быть подтверждена pilot; "
            "если standalone demand слаб, engine встраивается в существующие platforms.",
            None,
        ),
        (
            290,
            "Самый разрушительный вопрос: почему работа достойна защиты?",
            "Потому что она решает сформулированную low-level задачу end-to-end, содержит "
            "самостоятельную объяснимую модель, безопасную реализацию, static/dynamic components, "
            "формальные reports и воспроизводимую validation, при этом честно фиксирует границы и "
            "план закрытия V3/benchmark gaps.",
            None,
        ),
    ]

    story.extend(
        [
            p("15.5. Враждебные вопросы комиссии и ответы", H1),
            p(
                "В этом разделе: 42 вопроса. Не спорьте с комиссией на уровне лозунгов. Признайте "
                "реальный риск, объясните инженерное решение и назовите способ независимой проверки.",
                SMALL,
            ),
        ]
    )
    for idx, item in enumerate(hostile_questions):
        if idx and idx % 6 == 0:
            story.append(PageBreak())
            story.append(p("15.5. Враждебные вопросы: продолжение", H1))
        story.append(qa(*item))

    story.extend(
        [
            PageBreak(),
            p("16. Почему в модели именно 27 признаков", H1),
            callout(
                "Главный ответ комиссии",
                "Число 27 не выбиралось как целевой объём и не означает 27 возможных атак. Оно "
                "получилось после декомпозиции поддерживаемой модели на минимальные независимо "
                "объяснимые findings: базовые нарушения PE layout, целостность RUNTIME_FUNCTION, "
                "целостность UNWIND_INFO, статистические patterns, placement/permissions и четыре "
                "комбинированных подтверждения. Внутри aggregated finding unwind_anomalies дополнительно "
                "различаются 12 конкретных UA_* причин.",
                "cyan",
            ),
            p("Что считается отдельным признаком", H2),
            *bullets(
                [
                    "У него есть отдельная причина и инженерное значение.",
                    "Он может иметь собственную severity/weight и affected count.",
                    "Аналитик может проверить его отдельным ручным действием.",
                    "Он не является простой переформулировкой другого finding.",
                    "Он стабильно сериализуется в report и может использоваться backend policy.",
                ]
            ),
            p("Почему не считать каждый UA_* отдельным итоговым finding", H2),
            p(
                "UA_VERSION_UNKNOWN, UA_TRUNCATED, UA_BAD_OPCODE и другие flags относятся к деталям "
                "одной декодируемой UNWIND_INFO record. На уровне сводного assessment они агрегируются "
                "как unwind_anomalies, чтобы score не увеличивался многократно из-за одного "
                "повреждённого blob. При ручном анализе конкретная UA_* причина всё равно сохраняется.",
                BODY,
            ),
            p("Почему число не должно быть больше ради впечатления", H2),
            *bullets(
                [
                    "Дублирующие признаки создают double counting и искусственно завышают score.",
                    "Редкие неподтверждённые признаки увеличивают false positives.",
                    "Каждый новый finding требует specification rationale, tests, documentation, "
                    "report semantics и corpus calibration.",
                    "Полезность определяется покрытием классов нарушений и explainability, а не "
                    "количеством строк в списке.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("16.1. Декомпозиция 27 findings по слоям", H1),
            comparison_table(
                ["Слой", "Кол-во", "Findings", "Что защищает"],
                [
                    [
                        "PE layout и вход в metadata",
                        "6",
                        "section raw/virtual OOB, raw/virtual overlap, misalignment, exception directory OOB",
                        "Корректность отображения file bytes в image и доступность exception table.",
                    ],
                    [
                        "RUNTIME_FUNCTION table",
                        "7",
                        "no records, invalid ranges, RF OOB, unwind RVA OOB, unsorted, RF overlaps, duplicate Begin",
                        "Однозначность function ranges и ссылок на unwind records.",
                    ],
                    [
                        "UNWIND_INFO integrity",
                        "2",
                        "parse fail, aggregated unwind anomalies",
                        "Безопасное декодирование header/codes/tail/chains; внутри 12 UA_* причин.",
                    ],
                    [
                        "Reuse и handler statistics",
                        "3",
                        "moderate reuse, strong reuse, handler dominance",
                        "Выявление массовой централизации metadata/handlers.",
                    ],
                    [
                        "Placement и permissions",
                        "5",
                        "unwind exec/unusual/writable, handler nonexec/writable",
                        "Соответствие роли данных и кода section map и memory permissions.",
                    ],
                    [
                        "Комбинированные подтверждения",
                        "4",
                        "exec/nonexec handler, placement+integrity, reuse+dominance, writable pair",
                        "Усиление независимых, взаимно согласованных evidence без нового raw defect.",
                    ],
                    ["Итого", "27", "Пять evidence families и cross-family combinations.", "Полная реализованная static assessment model."],
                ],
                [34 * mm, 13 * mm, 73 * mm, CONTENT_W - 120 * mm],
            ),
            Spacer(1, 7),
            callout(
                "27 findings не равны 27 низкоуровневым проверкам",
                "Фактических проверяемых условий больше. Например, unwind_anomalies включает version, "
                "truncation, opcode, operand, CodeOffset, alignment, handler bounds и chain integrity. "
                "Итоговые findings — это устойчивый аналитический интерфейс, а не счётчик всех ветвей "
                "parser.",
                "blue",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("16.2. Какие вмешательства покрывает модель", H1),
            comparison_table(
                ["Класс вмешательства", "Какие признаки реагируют", "Покрытие"],
                [
                    [
                        "Обрезка/повреждение файла или секции",
                        "raw OOB, virtual OOB, exception directory OOB, parse fail, UA_TRUNCATED",
                        "Прямое: структура становится физически недоступной.",
                    ],
                    [
                        "Подмена размеров/адресов секций",
                        "OOB, overlaps, misalignment, unusual/exec/writable placement",
                        "Прямое для invalid layout, контекстное для необычного placement.",
                    ],
                    [
                        "Изменение function Begin/End",
                        "invalid_ranges, rf_oob, unsorted, overlaps, duplicate_begin",
                        "Прямое при нарушении диапазонов; корректная согласованная подмена может не выявиться.",
                    ],
                    [
                        "Перенаправление UnwindInfoRVA",
                        "unwind_rva_oob, parse_fail, unwind_anomalies, placement, reuse",
                        "Прямое при invalid target, эвристическое при корректном unusual target.",
                    ],
                    [
                        "Порча unwind header/codes",
                        "parse_fail и 12 UA_* flags",
                        "Прямое для unsupported/truncated/invalid encoding в поддерживаемой модели.",
                    ],
                    [
                        "Манипуляция handler RVA",
                        "UA_HANDLER_OOB, handler nonexec/writable, handler dominance, combinations",
                        "Прямое для OOB; контекстное для необычного, но допустимого адреса.",
                    ],
                    [
                        "Манипуляция chained records",
                        "UA_CHAIN_INVALID, UA_CHAIN_LOOP, UA_CHAIN_DEPTH_EXCEEDED, parse fail",
                        "Прямое для invalid/cyclic/deep chain в пределах текущего лимита.",
                    ],
                    [
                        "Массовое переиспользование metadata",
                        "reuse moderate/strong, reuse_dominance_combo",
                        "Статистический сигнал; legitimate compiler/runtime patterns возможны.",
                    ],
                    [
                        "Централизация обработчиков",
                        "handler_dominance, placement signals, runtime handler hits",
                        "Контекстный сигнал; общий benign runtime handler возможен.",
                    ],
                    [
                        "Writable/runtime-modifiable metadata",
                        "unwind_writable, handler_writable, writable combo, dynamic table APIs",
                        "Сильный context; JIT/runtime generation остаётся benign explanation.",
                    ],
                    [
                        "Динамическая регистрация таблиц",
                        "RtlAddFunctionTable/RtlInstallFunctionTableCallback events",
                        "Покрывается runtime collector только на реально пройденном execution path.",
                    ],
                ],
                [43 * mm, 65 * mm, CONTENT_W - 108 * mm],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("16.3. Что 27 признаков не покрывают", H1),
            *bullets(
                [
                    "<b>Семантически ложная, но формально корректная metadata.</b> Если attacker "
                    "согласованно подменил ranges и unwind codes, parser может не увидеть нарушения.",
                    "<b>Несоответствие машинному прологу.</b> Без disassembly проект не доказывает, "
                    "что unwind operations соответствуют фактическим инструкциям.",
                    "<b>Невыполненные runtime paths.</b> Dynamic collector видит только события "
                    "конкретного запуска.",
                    "<b>Arbitrary memory writes.</b> Изменение таблиц без отслеживаемых APIs может "
                    "остаться вне событий collector.",
                    "<b>Не-EH/Unwind техники.</b> Imports, entropy, code injection, network behavior, "
                    "capabilities и общая malware logic не входят в предмет модели.",
                    "<b>Новые форматы.</b> UNWIND_INFO v3 и другие architectures требуют отдельной "
                    "поддержки.",
                    "<b>Законная нестандартность.</b> Custom linker, JIT, protector или runtime могут "
                    "создать необычный, но корректный layout.",
                ]
            ),
            callout(
                "Почему это не опровергает модель",
                "Модель заявлена как структурный anomaly detector и triage aid, а не полный detector "
                "любого вмешательства. Корректность оценивается относительно заявленной области: "
                "находит ли она реализованные structural contradictions и честно ли сообщает "
                "ограничения.",
                "amber",
            ),
            p("Как расширить покрытие", H2),
            comparison_table(
                ["Пробел", "Необходимое расширение"],
                [
                    ["Metadata vs code", "Disassembly и сопоставление unwind operations с prolog/epilog."],
                    ["Runtime-generated tables", "Снимок зарегистрированных tables и разбор их records после API call."],
                    ["Arbitrary modifications", "Memory watchpoints, ETW/instrumentation или hypervisor-assisted tracing."],
                    ["Новые standards", "V3, ARM64/ARM64EC, x86 SEH как отдельные architecture models."],
                    ["Detection effectiveness", "Размеченный interference corpus и per-category benchmark."],
                ],
                [48 * mm, CONTENT_W - 48 * mm],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("16.4. Как доказывать достаточность 27 признаков", H1),
            p(
                "Достаточность нельзя доказать одной фразой «признаков много». Нужна traceability "
                "matrix: specification invariant или intervention class → check → finding → test "
                "fixture → expected report → ручной oracle.",
                BODY,
            ),
            comparison_table(
                ["Уровень доказательства", "Что должно существовать"],
                [
                    ["Specification coverage", "Список поддерживаемых invariants Microsoft PE/x64 unwind и ссылка на код."],
                    ["Finding coverage", "Для каждого из 27: positive fixture, benign negative case и report assertion."],
                    ["Internal anomaly coverage", "Для каждого UA_*: точечная mutation и ожидаемый bit/parse status."],
                    ["Intervention coverage", "Набор controlled mutations по адресу, размеру, opcode, handler, chain и permissions."],
                    ["Corpus compatibility", "Benign binaries разных toolchains/SDK, включая V3 после реализации."],
                    ["Differential evidence", "Сравнение decoded model с LIEF/LLVM/WinDbg на одинаковых samples."],
                    ["Statistical calibration", "Размеченный corpus и метрики по weak/contextual heuristics."],
                ],
                [48 * mm, CONTENT_W - 48 * mm],
            ),
            Spacer(1, 7),
            p("Когда можно сказать «покрывают вмешательства»", H2),
            p(
                "Только в ограниченной формулировке: набор покрывает реализованные классы "
                "структурных вмешательств и unusual organization, перечисленные в traceability "
                "matrix. Нельзя утверждать, что он покрывает любое вмешательство в EH/Unwind, пока "
                "нет сопоставления metadata с code, полного runtime monitoring и актуальной "
                "поддержки всех версий формата.",
                LEAD,
            ),
            callout(
                "Сильный ответ на «не мало ли 27?»",
                "Количество само по себе не является метрикой покрытия. 27 — это 27 независимых "
                "итоговых классов evidence; под ними находятся десятки низкоуровневых условий. "
                "Достаточность оценивается матрицей требований и mutation tests. Если новый "
                "независимый класс вмешательства не отображается ни в один finding, тогда нужен "
                "28-й; добавлять дубликаты ради числа неправильно.",
                "green",
            ),
            PageBreak(),
        ]
    )

    signs_questions = [
        (
            291,
            "Почему признаков именно 27?",
            "Это результат декомпозиции поддерживаемой модели на независимо объяснимые findings: "
            "6 PE layout, 7 RUNTIME_FUNCTION, 2 UNWIND integrity, 3 statistical, 5 placement и 4 "
            "combined. Число не задавалось заранее.",
            None,
        ),
        (
            292,
            "Не слишком ли мало 27 признаков?",
            "Количество не показывает coverage. Под 27 итоговыми findings находятся дополнительные "
            "низкоуровневые checks и 12 UA_* anomalies. Нужна traceability matrix по классам "
            "вмешательств, а не гонка за большим числом.",
            None,
        ),
        (
            293,
            "Не слишком ли много 27 признаков?",
            "Нет, если каждый независим, тестируем и ведёт к отдельному analyst action. Дублирующие "
            "условия объединены, а внутренние UA_* не начисляют отдельный score, чтобы избежать "
            "double counting.",
            None,
        ),
        (
            294,
            "Кто определил, что 27 достаточно?",
            "Это текущая engineering model, а не универсальный стандарт. Её достаточность проверяется "
            "относительно заявленных invariants и intervention classes. Новое независимое нарушение "
            "должно приводить к расширению модели.",
            None,
        ),
        (
            295,
            "Покрывают ли они любое вмешательство в EH/Unwind?",
            "Нет. Они покрывают перечисленные structural contradictions, placement и statistical "
            "patterns. Формально корректная согласованная подмена и несоответствие реальному коду "
            "могут остаться незамеченными.",
            None,
        ),
        (
            296,
            "Какие вмешательства покрываются лучше всего?",
            "Повреждение bounds, ranges, overlaps, RVA mapping, malformed unwind encoding, invalid "
            "handlers/chains и противоречивые permissions. Это прямые признаки, близкие к "
            "specification invariants.",
            None,
        ),
        (
            297,
            "Какие вмешательства покрываются только эвристически?",
            "Unusual section names, writable/executable placement, массовое reuse и handler dominance. "
            "Они могут быть законными, поэтому имеют context, thresholds и mitigations.",
            None,
        ),
        (
            298,
            "Почему нет отдельного finding для каждого opcode?",
            "Opcode-level reasons хранятся во внутренней UA_* mask. Итоговый finding агрегирует "
            "повреждение записи, чтобы одна record не завысила score несколькими производными "
            "симптомами.",
            None,
        ),
        (
            299,
            "Почему combined findings не являются дубликатами?",
            "Они не повторяют raw condition, а фиксируют взаимное подтверждение двух evidence. Их "
            "вес ниже базовых сильных нарушений и отражает снижение вероятности случайного benign "
            "объяснения.",
            None,
        ),
        (
            300,
            "Почему признаки разделены на families?",
            "Несколько сигналов одной природы менее убедительны, чем независимые подтверждения из "
            "table integrity, unwind integrity, placement, reuse и handler behavior. Families нужны "
            "для confidence и case interpretation.",
            None,
        ),
        (
            301,
            "Как избежать двойного учёта одного повреждения?",
            "Internal anomalies агрегируются, affected_count не превращается в линейный score, "
            "related findings имеют ограниченные weights, а assessment разделяет score, families и "
            "confidence.",
            None,
        ),
        (
            302,
            "Почему OOB получает больший вес, чем unusual section?",
            "OOB обычно нарушает возможность корректного отображения структуры в поддерживаемой "
            "модели. Необычное имя или placement может быть создано законным linker script и поэтому "
            "требует контекста.",
            None,
        ),
        (
            303,
            "Почему проверяется сортировка таблицы?",
            "Упорядоченность обеспечивает ожидаемую организацию и эффективный поиск по BeginAddress. "
            "Инверсии могут указывать на malformed или нестандартную таблицу, но сами по себе слабее "
            "overlap/OOB.",
            None,
        ),
        (
            304,
            "Почему проверяется duplicate BeginAddress?",
            "Несколько descriptions для одного начала функции создают неоднозначность выбора "
            "EndAddress и UnwindInfoRVA. Это отдельный дефект, даже если ranges формально не выходят "
            "за image.",
            None,
        ),
        (
            305,
            "Почему reuse может быть нормальным?",
            "Compiler folding, runtime helpers или общие prologs могут законно переиспользовать "
            "UNWIND_INFO. Поэтому moderate reuse подавляется без другого сигнала, а strong threshold "
            "рассматривается как triage pattern.",
            None,
        ),
        (
            306,
            "Почему handler dominance может быть нормальным?",
            "Языковой runtime может направлять множество функций в общий personality/handler. "
            "Реализация требует достаточного количества handlers и учитывает location/context.",
            None,
        ),
        (
            307,
            "Как проверить coverage каждого finding?",
            "Для каждого code нужен controlled positive sample, benign negative sample и assertion "
            "по JSON fields. Для percentage thresholds дополнительно нужны boundary tests ниже, на "
            "границе и выше порога.",
            None,
        ),
        (
            308,
            "Что такое mutation coverage вмешательств?",
            "Исходный корректный PE изменяется одной контролируемой операцией: range, RVA, opcode, "
            "handler, chain или section flag. Ожидается конкретный finding без несвязанных "
            "срабатываний.",
            None,
        ),
        (
            309,
            "Почему синтетические mutations недостаточны?",
            "Они дают точный ground truth, но не представляют всё разнообразие toolchains и "
            "protectors. Поэтому нужны реальные benign/protected/malicious samples и differential "
            "comparison.",
            None,
        ),
        (
            310,
            "Какой 28-й признак следует добавить?",
            "Не по числу, а после gap analysis. Наиболее важное расширение сейчас — V3 support и "
            "metadata-to-prolog consistency; последнее может породить отдельные mismatch findings "
            "после disassembly.",
            None,
        ),
        (
            311,
            "Может ли attacker обойти все 27?",
            "Да, сохранив формально корректную и статистически обычную metadata или переместив "
            "malicious logic за пределы исследуемой области. Это ограничение любой узкой anomaly "
            "model.",
            None,
        ),
        (
            312,
            "Тогда зачем нужны признаки, если их можно обойти?",
            "Обходимость не отменяет полезность: многие malformed, packed, experimental и corrupted "
            "cases оставляют структурные следы. Инструмент повышает стоимость сокрытия и ускоряет "
            "анализ обнаруживаемых случаев.",
            None,
        ),
        (
            313,
            "Покрывает ли модель JIT?",
            "Частично. Writable placement и dynamic function-table API activity создают context, но "
            "текущая версия не реконструирует полностью все runtime-generated records. Это "
            "направление расширения.",
            None,
        ),
        (
            314,
            "Покрывает ли модель protectors?",
            "Она покрывает те структурные и runtime patterns protector, которые попадают в текущую "
            "модель. Идентификация конкретного protector и универсальное unpacking не заявляются.",
            None,
        ),
        (
            315,
            "Как связать 27 признаков с нормативными документами?",
            "Hard findings выводятся из PE/x64 exception invariants Microsoft. Contextual findings "
            "должны быть отмечены как engineering heuristics и обоснованы benign corpus и manual "
            "review policy.",
            None,
        ),
        (
            316,
            "Почему признаки не записаны как YARA rules?",
            "YARA хорошо сопоставляет byte/string patterns, но здесь нужны parsed ranges, graph-like "
            "chains, ratios, section permissions и cross-record aggregation. YARA может использовать "
            "результат, но не заменяет model.",
            None,
        ),
        (
            317,
            "Можно ли менять набор признаков после релиза?",
            "Да, но stable finding codes нельзя переиспользовать с новым смыслом. Новые rules требуют "
            "schema/version decision, tests, evidence documentation и анализа влияния на score.",
            None,
        ),
        (
            318,
            "Как сравнить систему признаков с конкурентом?",
            "Составить общую taxonomy intervention classes и проверить, какие классы каждый tool "
            "детектирует, как локализует, объясняет и сколько даёт false positives. Сравнивать только "
            "число indicators неправильно.",
            None,
        ),
        (
            319,
            "Какова самая сильная сторона 27 признаков?",
            "Их traceability: от raw invariant или pattern до finding code, location, score effect, "
            "mitigation и manual validation step.",
            None,
        ),
        (
            320,
            "Какова самая слабая сторона 27 признаков?",
            "Отсутствие code-semantic validation и статистической калибровки contextual thresholds на "
            "большом размеченном corpus.",
            None,
        ),
    ]

    story.extend(
        [
            p("16.5. Вопросы комиссии по системе признаков", H1),
            p(
                "В этом разделе: 30 вопросов. Защищайте не магическое число 27, а метод построения, "
                "traceability, coverage boundaries и отсутствие double counting.",
                SMALL,
            ),
        ]
    )
    for idx, item in enumerate(signs_questions):
        if idx and idx % 6 == 0:
            story.append(PageBreak())
            story.append(p("16.5. Вопросы по признакам: продолжение", H1))
        story.append(qa(*item))

    story.extend(
        [
            PageBreak(),
            p("16.6. Какова точность модели", H1),
            callout(
                "Главный вывод",
                "Единого доказанного процента «точности модели» сейчас нет. Можно отдельно назвать "
                "наблюдаемые результаты compatibility, regression detection и robustness, но нельзя "
                "вычислить универсальную accuracy, sensitivity, precision или F1 без достаточно "
                "большого независимо размеченного корпуса положительных и отрицательных случаев.",
                "red",
            ),
            p("Какие показатели уже подтверждены", H2),
            comparison_table(
                ["Проверка", "Наблюдаемый результат", "Что это доказывает", "Чего не доказывает"],
                [
                    [
                        "Реальный benign corpus",
                        "106/106 файлов: valid reports, score 0; 174 795 RUNTIME_FUNCTION без parse failures/structural anomalies.",
                        "Совместимость и отсутствие false-positive findings на выбранном наборе.",
                        "Универсальную специфичность для всех Windows binaries.",
                    ],
                    [
                        "Synthetic regression set",
                        "6/6 ожидаемых результатов: 2 benign и 4 целевых suspicious samples.",
                        "Известные встроенные сценарии и report semantics работают как задумано.",
                        "Sensitivity на реальных attacks/protectors.",
                    ],
                    [
                        "Extended mutations",
                        "1 000/1 000 обработаны без аварии и некорректного отчёта.",
                        "Robustness parser/report pipeline на данном mutation strategy.",
                        "Правильную классификацию каждой мутации.",
                    ],
                    [
                        "Windows dynamic validation",
                        "124/124 schema/semantic-valid reports; 4/4 focused smoke scenarios.",
                        "Работу instrumentation и report contract в проверенных сценариях.",
                        "Полноту runtime path coverage.",
                    ],
                ],
                [38 * mm, 45 * mm, 45 * mm, CONTENT_W - 128 * mm],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("16.6. Точность: корректная статистическая интерпретация", H1),
            p("Что можно посчитать на benign corpus", H2),
            p(
                "Если считать каждый из 106 файлов независимым benign case, наблюдаемая file-level "
                "specificity относительно правила «ненулевой finding/score = положительный сигнал» "
                "составила 106/106 = <b>100%</b>. При простой биномиальной модели нижняя граница "
                "двустороннего 95%-го Wilson interval составляет приблизительно <b>96,5%</b>. Однако "
                "эта граница описывает только выборку при предположении случайной и независимой "
                "репрезентативности, которой текущий corpus полностью не гарантирует.",
                BODY,
            ),
            callout(
                "Как правильно произнести процент",
                "«На выбранном корпусе из 106 известных benign PE32+ AMD64 файлов наблюдаемая "
                "file-level специфичность составила 100%: ложных положительных срабатываний не было. "
                "Это результат конкретного корпуса, а не доказательство 100%-й специфичности на "
                "генеральной совокупности».",
                "green",
            ),
            p("Почему нельзя посчитать общую accuracy", H2),
            *bullets(
                [
                    "Нет большого representative positive corpus с ground truth по каждому "
                    "EH/Unwind intervention class.",
                    "Synthetic suspicious samples сконструированы под известные rules и завышают "
                    "оценку, если смешать их с реальными данными.",
                    "Единицей ground truth может быть file, function record, finding или конкретное "
                    "вмешательство; смешивать уровни нельзя.",
                    "Некоторые contextual findings не являются бинарной ошибкой: unusual placement "
                    "может быть истинным наблюдением, но иметь benign explanation.",
                    "Нулевой score не означает отсутствие malware, а положительный finding не означает "
                    "наличие malware; обычная malware-classification accuracy здесь неприменима.",
                ]
            ),
            p("Какие метрики пока неизвестны", H2),
            comparison_table(
                ["Метрика", "Текущий статус", "Что нужно"],
                [
                    ["Sensitivity / Recall", "Не установлена.", "Достаточно большой positive corpus по каждому intervention class."],
                    ["Precision / PPV", "Не установлена.", "Независимая ручная разметка всех positive findings."],
                    ["Overall accuracy", "Не установлена.", "Репрезентативный баланс positive/negative и фиксированный decision threshold."],
                    ["F1", "Не установлена.", "Достоверные precision и recall."],
                    ["ROC-AUC / PR-AUC", "Не установлены.", "Непрерывный score на большом labeled corpus и независимый test split."],
                    ["Parser semantic accuracy", "Частично проверена.", "Differential oracle и byte/record-level ground truth."],
                ],
                [42 * mm, 38 * mm, CONTENT_W - 80 * mm],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("16.6. План строгой оценки точности", H1),
            comparison_table(
                ["Этап", "Требование"],
                [
                    ["1. Taxonomy", "Зафиксировать классы вмешательств и единицу оценки: file, record и finding."],
                    ["2. Corpus", "Собрать benign, malformed, protector, JIT/runtime и malicious samples разных toolchains/SDK."],
                    ["3. Ground truth", "Двойная независимая разметка экспертами и разрешение разногласий."],
                    ["4. Split", "Разделить calibration/development и blind test sets по семействам, а не случайным копиям."],
                    ["5. Baselines", "Запустить LIEF/LLVM/PE tools и ручной oracle на тех же samples."],
                    ["6. Metrics", "Per-class recall, file/finding precision, specificity, F1, PR-AUC и bootstrap/Wilson intervals."],
                    ["7. Ablation", "Отключать families/mitigations и измерять вклад каждого решения."],
                    ["8. Thresholds", "Калибровать только на development set; test set использовать один раз."],
                    ["9. Error analysis", "Публиковать false positives/negatives и benign explanations, а не только средний процент."],
                ],
                [26 * mm, CONTENT_W - 26 * mm],
            ),
            Spacer(1, 8),
            p("Какой показатель должен быть главным", H2),
            p(
                "Для triage-системы важнее не одна overall accuracy, зависящая от доли benign файлов, "
                "а набор показателей: высокая specificity, чтобы не перегружать аналитика; per-class "
                "recall для формальных повреждений; precision на уровне findings; и время, "
                "сэкономленное до ручного подтверждения.",
                BODY,
            ),
            callout(
                "Почему нельзя назвать 100% точность",
                "Числа 106/106, 6/6, 1 000/1 000 и 4/4 относятся к разным экспериментам и разным "
                "свойствам. Складывать их в единый процент методологически неверно. Корректный вывод: "
                "на выполненных проверках получены идеальные наблюдаемые результаты, но statistical "
                "detection accuracy всей модели ещё не установлена.",
                "amber",
            ),
            PageBreak(),
        ]
    )

    accuracy_questions = [
        (
            321,
            "Какова точность модели в процентах?",
            "Универсальный процент пока не установлен. На выбранном benign corpus наблюдаемая "
            "file-level specificity составила 106/106 = 100%, а на шести synthetic regression "
            "samples получено 6/6 ожидаемых результатов. Эти результаты нельзя объединять в общую "
            "accuracy.",
            None,
        ),
        (
            322,
            "Почему нельзя сказать, что точность 100%?",
            "Потому что выборки ограничены и не содержат репрезентативного набора реальных "
            "положительных случаев. Ноль ошибок на текущем corpus не гарантирует ноль ошибок на "
            "других toolchains, protectors и format versions.",
            None,
        ),
        (
            323,
            "Что означает 106/106 benign?",
            "Все 106 выбранных известных benign файлов дали valid report и нулевой score без "
            "структурных unwind anomalies. Это наблюдаемая совместимость и отсутствие false positives "
            "на конкретном corpus.",
            None,
        ),
        (
            324,
            "Можно ли назвать specificity 100%?",
            "Можно только с уточнением «наблюдаемая на выбранном corpus». Для генеральной "
            "совокупности нужна репрезентативная случайная выборка; приблизительная нижняя Wilson "
            "граница для 106/106 равна 96,5%, но corpus bias остаётся.",
            None,
        ),
        (
            325,
            "Какова sensitivity?",
            "Не установлена, потому что нет достаточно большого независимо размеченного positive "
            "corpus по всем классам вмешательств. Четыре synthetic positive samples подтверждают "
            "регрессию, но не дают внешнюю sensitivity.",
            None,
        ),
        (
            326,
            "Какова precision?",
            "Не установлена. Нужны реальные predicted-positive cases и независимое экспертное "
            "подтверждение каждого finding. На одном benign corpus положительных предсказаний нет, "
            "поэтому PPV по нему не вычисляется.",
            None,
        ),
        (
            327,
            "Что доказывают 6/6 regression samples?",
            "Что два встроенных benign и четыре специально созданных suspicious сценария дают "
            "зафиксированные ожидаемые reports. Это functional regression, а не оценка "
            "генерализации.",
            None,
        ),
        (
            328,
            "Что доказывают 1 000 mutations?",
            "Устойчивость обработки в рамках mutation strategy: нет crash и некорректных reports. "
            "Это robustness, а не 1000 правильно классифицированных атак.",
            None,
        ),
        (
            329,
            "Что доказывают 124/124 Windows reports?",
            "Корректность schema/semantics и работоспособность dynamic pipeline в выполненных "
            "запусках. Это не измерение полноты наблюдения всех runtime paths.",
            None,
        ),
        (
            330,
            "Какая метрика важнее общей accuracy?",
            "Для triage важны per-class recall формальных дефектов, specificity и false-positive "
            "burden, precision findings и analyst time. Overall accuracy может быть искусственно "
            "высокой на преимущественно benign corpus.",
            None,
        ),
        (
            331,
            "Как получить научно обоснованную оценку?",
            "Создать taxonomy и blinded labeled corpus, отделить development от test set, провести "
            "двойную экспертную разметку и посчитать per-class metrics с confidence intervals и "
            "error analysis.",
            None,
        ),
        (
            332,
            "Как отвечать комиссии одной фразой?",
            "«На выбранном benign-корпусе из 106 файлов наблюдаемая специфичность равна 100%, но "
            "полная statistical accuracy модели пока не установлена из-за отсутствия большого "
            "независимо размеченного positive corpus».",
            None,
        ),
    ]

    story.extend(
        [
            p("16.7. Вопросы комиссии о точности", H1),
            p(
                "В этом разделе: 12 вопросов. Не смешивайте correctness, compatibility, robustness "
                "и detection accuracy.",
                SMALL,
            ),
        ]
    )
    for idx, item in enumerate(accuracy_questions):
        if idx and idx % 6 == 0:
            story.append(PageBreak())
            story.append(p("16.7. Вопросы о точности: продолжение", H1))
        story.append(qa(*item))

    story.extend(
        [
            PageBreak(),
            p("17. Готовый сценарий защиты проекта", H1),
            p(
                "Ниже приведён логический каркас выступления. Его не нужно читать дословно: задача — "
                "сохранить причинную последовательность и не перескакивать к деталям раньше времени.",
                LEAD,
            ),
            comparison_table(
                ["Слайд", "Главная мысль", "Что показать"],
                [
                    ["1. Тема", "Специализированный анализ PE32+ AMD64 EH/Unwind metadata.", "Название и одно предложение."],
                    ["2. Проблема", "Ручная проверка связанных records трудоёмка и плохо воспроизводима.", "RUNTIME_FUNCTION → UNWIND_INFO → handler."],
                    ["3. Актуальность", "Metadata нужна Windows и RE; format развивается; anomalies влияют на анализ.", "Microsoft model и V3 как evidence развития."],
                    ["4. Цель/задачи", "От safe parser до explainable report и runtime evidence.", "Краткая pipeline diagram."],
                    ["5. Архитектура", "Модульный монолит: core + CLI, Windows collector изолирован.", "Modules/data flow."],
                    ["6. Признаки", "27 итоговых findings, 12 UA_* details, 5 evidence families.", "Декомпозиция и priorities."],
                    ["7. Оценка", "Score — triage; confidence и mitigations ограничивают вывод.", "Один пример combined evidence."],
                    ["8. Динамика", "Наблюдает handlers/API/events конкретного запуска.", "Static/dynamic correlation."],
                    ["9. Отчёты", "JSON/HTML/CSV/Ghidra, hash и provenance.", "Фрагмент отчёта."],
                    ["10. Проверка", "Unit/regression/schema/mutations/benign corpus/Windows smoke.", "Только подтверждённые числа."],
                    ["11. Аналоги", "LIEF/PE tools/RE platforms решают части; проект — узкий explainable layer.", "Competitor map."],
                    ["12. Вклад", "Целостная методика и реализация, а не новый формат или malware classifier.", "Новизна и practical value."],
                    ["13. Ограничения", "V3, no disassembly, corpus calibration, limited dynamics.", "Честный roadmap."],
                    ["14. Итог", "Сокращает путь от binary к проверяемой analyst hypothesis.", "Один вывод без рекламы."],
                ],
                [22 * mm, 75 * mm, CONTENT_W - 97 * mm],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("17.1. Текст выступления на 7–10 минут", H1),
            p(
                "<b>Введение.</b> Тема моей работы — разработка инструмента структурного анализа и "
                "выявления аномалий в Windows PE32+ AMD64 metadata обработки исключений и раскрутки "
                "стека. Эти данные представлены exception directory, RUNTIME_FUNCTION и UNWIND_INFO "
                "и используются операционной системой при восстановлении контекста nonleaf functions.",
                BODY,
            ),
            p(
                "<b>Проблема.</b> В реальном binary таблица может содержать тысячи связанных records. "
                "Для корректной интерпретации недостаточно показать отдельные поля: необходимо "
                "проверить границы секций, отображение RVA, диапазоны функций, chains, unwind codes, "
                "handler addresses, permissions и статистические patterns. Ручной анализ занимает "
                "время и плохо воспроизводится.",
                BODY,
            ),
            p(
                "<b>Цель.</b> Целью стало создание самостоятельного инструмента, который безопасно "
                "разбирает недоверенный PE-файл, локализует нарушения и необычные patterns, объясняет "
                "причину каждого вывода и формирует переносимый отчёт для дальнейшей работы "
                "реверс-инженера.",
                BODY,
            ),
            p(
                "<b>Архитектура.</b> Проект реализован как модульный монолит на C17: отдельные modules "
                "отвечают за bytes и hashing, PE, unwind, heuristics, reports и Windows dynamic "
                "collector. Static core работает на Windows, Linux и macOS; dynamic collector "
                "изолирован и доступен только на Windows x64.",
                BODY,
            ),
            p(
                "<b>Система признаков.</b> В модели 27 итоговых findings. Это не произвольное число: "
                "6 относятся к PE layout, 7 к RUNTIME_FUNCTION table, 2 агрегируют UNWIND_INFO "
                "integrity, 3 описывают reuse и handler statistics, 5 — placement и permissions, 4 — "
                "взаимное подтверждение независимых сигналов. Внутри unwind_anomalies сохраняются "
                "12 низкоуровневых UA_* причин.",
                BODY,
            ),
            p(
                "<b>Интерпретация.</b> Формальные нарушения имеют больший приоритет, чем контекстные "
                "patterns. Score используется только для triage и не является вероятностью атаки. "
                "Confidence учитывает число независимых evidence families и снижается mitigations, "
                "если сигнал одиночный, sample мал или placement имеет нормальное объяснение.",
                BODY,
            ),
            p(
                "<b>Динамика.</b> Windows collector запускает target под Debug API и фиксирует "
                "exceptions, handler hits, VEH/VCH/UEF registrations и обращения к APIs динамических "
                "function tables. Эти данные не заменяют debugger и отражают только конкретный "
                "execution path, но позволяют подтвердить часть статических гипотез.",
                BODY,
            ),
            p(
                "<b>Результат.</b> Инструмент выпускает console, strict JSON, автономный HTML, CSV и "
                "Ghidra CSV; сохраняет SHA-256, version и build provenance. Ghidra importer переносит "
                "function ranges и warnings, не перезаписывая analyst names без необходимости.",
                BODY,
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("17.1. Текст выступления: продолжение", H1),
            p(
                "<b>Проверка.</b> Реализация проверяется unit и regression tests, JSON Schema и "
                "semantic validators, strict compiler warnings, sanitizers, mutation/fuzz workflows, "
                "benign corpus и Windows dynamic smoke scenarios. Эти проверки подтверждают "
                "устойчивость и заявленную compatibility, но не доказывают универсальную detection "
                "accuracy.",
                BODY,
            ),
            p(
                "<b>Аналоги.</b> LIEF и LLVM сильны как parsers/inspectors; pestudio, PE-bear и "
                "4n4lDetector — как широкие PE tools; IDA, Ghidra, Binary Ninja и radare2 — как "
                "полноценные RE platforms; WinDbg и x64dbg — как debuggers. Проект не заменяет их. "
                "Его место — специализированный explainable preprocessor, который автоматизирует "
                "одну глубокую область и передаёт evidence этим системам.",
                BODY,
            ),
            p(
                "<b>Новизна и значимость.</b> Новизна состоит не в изобретении PE или virtual unwind, "
                "а в целостной методике: safe parsing, cross-record checks, evidence families, "
                "mitigations, static/dynamic correlation и воспроизводимый report contract. "
                "Практическая ценность — сокращение пространства ручного поиска и возможность "
                "встроить результаты в backend или case database.",
                BODY,
            ),
            p(
                "<b>Ограничения.</b> Проект не анализирует семантику всего кода, не определяет malware, "
                "не покрывает все execution paths и пока поддерживает UNWIND_INFO v1/v2. После "
                "публикации Microsoft specification v3 это стало приоритетным compatibility gap. "
                "Также необходимы differential tests и большой размеченный corpus для статистической "
                "калибровки contextual heuristics.",
                BODY,
            ),
            p(
                "<b>Заключение.</b> Получен не просто parser, а законченная в заявленной области "
                "аналитическая цепочка от bytes до проверяемой гипотезы для reverse engineer. "
                "Сильная сторона проекта — объяснимость и воспроизводимость; дальнейшее развитие "
                "должно усиливать coverage и доказательность, не скрывая uncertainty.",
                BODY,
            ),
            callout(
                "Последняя фраза выступления",
                "Таким образом, работа автоматизирует наиболее формализуемую часть анализа Windows "
                "x64 EH/Unwind metadata и превращает её в воспроизводимый источник адресных evidence, "
                "который дополняет, а не заменяет профессиональные средства reverse engineering.",
                "cyan",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("17.2. Тактика ответа жёсткой комиссии", H1),
            comparison_table(
                ["Тип атаки", "Как отвечать"],
                [
                    ["«Это уже есть»", "Уточнить класс аналога, признать пересечение, затем назвать отличия workflow и evidence model."],
                    ["«Это никому не нужно»", "Отделить техническую полезность от product hypothesis и предложить измеримый pilot."],
                    ["«Мало данных»", "Согласиться с границей, не делать statistical claims, назвать план corpus/benchmark."],
                    ["«Почему не AI?»", "Показать formal invariants, отсутствие labels и требования explainability; ML оставить ranking layer."],
                    ["«Почему свой parser?»", "Обосновать trust boundary и вклад, затем признать maintenance risk и differential testing."],
                    ["«27 мало/много»", "Перевести разговор с числа на taxonomy, traceability и mutation coverage."],
                    ["«Нашли V3, значит проект сломан»", "Признать compatibility gap, ограничить scope v1/v2 и назвать P0 validation plan."],
                    ["«Где точность?»", "Не подменять correctness parser точностью detector; запросить/описать общий labeled benchmark."],
                    ["«Это malware detector?»", "Нет; это structural anomaly detector и analyst triage component."],
                    ["«Проект завершён?»", "В заявленной v1/v2 области core реализован; для широкого 1.0 нужны V3, MSVC gate и benchmark."],
                ],
                [47 * mm, CONTENT_W - 47 * mm],
            ),
            Spacer(1, 8),
            p("Формула сильного ответа", H2),
            callout(
                "Факт → граница → решение → проверка",
                "1. Назвать подтверждённый факт. 2. Признать точную границу. 3. Объяснить, почему "
                "выбрано текущее решение. 4. Назвать тест или эксперимент, который может проверить "
                "ответ независимо. Такая структура сильнее попытки любой ценой доказать, что проект "
                "идеален.",
                "green",
            ),
            p("Фразы, которые усиливают защиту", H2),
            *bullets(
                [
                    "«В пределах заявленной модели и версии формата…»",
                    "«Это формальное нарушение; в отличие от него следующий сигнал является "
                    "контекстной эвристикой…»",
                    "«Текущих данных недостаточно для статистического утверждения, поэтому…»",
                    "«Этот вывод можно независимо проверить следующим способом…»",
                    "«Конкурент сильнее в анализе кода, а наш инструмент — в пакетной "
                    "формализации именно этой области…»",
                ]
            ),
            p("Фразы, которые разрушают защиту", H2),
            *bullets(
                [
                    "«Аналогов вообще нет».",
                    "«27 признаков покрывают любые атаки».",
                    "«Score показывает вероятность вредоносности».",
                    "«Нейросеть не нужна, потому что правила всегда лучше».",
                    "«Собственный parser точно надёжнее LIEF».",
                    "«Проект полностью закончен и больше ничего делать не нужно».",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("17.3. Финальная памятка полной защиты", H1),
            comparison_table(
                ["Нужно помнить", "Точная позиция"],
                [
                    ["Что это", "Explainable structural anomaly analyzer для PE32+ AMD64 EH/Unwind metadata."],
                    ["Что не это", "Не antivirus, не universal malware classifier, не замена IDA/Ghidra/debugger."],
                    ["27 признаков", "27 итоговых evidence classes; под ними 12 UA_* и множество low-level checks."],
                    ["Актуальность", "Рабочая Windows ABI metadata, большие таблицы, сложные связи, живой evolving format."],
                    ["Новизна", "Интегрированная methodology и implementation, не изобретение PE/unwind."],
                    ["Рынок", "Нишевой professional component; ценность должна подтверждаться analyst-time pilot."],
                    ["Почему своё ядро", "Trust boundary, traceability, minimal deployment; риск закрывается external oracles."],
                    ["Почему без AI", "Formal invariants + нет labels + explainability; ML возможен как optional ranking."],
                    ["Главная сила", "Адресные, проверяемые, воспроизводимые evidence и stable report contract."],
                    ["Главная слабость", "Нет code semantics/V3/statistical calibration и полного runtime coverage."],
                    ["Главный следующий шаг", "V3, differential tests, corpus benchmark, затем SARIF/plugins/UI."],
                    ["Стиль ответа", "Точный факт, честная граница, инженерное решение, независимая проверка."],
                ],
                [47 * mm, CONTENT_W - 47 * mm],
            ),
            Spacer(1, 10),
            callout(
                "Главная мысль всей защиты",
                "Сила работы не в обещании обнаружить всё, а в том, что для ограниченной и технически "
                "важной области построена полная, объяснимая и проверяемая цепочка анализа. Комиссии "
                "нужно показать понимание не только возможностей, но и границ, потому что именно это "
                "отличает инженерный продукт от демонстрационного прототипа.",
                "cyan",
            ),
        ]
    )

    story.extend(
        [
            PageBreak(),
            p("18. Сценарий демонстрации проекта", H1),
            p(
                "Демонстрация должна доказывать три вещи: инструмент запускается, различает чистый и "
                "контролируемо повреждённый sample и позволяет перейти от finding к конкретному "
                "месту ручной проверки.",
                LEAD,
            ),
            comparison_table(
                ["Шаг", "Действие", "Что произнести"],
                [
                    ["1", "Показать --version.", "Версия tool/schema/build фиксируется в каждом report."],
                    ["2", "Запустить benign sample с --heuristics --json --html.", "Ожидается score 0 и отсутствие findings в текущей модели."],
                    ["3", "Открыть JSON metadata.", "Показать SHA-256, schema, sections, functions и assessment."],
                    ["4", "Запустить suspicious_unwind_oob.", "Показать unwind_rva_oob/parse_fail и representative location."],
                    ["5", "Сравнить score и confidence.", "Score ранжирует, confidence описывает силу интерпретации."],
                    ["6", "Открыть HTML.", "Показать автономный analyst-friendly report без внешних assets."],
                    ["7", "Сгенерировать Ghidra CSV.", "Результат переносится в ручной RE workflow."],
                    ["8", "Показать dynamic report заранее.", "Не запускать неизвестный binary на host; использовать проверенный VM artifact."],
                    ["9", "Показать тесты.", "Сборка и CTest подтверждают regression/report contracts."],
                ],
                [14 * mm, 67 * mm, CONTENT_W - 81 * mm],
            ),
            Spacer(1, 8),
            callout(
                "Правило безопасной демонстрации",
                "На защите не запускать непроверенный интернет-sample на основном компьютере. Для "
                "динамики использовать изолированную Windows VM или заранее сохранённый schema-valid "
                "report с hash и описанием сценария.",
                "red",
            ),
            p("Что подготовить заранее", H2),
            *bullets(
                [
                    "Два коротких sample: benign и один controlled suspicious.",
                    "Команды в текстовом файле без длинных путей и случайных аргументов.",
                    "Готовые JSON/HTML на случай медленной сборки.",
                    "Скриншоты ключевых блоков отчёта для презентации.",
                    "Проверенную Windows dynamic запись, а не live malware execution.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("18.1. Резервный план при сбое демонстрации", H1),
            comparison_table(
                ["Сбой", "Действие", "Как объяснить"],
                [
                    ["Не собирается на чужом ПК", "Показать release binary, package hash и CI/test evidence.", "Сборка зависит от toolchain; reproducible artifact подготовлен заранее."],
                    ["Нет Windows VM", "Показать сохранённый dynamic JSON/HTML и validation report.", "Dynamic mode platform-specific; evidence уже зафиксировано с provenance."],
                    ["Команда долго выполняется", "Перейти к заранее созданному report.", "Анализ deterministic; live run не является единственным доказательством."],
                    ["HTML не открывается", "Показать JSON и console.", "HTML — presentation layer, JSON — основной contract."],
                    ["Sample удалён антивирусом", "Использовать synthetic non-malicious fixtures.", "Для доказательства mechanics malware не требуется."],
                    ["Вопрос вне scope", "Назвать границу и способ проверки.", "Не импровизировать неизвестный факт."],
                ],
                [42 * mm, 59 * mm, CONTENT_W - 101 * mm],
            ),
            Spacer(1, 8),
            p("Что нельзя делать при сбое", H2),
            *bullets(
                [
                    "Не менять код на глазах комиссии.",
                    "Не скачивать случайный executable из интернета.",
                    "Не объяснять любой сбой «антивирусом» или «Windows».",
                    "Не выдавать заранее созданный report за только что выполненный запуск.",
                    "Не спорить с фактом ошибки: отделить environment failure от core result.",
                ]
            ),
            callout(
                "Сильная фраза при сбое",
                "«Live demonstration зависит от среды, поэтому я подготовил воспроизводимый artifact: "
                "в нём сохранены hash input, version инструмента, compiler/platform и schema-valid "
                "результат. Сейчас покажу тот же этап по отчёту».",
                "green",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("19. Карта доказательств для ключевых утверждений", H1),
            comparison_table(
                ["Утверждение", "Доказательство", "Ограничение"],
                [
                    ["Static core кроссплатформенный", "CMake presets/builds и отсутствие Windows API в static path.", "Dynamic collector только Windows x64."],
                    ["Parser устойчив к malformed input", "Bounds helpers, sanitizers, mutations/fuzz, error paths.", "Нельзя доказать отсутствие всех bugs."],
                    ["Benign compatibility высокая", "106/106 valid zero-score reports.", "Corpus ограничен выбранными vendors/toolchains и v1/v2."],
                    ["Известные anomalies обнаруживаются", "6 regression fixtures и unit tests UA_*.", "Synthetic set не измеряет external recall."],
                    ["Reports воспроизводимы", "SHA-256, version/schema/compiler/platform, validators.", "Environment влияет на dynamic execution path."],
                    ["Признаки объяснимы", "Evidence matrix, stable codes, affected count, manual steps.", "Thresholds ещё engineering defaults."],
                    ["Динамика работает", "124 reports, 4 focused smoke cases.", "Нет полного path coverage и DLL host runner."],
                    ["Проект имеет нишу", "Gap между parser/viewer/full RE platform и specialized report.", "Market demand требует interviews/pilot."],
                    ["Новизна существует", "Уникальная интеграция methods в одной реализации.", "Мировое первенство не доказано."],
                    ["Модель точна", "Только наблюдаемые corpus/regression результаты.", "Общая statistical accuracy неизвестна."],
                ],
                [43 * mm, 66 * mm, CONTENT_W - 109 * mm],
            ),
            Spacer(1, 8),
            p("Красные линии доказательности", H2),
            *bullets(
                [
                    "Не превращать отсутствие findings в доказательство безопасности.",
                    "Не превращать handler hit в доказательство malicious intent.",
                    "Не превращать 106 benign файлов в универсальную 100%-ю точность.",
                    "Не превращать отсутствие найденного полного аналога в патентную новизну.",
                    "Не превращать passing tests в доказательство отсутствия defects.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("20. Чек-лист за 24 часа до защиты", H1),
            comparison_table(
                ["Область", "Проверить"],
                [
                    ["Файлы", "PDF защиты, презентация, release package, hashes, два samples, reports."],
                    ["Команды", "--version, benign analysis, suspicious analysis, report generation, tests."],
                    ["Среда", "Ноутбук/питание, VM snapshot, offline copies, шрифты, PDF reader."],
                    ["Числа", "Версия, tests, corpus, runtime functions, mutations, Windows reports."],
                    ["Формулировки", "Актуальность, новизна, 27 признаков, точность, конкуренты, ограничения."],
                    ["Риски", "V3, no disassembly, no calibrated positive corpus, limited dynamics."],
                    ["Демо", "Проверить с нуля по таймеру; иметь screenshots и готовые reports."],
                    ["Безопасность", "Не запускать untrusted sample вне изолированной VM."],
                ],
                [42 * mm, CONTENT_W - 42 * mm],
            ),
            Spacer(1, 9),
            p("Пять чисел, которые нужно знать точно", H2),
            *bullets(
                [
                    "<b>27</b> итоговых findings.",
                    "<b>12</b> внутренних UA_* anomaly reasons.",
                    "<b>106/106</b> benign corpus reports без ненулевого score.",
                    "<b>174 795</b> разобранных RUNTIME_FUNCTION в этом corpus.",
                    "<b>1 000</b> расширенных mutations без crash/invalid report.",
                ]
            ),
            p("Пять ограничений, которые нужно назвать самому", H2),
            *bullets(
                [
                    "UNWIND_INFO v3 пока не поддерживается.",
                    "Нет сопоставления metadata с машинным prolog/epilog.",
                    "Нет большой независимой positive выборки и полной statistical accuracy.",
                    "Dynamic mode видит только конкретный execution path.",
                    "Проект не определяет malware и требует analyst review.",
                ]
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("21. Ответы, которые нельзя придумывать", H1),
            p(
                "Если комиссия просит факт, которого нет в документации или проверках, лучший ответ — "
                "отделить известное от неизвестного и предложить процедуру измерения.",
                LEAD,
            ),
            comparison_table(
                ["Нельзя говорить без данных", "Корректный ответ"],
                [
                    ["«Рынок составляет N миллионов»", "Размер рынка не оценён; нужны сегментация и interviews."],
                    ["«Точность 100%»", "100% наблюдаемая specificity только на выбранных 106 benign files."],
                    ["«Все protectors обнаруживаются»", "Покрываются только patterns, попадающие в текущую model."],
                    ["«V3 нигде не используется»", "V3 опубликована Microsoft; распространённость нужно измерять corpus."],
                    ["«LIEF разбирает хуже»", "Нужно differential testing; априори превосходство не заявляется."],
                    ["«Нейросеть даст хуже»", "Без benchmark сравнение невозможно; rules лучше обоснованы для invariants."],
                    ["«Проект первый в мире»", "Найдена редкая комбинация функций; мировое первенство не доказано."],
                    ["«MSVC точно пройдёт»", "Нужен фактически выполненный независимый gate."],
                    ["«Ошибок в коде нет»", "Пройдены заявленные quality gates; абсолютная безошибочность невозможна."],
                ],
                [64 * mm, CONTENT_W - 64 * mm],
            ),
            Spacer(1, 10),
            callout(
                "Универсальный ответ при неизвестном факте",
                "«Этого показателя в текущей работе нет, поэтому я не буду придумывать значение. "
                "Его можно получить следующим экспериментом: … В работе подтверждено только: …»",
                "green",
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            p("22. Итоговая позиция проекта", H1),
            p(
                "EH/Unwind Analyzer — самостоятельный специализированный инструмент структурного "
                "анализа Windows PE32+ AMD64 exception/unwind metadata. Он не конкурирует с IDA, "
                "Ghidra или WinDbg по широте; его преимущество — автоматический, объяснимый и "
                "воспроизводимый первый проход по узкой, технически важной области.",
                LEAD,
            ),
            p("Что уже является сильным результатом", H2),
            *bullets(
                [
                    "Сквозная реализация от untrusted bytes до analyst report.",
                    "27 формализованных findings и 12 внутренних anomaly reasons.",
                    "Разделение hard violations, heuristics, confidence и mitigations.",
                    "Static cross-platform core и Windows runtime evidence.",
                    "Schema-validated JSON, offline HTML, CSV и Ghidra integration.",
                    "Развитая система tests, mutations, corpus и release artifacts.",
                ]
            ),
            p("Что необходимо для максимально сильного продукта", H2),
            *bullets(
                [
                    "Поддержать UNWIND_INFO v3.",
                    "Провести differential testing и независимый MSVC gate.",
                    "Добавить metadata-to-prolog consistency analysis.",
                    "Собрать independently labeled corpus и измерить per-class accuracy.",
                    "Провести market pilot и измерить сокращение analyst time.",
                    "После этого развивать SARIF, plugins, backend/БД и frontend.",
                ]
            ),
            callout(
                "Финальный вывод",
                "Проект достоин защиты не потому, что он «идеален» или «не имеет аналогов», а потому "
                "что сложная низкоуровневая задача доведена до законченной инженерной системы с "
                "объяснимыми решениями, воспроизводимыми результатами и честно установленными "
                "границами дальнейшего развития.",
                "cyan",
            ),
        ]
    )

    return story


def build_appendix() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(APPENDIX),
        pagesize=A4,
        leftMargin=LEFT,
        rightMargin=RIGHT,
        topMargin=TOP,
        bottomMargin=BOTTOM,
        title="EH/Unwind Analyzer: полная защита проекта",
        author="EH/Unwind Analyzer project",
        subject="Конкуренты, актуальность, новизна, признаки, точность и сценарий защиты",
    )
    doc.build(build_story(), onFirstPage=header_footer, onLaterPages=header_footer)


def merge() -> None:
    source = TARGET if TARGET.exists() else BASE_SOURCE
    original = PdfReader(str(source))
    front = PdfReader(str(FRONT))
    appendix = PdfReader(str(APPENDIX))
    writer = PdfWriter()
    for page in front.pages:
        writer.add_page(page)
    base_start = 2
    base_end = min(30, len(original.pages))
    for page in original.pages[base_start:base_end]:
        writer.add_page(page)
    for page in appendix.pages:
        writer.add_page(page)
    writer.add_metadata(
        {
            "/Title": "EH/Unwind Analyzer: полная защита проекта",
            "/Author": "EH/Unwind Analyzer project",
            "/Subject": "Полный комплект подготовки к защите проекта",
            "/Keywords": "PE, AMD64, UNWIND_INFO, RUNTIME_FUNCTION, конкуренты, reverse engineering",
        }
    )
    with MERGED.open("wb") as fh:
        writer.write(fh)
    MERGED.replace(TARGET)
    print(f"source_pages={len(original.pages)}")
    print(f"front_pages={len(front.pages)}")
    print(f"preserved_base_pages={base_end - base_start}")
    print(f"appendix_pages={len(appendix.pages)}")
    print(f"total_pages={len(front.pages) + (base_end - base_start) + len(appendix.pages)}")
    print(f"target={TARGET}")


if __name__ == "__main__":
    build_front_matter()
    build_appendix()
    merge()
