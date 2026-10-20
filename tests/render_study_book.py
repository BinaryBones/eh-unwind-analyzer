#!/usr/bin/env python3
"""Render the Russian EH/Unwind Analyzer study course from Markdown to PDF."""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

from PIL import Image as PilImage
from PIL import ImageDraw, ImageFont
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "ru" / "EH_Unwind_Analyzer_Учебный_курс.md"
OUTPUT = ROOT / "docs" / "ru" / "EH_Unwind_Analyzer_Учебная_книга.pdf"
ASSETS = ROOT / "book_source" / "study_assets"

NAVY = "#10243E"
BLUE = "#1565C0"
CYAN = "#008C95"
GREEN = "#19705B"
ORANGE = "#B54708"
RED = "#B42318"
INK = "#17212B"
GRAY = "#586474"
LIGHT_BLUE = "#EAF3FA"
LIGHT_CYAN = "#E8F7F7"
LIGHT_GREEN = "#E9F6F1"
LIGHT_ORANGE = "#FFF3E8"
LIGHT_GRAY = "#F2F4F7"
MID_GRAY = "#D7DEE8"
WHITE = "#FFFFFF"


def pick_font(candidates: list[str]) -> str:
    for item in candidates:
        if Path(item).is_file() and Path(item).suffix.lower() == ".ttf":
            return item
    raise RuntimeError(f"No usable font in: {candidates}")


def register_fonts() -> None:
    fonts = {
        "Book": [
            "C:/Windows/Fonts/arial.ttf",
            "C:/Windows/Fonts/calibri.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ],
        "Book-Bold": [
            "C:/Windows/Fonts/arialbd.ttf",
            "C:/Windows/Fonts/calibrib.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ],
        "Book-Italic": [
            "C:/Windows/Fonts/ariali.ttf",
            "C:/Windows/Fonts/calibrii.ttf",
            "/System/Library/Fonts/Supplemental/Arial Italic.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
        ],
        "Book-Mono": [
            "C:/Windows/Fonts/consola.ttf",
            "C:/Windows/Fonts/cour.ttf",
            "/System/Library/Fonts/SFNSMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ],
    }
    for name, candidates in fonts.items():
        pdfmetrics.registerFont(TTFont(name, pick_font(candidates)))
    pdfmetrics.registerFontFamily(
        "Book", normal="Book", bold="Book-Bold", italic="Book-Italic",
        boldItalic="Book-Bold",
    )


def pil_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = (
        [
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
            "C:/Windows/Fonts/calibrib.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
        if bold
        else [
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "C:/Windows/Fonts/arial.ttf",
            "C:/Windows/Fonts/calibri.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    )
    return ImageFont.truetype(pick_font(candidates), size)


def wrapped_lines(draw: ImageDraw.ImageDraw, text: str, font, width: int) -> list[str]:
    result: list[str] = []
    for source_line in text.splitlines() or [""]:
        words = source_line.split()
        if not words:
            result.append("")
            continue
        line = words[0]
        for word in words[1:]:
            trial = f"{line} {word}"
            if draw.textbbox((0, 0), trial, font=font)[2] <= width:
                line = trial
            else:
                result.append(line)
                line = word
        result.append(line)
    return result


def draw_center(draw, rect, text, font, fill=INK, spacing=7) -> None:
    x0, y0, x1, y1 = rect
    lines = wrapped_lines(draw, text, font, x1 - x0 - 32)
    heights = [draw.textbbox((0, 0), line or " ", font=font)[3] for line in lines]
    total = sum(heights) + spacing * max(0, len(lines) - 1)
    y = y0 + ((y1 - y0) - total) / 2
    for line, height in zip(lines, heights):
        box = draw.textbbox((0, 0), line, font=font)
        x = x0 + ((x1 - x0) - (box[2] - box[0])) / 2
        draw.text((x, y), line, font=font, fill=fill)
        y += height + spacing


def box(draw, rect, text, fill, outline, font) -> None:
    draw.rounded_rectangle(rect, radius=24, fill=fill, outline=outline, width=4)
    draw_center(draw, rect, text, font)


def arrow(draw, start, end, color=BLUE, width=7) -> None:
    draw.line([start, end], fill=color, width=width)
    x1, y1 = start
    x2, y2 = end
    dx, dy = x2 - x1, y2 - y1
    length = max((dx * dx + dy * dy) ** 0.5, 1.0)
    ux, uy = dx / length, dy / length
    px, py = -uy, ux
    size = 20
    draw.polygon(
        [
            (x2, y2),
            (x2 - ux * size + px * size * 0.55, y2 - uy * size + py * size * 0.55),
            (x2 - ux * size - px * size * 0.55, y2 - uy * size - py * size * 0.55),
        ],
        fill=color,
    )


def canvas(title: str, height: int = 980):
    image = PilImage.new("RGB", (1800, height), WHITE)
    draw = ImageDraw.Draw(image)
    draw.text((70, 42), title, font=pil_font(42, True), fill=NAVY)
    return image, draw


def save_asset(name: str, image: PilImage.Image) -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    image.save(ASSETS / name, quality=95)


def generate_assets() -> None:
    title_font = pil_font(30, True)
    small = pil_font(23)

    image, draw = canvas("Статический и динамический режимы")
    box(draw, (80, 210, 400, 490), "PE32+ x64\nфайл", LIGHT_BLUE, BLUE, title_font)
    box(draw, (520, 120, 930, 400), "Статический анализ\nЧтение байтов\nбез запуска", LIGHT_CYAN, CYAN, title_font)
    box(draw, (520, 530, 930, 810), "Динамический анализ\nЗапуск под\nWindows Debug API", LIGHT_ORANGE, ORANGE, title_font)
    box(draw, (1080, 235, 1600, 695), "Единая модель доказательств\nструктура + события\nоценка + отчеты", LIGHT_GREEN, GREEN, title_font)
    arrow(draw, (400, 350), (520, 260))
    arrow(draw, (400, 350), (520, 670))
    arrow(draw, (930, 260), (1080, 360))
    arrow(draw, (930, 670), (1080, 560))
    save_asset("01_static_dynamic.png", image)

    image, draw = canvas("Упрощенная модель стека Windows x64", 1120)
    layers = [
        ("Аргументы 5 и далее", LIGHT_GRAY),
        ("Shadow space: 32 байта", LIGHT_BLUE),
        ("Адрес возврата", LIGHT_ORANGE),
        ("Сохраненные nonvolatile-регистры", LIGHT_CYAN),
        ("Локальные переменные и временные данные", LIGHT_GREEN),
    ]
    y = 160
    for index, (text, fill) in enumerate(layers):
        box(draw, (410, y, 1390, y + 145), text, fill, BLUE if index < 3 else GREEN, title_font)
        y += 150
    arrow(draw, (250, 850), (250, 195), ORANGE, 9)
    draw.text((95, 875), "рост адресов", font=small, fill=ORANGE)
    draw.text((1450, 170), "RSP до call", font=small, fill=GRAY)
    draw.text((1450, 470), "RSP после call", font=small, fill=GRAY)
    draw.text((1450, 770), "RSP в теле", font=small, fill=GRAY)
    save_asset("02_stack.png", image)

    image, draw = canvas("Логическая структура PE-файла", 1200)
    parts = [
        ("DOS header + e_lfanew", LIGHT_GRAY),
        ("PE signature: PE\\0\\0", LIGHT_BLUE),
        ("COFF header", LIGHT_CYAN),
        ("Optional header PE32+ + Data Directories", LIGHT_GREEN),
        ("Section table", LIGHT_ORANGE),
        (".text  код  RX", "#FCE8E6"),
        (".rdata  данные  R", LIGHT_BLUE),
        (".pdata  RUNTIME_FUNCTION", LIGHT_CYAN),
        (".xdata  UNWIND_INFO", LIGHT_GREEN),
    ]
    y = 135
    for text, fill in parts:
        box(draw, (280, y, 1510, y + 100), text, fill, NAVY, small)
        y += 105
    save_asset("03_pe_layout.png", image)

    image, draw = canvas("RVA, VA и смещение в файле", 940)
    box(draw, (90, 220, 480, 500), "RVA\n0x2350", LIGHT_BLUE, BLUE, title_font)
    box(draw, (700, 100, 1120, 360), "VA\nImageBase + RVA\n0x140002350", LIGHT_GREEN, GREEN, title_font)
    box(draw, (700, 540, 1120, 800), "File offset\nRawPtr + delta\n0x750", LIGHT_CYAN, CYAN, title_font)
    box(draw, (1330, 280, 1710, 620), "Секция\nVA 0x2000\nRawPtr 0x400", LIGHT_ORANGE, ORANGE, title_font)
    arrow(draw, (480, 320), (700, 230))
    arrow(draw, (480, 400), (700, 670))
    arrow(draw, (1330, 390), (1120, 250))
    arrow(draw, (1330, 510), (1120, 670))
    save_asset("04_addresses.png", image)

    image, draw = canvas("Связь .pdata и .xdata", 980)
    box(draw, (80, 260, 470, 650), ".pdata\nRUNTIME_FUNCTION\nBegin RVA\nEnd RVA\nUnwind RVA", LIGHT_CYAN, CYAN, title_font)
    box(draw, (650, 150, 1130, 760), ".xdata\nUNWIND_INFO\nversion + flags\nprolog size\nunwind codes\nhandler или chain", LIGHT_GREEN, GREEN, title_font)
    box(draw, (1320, 260, 1720, 650), "Результат\nкак восстановить\nRSP и регистры", LIGHT_BLUE, BLUE, title_font)
    arrow(draw, (470, 450), (650, 450))
    arrow(draw, (1130, 450), (1320, 450))
    save_asset("05_pdata_xdata.png", image)

    image, draw = canvas("Что делает Windows при исключении", 1180)
    items = [
        ("Возникло исключение", LIGHT_ORANGE, ORANGE),
        ("Уведомление отладчика: first chance", LIGHT_BLUE, BLUE),
        ("VEH: векторные обработчики", LIGHT_CYAN, CYAN),
        ("Поиск RUNTIME_FUNCTION по текущему RIP", LIGHT_GREEN, GREEN),
        ("Чтение UNWIND_INFO и поиск frame handler", LIGHT_GREEN, GREEN),
        ("Обработано?", LIGHT_ORANGE, ORANGE),
        ("Нет: second chance / UEF / завершение", "#FCE8E6", RED),
    ]
    y = 120
    centers = []
    for text, fill, outline in items:
        box(draw, (370, y, 1430, y + 115), text, fill, outline, small)
        centers.append((900, y + 115))
        y += 145
    for i in range(len(centers) - 1):
        arrow(draw, centers[i], (900, centers[i + 1][1] - 115), BLUE, 5)
    save_asset("06_exception_flow.png", image)

    image, draw = canvas("Архитектура EH/Unwind Analyzer", 1180)
    modules = [
        (80, 155, 370, 350, "CLI\nmain.c", LIGHT_BLUE, BLUE),
        (470, 155, 760, 350, "PE parser\npe.c", LIGHT_CYAN, CYAN),
        (860, 155, 1190, 350, "UNWIND decoder\nunwind.c", LIGHT_CYAN, CYAN),
        (1290, 155, 1710, 350, "Heuristics\nheuristics.c", LIGHT_ORANGE, ORANGE),
        (250, 545, 680, 770, "Dynamic collector\ndynamic_win.c\nWindows only", LIGHT_ORANGE, ORANGE),
        (820, 545, 1240, 770, "Reports\nreport.c", LIGHT_GREEN, GREEN),
        (1380, 545, 1710, 770, "Ghidra\nimporter", LIGHT_GREEN, GREEN),
        (600, 925, 1200, 1080, "util.c + app_info.c", LIGHT_GRAY, GRAY),
    ]
    for x0, y0, x1, y1, text, fill, outline in modules:
        box(draw, (x0, y0, x1, y1), text, fill, outline, title_font)
    for start, end in [
        ((370, 250), (470, 250)), ((760, 250), (860, 250)),
        ((1190, 250), (1290, 250)), ((1500, 350), (1080, 545)),
        ((1300, 350), (470, 545)), ((1240, 655), (1380, 655)),
        ((800, 925), (500, 770)), ((1000, 925), (1020, 770)),
    ]:
        arrow(draw, start, end, BLUE, 5)
    save_asset("07_architecture.png", image)

    image, draw = canvas("Как строится итоговая оценка", 980)
    box(draw, (70, 180, 390, 440), "Наблюдения\nсчетчики\nразмещение\nповторы", LIGHT_BLUE, BLUE, title_font)
    box(draw, (500, 130, 860, 490), "Findings\nкод\nсемейство\nseverity\nвес", LIGHT_ORANGE, ORANGE, title_font)
    box(draw, (970, 130, 1330, 490), "Score 0..100\nи evidence\nlevel", LIGHT_CYAN, CYAN, title_font)
    box(draw, (1420, 180, 1740, 440), "Вердикт\nи ручная\nпроверка", LIGHT_GREEN, GREEN, title_font)
    box(draw, (540, 650, 1290, 860), "Mitigations снижают confidence,\nно не стирают факты", LIGHT_GRAY, GRAY, title_font)
    arrow(draw, (390, 310), (500, 310))
    arrow(draw, (860, 310), (970, 310))
    arrow(draw, (1330, 310), (1420, 310))
    arrow(draw, (900, 650), (760, 490), GRAY, 5)
    arrow(draw, (1050, 650), (1150, 490), GRAY, 5)
    save_asset("08_heuristics.png", image)

    image, draw = canvas("Цикл динамического коллектора Windows", 1150)
    items = [
        ("CreateProcess с флагами отладки", LIGHT_BLUE, BLUE),
        ("WaitForDebugEvent", LIGHT_CYAN, CYAN),
        ("Обновление модулей и установка INT3", LIGHT_ORANGE, ORANGE),
        ("Разбор EXCEPTION_DEBUG_EVENT", LIGHT_GREEN, GREEN),
        ("Восстановление байта, RIP, single-step, re-arm", LIGHT_ORANGE, ORANGE),
        ("Запись события и ContinueDebugEvent", LIGHT_GREEN, GREEN),
        ("Exit или timeout", "#FCE8E6", RED),
    ]
    y = 115
    for text, fill, outline in items:
        box(draw, (330, y, 1470, y + 112), text, fill, outline, small)
        y += 140
    for y0 in range(227, 927, 140):
        arrow(draw, (900, y0), (900, y0 + 28), BLUE, 5)
    save_asset("09_dynamic_loop.png", image)

    image, draw = canvas("От ядра к полноценной информационной системе", 930)
    box(draw, (70, 260, 390, 600), "Бинарник", LIGHT_BLUE, BLUE, title_font)
    box(draw, (520, 180, 900, 680), "Ядро\nCLI-процесс\nJSON / HTML / CSV", LIGHT_CYAN, CYAN, title_font)
    box(draw, (1030, 180, 1370, 680), "Backend\nочередь задач\nвалидация\nхранилище", LIGHT_ORANGE, ORANGE, title_font)
    box(draw, (1500, 120, 1760, 370), "БД", LIGHT_GREEN, GREEN, title_font)
    box(draw, (1500, 500, 1760, 750), "Frontend", LIGHT_GREEN, GREEN, title_font)
    arrow(draw, (390, 430), (520, 430))
    arrow(draw, (900, 430), (1030, 430))
    arrow(draw, (1370, 360), (1500, 260))
    arrow(draw, (1370, 520), (1500, 620))
    save_asset("10_integration.png", image)

    image, draw = canvas("Пирамида проверки качества", 1040)
    levels = [
        (250, 820, 1550, 950, "Реальный benign-корпус: 106 PE-файлов", LIGHT_BLUE, BLUE),
        (360, 650, 1440, 800, "Регрессии + schema + semantic invariants", LIGHT_CYAN, CYAN),
        (490, 480, 1310, 630, "Unit tests + mutation tests", LIGHT_GREEN, GREEN),
        (620, 310, 1180, 460, "ASan / UBSan / strict warnings", LIGHT_ORANGE, ORANGE),
        (750, 140, 1050, 290, "Windows dynamic smoke", "#FCE8E6", RED),
    ]
    for x0, y0, x1, y1, text, fill, outline in levels:
        box(draw, (x0, y0, x1, y1), text, fill, outline, small)
    save_asset("11_validation.png", image)

    image, draw = canvas("Сценарий демонстрации на защите", 920)
    items = [
        ("1. Назвать проблему", LIGHT_BLUE, BLUE),
        ("2. Показать архитектуру", LIGHT_CYAN, CYAN),
        ("3. Запустить анализ", LIGHT_ORANGE, ORANGE),
        ("4. Объяснить отчет", LIGHT_GREEN, GREEN),
        ("5. Показать тесты", LIGHT_CYAN, CYAN),
        ("6. Честно назвать границы", LIGHT_GRAY, GRAY),
    ]
    x = 50
    for text, fill, outline in items:
        box(draw, (x, 275, x + 255, 600), text, fill, outline, small)
        if x < 1500:
            arrow(draw, (x + 255, 438), (x + 285, 438), BLUE, 4)
        x += 290
    save_asset("12_defense.png", image)


def inline_markup(text: str) -> str:
    code_spans: list[str] = []

    def remember_code(match: re.Match[str]) -> str:
        code_spans.append(match.group(1))
        return f"@@EHUA_CODE_{len(code_spans) - 1}@@"

    text = re.sub(r"`([^`]+)`", remember_code, text)
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(
        r"\[([^\]]+)\]\((https?://[^)]+)\)",
        r'<link href="\2" color="#1565C0">\1</link>',
        text,
    )
    for index, code in enumerate(code_spans):
        text = text.replace(
            f"@@EHUA_CODE_{index}@@",
            f'<font name="Book-Mono">{html.escape(code, quote=False)}</font>',
        )
    return text


def styles(fundamental: bool = False):
    base = getSampleStyleSheet()
    body_size = 10.6 if fundamental else 9.9
    body_leading = 15.6 if fundamental else 14.2
    list_size = 10.2 if fundamental else 9.5
    list_leading = 14.9 if fundamental else 13.6
    return {
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Book", fontSize=body_size,
            leading=body_leading, textColor=colors.HexColor(INK), spaceAfter=8,
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName="Book-Bold", fontSize=18,
            leading=22, textColor=colors.HexColor(NAVY), spaceBefore=8,
            spaceAfter=8, keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontName="Book-Bold", fontSize=14,
            leading=18, textColor=colors.HexColor(BLUE), spaceBefore=8,
            spaceAfter=6, keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "H3", parent=base["Heading3"], fontName="Book-Bold", fontSize=11.5,
            leading=15, textColor=colors.HexColor(CYAN), spaceBefore=7,
            spaceAfter=4, keepWithNext=True,
        ),
        "bullet": ParagraphStyle(
            "Bullet", parent=base["BodyText"], fontName="Book", fontSize=list_size,
            leading=list_leading, leftIndent=15, firstLineIndent=-9, spaceAfter=4,
        ),
        "number": ParagraphStyle(
            "Number", parent=base["BodyText"], fontName="Book", fontSize=list_size,
            leading=list_leading, leftIndent=18, firstLineIndent=-12, spaceAfter=4,
        ),
        "quote": ParagraphStyle(
            "Quote", parent=base["BodyText"], fontName="Book-Italic", fontSize=9.4,
            leading=13.5, leftIndent=12, rightIndent=8, borderColor=colors.HexColor(CYAN),
            borderWidth=2, borderPadding=8, backColor=colors.HexColor(LIGHT_CYAN),
            spaceBefore=4, spaceAfter=7,
        ),
        "code": ParagraphStyle(
            "Code", parent=base["Code"], fontName="Book-Mono", fontSize=7.5,
            leading=10.2, textColor=colors.HexColor(NAVY), leftIndent=4,
            rightIndent=4, borderColor=colors.HexColor(MID_GRAY), borderWidth=0.5,
            borderPadding=7, backColor=colors.HexColor(LIGHT_GRAY),
            spaceBefore=4, spaceAfter=7,
        ),
        "caption": ParagraphStyle(
            "Caption", parent=base["BodyText"], fontName="Book-Italic", fontSize=8,
            leading=10, textColor=colors.HexColor(GRAY), alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "table": ParagraphStyle(
            "TableCell", parent=base["BodyText"], fontName="Book", fontSize=7.3,
            leading=9.4, textColor=colors.HexColor(INK),
        ),
        "table_header": ParagraphStyle(
            "TableHeader", parent=base["BodyText"], fontName="Book-Bold",
            fontSize=7.3, leading=9.4, textColor=colors.white, alignment=TA_CENTER,
        ),
        "toc1": ParagraphStyle(
            "TOC1", fontName="Book-Bold", fontSize=10, leading=13,
            leftIndent=0, firstLineIndent=0, textColor=colors.HexColor(NAVY),
            spaceBefore=4,
        ),
        "toc2": ParagraphStyle(
            "TOC2", fontName="Book", fontSize=8.8, leading=11.5,
            leftIndent=14, firstLineIndent=0, textColor=colors.HexColor(INK),
        ),
        "toc3": ParagraphStyle(
            "TOC3", fontName="Book", fontSize=8, leading=10.5,
            leftIndent=28, firstLineIndent=0, textColor=colors.HexColor(GRAY),
        ),
    }


class NumberedCanvasMixin:
    pass


class StudyDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str, header_title: str, **kwargs):
        super().__init__(filename, **kwargs)
        self.header_title = header_title
        self.heading_counter = 0
        frame = Frame(
            self.leftMargin, self.bottomMargin, self.width, self.height,
            id="normal", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        )
        self.addPageTemplates(PageTemplate(id="main", frames=frame, onPage=self.draw_page))

    def beforeDocument(self) -> None:
        self.heading_counter = 0

    def draw_page(self, canvas, doc) -> None:
        page = canvas.getPageNumber()
        if page == 1:
            return
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor(MID_GRAY))
        canvas.line(1.8 * cm, A4[1] - 1.35 * cm, A4[0] - 1.8 * cm, A4[1] - 1.35 * cm)
        canvas.setFont("Book", 7.5)
        canvas.setFillColor(colors.HexColor(GRAY))
        canvas.drawString(1.8 * cm, A4[1] - 1.1 * cm, self.header_title)
        canvas.drawRightString(A4[0] - 1.8 * cm, 1.0 * cm, str(page))
        canvas.restoreState()

    def afterFlowable(self, flowable) -> None:
        if not isinstance(flowable, Paragraph):
            return
        level = getattr(flowable, "_heading_level", None)
        if level is None:
            return
        text = flowable.getPlainText()
        key = f"h{self.heading_counter}"
        self.heading_counter += 1
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level - 1, closed=level > 1)
        self.notify("TOCEntry", (level, text, self.page, key))


def cover_story(st, fundamental: bool = False, strict: bool = False, source_name: str = "") -> list:
    is_beginner_book = "Нович" in source_name or "нович" in source_name or "Большой" in source_name
    is_reverse_base = "База_для_реверс" in source_name or "Windows_Linux_Embedded" in source_name
    title = ParagraphStyle(
        "CoverTitle", fontName="Book-Bold", fontSize=27, leading=33,
        textColor=colors.white, alignment=TA_CENTER, spaceAfter=18,
    )
    subtitle = ParagraphStyle(
        "CoverSub", fontName="Book", fontSize=13, leading=18,
        textColor=colors.HexColor(NAVY), alignment=TA_CENTER,
    )
    meta = ParagraphStyle(
        "CoverMeta", fontName="Book", fontSize=10, leading=14,
        textColor=colors.HexColor(GRAY), alignment=TA_CENTER,
    )
    if is_reverse_base:
        cover_name = (
            "БАЗА ДЛЯ<br/>"
            "РЕВЕРС-ИНЖЕНЕРА<br/><br/>"
            "<font size='17'>Windows, Linux, embedded, firmware,<br/>"
            "процессоры, стек, ABI, компиляторы и инструменты</font>"
        )
    elif strict:
        cover_name = (
            "СТРОГИЙ УЧЕБНЫЙ КУРС<br/>"
            "ПО РЕВЕРС-ИНЖИНИРИНГУ<br/><br/>"
            "<font size='17'>От нулевой подготовки до полного разбора<br/>"
            "EH/Unwind Analyzer</font>"
        )
    elif fundamental:
        if is_beginner_book:
            cover_name = (
                "БОЛЬШОЙ УЧЕБНИК<br/>"
                "ДЛЯ НОВИЧКА<br/><br/>"
                "<font size='17'>От полного нуля в IT до понимания<br/>"
                "Windows x64, PE/COFF, unwind и EH/Unwind Analyzer</font>"
            )
        else:
            cover_name = (
                "ФУНДАМЕНТАЛЬНЫЙ УЧЕБНИК<br/>"
                "ПО РЕВЕРС-ИНЖИНИРИНГУ<br/><br/>"
                "<font size='17'>Windows x64, PE/COFF, исключения, unwind<br/>"
                "и полная анатомия EH/Unwind Analyzer</font>"
            )
    else:
        cover_name = (
            "EH/UNWIND ANALYZER<br/><br/>"
            "<font size='18'>Учебная книга для понимания проекта<br/>"
            "и подготовки к защите</font>"
        )
    table = Table(
        [[
            Paragraph(cover_name, title)
        ]],
        colWidths=[16.2 * cm],
        rowHeights=[9.0 * cm],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(NAVY)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor(CYAN)),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
    ]))
    if is_reverse_base:
        subtitle_text = (
            "Универсальный фундаментальный учебник: от битов, памяти, "
            "регистров, функций и компиляции до PE, ELF, raw firmware, "
            "Cortex-M, embedded Linux, JTAG/SWD, Ghidra, отладки и методики "
            "проверяемого reverse engineering."
        )
    elif strict:
        subtitle_text = (
            "Последовательное техническое обучение без пропуска предпосылок: "
            "от представления данных и исполнения C-программы до Windows x64 "
            "exception handling, reverse engineering и построчного устройства "
            "аналитического ядра."
        )
    elif is_beginner_book:
        subtitle_text = (
            "Медленный вход для человека без IT-базы: от байта, файла и памяти "
            "до C, Windows x64 ABI, PE/COFF, unwind metadata, эвристик, "
            "динамического анализа, отчётов и защиты ВКР."
        )
    elif fundamental:
        subtitle_text = (
            "Системный курс от двоичного представления, C и x86-64 до "
            "практического статического и динамического анализа. Отдельный том "
            "пошагово разбирает фактический исходный код проекта, отчёты, "
            "эвристики, тестирование и интеграцию."
        )
    else:
        subtitle_text = (
            "От нулевой базы до уверенного объяснения PE32+, Windows x64 "
            "exception handling, статических эвристик, динамического анализа "
            "и архитектуры программного продукта."
        )

    return [
        Spacer(1, 2.1 * cm),
        table,
        Spacer(1, 0.8 * cm),
        Paragraph(subtitle_text, subtitle),
        Spacer(1, 1.0 * cm),
        Paragraph(
            "Версия проекта: 1.0.0<br/>"
            "Составлено по фактическому исходному коду проекта<br/>"
            "26 июня 2026 года",
            meta,
        ),
        PageBreak(),
    ]


def table_from_rows(rows: list[list[str]], st):
    if not rows:
        return Spacer(1, 1)
    width = 16.8 * cm
    columns = len(rows[0])
    weights = []
    for idx in range(columns):
        max_len = max(len(row[idx]) if idx < len(row) else 0 for row in rows)
        weights.append(min(max(max_len, 8), 42))
    total = sum(weights)
    widths = [width * value / total for value in weights]
    data = []
    for row_index, row in enumerate(rows):
        style = st["table_header"] if row_index == 0 else st["table"]
        data.append([
            Paragraph(inline_markup(row[idx].strip()), style)
            for idx in range(columns)
        ])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(NAVY)),
        ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor(MID_GRAY)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(LIGHT_GRAY)]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def parse_markdown(text: str, st) -> list:
    lines = text.splitlines()
    story: list = []
    paragraph: list[str] = []
    code: list[str] = []
    quote: list[str] = []
    table_rows: list[list[str]] = []
    in_code = False
    seen_h1 = False

    def flush_paragraph() -> None:
        if paragraph:
            story.append(Paragraph(inline_markup(" ".join(paragraph)), st["body"]))
            paragraph.clear()

    def flush_quote() -> None:
        if quote:
            story.append(Paragraph(inline_markup(" ".join(quote)), st["quote"]))
            quote.clear()

    def flush_table() -> None:
        if table_rows:
            cleaned = [
                row for row in table_rows
                if not all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in row)
            ]
            story.append(table_from_rows(cleaned, st))
            story.append(Spacer(1, 5))
            table_rows.clear()

    def flush_all() -> None:
        flush_paragraph()
        flush_quote()
        flush_table()

    for raw in lines:
        line = raw.rstrip()
        if line.startswith("```"):
            flush_all()
            if in_code:
                story.append(Paragraph(
                    html.escape("\n".join(code)).replace("\n", "<br/>").replace(" ", "&#160;"),
                    st["code"],
                ))
                code.clear()
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code.append(line)
            continue
        if line.strip() == "<!-- pagebreak -->":
            flush_all()
            story.append(PageBreak())
            continue
        image_match = re.fullmatch(r"!\[([^\]]*)\]\(([^)]+)\)", line.strip())
        if image_match:
            flush_all()
            caption, rel_path = image_match.groups()
            image_path = SOURCE.parent / rel_path
            with PilImage.open(image_path) as pic:
                ratio = pic.height / pic.width
            width = 16.3 * cm
            height = min(width * ratio, 17.5 * cm)
            story.append(Image(str(image_path), width=width, height=height, hAlign="CENTER"))
            if caption:
                story.append(Paragraph(inline_markup(caption), st["caption"]))
            continue
        if line.startswith("|") and line.endswith("|"):
            flush_paragraph()
            flush_quote()
            table_rows.append([cell.strip() for cell in line.strip("|").split("|")])
            continue
        if table_rows:
            flush_table()
        if not line.strip():
            flush_all()
            continue
        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            flush_all()
            level = len(heading.group(1))
            if level == 1:
                if seen_h1:
                    story.append(PageBreak())
                seen_h1 = True
            p = Paragraph(inline_markup(heading.group(2)), st[f"h{level}"])
            p._heading_level = level
            story.append(p)
            continue
        if line.startswith("> "):
            flush_paragraph()
            quote.append(line[2:].strip())
            continue
        if quote:
            flush_quote()
        bullet = re.match(r"^-\s+(.+)$", line)
        if bullet:
            flush_paragraph()
            story.append(Paragraph("• " + inline_markup(bullet.group(1)), st["bullet"]))
            continue
        numbered = re.match(r"^(\d+)\.\s+(.+)$", line)
        if numbered:
            flush_paragraph()
            story.append(Paragraph(
                f"{numbered.group(1)}. " + inline_markup(numbered.group(2)),
                st["number"],
            ))
            continue
        paragraph.append(line.strip())
    flush_all()
    return story


def render(source: Path = SOURCE, output: Path = OUTPUT) -> None:
    register_fonts()
    generate_assets()
    reverse_base = (
        "База_для_реверс" in source.name
        or "База_для_реверс" in output.name
        or "Windows_Linux_Embedded" in source.name
        or "Windows_Linux_Embedded" in output.name
    )
    strict = "Строгий" in source.name or "Строгий" in output.name
    beginner = (
        "Нович" in source.name
        or "Нович" in output.name
        or "Большой" in source.name
        or "Большой" in output.name
    )
    fundamental = (
        reverse_base
        or
        strict
        or "Фундаменталь" in source.name
        or "Фундаменталь" in output.name
        or beginner
    )
    st = styles(fundamental)
    toc = TableOfContents()
    toc.levelStyles = [st["toc1"], st["toc2"], st["toc3"]]
    toc.dotsMinLevel = 0
    toc_story = [
        Paragraph("Содержание", st["h1"]),
        Spacer(1, 8),
        toc,
        PageBreak(),
    ]
    story = cover_story(st, fundamental, strict, source.name + output.name) + toc_story + parse_markdown(source.read_text(encoding="utf-8"), st)
    output.parent.mkdir(parents=True, exist_ok=True)
    doc = StudyDocTemplate(
        str(output),
        header_title=(
            "База для реверс-инженера: Windows, Linux и embedded"
            if reverse_base
            else (
            "Строгий курс reverse engineering и EH/Unwind Analyzer"
            if strict
            else (
                "Большой учебник для новичка: EH/Unwind Analyzer"
                if beginner else
                (
                    "Фундаментальный курс reverse engineering и EH/Unwind Analyzer"
                    if fundamental else
                "EH/Unwind Analyzer: учебный курс"
                )
            )
            )
        ),
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=1.65 * cm,
        bottomMargin=1.45 * cm,
        title=(
            "База для реверс-инженера с нуля: Windows, Linux и embedded"
            if reverse_base
            else (
            "Строгий учебный курс по reverse engineering и EH/Unwind Analyzer"
            if strict
            else (
                "Большой учебник для новичка по EH/Unwind Analyzer"
                if beginner else
                (
                    "Фундаментальный учебник по reverse engineering и EH/Unwind Analyzer"
                    if fundamental else
                "EH/Unwind Analyzer: учебная книга"
                )
            )
            )
        ),
        author="Project documentation",
        subject=(
            "Universal reverse engineering fundamentals: Windows, Linux, embedded and firmware"
            if reverse_base
            else "PE32+, Windows x64 unwind metadata and EH/Unwind Analyzer"
        ),
    )
    doc.multiBuild(story)


if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else SOURCE
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else OUTPUT
    render(src, dst)
