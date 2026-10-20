#!/usr/bin/env python3
from __future__ import annotations

import shutil
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "docs" / "ru" / "ПО ПРИЗНАКАМ НОВАЯ ВЕРСИЯ.pdf"
BACKUP = ROOT / "docs" / "ru" / "ПО ПРИЗНАКАМ НОВАЯ ВЕРСИЯ - до добавления метрик.pdf"
SOURCE_TXT = ROOT / "docs" / "ru" / "ПО ПРИЗНАКАМ НОВАЯ ВЕРСИЯ - приложение метрики.txt"
TMP_DIR = ROOT.parent / "tmp" / "pdfs" / "features_metrics_appendix"
APPENDIX = TMP_DIR / "metrics_appendix.pdf"
COMBINED = TMP_DIR / "combined.pdf"
FONT = Path(
    r"C:\Users\Templar\.cache\codex-runtimes\codex-primary-runtime"
    r"\dependencies\native\poppler\Library\share\fonts\DejaVuSans.ttf"
)


TEXT_LOG: list[str] = []


def log(text: str) -> None:
    TEXT_LOG.append(text.rstrip() + "\n")


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont("DejaVu", str(FONT)))


def make_styles():
    base = getSampleStyleSheet()
    for style in base.byName.values():
        style.fontName = "DejaVu"
    base.add(
        ParagraphStyle(
            "MetricTitle",
            parent=base["Title"],
            fontName="DejaVu",
            fontSize=23,
            leading=29,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#1d3557"),
            spaceAfter=12,
        )
    )
    base.add(
        ParagraphStyle(
            "MetricH1",
            parent=base["Heading1"],
            fontName="DejaVu",
            fontSize=18,
            leading=23,
            textColor=colors.HexColor("#1d3557"),
            spaceBefore=8,
            spaceAfter=9,
        )
    )
    base.add(
        ParagraphStyle(
            "MetricH2",
            parent=base["Heading2"],
            fontName="DejaVu",
            fontSize=13.5,
            leading=18,
            textColor=colors.HexColor("#263238"),
            spaceBefore=8,
            spaceAfter=5,
        )
    )
    base.add(
        ParagraphStyle(
            "MetricBody",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=9.2,
            leading=13.2,
            spaceAfter=4.5,
        )
    )
    base.add(
        ParagraphStyle(
            "MetricSmall",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=7.6,
            leading=10.2,
            spaceAfter=2,
        )
    )
    base.add(
        ParagraphStyle(
            "MetricBullet",
            parent=base["BodyText"],
            fontName="DejaVu",
            fontSize=8.9,
            leading=12.4,
            leftIndent=11,
            firstLineIndent=-7,
            spaceAfter=2,
        )
    )
    return base


ST = None
STORY: list = []


def p(text: str) -> None:
    log(text)
    STORY.append(Paragraph(text, ST["MetricBody"]))


def h1(text: str) -> None:
    log("\n# " + text)
    STORY.append(Paragraph(text, ST["MetricH1"]))


def h2(text: str) -> None:
    log("\n## " + text)
    STORY.append(Paragraph(text, ST["MetricH2"]))


def bullets(items: list[str]) -> None:
    for item in items:
        log("- " + item)
        STORY.append(Paragraph("- " + item, ST["MetricBullet"]))
    STORY.append(Spacer(1, 4))


def numbered(items: list[str]) -> None:
    for index, item in enumerate(items, 1):
        log(f"{index}. {item}")
        STORY.append(Paragraph(f"{index}. {item}", ST["MetricBullet"]))
    STORY.append(Spacer(1, 4))


def table(headers: list[str], rows: list[list[object]], widths_mm: list[float]) -> None:
    log("\n" + " | ".join(headers))
    for row in rows:
        log(" | ".join(str(x) for x in row))
    data = [[Paragraph(str(h), ST["MetricSmall"]) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(cell), ST["MetricSmall"]) for cell in row])
    tbl = Table(data, colWidths=[w * mm for w in widths_mm], repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, -1), "DejaVu"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3.5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3.5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    STORY.append(tbl)
    STORY.append(Spacer(1, 7))


def pagebreak() -> None:
    STORY.append(PageBreak())
    log("\n--- page break ---")


def footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("DejaVu", 7.2)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    width, _ = A4
    canvas.drawString(18 * mm, 10 * mm, "ПО ПРИЗНАКАМ НОВАЯ ВЕРСИЯ - приложение о метриках")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"прил., стр. {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
    canvas.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
    canvas.restoreState()


def build_appendix() -> None:
    STORY.append(Spacer(1, 16 * mm))
    STORY.append(Paragraph("Приложение: метрики проекта и как их защищать", ST["MetricTitle"]))
    p(
        "Короткий ответ на защите: в проекте есть конкретные метрики, но они не являются статистической вероятностью вредоносности. "
        "Это инженерные triage-метрики для приоритизации ручного анализа: счетчики структурных нарушений, доли, score 0..100, "
        "suspicion = score / 100, confidence, evidence level, dynamic signal count, case strength и флаг requires_manual_review. "
        "Окончательный вывод делает реверс-инженер по цепочке evidence: PE sections -> RUNTIME_FUNCTION -> UNWIND_INFO -> finding -> report -> ручная проверка."
    )
    h1("1. Какие метрики реально есть")
    table(
        ["Группа", "Метрики", "Где видны", "Что означают"],
        [
            [
                "Структурные счетчики",
                "section_raw_oob, section_virtual_oob, overlaps, misaligned, rf_invalid_ranges, rf_oob, parse_fail",
                "JSON: pe_validation, heuristic_analysis",
                "Сколько конкретных структурных проблем найдено в PE/.pdata/UNWIND_INFO.",
            ],
            [
                "Доли и ratios",
                "unwind_reuse_ratio, unwind_unique_ratio, handler_reuse_ratio; проценты parse/range проблем",
                "JSON и finding messages",
                "Насколько проблема массовая, а не единичная.",
            ],
            [
                "Score",
                "score 0..100",
                "heuristic_analysis.score, HTML card, console",
                "Сумма весов сработавших признаков, ограниченная 0..100.",
            ],
            [
                "Suspicion",
                "suspicion = score / 100",
                "heuristic_analysis.suspicion",
                "Нормированная форма score. Это не вероятность.",
            ],
            [
                "Confidence",
                "confidence 0.05..0.90 static, final_confidence до 0.98",
                "heuristic_analysis.confidence, assessment.final_confidence",
                "Уверенность в интерпретации evidence с учетом разнообразия сигналов и ослабляющих правил.",
            ],
            [
                "Evidence level",
                "none, weak, medium, strong",
                "heuristic_analysis.evidence_level, assessment",
                "Качественная сила evidence по счетчикам severity и score.",
            ],
            [
                "Dynamic metrics",
                "exceptions_seen, handler hits, VEH/VCH/UEF, RtlAddFunctionTable, dynamic_signal_count",
                "dynamic_validation, assessment",
                "Что реально наблюдалось при запуске target под Debug API.",
            ],
            [
                "Итоговая классификация",
                "verdict, final_verdict, case_strength, static_dynamic_correlation",
                "heuristic_analysis, assessment",
                "Техническая сводка для triage, не автоматический приговор.",
            ],
        ],
        [31, 45, 38, 55],
    )
    h2("Главный вывод")
    bullets(
        [
            "Метрики есть и они формализованы в коде и JSON schema.",
            "Метрики являются эвристическими, инженерными, объяснимыми и воспроизводимыми.",
            "Проект не утверждает ROC/AUC-калибровку, вероятность malware или универсальные пороги для всех packer/protector families.",
            "Реверс-инженер обязан читать findings, representative RVA, section context, weakening rules и manual_validation_steps.",
        ]
    )
    pagebreak()

    h1("2. Как считается score 0..100")
    p(
        "Score начинается с 0. Каждый сработавший finding добавляет фиксированный вес. После добавления весов значение ограничивается диапазоном 0..100. "
        "Поэтому score - это шкала подозрительности по инженерной матрице, а не статистическая вероятность."
    )
    table(
        ["Finding / ситуация", "Вес", "Комментарий"],
        [
            ["pe_section_raw_oob", "+25", "Секция указывает raw range за пределами файла."],
            ["pe_section_virtual_oob", "+20", "Virtual range секции выходит за SizeOfImage."],
            ["pe_section_raw_overlap", "+15", "Raw ranges секций пересекаются."],
            ["pe_section_virtual_overlap", "+20", "Virtual ranges секций пересекаются."],
            ["pe_section_misaligned", "+8", "Нарушены alignment/header invariants."],
            ["pe_exception_directory_oob", "+25", "Exception directory отсутствует, неполон или нечитабелен при заявленном наличии."],
            ["no_runtime_functions", "+10", "Нет .pdata при наличии executable sections; может быть benign leaf-only."],
            ["invalid_ranges", "+10 / +20", "End <= Begin; high если доля > 1%."],
            ["rf_oob", "+10 / +25", "Begin/End вне SizeOfImage; high если доля > 1%."],
            ["unwind_rva_oob", "+10 / +25", "UnwindInfoRVA отсутствует или вне image; high если доля > 1%."],
            ["rf_unsorted", "+15", "Таблица не отсортирована по BeginAddress."],
            ["rf_overlaps", "+25", "Диапазоны функций перекрываются после сортировки."],
            ["duplicate_begin", "+10", "Дублируется BeginAddress."],
            ["unwind_parse_fail", "+10 / +25", "UNWIND_INFO не парсится; high если доля > 1%."],
            ["unwind_anomalies", "+10 / +20", "Аномалии в version/opcode/chain/etc.; high если доля > 5%."],
            ["unwind_reuse_moderate", "+10", "Reuse > 10%, n > 200 и есть подтверждающий статический сигнал."],
            ["unwind_reuse_strong", "+20", "Reuse > 30% при n > 200."],
            ["handler_dominance", "+15", "Один handler доминирует: handler_count > 50 и reuse ratio > 0.80."],
            ["unwind_in_exec_section", "+20", "Unwind metadata лежит в executable section."],
            ["unwind_unusual_section", "+8 / +15", "Unwind metadata не в xdata/rdata/pdata-like section; high если > 5%."],
            ["unwind_writable_section", "+10 / +18", "Unwind metadata лежит в writable section; high если > 5%."],
            ["handler_nonexec_section", "+15", "Handler target в non-exec или неизвестной section."],
            ["handler_writable_section", "+10", "Handler target в writable section."],
            ["placement_exec_nonexec_handler_combo", "+10", "Комбинация executable unwind metadata и non-exec handler."],
            ["placement_integrity_combo", "+8", "Placement anomaly подтверждена integrity-проблемой."],
            ["reuse_dominance_combo", "+8", "Heavy unwind reuse совпал с dominant handler."],
            ["writable_metadata_handler_combo", "+10", "Writable unwind metadata совпала с writable handler target."],
        ],
        [58, 25, 84],
    )
    h2("Пороги verdict")
    table(
        ["Score", "verdict", "Как читать"],
        [
            ["0..14", "no_strong_static_anomalies", "Сильных статических признаков нет, но это не доказывает benign."],
            ["15..39", "low_suspicion", "Есть слабое/локальное основание для проверки."],
            ["40..69", "moderate_suspicion", "Есть значимый набор признаков, нужен разбор в Ghidra/PE viewer."],
            ["70..100", "high_suspicion", "Сильная структурная картина, ручная проверка обязательна."],
        ],
        [28, 50, 91],
    )
    pagebreak()

    h1("3. Как считать доли и ratios")
    p(
        "Многие признаки важны не только фактом срабатывания, но и масштабом. Одна странная запись в маленьком файле и массовая поломка таблицы - разные ситуации. "
        "Поэтому проект считает счетчики и отношения."
    )
    table(
        ["Метрика", "Формула", "Интерпретация"],
        [
            ["invalid_ranges_pct", "rf_invalid_ranges / total", "Доля записей .pdata, где EndAddress <= BeginAddress."],
            ["oob_pct", "rf_oob / total", "Доля функций, чей begin/end выходит за SizeOfImage."],
            ["unwind_oob_pct", "rf_unwind_oob / total", "Доля записей с unmappable/out-of-image UnwindInfoRVA."],
            ["unwind_fail_pct", "unwind_parse_fail / total", "Доля UNWIND_INFO, которые не удалось разобрать."],
            ["unwind_anom_pct", "unwind_anomalies / total", "Доля записей с нефомальными unwind anomalies."],
            ["unwind_reuse_ratio", "max_count_same_UnwindInfoRVA / total", "Насколько много функций ссылается на один и тот же unwind blob."],
            ["unwind_unique_ratio", "unique_UnwindInfoRVA / total", "Насколько разнообразна unwind metadata."],
            ["handler_reuse_ratio", "max_count_same_HandlerRVA / handler_count", "Насколько один handler доминирует среди функций с handler."],
        ],
        [45, 55, 69],
    )
    h2("Пороговые правила")
    bullets(
        [
            "1% для invalid_ranges, rf_oob, unwind_rva_oob и unwind_parse_fail: выше этого проблема считается не единичной.",
            "5% для unwind_anomalies и placement prevalence: выше этого видна широкая структурная картина.",
            "10% для moderate unwind reuse: учитывается только при total > 200 и наличии другого статического подтверждения.",
            "30% для strong unwind reuse: много функций указывают на один UnwindInfoRVA при total > 200.",
            "80% для handler dominance: один handler покрывает подавляющее большинство функций с handler, но benign runtime-like context может подавить finding.",
        ]
    )
    h2("Как объяснить на защите")
    p(
        "Если спросили, почему используются проценты: потому что абсолютный счетчик без denominator вводит в заблуждение. "
        "Например, 1 parse failure из 3 функций и 1 parse failure из 300 функций имеют разный аналитический вес. "
        "В отчете поэтому надо смотреть одновременно total, affected_count и ratio."
    )
    pagebreak()

    h1("4. Confidence: уверенность, а не вероятность")
    p(
        "Confidence показывает не вероятность вредоносности, а уверенность проекта в интерпретации статического verdict. "
        "Он растет, когда evidence разнообразно и сильно, и уменьшается, когда сигнал одиночный, выборка маленькая или есть benign explanation."
    )
    table(
        ["Компонент", "Значение"],
        [
            ["База", "0.15"],
            ["Если score == 0", "0.20 перед penalty"],
            ["За каждое evidence family", "+0.11"],
            ["За каждый high/critical finding", "+0.08"],
            ["За каждый medium finding", "+0.04"],
            ["Hard table-integrity bonus", "+0.08 при invalid ranges / rf_oob / unwind_oob / overlaps"],
            ["Hard unwind-integrity bonus", "+0.08 при parse_fail / unwind_anomalies"],
            ["single_signal_only", "-0.12 если один non-strong finding"],
            ["small_sample_size", "-0.06 если total < 32, findings есть, strong нет"],
            ["placement_only_signal", "-0.10 если есть только unusual placement без integrity/exec/writable context"],
            ["single_family_only", "-0.08 если evidence из одной family и strong нет"],
            ["Static clamp", "0.05..0.90"],
        ],
        [62, 104],
    )
    h2("Final confidence")
    p(
        "В блоке assessment final_confidence стартует от static confidence. Если dynamic session завершена полноценно и есть dynamic signals, добавляется +0.10. "
        "Если есть static/dynamic correlation, добавляется еще +0.10. Верхняя граница final_confidence - 0.98. "
        "Это все еще не probability; это удобная шкала надежности evidence chain."
    )
    pagebreak()

    h1("5. Evidence level, case strength и dynamic metrics")
    h2("Static evidence level")
    table(
        ["Level", "Правило"],
        [
            ["strong", "strong_count >= 2 или score >= 70"],
            ["medium", "strong_count >= 1 или medium_count >= 2 или score >= 30"],
            ["weak", "есть findings или score > 0, но нет medium/strong условий"],
            ["none", "finding_count == 0 и score == 0"],
        ],
        [35, 130],
    )
    h2("Dynamic signal count")
    table(
        ["Категория", "Когда добавляет 1 к dynamic_signal_count"],
        [
            ["unwind handler", "unwind_handler_hits > 0"],
            ["VEH", "veh_hits > 0 или veh_registrations > 0"],
            ["VCH", "vch_hits > 0 или vch_registrations > 0"],
            ["UEF", "uef_hits > 0 или uef_set_calls > 0"],
            ["Dynamic function tables", "rtl_add_function_table_calls > 0 или rtl_install_function_table_cb_calls > 0"],
            ["Second chance", "second_chance_seen > 0"],
        ],
        [48, 118],
    )
    h2("Runtime evidence level")
    bullets(
        [
            "strong: handler hit и минимум один дополнительный medium runtime signal.",
            "medium: handler hit или минимум два medium runtime signals.",
            "weak: только слабая runtime activity, например first-chance exceptions или registrations.",
            "none: runtime activity нет или dynamic mode не запускался.",
            "Если session неполная, timeout или instrumentation incomplete, runtime evidence cap = weak.",
        ]
    )
    h2("Case strength")
    table(
        ["case_strength", "Правило"],
        [
            ["strong_correlated_case", "Есть static/dynamic correlation и static или runtime evidence = strong."],
            ["medium_correlated_case", "Есть correlation и static или runtime evidence = medium."],
            ["strong_unconfirmed_case", "Strong static/runtime evidence без cross-layer correlation."],
            ["medium_case", "Medium static/runtime evidence."],
            ["weak_case", "Только weak evidence."],
            ["no_case", "Нет meaningful evidence."],
        ],
        [55, 111],
    )
    pagebreak()

    h1("6. Метрики качества проекта и валидации")
    p(
        "Кроме метрик одного анализа, в проекте есть validation/evidence метрики качества: сколько тестов прошло, сколько отчетов валидны, "
        "сколько файлов corpus flagged, время анализа и outcomes dynamic corpus. Они нужны для защиты работоспособности инструмента, "
        "но не заменяют per-file score."
    )
    table(
        ["Метрика качества", "Пример из evidence 1.0.0", "Смысл"],
        [
            ["CTest", "MinGW Release 16/16 PASS, MSVC Release 16/16 PASS", "Сборка и unit/regression проверки проходят."],
            ["Real benign static corpus", "106/106 PASS, score 0", "Совместимость на реальных benign PE без срабатываний."],
            ["Labeled static corpus", "14/14 PASS, 12 anomalous flagged", "Синтетические признаки обнаруживаются."],
            ["Dynamic smoke", "4/4 PASS", "Контролируемые VEH/VCH/UEF/RtlFunctionTable сценарии работают."],
            ["Dynamic full corpus", "124/124 valid", "Динамические отчеты структурно валидны."],
            ["Performance", "median 9 ms, p95 10 ms, max 15 ms на labeled static corpus", "Static анализ быстрый на тестовом наборе."],
        ],
        [43, 55, 68],
    )
    h2("Чего пока нет")
    bullets(
        [
            "Нет заявленной ROC/AUC калибровки.",
            "Нет утверждения, что score = вероятность malware.",
            "Нет универсального threshold для всех компиляторов, protectors и JIT/runtime scenarios.",
            "Есть scaffold `tests/score_sweep.py`, который позволяет расширять corpus и сравнивать пороги в будущей работе.",
        ]
    )
    pagebreak()

    h1("7. Как читать отчет по метрикам")
    numbered(
        [
            "Сначала проверь report_metadata: версия tool/schema, SHA-256 input, command line, strict_abi/follow_chain.",
            "Посмотри total runtime functions. Маленький total усиливает риск переинтерпретации ratios.",
            "Открой pe_validation: если уже PE layout сломан, дальнейшие признаки читаются в этом контексте.",
            "Прочитай heuristic_analysis.score, suspicion, verdict, evidence_level.",
            "Не останавливайся на score. Открой findings: code, family, severity, affected_count, representative_rva, representative_section.",
            "Сравни counters и ratios: массовая ли проблема или один локальный случай.",
            "Проверь confidence и weakening_rules_applied. Если есть mitigation, вывод должен звучать осторожнее.",
            "Если dynamic_validation есть, сначала проверь ok/timed_out/target_exited/instrumentation_complete.",
            "Потом смотри dynamic_signal_count, runtime_evidence_level и static_dynamic_correlation.",
            "Заверши manual_validation_steps: Ghidra, PE viewer, hex view, debugger/lab.",
        ]
    )
    h2("Примеры формулировок")
    bullets(
        [
            "Score 0: инструмент не нашел сильных статических anomalies; это не доказательство benign semantics.",
            "Low score + low confidence: есть одиночный сигнал, его надо проверить вручную, особенно если sample small.",
            "High score + strong evidence: структура PE/unwind сильно отличается от нормальной, но причина устанавливается manual validation.",
            "Runtime signals only: динамика что-то показала, но статической корреляции нет; это отдельное наблюдение, не полный proof graph.",
            "Strong correlated case: лучший сценарий evidence, потому что static suspicious context подтвержден runtime behavior.",
        ]
    )
    pagebreak()

    h1("8. Ответы на вопросы комиссии")
    table(
        ["Вопрос", "Короткий ответ"],
        [
            [
                "Есть ли в проекте метрики?",
                "Да. Есть счетчики, ratios, score 0..100, suspicion, confidence, evidence_level, dynamic_signal_count, case_strength и validation metrics.",
            ],
            [
                "Это вероятность вредоносности?",
                "Нет. Score и confidence являются инженерными эвристическими шкалами. Проект не заявляет статистическую вероятность.",
            ],
            [
                "Кто принимает итоговое решение?",
                "Реверс-инженер. Проект дает structured evidence и manual validation plan, а не автоматический юридический/вредоносный verdict.",
            ],
            [
                "Как считается score?",
                "Аддитивно по матрице весов findings с clamp 0..100. Например parse fail, OOB, suspicious placement, reuse/dominance и combo-сигналы добавляют разные веса.",
            ],
            [
                "Как оценивать confidence?",
                "По разнообразию и силе evidence: families, strong/medium findings, hard integrity bonuses; затем применяются weakening rules.",
            ],
            [
                "Почему нужны weakening rules?",
                "Чтобы одиночный сигнал, маленькая выборка или benign placement не выглядели слишком уверенно.",
            ],
            [
                "Что такое case_strength?",
                "Итоговый класс evidence: no/weak/medium/strong_unconfirmed/medium_correlated/strong_correlated case.",
            ],
            [
                "Как доказать воспроизводимость?",
                "Показать JSON schema, report metadata, SHA-256 input, CTest gates, corpus summaries и score_sweep scaffold.",
            ],
        ],
        [47, 120],
    )
    h2("Финальная защитная формулировка")
    p(
        "В работе используются не ML-метрики классификации, а объяснимые инженерные метрики анализа EH/Unwind metadata. "
        "Они позволяют количественно ранжировать подозрительность, показать силу и разнообразие evidence, отделить статические признаки от runtime observations "
        "и сформировать план ручной валидации. Поэтому корректный вывод звучит так: инструмент не заменяет реверс-инженера, а дает воспроизводимую evidence-based основу для его решения."
    )


def write_appendix() -> None:
    global ST
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    register_fonts()
    ST = make_styles()
    build_appendix()
    doc = SimpleDocTemplate(
        str(APPENDIX),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="Приложение о метриках",
        author="EH/Unwind Analyzer project",
    )
    doc.build(STORY, onFirstPage=footer, onLaterPages=footer)
    SOURCE_TXT.write_text("\n".join(TEXT_LOG), encoding="utf-8")


def merge() -> None:
    if not TARGET.exists():
        raise FileNotFoundError(TARGET)
    if not BACKUP.exists():
        shutil.copy2(TARGET, BACKUP)
    writer = PdfWriter()
    for path in (TARGET, APPENDIX):
        reader = PdfReader(str(path))
        for page in reader.pages:
            writer.add_page(page)
    with COMBINED.open("wb") as f:
        writer.write(f)
    shutil.copy2(COMBINED, TARGET)


def main() -> int:
    write_appendix()
    merge()
    print(TARGET)
    print(BACKUP)
    print(APPENDIX)
    print(SOURCE_TXT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
