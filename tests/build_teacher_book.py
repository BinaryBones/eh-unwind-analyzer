#!/usr/bin/env python3
"""Assemble the strict Russian teaching course from reviewed chapter sources."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHAPTER_DIR = ROOT / "book_source" / "teacher_book"
OUTPUT = ROOT / "docs" / "ru" / "EH_Unwind_Analyzer_Строгий_учебный_курс.md"

CHAPTERS = [
    "00_teacher_contract.md",
    "01_from_source_to_running_process.md",
    "02_data_memory_addresses.md",
    "03_cpu_functions_stack_abi.md",
    "04_windows_process_threads_exceptions.md",
    "05_pe_format_as_loader_contract.md",
    "06_exception_dispatch_unwind_theory.md",
    "07_reverse_engineering_method_ghidra_debugger.md",
    "10_project_system_model.md",
    "11_main_cli_lifecycle.md",
    "12_util_byte_foundation.md",
    "13_pe_parser_complete.md",
    "14_unwind_decoder_complete.md",
    "15_heuristics_evidence_engine.md",
    "16_dynamic_windows_collector.md",
    "17_reporting_assessment_integration.md",
    "18_build_tests_release_readiness.md",
    "19_benign_richer_byte_to_report.md",
    "20_suspicious_samples_investigations.md",
    "21_problems_with_complete_solutions.md",
    "23_technical_evidence_and_coverage.md",
    "24_twenty_seven_findings_rationale.md",
    "25_accuracy_validation_and_experiment_design.md",
    "26_unwind_v3_compatibility.md",
    "22_glossary_sources_and_defense_map.md",
]

DIAGRAMS_AFTER = {
    "00_teacher_contract.md": (
        "../../book_source/study_assets/01_static_dynamic.png",
        "Статический и динамический режимы образуют разные слои доказательств.",
    ),
    "03_cpu_functions_stack_abi.md": (
        "../../book_source/study_assets/02_stack.png",
        "Логическая модель стека Windows x64.",
    ),
    "05_pe_format_as_loader_contract.md": (
        "../../book_source/study_assets/03_pe_layout.png",
        "Основные области PE image.",
    ),
    "06_exception_dispatch_unwind_theory.md": (
        "../../book_source/study_assets/05_pdata_xdata.png",
        "Связь function table и unwind records.",
    ),
    "07_reverse_engineering_method_ghidra_debugger.md": (
        "../../book_source/study_assets/06_exception_flow.png",
        "Уровни прохождения исключения в исследуемом процессе.",
    ),
    "10_project_system_model.md": (
        "../../book_source/study_assets/07_architecture.png",
        "Модульная архитектура EH/Unwind Analyzer.",
    ),
    "15_heuristics_evidence_engine.md": (
        "../../book_source/study_assets/08_heuristics.png",
        "Преобразование наблюдений в findings и итоговую assessment.",
    ),
    "16_dynamic_windows_collector.md": (
        "../../book_source/study_assets/09_dynamic_loop.png",
        "Главный цикл Windows dynamic collector.",
    ),
    "17_reporting_assessment_integration.md": (
        "../../book_source/study_assets/10_integration.png",
        "Интеграция ядра с backend, хранилищем и frontend.",
    ),
    "18_build_tests_release_readiness.md": (
        "../../book_source/study_assets/11_validation.png",
        "Уровни проверки качества проекта.",
    ),
    "22_glossary_sources_and_defense_map.md": (
        "../../book_source/study_assets/12_defense.png",
        "Последовательность технической демонстрации на защите.",
    ),
}


def assemble() -> str:
    missing = [name for name in CHAPTERS if not (CHAPTER_DIR / name).is_file()]
    if missing:
        raise FileNotFoundError(f"Missing teacher-book chapters: {missing}")

    parts = [
        "# Строгий учебный курс по reverse engineering и EH/Unwind Analyzer",
        "",
        "## Назначение издания",
        "",
        (
            "Это последовательный технический курс для читателя без исходной "
            "подготовки. Он вводит понятия в порядке зависимостей, выводит связи "
            "между C, машинным исполнением, Windows x64 ABI, PE/COFF, обработкой "
            "исключений и reverse engineering, а затем разбирает фактический "
            "исходный код EH/Unwind Analyzer по модулям, данным, ошибкам, тестам "
            "и отчётам."
        ),
        "",
        (
            "Материал не заявляет, что чтение одной книги автоматически заменяет "
            "практику профессионального reverse engineer. Он формирует строгий "
            "фундамент именно для понимания проекта, его защиты и дальнейшей "
            "практической подготовки."
        ),
        "",
        "Версия проекта: `1.0.0`. Версия report schema: `1.3.0`.",
        "",
    ]

    for name in CHAPTERS:
        text = (CHAPTER_DIR / name).read_text(encoding="utf-8").strip()
        parts.extend([text, ""])
        diagram = DIAGRAMS_AFTER.get(name)
        if diagram:
            path, caption = diagram
            parts.extend([f"![{caption}]({path})", ""])

    return "\n".join(parts).rstrip() + "\n"


def main() -> None:
    OUTPUT.write_text(assemble(), encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
