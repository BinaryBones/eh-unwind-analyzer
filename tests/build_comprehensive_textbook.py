#!/usr/bin/env python3
"""Build the comprehensive Russian EH/Unwind Analyzer textbook source."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHAPTER_DIR = ROOT / "book_source" / "teacher_book"
BOOK_DIR = ROOT / "docs" / "ru" / "УЧЕБНИК"
OUTPUT = BOOK_DIR / "EH_Unwind_Analyzer_Фундаментальный_учебник.md"

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
    "02_data_memory_addresses.md": (
        "../../book_source/study_assets/04_addresses.png",
        "RVA, VA и file offset являются разными координатами одного объекта.",
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


def front_matter() -> str:
    return """# EH/Unwind Analyzer: фундаментальный учебник с полного нуля

## Назначение книги

Эта книга написана как самостоятельный учебник по теме ВКР, а не как краткая пояснительная записка. Её цель - провести читателя от состояния «я никогда не сталкивался с reverse engineering, PE-файлами и Windows unwind» до состояния, в котором он способен читать исходный код EH/Unwind Analyzer, понимать отчёты, объяснять архитектуру проекта, проверять результаты руками и защищать инженерные решения.

Материал намеренно идёт медленно. В низкоуровневых темах опасна иллюзия понимания: можно выучить, что `RVA` - это relative virtual address, но не понимать, почему это не file offset; можно запомнить `UNWIND_INFO`, но не понимать, зачем Windows нужен prolog; можно увидеть score 70 и ошибочно принять его за 70 процентов вероятности вредоносности. Поэтому каждый важный термин вводится через назначение, структуру, место в соседних понятиях, представление в файле или памяти, использование в проекте и способ проверки.

Книга ориентируется на учебный принцип лучших работ по reverse engineering и системному программированию: сначала строится понятийная лестница, затем показываются реальные структуры, затем читатель проходит сквозной пример, а после этого учится делать проверяемый вывод. Текст не копирует чужие книги и не имитирует конкретного автора; он использует сильную учебную идею таких трудов: уважать читателя, не прятать сложность и связывать теорию с практическим объектом.

## Что именно изучается

Предмет книги - не «поиск вирусов» и не абстрактный анализ программ. Предмет - защитный анализ Windows PE32+ AMD64 exception/unwind metadata.

Проект EH/Unwind Analyzer делает следующее:

- читает недоверенный PE-файл как последовательность байтов;
- проверяет PE headers, sections, alignments, overlaps и exception directory;
- извлекает массив `RUNTIME_FUNCTION` из `.pdata`;
- декодирует `UNWIND_INFO` из `.xdata` или других секций;
- оценивает структурные, адресные, placement- и reuse-аномалии;
- формирует объяснимые findings, score, confidence, verdict и manual validation steps;
- на Windows может запустить target под Debug API и собрать runtime evidence по exceptions, handlers, VEH, VCH, UEF и dynamic function tables;
- создаёт console, CSV, Ghidra CSV, JSON и HTML отчёты;
- проходит unit, regression, schema, semantic, fuzz и dynamic validation checks.

## Официальные источники и граница утверждений

Там, где речь идёт о формате PE, Windows x64 ABI, `RUNTIME_FUNCTION`, `UNWIND_INFO`, exception handling и Debug API, нормативной основой служит документация Microsoft Learn. Там, где речь идёт о CMake, JSON Schema, Ghidra или Python, используются официальные документы соответствующих проектов. Там, где речь идёт о фактическом поведении EH/Unwind Analyzer, источником является исходный код проекта, тесты и отчёты в репозитории.

В книге различаются четыре типа утверждений:

| Тип утверждения | Что означает | Пример |
|---|---|---|
| Нормативное | Следует из официальной спецификации или документации API | `RUNTIME_FUNCTION` для AMD64 содержит begin, end и unwind-address поля |
| Реализационное | Следует из исходного кода проекта | `pe.c` хранит имя секции в `char name[9]` |
| Наблюдательное | Получено из конкретного sample или отчёта | `benign_richer.exe` содержит 3 runtime-function records |
| Аналитическое | Является выводом из фактов | Writable unwind metadata требует ручной проверки |

Эта граница очень важна для защиты ВКР. Нельзя выдавать эвристику проекта за закон PE/COFF. Нельзя считать один динамический запуск доказательством всех возможных путей исполнения. Нельзя говорить, что `score` является вероятностью, пока нет эмпирической калибровки на размеченном корпусе.

## Как книга объясняет английские термины

Большая часть терминов в системном программировании остаётся на английском: `image`, `section`, `runtime function`, `unwind`, `handler`, `debug event`, `score`, `confidence`. Это не украшение речи и не попытка сделать текст сложнее. Эти слова используются в документации Microsoft, в исходном коде, в Ghidra, в debugger, в JSON report и в публикациях по reverse engineering.

Поэтому правило книги такое:

- английский термин сохраняется там, где он является техническим именем;
- рядом даётся русское объяснение смысла;
- термин связывается с соседними понятиями;
- показывается, где он живёт: в файле, памяти, коде проекта, отчёте или процессе;
- отдельно называются типичные ошибки понимания.

Например, `image` в PE-контексте не равно обычной «картинке». Это образ исполняемого файла, подготовленный для отображения загрузчиком в виртуальное адресное пространство процесса. `Section` не просто «раздел текста», а запись в section table плюс соответствующий raw/virtual диапазон. `Handler` не любой обработчик в стиле пользовательского интерфейса, а функция, участвующая в обработке exception.

## Карта технологий проекта

| Слой | Технология | Зачем нужна | Где проявляется в проекте |
|---|---|---|---|
| Язык ядра | C17 | Безопасное и переносимое низкоуровневое чтение байтов, структур и чисел | `src/`, `include/`, unit tests |
| Сборка | CMake | Описание targets, options, tests и packaging | `CMakeLists.txt`, `CMakePresets.json` |
| Компиляторы | GCC/MinGW-w64, MSVC, Clang | Проверка переносимости и Windows x64 builds | build scripts, CI profiles |
| Исполняемый формат | PE/COFF PE32+ | Основной объект статического анализа | `pe.c`, `pe.h` |
| Архитектура | AMD64/x86-64 | Регистры, стек, calling convention, unwind rules | `unwind.c`, tests |
| ОС/API | Windows Debug API | Динамический сбор evidence | `dynamic_win.c` |
| Отчёты | JSON, HTML, CSV | Машинная и человеческая форма результата | `report.c`, schema |
| Интеграция | Ghidra + Python script | Ручная проверка функций и комментариев | `ghidra/import_unwind_csv.py` |
| Тестирование | CTest, Python tests | Проверка контрактов, схем и регрессий | `tests/` |
| Надёжность | ASan, UBSan, fuzzing | Поиск unsafe paths и malformed input cases | sanitizer/fuzz presets |
| Документация | Markdown, PDF | Учебные материалы и защита проекта | `docs/ru/`, `book_source/` |

## Сквозной маршрут читателя

Книга построена так, чтобы читатель не прыгал через пропасть. Сначала он узнаёт, что программа на диске - это байты, а не исходный код. Потом разбирает числа, адреса и память. Затем переходит к CPU, стеку и ABI. Только после этого появляются PE, exception directory, `RUNTIME_FUNCTION` и `UNWIND_INFO`. Затем вводится reverse engineering как метод доказательства, и только после этой базы начинается полный разбор исходного кода проекта.

Сквозной объект исследования:

```text
tests/samples/bin/benign_richer.exe
```

Сквозной маршрут данных:

```text
argv
-> parse_args
-> buf_init_from_file
-> pe_parse
-> unwind_read_runtime_functions
-> unwind_parse
-> heuristics_analyze
-> dynamic_collect_windows, если включён --dynamic
-> report_write_json_ex / report_write_html / report_write_csv
```

После прочтения книги читатель должен уметь не только повторять термины, но и объяснять, почему данные идут именно так, где возможна ошибка, какое поле отчёта связано с каким участком кода и как проверить утверждение независимо.

## Как работать с книгой

Не стоит читать эту книгу как набор шпаргалок. Лучше читать её как инженерный тренажёр. После каждой крупной части нужно остановиться и ответить на три вопроса:

1. Какой новый объект появился?
2. Где он представлен физически: в файле, памяти, коде или отчёте?
3. Какая функция проекта его читает, проверяет или выводит?

Если на эти вопросы нельзя ответить, термин ещё не понят. Например, `RVA` понятен только тогда, когда читатель может вручную выполнить перевод через section table и объяснить, почему этот перевод может не сработать.

## Минимальный словарь перед стартом

| Термин | Первое рабочее объяснение |
|---|---|
| `byte` | Минимальная единица данных, с которой работает анализатор при чтении файла |
| `file offset` | Позиция байта от начала файла на диске |
| `VA` | Адрес в виртуальном адресном пространстве процесса |
| `RVA` | Адрес относительно базы загруженного image |
| `image` | PE-файл как объект, который loader отображает в память |
| `section` | Именованный raw/virtual диапазон PE-файла с характеристиками |
| `ABI` | Двоичный договор между кодом, компилятором, ОС и runtime |
| `unwind` | Восстановление предыдущего stack frame при исключении или stack walk |
| `handler` | Код, который может обработать exception или участвовать в unwind |
| `finding` | Именованное свидетельство, созданное правилом проекта |
| `score` | Ограниченная инженерная сумма подозрительных сигналов |
| `confidence` | Правиловая уверенность в интерпретации, не статистическая вероятность |

"""


def assemble() -> str:
    missing = [name for name in CHAPTERS if not (CHAPTER_DIR / name).is_file()]
    if missing:
        raise FileNotFoundError(f"Missing teacher-book chapters: {missing}")

    parts = [
        front_matter().strip(),
        "",
        "<!-- pagebreak -->",
        "",
    ]

    for name in CHAPTERS:
        text = (CHAPTER_DIR / name).read_text(encoding="utf-8").strip()
        text = text.replace("15 automated CTest cases", "16 automated CTest cases")
        parts.extend([text, ""])
        diagram = DIAGRAMS_AFTER.get(name)
        if diagram:
            path, caption = diagram
            parts.extend([f"![{caption}]({path})", ""])

    parts.extend([
        "# Заключение. Что должен унести читатель",
        "",
        "После полного прохождения учебника читатель должен видеть проект не как набор файлов, а как систему доказательств. PE parser создаёт карту местности. Unwind decoder читает механизм восстановления стека. Heuristic engine не угадывает вредоносность, а формирует именованные evidence records. Dynamic collector отвечает на другой вопрос: что произошло в наблюдаемом запуске. Reports превращают внутреннюю модель в проверяемый внешний контракт.",
        "",
        "Главное умение после этой книги - не нажать правильную команду, а построить цепочку объяснения:",
        "",
        "```text",
        "байт в файле",
        "-> поле PE/UNWIND структуры",
        "-> проверка в исходном коде",
        "-> finding или отсутствие finding",
        "-> поле JSON/HTML отчёта",
        "-> ручная проверка в Ghidra/debugger",
        "-> осторожный инженерный вывод",
        "```",
        "",
        "Именно такая цепочка делает ВКР защищаемой: в ней каждое утверждение можно проверить, повторить и отделить от предположения.",
        "",
    ])

    return "\n".join(parts).rstrip() + "\n"


def main() -> None:
    BOOK_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(assemble(), encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
