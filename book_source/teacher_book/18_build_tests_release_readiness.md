# Том II. Глава 9. Сборка, тестирование, воспроизводимость и степень готовности

## Что значит «проект работает»

Фраза «работает без ошибок» должна быть разложена на проверяемые утверждения:

- source compiles в заявленных toolchains;
- compiler не выдаёт warnings при strict flags;
- unit tests проходят;
- regression samples дают ожидаемые reports;
- malformed inputs не вызывают memory errors;
- JSON соответствует schema;
- HTML escaping сохраняет security;
- CLI exit codes соответствуют contract;
- release package содержит нужные artifacts;
- Windows dynamic branch проверен на Windows x64;
- реальные benign binaries не создают неприемлемый уровень false positives.

Ни один отдельный successful run не доказывает все пункты.

## CMake project model

Top-level project:

```cmake
project(
    eh_unwind_analyzer
    VERSION 1.0.0
    DESCRIPTION "Static and dynamic analyzer for Windows x64 EH/Unwind metadata"
    LANGUAGES C
)
```

Минимальная CMake version 3.23. Language standard:

```cmake
target_compile_features(ehua_core PUBLIC c_std_17)
```

Core собирается как static library:

```cmake
add_library(ehua_core STATIC ...)
```

CLI:

```cmake
add_executable(eh_unwind_analyzer src/main.c)
target_link_libraries(eh_unwind_analyzer PRIVATE ehua_core)
```

Это modular monolith: один deployable CLI, внутри которого modules разделены C interfaces. Static library позволяет будущему native adapter link against core, но public API пока ориентирован на внутренние structs и не обещает ABI stability.

## Core sources

Library включает:

```text
app_info.c
dynamic_win.c
heuristics.c
pe.c
report.c
unwind.c
util.c
```

`main.c` не входит в library. Поэтому CLI orchestration отделена от analysis modules.

## Platform checks

Если build выполняется на Windows, pointer size должен быть 64 bit:

```cmake
if(WIN32 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR ...)
endif()
```

Это не запрещает 64-bit Linux/macOS static build. Проверка относится только к Windows runtime branch.

При MinGW определяется:

```text
__USE_MINGW_ANSI_STDIO=1
```

Это обеспечивает ожидаемое formatting behavior для некоторых specifiers.

## Warning policy

MSVC:

```text
/W4
/permissive-
/WX при warnings-as-errors
```

GCC/Clang:

```text
-Wall
-Wextra
-Wpedantic
-Wconversion
-Wshadow
-Wformat=2
-Werror
```

Warnings as errors включены в base preset. Это предотвращает накопление известных compiler diagnostics.

Warning-free build не доказывает отсутствие bugs, но повышает minimum discipline C code.

## Instrumentation

Sanitizer preset:

```text
AddressSanitizer
UndefinedBehaviorSanitizer
-fno-omit-frame-pointer
```

ASan обнаруживает многие out-of-bounds, use-after-free и related memory errors. UBSan обнаруживает ряд undefined operations.

Они доступны с GCC/Clang, не с текущим MSVC configuration.

Coverage preset использует:

```text
--coverage -O0 -g
```

Sanitizers и coverage запрещены одновременно, чтобы избежать сложной и неподдерживаемой instrumentation combination.

## Presets

Configure presets:

```text
debug
release
sanitize
coverage
```

Все наследуют Ninja generator, tests enabled, compile commands export и warnings-as-errors.

Типичный release cycle:

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release
```

Preset фиксирует повторяемый набор options и уменьшает зависимость от ручной command line.

## Unit test executables

CTest создаёт девять C unit test binaries.

### `unit_unwind`

Проверяет decoder:

- operation decoding;
- code order;
- flags;
- operand length;
- chain errors;
- boundary conditions.

### `unit_heuristics`

Проверяет базовые static score, placement, verdict и confidence.

### `unit_heuristics_mitigations`

Проверяет weakening rules:

- single signal;
- small sample;
- placement only;
- single family.

### `unit_heuristics_context`

Проверяет context-sensitive rules:

- benign handler dominance suppression;
- dominance при corroborating context;
- writable metadata and handler combination.

### `unit_heuristics_combos`

Проверяет additional combination findings и weights.

### `unit_core_edges`

Проверяет:

- empty function table;
- resource-only image;
- overflow/bounds;
- RVA mapping;
- nested overlaps;
- PE structure findings.

### `unit_report_json`

Проверяет:

- complete static/dynamic serialization;
- metadata;
- findings/events;
- UTF-8 safety;
- expected JSON fragments.

### `unit_report_html`

Проверяет:

- HTML escaping;
- dashboard sections;
- filter script;
- отсутствие unescaped hostile strings.

### `unit_matrix_report`

Проверяет combined assessment:

- strong static without dynamic;
- weak static plus weak runtime;
- strong correlated case;
- comma placement around optional blocks;
- final verdict and case strength.

## Assertions в release unit tests

C `assert` обычно отключается macro `NDEBUG` в release builds. CMake принудительно undefines:

```text
/UNDEBUG для MSVC
-UNDEBUG для GCC/Clang
```

Иначе release CTest мог бы «пройти», не выполнив проверки assertions.

## Python integration tests

При наличии Python добавляются ещё семь tests.

### `regression_samples`

Запускает CLI на synthetic PE corpus и проверяет `tests/samples/manifest.json`.

Corpus включает:

```text
benign_minimal.exe
benign_richer.exe
suspicious_unwind_oob.exe
suspicious_unwind_writable.exe
suspicious_section_raw_oob.exe
suspicious_eh_unwind_tamper.exe
```

Manifest проверяет paths внутри generated JSON, minimum score, verdict и case strength.

### `dynamic_validator`

Проверяет validator logic для Windows dynamic reports. На non-Windows это не заменяет реальный Debug API smoke.

### `report_semantics`

Проверяет semantic relationships report, а не только JSON syntax.

### `release_metadata`

Проверяет consistency version, schema и release files.

### `release_hygiene`

Проверяет, что source tree и install rules не пропускают AppleDouble
`._*`, `.DS_Store`, Python cache, `.plist` и неоднозначные старые Windows
executables. Дополнительно закрепляет фильтрацию real-corpus runner и CPack.

### `cli_contract`

Проверяет arguments, exit codes, expected outputs и errors.

### `mutation_fuzz`

Создаёт 120 deterministic mutated inputs и запускает parser через CLI. Цель — обнаружить crashes, hangs и unsafe malformed-input paths.

Это mutation testing, а не exhaustive fuzzing.

## Общее число CTest cases

Девять unit tests плюс семь Python tests дают:

```text
16 CTest tests
```

Именно это число относится к финальной release-candidate configuration.

## Regression corpus semantics

Synthetic samples полезны, потому что каждое изменение контролируется и ожидаемый signal известен.

`benign_minimal` и `benign_richer` ожидают:

```text
score 0
no_strong_static_anomalies
evidence none
manual review false
case no_case
```

`suspicious_unwind_oob` проверяет broken pointer и parse failure.

`suspicious_unwind_writable` проверяет placement.

`suspicious_section_raw_oob` проверяет file layout and overlap.

`suspicious_eh_unwind_tamper` проверяет writable metadata, non-executable/writable handler и combined case.

Synthetic corpus не измеряет false-positive rate на diverse real software.

## Реальный benign corpus

В проектной validation использовался corpus 106 реальных PE files. Его роль:

- проверить parser на разнообразных compiler/linker layouts;
- обнаружить unexpected failures;
- оценить benign false positives;
- проверить performance.

Для научной воспроизводимости нужно сохранять:

- список SHA-256;
- происхождение файлов;
- license/redistribution constraints;
- tool version;
- exact command;
- machine-readable aggregate results.

Если corpus не включён в repository из-за licensing, manifest hashes и acquisition procedure должны быть documented.

Фраза «проверено на 106 файлах» без списка и результатов слабее воспроизводимого benchmark.

На финальной revision повторный прогон дал:

```text
106/106 valid reports
174 795 RUNTIME_FUNCTION records
0 parse failures
0 structural unwind anomalies
0 nonzero heuristic scores
maximum analysis time 765 ms
```

Исходные PE остаются в `real_samples/inbox` для локальной инженерной проверки,
но не включаются в публичные source/customer ZIP из-за размера и необходимости
отдельно учитывать redistribution terms. Их происхождение и download hashes
записаны в `real_samples/SOURCES.md`.

## Fuzzing levels

Проект имеет два уровня.

Deterministic mutation runner изменяет bytes existing samples и запускает full CLI.

Optional libFuzzer target:

```text
ehua_parser_fuzzer
```

Он доступен при `EHUA_BUILD_FUZZER=ON` и Clang с libFuzzer runtime.

LibFuzzer выполняет coverage-guided input generation и может значительно глубже исследовать parser state space. Для release readiness полезно сохранять seed corpus и regression inputs для найденных crashes.

Fuzzing не доказывает отсутствие vulnerabilities. Оно увеличивает explored input space.

На финальной revision выполнены 1000 deterministic mutations:

```text
accepted valid reports: 634
controlled rejected inputs: 366
crashes, hangs, invalid reports: 0
```

LibFuzzer target успешно собирается Homebrew LLVM 21. Полная bounded campaign
остаётся Linux CI gate; локальная macOS campaign с крупными PE seeds оказалась
медленнее установленного wall-clock budget.

## Sanitizer limitations

ASan/UBSan на macOS/Linux проверяют static code paths и non-Windows dynamic stub. Windows-specific branch под `#ifdef _WIN32` при таком run не компилируется и не исполняется.

Для dynamic branch нужны:

- Windows x64 build;
- MSVC warning build;
- MinGW build;
- smoke targets;
- желательно Application Verifier или Windows-compatible sanitizer where supported.

Cross-compilation MinGW подтверждает compile compatibility, но не runtime correctness Debug API.

## Dynamic smoke validation

`tests/run_dynamic_smoke_windows.bat` запускает четыре purpose-built targets.

Parameters:

```text
--timeout-ms 8000
--trace-steps 32 для handler targets
--json report path
```

После runs `validate_dynamic_reports.py` сверяет reports со schema и expected counters.

Это минимальная обязательная проверка перед заявлением, что dynamic mode работает.

На Windows x64 8 июня 2026 года получены следующие результаты:

```text
124/124 schema/semantic-valid reports
86 started dynamic sessions
54 normal completions
32 controlled timeouts
4/4 focused smoke scenarios
0 dropped events
trace budget violations: 0
```

Полный набор можно проверить без выполнения targets:

```sh
python3 tests/validate_dynamic_corpus_evidence.py
```

При наличии исходных corpus roots валидатор дополнительно пересчитывает
размеры и SHA-256 каждого входного PE.

Для более сильной validation нужны:

- Windows 10/11;
- разные patch levels;
- MSVC и MinGW analyzer builds;
- single-thread и multi-thread target;
- module unload/reload;
- high event volume;
- timeout target;
- invalid handler RVA;
- JIT/dynamic table from real runtime;
- anti-debug-aware sample.

## CLI exit codes

Main orchestration различает:

- argument/usage error;
- parse/read failure;
- requested stage failure;
- report write failure.

Даже если heuristic или dynamic stage failed, code может попытаться записать partial report. Process exit code остаётся nonzero, чтобы automation не приняла partial result за complete success.

Backend должен проверять и exit code, и JSON status. Только один из них недостаточен.

## Report schema validation

Generated JSON должен проверяться против `docs/report.schema.json`.

Schema validation отвечает на вопрос:

```text
соответствует ли structure declared contract
```

Она не отвечает:

```text
верны ли вычисленные addresses и score
```

Для второго нужны semantic tests и golden cases.

## Release metadata

Project version CMake `1.0.0`, package version `1.0.0`. Stable final означает, что текущая ревизия объявлена презентационной и проходит финальные release gates.

Report schema `1.0.0`.

Version dimensions:

```text
tool implementation version
package/release version
report schema version
heuristic policy version, пока отсутствует отдельно
```

Их не следует смешивать.

## Installation

CMake installs:

- CLI в `bin`;
- docs;
- Ghidra integration;
- examples;
- README, LICENSE, CHANGELOG, SECURITY, CONTRIBUTING.

Core static library не включена в install targets. Если коллега хочет link directly, потребуется добавить library/header installation и stable API policy. Для subprocess integration это не нужно.

## CPack

CPack generator создаёт ZIP:

```text
eh-unwind-analyzer-1.0.0-System-Processor.zip
```

Archive package является distribution artifact, а не отдельным изменённым проектом. Source workspace остаётся основным местом edits. Архив содержит installed artifacts согласно CMake rules, поэтому он может намеренно не включать source и tests.

Именно это объясняет прежнее недоразумение: Windows project folder и release archive выполняют разные роли.

CPack package является native installed package. Дополнительно
`scripts/create_release_bundles.py` формирует delivery set для разных
получателей. Это четыре архива, но не четыре разные реализации программы.

### Windows x64 package

```text
eh-unwind-analyzer-1.0.0-windows-x64.zip
```

Содержит проверенный MinGW-w64 executable, пользовательскую документацию,
JSON Schema, examples, Ghidra importer и release passport. Это основной пакет
для Windows-заказчика. В нём нет source tree, test corpus и промежуточных
build artifacts.

### macOS arm64 package

```text
eh-unwind-analyzer-1.0.0-Darwin-arm64.zip
```

Это CPack build для Apple Silicon. Он выполняет статический анализ Windows
PE-файлов, формирует reports и поддерживает Ghidra workflow. Windows dynamic
collector в macOS binary недоступен и возвращает controlled unsupported
result.

### Source package

```text
eh-unwind-analyzer-1.0.0-source.zip
```

Содержит C source, headers, CMake, tests, CI, документацию, исходники книги,
release scripts и manifests. Он предназначен разработчику или заказчику,
которому передаётся исходный код. Реальные сторонние PE-файлы и локальные
build directories не включаются.

### Evidence package

```text
eh-unwind-analyzer-1.0.0-evidence.zip
```

Содержит не программу для обычного запуска, а проверяемую доказательную базу:
124 individual JSON reports, logs, aggregate CSV/JSON/Markdown, итоговый DOCX,
schema и validators. Его назначение — аудит утверждений о Windows dynamic
validation.

Все package hashes записываются в `release-output/SHA256SUMS.txt`.
Повторная сборка release bundles дала те же SHA-256, то есть их content
reproducible при неизменном source tree и native CPack input.

Convenience scripts больше не создают неоднозначный executable в корне:

```text
build_mingw.bat -> build\mingw-local\eh_unwind_analyzer.exe
build_msvc.bat  -> build\msvc-local\eh_unwind_analyzer.exe
```

## Readiness dimensions

Готовность нельзя выразить одним абсолютным процентом без шкалы.

### Static core

Сильные стороны:

- bounded parser;
- PE structure validation;
- detailed unwind decoder;
- explainable heuristics;
- JSON/HTML/CSV;
- unit/regression/fuzz tests;
- cross-platform file analysis.

Остаточные задачи:

- broader real corpus calibration;
- full code/metadata correspondence analysis;
- policy versioning;
- expanded formats/architectures.

### Dynamic core

Сильные стороны:

- functional Windows debugger loop;
- handler/API breakpoints;
- per-thread re-arm;
- events and trace;
- smoke targets.
- фактическая MinGW-w64 Windows validation на 124 reports;
- воспроизводимый evidence validator.

Остаточные задачи:

- production sandbox;
- remote dynamic table decoding;
- richer context;
- финальный независимый MSVC gate;
- concurrency/module-lifetime hardening.

### Product platform

CLI core готов к ручному и backend subprocess use.

Для multi-user product отсутствуют в самом core:

- authentication;
- upload API;
- queue;
- database;
- worker isolation;
- frontend;
- observability;
- retention policy.

Это не обязано входить в analytical core; другой человек может построить платформу вокруг JSON contract.

## Можно ли защищать как ВКР

Да, если формулировка соответствует фактическому scope:

```text
разработан инструмент статического анализа PE32+ AMD64 EH/unwind metadata
с explainable heuristic assessment,
Windows-only dynamic evidence collection,
machine-readable and interactive reports,
Ghidra integration,
automated tests and reproducible build
```

Нельзя заявлять:

- универсальный reverse engineering suite;
- гарантированный malware detector;
- полную динамическую песочницу;
- поддержку всех PE architectures;
- доказанную statistical accuracy без benchmark.

Сильная защита показывает не отсутствие границ, а осознанное управление ими.

## Release gate перед передачей

Перед каждым release:

1. Clean configure release.
2. Build with warnings-as-errors.
3. Run 16 CTest tests.
4. Run sanitizer suite.
5. Run mutation fuzz.
6. Validate synthetic corpus.
7. Validate representative real corpus.
8. Build Windows MSVC and MinGW.
9. Run Windows dynamic smoke.
10. Validate JSON schema.
11. Generate HTML and inspect hostile escaping sample.
12. Verify version consistency.
13. Build native CPack package.
14. Build Windows, source and evidence delivery packages.
15. Revalidate extracted source/evidence packages.
16. Compute and verify all package SHA-256.
17. Publish known limitations and compiler gates.

## Фактический паспорт качества final revision

На 8 июня 2026 года зафиксированы:

| Gate | Result |
|---|---:|
| Release CTest | 16/16 |
| ASan/UBSan CTest | 16/16 |
| Coverage CTest | 16/16 |
| Line coverage без Windows-only branch | 86,3% |
| Function coverage | 96,2% |
| Branch coverage | 62,8% |
| Deterministic mutations | 1000 PASS |
| Real benign corpus | 106/106 |
| Windows report validation | 124/124 |
| Focused dynamic smoke | 4/4 |
| Clang Static Analyzer | 0 findings |
| Extracted source package | 16/16 |
| Extracted evidence package | 124/124 |

Эти цифры относятся к конкретной revision и не заменяют future regression
testing. Проверенный Windows binary — MinGW-w64. Поэтому версия остаётся
`1.0.0`, когда independent MSVC job и Windows dynamic corpus пройдены на той же release revision.

## Итог

Проект уже вышел за уровень одноразового prototype: у него есть modular core, strict build, report contract, tests, fuzzing, release metadata и dynamic smoke infrastructure.

Однако «полностью законченный top product» требует operational layer и дальнейшей empirical validation. Наиболее точная характеристика текущего состояния:

```text
зрелое ядро исследовательского инструмента release-candidate уровня,
готовое к ВКР, ручному использованию и backend integration,
но не завершённая multi-user sandbox platform
```

Такое определение не уменьшает ценность работы. Оно правильно отделяет завершённость аналитического ядра от завершённости всей будущей информационной системы.
