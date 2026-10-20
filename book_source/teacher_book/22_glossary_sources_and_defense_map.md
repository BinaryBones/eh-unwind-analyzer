# Приложение A. Связный терминологический указатель

## Как пользоваться указателем

Определения ниже не заменяют основные лекции. Они предназначены для повторения. Термин следует понимать вместе с указанным отношением к соседним понятиям и проекту.

## Программа, файл и исполнение

**Source code** — текст программы на языке программирования. Для C он проходит preprocessing и compilation. В проекте source code находится в `src/`, `include/` и tests.

**Preprocessor** — стадия C translation, обрабатывающая `#include`, macros и conditional compilation. Благодаря `#ifdef _WIN32` один source file содержит Windows implementation и non-Windows stub.

**Compiler** — программа, переводящая translation units в object code и выполняющая diagnostics/optimization. Clang, GCC и MSVC поддерживаются build system в разных средах.

**Object file** — результат отдельной compilation unit до окончательного linking. Содержит machine code, data, symbols и relocations, но ещё не является готовым executable image.

**Linker** — компоновщик, объединяющий object files и libraries, разрешающий symbols и создающий PE image.

**Executable image** — файл, предназначенный для отображения loader в memory; в Windows обычно EXE или DLL в формате PE.

**Loader** — часть runtime system, отображающая image sections, применяющая relocations, разрешающая imports и подготавливающая process execution.

**Process** — выполняющийся экземпляр программы с virtual address space, handles, modules и threads.

**Thread** — единица исполнения внутри process, имеющая собственные registers, stack и instruction pointer.

**Module** — загруженный PE image внутри process: main EXE или DLL.

**Host** — операционная система и machine, на которых работает analyzer.

**Target** или **debuggee** — программа, которую analyzer исследует или запускает под debugger.

## Данные и адреса

**Bit** — минимальная binary unit со значением 0 или 1.

**Byte** — в рассматриваемых платформах восемь bits.

**Unsigned integer** — целое без знака; все bit combinations выражают nonnegative value.

**Signed integer** — целое со знаком; на современных systems обычно two's complement.

**Overflow** — результат arithmetic вне диапазона типа. Для unsigned C он вычисляется modulo power of two; для signed overflow поведение undefined.

**Endianness** — порядок bytes многобайтового значения. PE AMD64 использует little-endian.

**Little-endian** — least significant byte хранится по меньшему адресу.

**Pointer** — typed C value, обозначающее address object/function в адресном пространстве текущего процесса.

**File offset** — позиция byte в файле на диске.

**Virtual Address, VA** — адрес в virtual address space process.

**Relative Virtual Address, RVA** — VA относительно module base: `RVA = VA - base`.

**ImageBase** — preferred base PE image из optional header.

**Actual module base** — фактический base загруженного module; может отличаться из-за ASLR.

**ASLR** — Address Space Layout Randomization, выбор изменяемых bases для усложнения предсказания addresses.

**Address range** — interval addresses. В проекте функции представлены полуинтервалом `[begin,end)`.

**Out of bounds, OOB** — address или range выходит за declared boundary, например file size или SizeOfImage.

**Alignment** — требование кратности address/offset определённому числу bytes.

**Saturation** — ограничение результата maximum/minimum вместо wraparound; используется при aggregate stack size.

## CPU и ABI

**Instruction Set Architecture, ISA** — модель instructions, registers, address sizes и архитектурных effects. Проект ориентирован на AMD64/x86-64 target.

**Machine code** — bytes instructions конкретной ISA.

**Assembly language** — textual representation machine instructions.

**Register** — быстрое архитектурное состояние CPU.

**Instruction pointer** — register address следующей/текущей instruction; на x86-64 `RIP`.

**Stack pointer** — register вершины stack; на x86-64 `RSP`.

**Flags register** — register condition/control bits; в context используется `EFlags`.

**Application Binary Interface, ABI** — правила двоичного взаимодействия: argument registers, preserved registers, stack alignment, object formats и unwind conventions.

**Calling convention** — часть ABI, описывающая передачу arguments, return value и register preservation.

**Volatile register** — register, который callee может изменить без восстановления.

**Nonvolatile register** — register, который callee обязан сохранить и восстановить, если использует.

**Shadow space** — 32-byte область, резервируемая caller в Windows x64 для первых четырёх register arguments.

**Stack alignment** — требование к кратности `RSP` в определённых execution points.

**Function** — region code с agreed entry/return semantics.

**Caller** — function, выполняющая call.

**Callee** — вызываемая function.

**Prolog** — ограниченная начальная sequence, создающая stack frame и сохраняющая nonvolatile state.

**Epilog** — sequence, отменяющая frame effects и возвращающая control caller.

**Stack frame** — часть thread stack и register relation, принадлежащая одному active function invocation.

**Frame pointer/register** — nonvolatile register, используемый как стабильная reference point frame.

**Leaf function** — функция, для которой Windows может выполнить простую unwind без table entry при соблюдении ABI constraints.

**Nonleaf function** — функция, обычно требующая unwind metadata из-за calls, stack allocation или nonvolatile state.

**Context** — snapshot выбранного архитектурного состояния thread.

## PE/COFF

**PE** — Portable Executable, Windows image format.

**COFF** — Common Object File Format, структура object/image headers и related records.

**DOS header** — начальный compatibility header PE с signature `MZ`.

**`e_lfanew`** — field по offset `0x3C`, указывающее file offset PE signature.

**PE signature** — bytes `PE\0\0`.

**COFF file header** — header с Machine, NumberOfSections и SizeOfOptionalHeader.

**Optional header** — обязательный для image header с ImageBase, sizes, alignments и data directories.

**PE32+** — 64-bit variant optional header, magic `0x20B`.

**Machine type** — architecture identifier; AMD64 имеет value `0x8664`.

**Section** — basic unit code/data mapping в PE.

**Section header** — record с name, virtual/raw ranges и characteristics.

**VirtualSize** — значимый virtual size section.

**SizeOfRawData** — размер file-backed section bytes.

**PointerToRawData** — file offset начала raw section data.

**Characteristics** — bit flags назначения/permissions section.

**Data directory** — RVA+size системной table в optional header.

**Exception directory** — data directory, указывающая AMD64 runtime function table.

**`.text`** — распространённое имя executable code section; имя не является жёстким нормативным условием.

**`.pdata`** — распространённое имя section runtime function entries.

**`.xdata`** — распространённое имя section unwind records.

**`.bss`** — распространённое имя zero-initialized virtual data без обязательных raw bytes.

**`.idata`** — распространённое имя import data.

**SizeOfImage** — declared size загруженного image в RVA space.

**SizeOfHeaders** — file/memory extent PE headers.

**SectionAlignment** — alignment virtual sections.

**FileAlignment** — alignment raw section data.

## Исключения и unwind

**Exception** — событие, прерывающее normal instruction flow и инициирующее Windows dispatch.

**Exception code** — numeric identifier класса exception.

**Structured Exception Handling, SEH** — Windows mechanism поиска и обработки exceptions.

**Dispatch** — поиск подходящего handler.

**Unwind** — восстановление caller states и сворачивание frames.

**Virtual unwind** — вычисление caller context без исполнения original epilog.

**Search phase** — проход frames для выбора handler.

**Unwind phase** — фактическое сворачивание до выбранной точки.

**`RUNTIME_FUNCTION`** — AMD64 record `{BeginRVA, EndRVA, UnwindRVA}`.

**Function table** — sorted array `RUNTIME_FUNCTION`.

**`UNWIND_INFO`** — variable-length record effects prolog, handler или chain.

**Version** — format version в low three bits header.

**Flags** — high five bits header, включая EHANDLER, UHANDLER и CHAININFO.

**`SizeOfProlog`** — длина declared prolog в bytes.

**`CountOfCodes`** — число two-byte unwind slots, не число logical operations.

**`UNWIND_CODE`** — two-byte slot с CodeOffset и opcode/OpInfo.

**CodeOffset** — offset в prolog, связанный с operation.

**Opcode** — тип unwind operation.

**Operand** — дополнительное encoded value operation.

**`UWOP_PUSH_NONVOL`** — описание push nonvolatile register.

**`UWOP_ALLOC_SMALL`** — compact small stack allocation.

**`UWOP_ALLOC_LARGE`** — stack allocation с additional operands.

**`UWOP_SET_FPREG`** — установка frame register.

**`UWOP_SAVE_NONVOL`** — сохранение GP nonvolatile register в stack slot.

**`UWOP_SAVE_XMM128`** — сохранение nonvolatile XMM register.

**`UWOP_PUSH_MACHFRAME`** — описание system machine frame.

**Handler RVA** — image-relative адрес frame handler.

**Chained unwind info** — record, ссылающаяся на primary runtime function/unwind description.

**Frame-based handler** — handler, связанный с stack frame через unwind metadata.

**VEH** — Vectored Exception Handler, process-level registration до frame search.

**VCH** — Vectored Continue Handler, vectored continuation mechanism.

**UEF** — Unhandled Exception Filter, top-level process filter.

**Dynamic function table** — runtime-registered table для generated code.

**JIT compiler** — Just-In-Time compiler, создающий machine code во время process execution.

**Fragment в Unwind V3** — непрерывный диапазон machine code, описанный одной
парой `RUNTIME_FUNCTION` и `UNWIND_INFO_V3`.

**WOD** — Winding Operation Descriptor, variable-length descriptor одной
операции unwind в V3.

**WOD pool** — packed byte array всех WOD prolog и epilog одного V3 fragment.

**PayloadWords** — число 16-bit words payload V3 после четырёхбайтового
header; handler или chained record в это число не входят.

## Debugging

**Debugger** — process/tool, управляющий target через Debug API.

**Debug event** — Windows notification о create/exit, DLL load или exception.

**`WaitForDebugEvent`** — ожидание следующего event.

**`ContinueDebugEvent`** — продолжение target с указанным status.

**First chance** — первое уведомление debugger до окончательной application handling.

**Second chance** — уведомление после неуспешного normal handling.

**`DBG_CONTINUE`** — debugger объявляет event обработанным.

**`DBG_EXCEPTION_NOT_HANDLED`** — debugger передаёт ordinary exception дальнейшей системе dispatch.

**Breakpoint** — контролируемая остановка execution по адресу/условию.

**Software breakpoint** — замена instruction byte на trap instruction.

**`INT3`** — однобайтовая x86 breakpoint instruction `0xCC`.

**Original byte** — byte target code, сохранённый до вставки `INT3`.

**Re-arm** — повторная установка breakpoint после исполнения original instruction.

**Trap Flag, TF** — bit `EFlags`, вызывающий single-step exception после одной instruction.

**Single-step** — режим пошагового исполнения.

**Pending re-arm** — association thread с breakpoint, который нужно восстановить на следующем single-step.

**Remote process memory** — память target, читаемая/изменяемая analyzer через Debug API.

**Instruction cache** — CPU cache fetched instructions; после code modification требуется flush.

**Timeout** — верхняя граница времени dynamic session, но не security sandbox.

**Trace** — в проекте bounded sequence RIP после handler hit, не полный execution log.

## Анализ и доказательства

**Parser** — component, преобразующий bytes в structured fields с bounds checks.

**Decoder** — component, интерпретирующий encoded domain structure, например unwind operations.

**Invariant** — условие, которое должно сохраняться для корректной model.

**Observation** — непосредственно полученный факт конкретного file/run.

**Finding** — named analytical record, созданный rule из observations.

**Severity** — qualitative importance finding: medium/high и т. п.

**Evidence family** — группа related findings одного analytical слоя.

**Score** — bounded engineering sum weights 0–100.

**Suspicion** — в проекте `score / 100`, не probability.

**Confidence** — rule-based оценка силы/разнообразия evidence, не эмпирически калиброванная probability.

**Verdict** — categorical label по thresholds.

**Weakening rule** — правило, снижающее confidence при benign alternatives или недостатке context.

**Mitigation** — internal C name weakening rule; не исправляет input.

**Correlation** — relation static и dynamic evidence. Aggregate correlation слабее exact address-level identity.

**False positive** — benign object, ошибочно classified suspicious.

**False negative** — suspicious behavior, не обнаруженное analyzer.

**Ground truth** — эталонная разметка, относительно которой проверяется
правильность результата.

**True positive, TP** — размеченное нарушение, которое инструмент обнаружил.

**True negative, TN** — корректный объект, который инструмент не отметил
положительным сигналом.

**Sensitivity / Recall** — доля обнаруженных положительных примеров:
`TP / (TP + FN)`.

**Specificity** — доля правильно отклонённых отрицательных примеров:
`TN / (TN + FP)`.

**Precision** — доля подтверждённых сигналов среди всех положительных
сигналов: `TP / (TP + FP)`.

**F1** — гармоническое среднее precision и recall.

**Confidence interval** — диапазон статистически правдоподобных значений
параметра при заданной модели выборки; не устраняет смещение corpus.

**Calibration** — подбор/проверка thresholds на размеченном corpus.

**Corpus** — набор samples для testing/measurement.

**Regression test** — test, сохраняющий ранее установленное expected behavior.

**Unit test** — проверка отдельного module/contract.

**Integration test** — проверка взаимодействия components и external outputs.

**Fuzzing** — генерация множества inputs для поиска crashes и unsafe paths.

**Mutation fuzzing** — изменение seed inputs.

**Coverage-guided fuzzing** — генерация inputs с использованием code coverage feedback.

**ASan** — AddressSanitizer.

**UBSan** — UndefinedBehaviorSanitizer.

**Reproducibility** — возможность повторить analysis с тем же input, versions и commands.

## Отчёты и интеграция

**Serialization** — преобразование in-memory model во внешний format.

**CSV** — flat tabular text format.

**JSON** — structured text format objects/arrays/scalars.

**HTML** — document markup; report является self-contained dashboard.

**Schema** — formal description allowed JSON structure and types.

**Schema version** — version public data contract.

**Provenance** — сведения о происхождении result: input hash, tool/build, time, command.

**SHA-256** — 256-bit cryptographic hash, используемый для identity bytes.

**Atomic write** — запись temporary file и rename, предотвращающие наблюдение partial result.

**UTF-8** — variable-length Unicode encoding, валидируемая report writer.

**Escaping** — преобразование special characters для безопасного JSON/HTML representation.

**Content Security Policy, CSP** — browser policy, ограничивающая sources content в HTML report.

**Backend** — server-side application, управляющее upload, jobs, core execution и persistence.

**Frontend** — user interface, взаимодействующее с backend API.

**API** — формальный интерфейс между components. CLI+JSON также является API, хотя не network API.

**Subprocess** — отдельный OS process, запускаемый backend для analysis.

**Job queue** — механизм асинхронного планирования analyses.

**Database** — persistent structured storage jobs/reports.

**Raw JSON** — неизменённый full report; рекомендуется сохранять как source of truth.

**Normalization** — выделение indexed fields JSON в relational/search structures.

**Sandbox** — изолированная execution environment. Debugger и timeout сами по себе sandbox не образуют.

**Release candidate, RC** — предварительный release, близкий к stable, но ещё допускающий blocking changes.

# Приложение B. Нормативные и технические источники

## Microsoft

1. [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — PE/COFF headers, sections, RVA, directories и `.pdata`.
2. [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170) — `RUNTIME_FUNCTION`, `UNWIND_INFO`, operations и unwind procedure.
3. [x64 Unwind Information V3](https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3?view=msvc-170) — preview layout V3, explicit epilogs, WOD pool и Intel APX registers.
4. [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170) — registers, arguments, alignment и unwindability.
5. [x64 prolog and epilog](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-170) — ограничения prolog/epilog.
6. [Structured Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling) — общая модель SEH.
7. [Debugging Events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events) — lifecycle debug events.
8. [Writing the Debugger's Main Loop](https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop) — `WaitForDebugEvent`/`ContinueDebugEvent`.
9. [AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler).
10. [SetUnhandledExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter).
11. [RtlAddFunctionTable](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable).
12. [RtlAddGrowableFunctionTable](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdgrowablefunctiontable).
13. [WaitForDebugEventEx](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugeventex).

## Стандарты и документация tools

1. ISO/IEC 9899:2018 — язык C17. Текст стандарта может распространяться на условиях ISO; для практического reference используется документация compiler и committee drafts.
2. AMD64 Architecture Programmer's Manual — architecture registers, instructions и exception model.
3. Intel 64 and IA-32 Architectures Software Developer's Manual — x86-64 instruction and system semantics.
4. [CMake Documentation](https://cmake.org/cmake/help/latest/) — targets, presets, CTest и CPack.
5. [Ghidra Documentation](https://ghidra-sre.org/) — import, disassembly, decompiler и scripting.
6. [JSON Schema](https://json-schema.org/specification) — формальная валидация JSON documents.
7. [NIST Static Analysis Tool Study Methodology](https://www.nist.gov/system/files/documents/2021/03/24/CAS%202012%20Static%20Analysis%20Tool%20Study%20Methodology.pdf) — различие accuracy, precision и recall при оценке analysis tools.
8. [NIST/SEMATECH e-Handbook of Statistical Methods](https://www.itl.nist.gov/div898/handbook/) — основы статистической оценки и confidence intervals.

# Приложение C. Карта ответов на защите

## Что делает проект

Проект анализирует Windows PE32+ AMD64 files. Он безопасно читает PE layout, извлекает exception directory, декодирует `RUNTIME_FUNCTION` и `UNWIND_INFO`, выявляет structural/placement/reuse anomalies, а на Windows может запустить target под Debug API и наблюдать exception-related registrations, handler hits и dynamic function tables. Результаты выводятся в terminal, CSV, JSON и HTML.

## Почему это нужно

EH/unwind metadata требуется Windows для exception dispatch, stack unwinding и debugging. Она также содержит function boundaries, stack effects и handler relations, полезные reverse engineer даже без symbols. Повреждённая или необычно организованная metadata может указывать на corruption, custom runtime, JIT, obfuscation или exception-driven control flow.

## В чём научно-техническая задача

Задача состоит не в чтении одного поля PE, а в построении безопасного and explainable pipeline:

```text
untrusted bytes
-> validated structural model
-> decoded ABI metadata
-> evidence aggregation
-> optional runtime observations
-> reproducible reports
```

## Почему архитектура не microservices

Core — modular monolith: static C library плюс CLI. Для одного analytical tool это уменьшает deployment complexity и сохраняет чёткие module boundaries. Backend, database, queue и Windows dynamic workers могут быть отдельными services вокруг stable JSON/CLI contract.

## Почему static работает на macOS/Linux

Static parser не исполняет input и не вызывает Windows loader. Он интерпретирует bytes по documented PE format. Dynamic mode требует actual Windows Debug API и поэтому Windows-only.

## Почему score не probability

Weights и thresholds заданы engineering rules. Нет обученной model и empirical probability calibration. Score ранжирует anomaly evidence; confidence оценивает разнообразие и strength rules.

## Что означает successful analysis

Input прочитан; минимальная PE32+ AMD64 model извлечена; requested stages завершились; outputs записаны. Это не означает, что file benign или что все возможные behaviors исследованы.

## Что является главным ограничением

Static stage не сравнивает полностью metadata с machine-code prolog и не анализирует весь binary semantics. Dynamic stage покрывает только достигнутый path и должен запускаться в isolated Windows environment.

## Можно ли подключить frontend и database без изменения core

Да. Backend запускает CLI как subprocess, валидирует JSON schema и сохраняет raw report. Core changes нужны только для новых analytical fields или stable native API, но не для обычной web integration.

## Почему проект готов к ВКР

Есть работающий core, объяснимая архитектура, documented standards, static and dynamic modes, structured reports, Ghidra integration, strict build, 15 automated CTest cases, fuzzing, synthetic and real-corpus validation и явно сформулированные limitations.

## Что развивать после ВКР

Приоритеты:

1. Windows sandbox worker.
2. Remote decoding dynamic function tables.
3. Code-to-unwind correspondence.
4. Broader labeled corpus and calibration.
5. Backend/database/frontend.
6. Versioned heuristic policy.
7. Richer typed event schema.
