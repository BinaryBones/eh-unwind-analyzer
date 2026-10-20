# Лекция 7. Метод reverse engineering: от наблюдения к проверяемому выводу

## Reverse engineering как дисциплина вывода

**Reverse engineering**, далее обратный анализ или реверс-инжиниринг, — восстановление структуры, поведения и назначения программной системы по доступным артефактам без опоры на её исходную design documentation. Для бинарного анализа артефактами служат bytes файла, machine code, metadata, imports, runtime memory, execution events и результаты контролируемых экспериментов.

Обратный анализ не сводится к чтению disassembly. Disassembly является одним представлением. Надёжный вывод строится как цепочка:

```text
наблюдаемый факт
-> интерпретация по формату или ABI
-> гипотеза о поведении
-> независимая проверка
-> ограниченный вывод
```

Если аналитик перепрыгивает от одного необычного byte к заключению о назначении программы, он совершает логическую ошибку. EH/Unwind Analyzer специально разделяет raw facts, findings, score, confidence и manual validation steps, чтобы сделать эту дисциплину явной.

## Статический и динамический анализ

**Static analysis** исследует файл и производные представления без исполнения target. Он воспроизводим для одного и того же файла и не зависит от достигнутого runtime path. Статический анализ способен охватить недостигаемые в одном запуске sections и records, но не доказывает, что code был выполнен.

**Dynamic analysis** наблюдает конкретное исполнение. Он подтверждает достигнутые события и значения состояния, но охватывает только path, определённый аргументами, environment, timing и внешними данными.

Эти методы не конкурируют. Они отвечают на разные вопросы.

Статика может установить:

```text
UNWIND_INFO указывает HandlerRVA 0x5120
```

Динамика может установить:

```text
VA base+0x5120 был достигнут потоком 1480 после exception
```

Только совместно они подтверждают, что handler, заявленный конкретной metadata, реально участвовал в исследованном execution path. Даже этот вывод не объясняет назначение handler; для этого требуется code analysis.

## Нормативный факт, implementation fact и аналитический вывод

Рабочие записи должны маркировать происхождение утверждений.

**Нормативный факт** следует из specification или ABI. Например: `RUNTIME_FUNCTION` AMD64 содержит три image-relative 32-bit fields.

**Implementation fact** следует из исходного кода инструмента. Например: проект начисляет 25 score points за exception directory out of bounds.

**Observation** следует из конкретного sample или run. Например: в `benign_richer.exe` exception directory имеет RVA `0x3000` и size `0x24`.

**Analytical conclusion** связывает факты и наблюдения. Например: directory содержит три полных entries и не имеет incomplete tail.

Вес heuristic не является нормативным фактом Microsoft. Отсутствие такого различия делает объяснение проекта научно некорректным.

## Chain of custody для бинарного артефакта

До анализа следует зафиксировать identity input:

- исходный путь;
- размер;
- SHA-256;
- время получения;
- источник;
- условия хранения;
- копию для работы.

**SHA-256** — cryptographic hash function, формирующая 256-bit digest. В проекте digest кодируется 64 lowercase hexadecimal symbols. Hash позволяет проверить, что два отчёта относятся к одним bytes. Он не подтверждает добросовестность источника и не является digital signature.

Проект записывает `input_sha256` и `input_size` в report metadata. Это связывает analytical output с exact input.

При динамическом анализе неизвестного binary следует использовать изолированную Windows environment, snapshot и контролируемую сеть. Тот факт, что collector не предназначен для обхода защит, не делает запуск неизвестного файла безопасным.

## Первый проход: определить класс объекта

До изучения functions нужно ответить:

- является ли input PE image;
- какая архитектура указана;
- EXE это или DLL;
- каковы section layout и permissions;
- присутствует ли exception directory;
- не повреждены ли ranges;
- совпадает ли hash с ожидаемым sample.

EH/Unwind Analyzer автоматизирует часть этого прохода только для PE32+ AMD64. Он не заменяет универсальный PE viewer, signature verification, import analysis или malware sandbox.

## Ghidra как статическая платформа

Ghidra — framework для software reverse engineering. Для проекта важны:

- import PE;
- memory map;
- disassembler;
- function manager;
- decompiler;
- symbol and reference navigation;
- scripting.

После import Ghidra строит собственную program database. Она не равна исходному PE-файлу. В ней хранятся разобранные memory blocks, functions, labels, references, types и пользовательские annotations.

**Disassembler** переводит machine-code bytes в assembly instructions согласно выбранной architecture и address context.

**Decompiler** строит high-level intermediate representation и затем C-like text. Его output не является исходным C-кодом. Имена, types и control structures являются реконструкцией, подверженной ошибкам.

## Адресная синхронизация

EH/Unwind Analyzer выводит RVA. Ghidra обычно показывает image-based addresses. Для declared base:

```text
GhidraAddress = ImageBase + RVA
```

Если Ghidra imported image с base `0x140000000`, то function begin RVA `0x1010` находится по:

```text
0x140000000 + 0x1010 = 0x140001010
```

В debugger:

```text
RuntimeVA = ActualModuleBase + RVA
```

RVA служит стабильным идентификатором позиции внутри image между static и dynamic representations.

Нужно всегда записывать, какой тип адреса используется. Строка `0x140001010` без обозначения VA или preferred VA недостаточна.

## Импорт CSV из проекта

Проект способен сформировать Ghidra-oriented CSV:

```text
begin_rva,end_rva,name,comment
```

Импортирующий script может:

- создать или уточнить function boundaries;
- присвоить synthetic names вида `sub_00001010`;
- добавить comment с decoded unwind summary.

Это enrichment, а не доказательство правильности decompilation. Если metadata повреждена или намеренно искажена, автоматически созданные function boundaries также могут быть неверны. Поэтому findings table должна проверяться до массового доверия imported map.

## Анализ функции по слоям

Для каждой подозрительной function рекомендуется одна и та же последовательность.

Сначала установить boundary source: определена ли функция по `.pdata`, symbol, call target, prolog pattern или manual creation.

Затем исследовать raw instructions:

- какие bytes образуют prolog;
- как изменяется `RSP`;
- какие nonvolatile registers сохраняются;
- выполняются ли calls;
- где находятся epilogs;
- имеются ли indirect branches.

После этого сравнить metadata:

- совпадает ли `SizeOfProlog`;
- соответствует ли `ALLOC_*` изменению `RSP`;
- совпадают ли `PUSH_NONVOL` и `SAVE_NONVOL`;
- соответствует ли frame register;
- указывает ли handler на executable code.

Лишь затем исследовать decompiler output и data flow.

## Сопоставление prolog и UNWIND_INFO

Пусть disassembly начинается:

```asm
sub rsp, 28h
```

Immediate `0x28` равен 40 decimal bytes. Metadata `UWOP_ALLOC_SMALL` с `OpInfo = 4` также описывает:

```text
4 * 8 + 8 = 40
```

Совпадение подтверждает semantic correspondence для allocation.

Если metadata заявляет сохранение `RBX`, нужно найти соответствующий `push rbx` или store в stack slot в пределах prolog. Если instruction находится после declared `SizeOfProlog`, metadata и code расходятся.

Такой анализ выполняется instruction-by-instruction. Недостаточно увидеть, что общий stack size похож.

## Control flow graph

**Control Flow Graph**, сокращённо CFG, — ориентированный граф, vertices которого являются basic blocks, а edges — возможные передачи управления.

**Basic block** — последовательность instructions с одним входом и завершением на branch, return, call с особой моделью или другом boundary.

Exception-based flow может отсутствовать в обычных explicit branch edges. Handler address приходит из metadata или runtime registration. Поэтому EH/Unwind analysis добавляет к CFG неявные связи:

```text
protected function/frame -> frame handler
registration call -> registered VEH/VCH/UEF
exception event -> reached handler
```

Эти связи нужно хранить отдельно от прямых machine-code jumps, потому что их semantics и условия активации различаются.

## Data flow

**Data flow analysis** исследует происхождение и использование values. Для API registration:

```text
RCX/RDX/R8/R9 at function entry
```

являются ABI locations аргументов. Однако регистровое значение само по себе может быть pointer, integer, handle или bit field в зависимости от prototype.

Для `AddVectoredExceptionHandler`:

```text
RCX = First
RDX = Handler
```

Для `RtlAddFunctionTable`:

```text
RCX = FunctionTable
RDX = EntryCount
R8  = BaseAddress
```

После capture нужно проверить pointer ranges, memory protection, module ownership и pointed data. Collector пока записывает arguments, но не выполняет полный remote table parser.

## Cross-reference analysis

**Cross-reference**, сокращённо xref, — связь между местом использования и target address, symbol или data object.

Для dominant handler следует определить:

- сколько `UNWIND_INFO` records на него ссылаются;
- какие functions покрываются этими records;
- принадлежит ли handler compiler runtime;
- кто вызывает или регистрирует related code;
- есть ли indirect references;
- какие exception codes он проверяет;
- куда передаёт control.

Высокий reuse может быть нормален для language runtime. Решение требует context, а не только ratio.

## Debugger breakpoint strategy

Каждый breakpoint должен отвечать на сформулированный вопрос.

Breakpoint на registration API отвечает: была ли регистрация, и какие arguments переданы?

Breakpoint на handler entry отвечает: был ли handler фактически достигнут?

Breakpoint на `RtlAddFunctionTable` отвечает: регистрировалась ли dynamic table?

Breakpoint на конкретный instruction после handler отвечает: какой branch выбран после проверки exception?

Избыточные breakpoints создают data volume, но не обязательно увеличивают evidence.

## Software breakpoint limitations

Запись `0xCC` изменяет target memory. Это вмешательство может быть обнаружено anti-debug logic, конфликтовать с self-modifying code или racing threads.

Если другой поток исполняет address между снятием и re-arm breakpoint, hit может быть пропущен. Per-thread pending list исправляет логическую потерю re-arm, но не устраняет все concurrency races inherent software breakpoints.

Hardware breakpoints не изменяют code bytes, но ограничены register resources и имеют собственные semantics. Текущий проект их не использует.

Следовательно, отсутствие hit не доказывает, что code никогда не исполнялся при всех условиях.

## First-chance workflow

При first-chance exception аналитик фиксирует:

- exception code;
- exception address;
- thread;
- module and RVA;
- register context;
- stack;
- наличие ожидаемого handler;
- дальнейший continuation status.

Затем debugger должен передать исключение системе как unhandled, если цель — наблюдать обычную application dispatch. Именно так поступает collector.

Если debugger объявит исключение handled, application handlers могут не получить управление. Это пример того, как метод наблюдения способен изменить объект наблюдения.

## Handler investigation

При попадании в handler необходимо определить:

- класс handler: frame-based, VEH, VCH или UEF;
- prototype и arguments;
- exception record fields;
- context record usage;
- return disposition;
- writes to context;
- transfers to dispatcher or original path;
- повторное создание exception.

VEH получает `PEXCEPTION_POINTERS`, включающий pointers на exception record и context record. Изменение context может перенаправить выполнение. Но факт записи в context ещё нужно связать с последующим `RIP`.

Текущий collector фиксирует handler hit и ограниченную RIP trace, но не сериализует полный context diff. Это одна из честных границ продукта.

## Static-dynamic correlation

Correlation должна иметь явный join key. В проекте им может быть:

- handler RVA;
- module + offset;
- event type;
- function range;
- section property;
- dynamic table base.

Например:

```text
static:
HandlerRVA 0x5120 находится в writable section

dynamic:
handler VA ActualBase+0x5120 был достигнут

correlated conclusion:
статически заявленный handler из writable section участвовал в данном run
```

Project-level `has_static_dynamic_correlation` использует более агрегированные rules: suspicious static handler context плюс handler hits, либо placement anomalies плюс runtime function table registration. Это useful summary, но manual investigation должна сохранять exact address relation.

## Evidence strength и falsifiability

Хорошая гипотеза допускает проверку, способную её опровергнуть.

Гипотеза:

```text
dominant handler является normal compiler runtime helper
```

Проверки:

- symbol or signature identification;
- comparison с binaries того же compiler;
- code semantics;
- exception codes;
- references from normal try/catch functions.

Гипотеза:

```text
handler реализует exception-driven dispatcher
```

Проверки:

- изменяет `ContextRecord.Rip`;
- выбирает destinations по state;
- вызывается для множества protected functions;
- dynamic trace уходит в dispatcher loop;
- control-flow pattern воспроизводится при разных inputs.

Вывод должен сохранять альтернативные объяснения, пока они не исключены.

## Отчёт reverse engineer

Полноценный analytical report включает:

- input identity;
- environment and tool versions;
- scope;
- observations;
- адреса с указанием coordinate system;
- screenshots или disassembly excerpts;
- static findings;
- runtime events;
- correlations;
- excluded hypotheses;
- remaining uncertainty;
- reproducible commands.

JSON проекта является machine-readable evidence package. HTML является human-review projection той же модели. Ни один из них автоматически не заменяет narrative analyst report о semantics code.

## Практический протокол для EH/Unwind Analyzer

1. Вычислить SHA-256 и сохранить sample.
2. Запустить static mode с JSON, HTML и Ghidra CSV.
3. Проверить PE structural counters.
4. Отсортировать findings по severity и family.
5. Для каждого representative RVA выполнить RVA-to-VA и RVA-to-file-offset conversion.
6. Открыть соответствующий record и function в Ghidra.
7. Сопоставить prolog и unwind codes.
8. Исследовать handler xrefs и code semantics.
9. На Windows запустить dynamic mode с контролируемыми arguments.
10. Сопоставить events с static addresses.
11. Проверить manual validation steps из report.
12. Сформулировать conclusion с границами evidence.

Эта последовательность превращает output инструмента в метод исследования, а не в замену профессионального анализа.

## Что означает компетентность после лекции

Студент должен уметь:

- отделять disassembly от decompilation;
- объяснять, почему static и dynamic evidence не взаимозаменяемы;
- преобразовывать RVA между Ghidra и runtime debugger;
- проверить `UNWIND_INFO` по prolog instructions;
- исследовать handler не только по адресу, но по data flow и return semantics;
- назвать вмешательство software breakpoint;
- сформулировать вывод так, чтобы было видно, что доказано, а что остаётся гипотезой.

