# Лекция 6. Диспетчеризация исключений и теория раскрутки Windows x64

## Центральная проблема

В момент исключения Windows получает состояние текущего потока: `RIP`, `RSP`, регистры и описание исключения. Чтобы искать обработчик выше по цепочке вызовов, системе необходимо последовательно восстановить состояния вызывающих функций.

На x86-64 это нельзя надёжно сделать только по машинному коду и нельзя считать, что каждая функция использует постоянный frame pointer. Compiler может изменять `RSP`, сохранять nonvolatile registers в разных местах и выполнять оптимизации. Поэтому Windows x64 ABI вводит ограничения на prolog и epilog и требует unwind metadata для nonleaf functions.

**Unwind**, далее раскрутка, — вычисление состояния caller из состояния callee. Оно включает восстановление stack pointer, instruction pointer и сохранённых nonvolatile registers. Слово «раскрутка» описывает движение от более глубокого stack frame к более раннему.

## Leaf и nonleaf function

**Leaf function** в данном контексте — функция, которая не изменяет nonvolatile state таким способом, который требует unwind description, и не вызывает другие функции. Если для текущего `RIP` отсутствует `RUNTIME_FUNCTION`, Windows может рассматривать frame как leaf: return address находится по `[RSP]`, после чего виртуальный `RSP` увеличивается на восемь.

**Nonleaf function** может выделять stack space, сохранять nonvolatile registers, устанавливать frame register и вызывать другие функции. Для неё требуется table entry.

Отсутствие `.pdata` не всегда является ошибкой. Image, состоящий только из leaf code, теоретически может не иметь записей. Поэтому эвристика `no_runtime_functions` имеет medium severity и прямо требует проверки сложности code. Если executable sections отсутствуют, проект даже не начисляет score и фиксирует информационное объяснение resource-only или forwarding image.

## RUNTIME_FUNCTION как индекс диапазона кода

На AMD64 запись имеет три 32-разрядных RVA:

```c
typedef struct RuntimeFunction {
    uint32_t begin_rva;
    uint32_t end_rva;
    uint32_t unwind_rva;
} RuntimeFunction;
```

Она описывает:

```text
[BeginAddress, EndAddress) -> UnwindInfoAddress
```

Диапазон является полуинтервалом. Запись применима, если:

```text
BeginAddress <= ControlPcRVA < EndAddress
```

Таблица должна быть отсортирована по `BeginAddress`. Сортировка позволяет системе эффективно искать запись по текущему control PC. Overlap и duplicate begin нарушают однозначность отображения code address в metadata.

Все адреса image-relative. Это делает table независимой от actual base при ASLR. Для получения VA:

```text
FunctionVA = ModuleBase + BeginRVA
UnwindVA   = ModuleBase + UnwindRVA
```

## UNWIND_INFO как описание обратного действия

Prolog изменяет входной context функции. Он может уменьшить `RSP`, сохранить `RBX`, `RBP`, `RSI`, `RDI`, `R12`–`R15`, сохранить nonvolatile XMM registers и установить frame pointer.

`UNWIND_INFO` кодирует действия, необходимые для отмены этих изменений. Это не копия инструкций и не общий bytecode CPU. Это компактная domain-specific encoding Windows ABI.

Header версии 1 занимает четыре bytes:

```text
byte 0: Version, 3 bits; Flags, 5 bits
byte 1: SizeOfProlog
byte 2: CountOfCodes
byte 3: FrameRegister, 4 bits; FrameOffset, 4 bits
```

После header расположен массив `UNWIND_CODE`. Каждая базовая slot занимает два bytes:

```text
CodeOffset : 1 byte
UnwindOp   : 4 bits
OpInfo     : 4 bits
```

Некоторые operations потребляют дополнительные slots как operands. Поэтому `CountOfCodes` — число двухбайтовых slots, а не число логических операций.

## Version и Flags

Три младших bits первого byte образуют `Version`. Нормативная Microsoft documentation для классической структуры описывает version 1. Проект также поддерживает version 2 epilog descriptors в ограниченной decoder policy, потому что такие данные встречаются в современных toolchains.

Пять старших bits образуют `Flags`. Для version 1 существенны:

```text
UNW_FLAG_EHANDLER = 1
UNW_FLAG_UHANDLER = 2
UNW_FLAG_CHAININFO = 4
```

`EHANDLER` означает наличие exception handler, используемого в search phase. `UHANDLER` означает termination handler, используемый в unwind phase. Оба формата хвоста содержат handler RVA после выровненного массива codes.

`CHAININFO` означает, что хвост содержит не handler RVA, а связанную `RUNTIME_FUNCTION`. Chained record переиспользует primary unwind information для фрагмента функции.

Сочетание `CHAININFO` с handler flags противоречит формату. Decoder должен фиксировать invalid chain, а не выбирать произвольную интерпретацию хвоста.

## SizeOfProlog и CodeOffset

`SizeOfProlog` — длина prolog в bytes. `CodeOffset` указывает offset после инструкции prolog, эффект которой описывает operation. Codes хранятся в descending order по `CodeOffset`, потому что раскрутка отменяет prolog в обратной последовательности.

Если exception произошёл внутри prolog, нельзя отменять instructions, которые ещё не были выполнены. Windows учитывает control PC относительно prolog. Статический проект не выполняет полный `RtlVirtualUnwind` для конкретного `ControlPc`; он проверяет structural order и агрегирует effects всей записи.

`CodeOffset > SizeOfProlog` является anomaly, потому что operation заявляет эффект за пределами declared prolog. Нарушение descending order также фиксируется.

## FrameRegister и FrameOffset

Четыре младших bits четвёртого header byte кодируют frame register. Значение zero означает отсутствие frame register. Остальные значения используют register numbering unwind format.

Четыре старших bits задают scaled offset. Реальный offset:

```text
FrameOffsetBytes = FrameOffset * 16
```

Если frame register отсутствует, ненулевой offset не имеет корректного смысла. Если указан volatile register, decoder отмечает operand anomaly, потому что frame register должен соответствовать ABI constraints.

Frame pointer не равен автоматически `RBP`. Encoding может указать другой допустимый nonvolatile register. Поэтому reverse engineer должен читать поле, а не переносить привычку из неиспользуемой compilation model.

## UWOP_PUSH_NONVOL

`UWOP_PUSH_NONVOL` описывает сохранение nonvolatile general-purpose register инструкцией push. `OpInfo` кодирует register.

Push уменьшает `RSP` на восемь и записывает register. При unwind операция читает сохранённое значение и увеличивает `RSP`. Для summary проекта фиксированный stack effect увеличивается на 8 bytes, а bit register добавляется в `saved_nonvol_mask`.

Если `OpInfo` указывает volatile register или `RSP`, metadata сомнительна. Decoder отмечает bad operand или operand sanity anomaly.

## UWOP_ALLOC_SMALL

`UWOP_ALLOC_SMALL` кодирует небольшое выделение stack:

```text
AllocationSize = OpInfo * 8 + 8
```

Operation не требует дополнительного slot. Возможный диапазон при четырёхбитовом `OpInfo`:

```text
8, 16, ..., 128 bytes
```

Для sample `benign_richer.exe` `OpInfo = 4`, поэтому:

```text
4 * 8 + 8 = 40 bytes
```

Это значение появляется в `fixed_stack_bytes` JSON report.

## UWOP_ALLOC_LARGE

`UWOP_ALLOC_LARGE` имеет два encoding modes.

При `OpInfo = 0` следующий slot хранит 16-разрядное значение, масштабированное на восемь:

```text
AllocationSize = operand16 * 8
```

При `OpInfo = 1` следующие два slots образуют полное 32-разрядное allocation size без scaling.

Другие `OpInfo` недопустимы. Недостаток operand slots означает truncated record.

Проект вычисляет fixed stack size с saturating behavior. Если сумма выходит за `uint32_t`, она ограничивается максимальным значением и помечается anomaly. Это предпочтительнее wraparound, при котором огромный stack effect ошибочно превратился бы в малое число.

## UWOP_SET_FPREG

`UWOP_SET_FPREG` сообщает, что prolog установил declared frame register. Дополнительных operands нет. Смысл операции зависит от header fields `FrameRegister` и `FrameOffset`.

Если header не задаёт frame register, наличие `SET_FPREG` противоречиво. Если declared frame register не является допустимым nonvolatile register, decoder отмечает anomaly.

При анализе disassembly нужно найти instruction, которая формирует relation:

```text
FrameRegister = RSP + FrameOffsetBytes
```

или эквивалентную разрешённую форму prolog.

## UWOP_SAVE_NONVOL и UWOP_SAVE_NONVOL_FAR

Эти operations описывают сохранение nonvolatile general-purpose register через memory store, а не push.

`UWOP_SAVE_NONVOL` использует один дополнительный slot:

```text
StackOffset = operand16 * 8
```

`UWOP_SAVE_NONVOL_FAR` использует два slots:

```text
StackOffset = operand32
```

Operation сообщает место сохранения register относительно stack frame. Она не означает дополнительное выделение stack: allocation обычно описывается отдельным `ALLOC_SMALL` или `ALLOC_LARGE`. Поэтому summary добавляет register в mask, но не должен дважды прибавлять offset к `fixed_stack_bytes`.

## XMM operations

`UWOP_SAVE_XMM128` и `UWOP_SAVE_XMM128_FAR` описывают сохранение nonvolatile SIMD register.

Обычная форма использует:

```text
StackOffset = operand16 * 16
```

Far form использует полный 32-разрядный offset. Масштаб 16 соответствует размеру 128-bit XMM value и alignment constraints.

Проект хранит `saved_xmm_mask`, где bit N означает XMMN. На Windows x64 ABI nonvolatile являются XMM6–XMM15. Сохранение volatile XMM register в unwind metadata вызывает sanity signal.

## UWOP_PUSH_MACHFRAME

`UWOP_PUSH_MACHFRAME` описывает machine frame, созданный при переходе через interrupt или exception mechanism. `OpInfo` различает frame с error code и без него.

Эта operation не эквивалентна обычному `push`. Она моделирует системный набор полей, включающий control state. Stack effect зависит от variant. Неподдерживаемое `OpInfo` является bad operand.

В обычном прикладном code такая operation редка, но decoder обязан корректно распознавать её, иначе valid system-oriented metadata будет ошибочно объявлена повреждённой.

## Padding и выравнивание хвоста

Поскольку каждый code slot имеет два bytes, конец массива может оказаться не выровнен на четыре bytes. Handler RVA или chained `RUNTIME_FUNCTION` должен начинаться на DWORD boundary.

Если `CountOfCodes` нечётно, после последнего значимого slot присутствует padding slot:

```text
tail_offset = 4 + 2 * align_up(CountOfCodes, 2)
```

или эквивалентно количество slots округляется до чётного.

Ошибка здесь смещает чтение handler RVA на два bytes и полностью разрушает последующую интерпретацию. Поэтому alignment является самостоятельным проверяемым invariant.

## Handler tail

При `EHANDLER` или `UHANDLER` после aligned code array находится 32-разрядный `HandlerRVA`. За ним может следовать language-specific data, формат которых зависит от конкретного handler.

EH/Unwind Analyzer читает только handler RVA. Он не декодирует C scope tables, C++ exception structures или конкретные compiler runtime records. Поэтому `has_handler = true` означает наличие frame handler pointer по общему формату, но не раскрывает семантику языка.

Heuristic engine проверяет section, в которую попадает handler RVA:

- отсутствующая или non-executable section;
- writable section;
- dominance одного handler среди множества records.

Эти свойства не подменяют disassembly handler.

## Chained unwind info

При `CHAININFO` хвост содержит полную тройку:

```text
BeginAddress
EndAddress
UnwindInfoAddress
```

Она связывает текущий fragment с другой unwind record. Chaining позволяет описывать discontiguous или разделённые prolog regions без полного дублирования.

Decoder проверяет:

- правильность flag combination;
- валидность range;
- нахождение адресов внутри image;
- отсутствие очевидного self-loop;
- ограничение глубины follow;
- отсутствие цикла по уже посещённым unwind RVA.

Ограничение глубины является защитой parser, а не свойством Windows semantics. Без него специально созданная длинная цепочка могла бы вызвать чрезмерную работу или recursion.

## Virtual unwind

**Virtual unwind** означает вычисление caller context без фактического исполнения epilog. В логической форме система:

1. находит table entry для текущего `RIP`;
2. определяет положение внутри prolog, body или epilog;
3. применяет relevant unwind operations;
4. восстанавливает nonvolatile registers;
5. получает return address;
6. формирует caller `RIP` и `RSP`;
7. повторяет поиск для caller.

Если текущий адрес находится в epilog, Windows может распознать разрешённую форму epilog и симулировать оставшиеся действия. Именно поэтому x64 ABI ограничивает структуру epilog.

EH/Unwind Analyzer не является stack walker. Он декодирует metadata вне конкретного runtime context. Поэтому он способен сказать, что record описывает 40-byte allocation и сохранение register, но не вычисляет caller context для заданных `RIP/RSP`.

## Search phase и unwind phase

Во время search phase dispatcher проверяет frame handlers, чтобы определить, может ли какой-либо из них обработать exception. Контекст виртуально перемещается вверх, но реальное выполнение функции ещё не сворачивается.

После выбора handler начинается unwind phase. Система возвращается по frames до target, вызывает termination handlers и восстанавливает состояние согласно правилам.

Различие объясняет флаги `EHANDLER` и `UHANDLER`. Один handler может участвовать в поиске, другой — в cleanup при раскрутке.

## Почему metadata интересна reverse engineer

Unwind metadata создана прежде всего для runtime correctness, но содержит структурные сведения:

- границы функций;
- наличие prolog и его размер;
- fixed stack allocation;
- nonvolatile registers;
- frame register;
- handler address;
- chain relations.

Даже если symbols удалены, `.pdata` сохраняет function ranges для многих nonleaf functions. Это делает её источником восстановления function map.

Одновременно защитные системы, packers, virtual machines и JIT runtimes могут:

- централизовать handlers;
- регистрировать dynamic tables;
- размещать metadata необычно;
- использовать exception-driven control flow;
- создавать records, затрудняющие автоматический анализ.

Но необычность не равна вредоносности. Compiler runtime, managed runtime и JIT также законно используют сложные handlers и dynamic tables. Поэтому проект строит evidence, а не бинарный детектор.

## Инварианты, которые проверяет проект

Инварианты `RUNTIME_FUNCTION`:

```text
EndRVA > BeginRVA
BeginRVA < SizeOfImage
EndRVA <= SizeOfImage
UnwindRVA != 0
UnwindRVA < SizeOfImage
table sorted by BeginRVA
ranges do not overlap
```

Инварианты `UNWIND_INFO`:

```text
supported version
header and all operand slots are file-backed
CodeOffset <= SizeOfProlog
CodeOffset order is descending
opcode and OpInfo combination is valid
tail is correctly aligned
handler and chain addresses are plausible
chain traversal is bounded and acyclic
```

Нарушение отдельного invariant локализуется в `UnwindSummary.anomalies` или `parse_error`. Затем heuristic layer агрегирует число нарушений и их распространённость.

## Разбор фактической записи sample

Для одной функции `benign_richer.exe`:

```text
RUNTIME_FUNCTION:
BeginRVA  = 0x1010
EndRVA    = 0x1029
UnwindRVA = 0x4004
```

Функция занимает:

```text
0x1029 - 0x1010 = 0x19 = 25 bytes
```

По `UnwindRVA 0x4004` decoder читает header версии 1. `SizeOfProlog = 4`. Массив codes содержит `UWOP_ALLOC_SMALL` с `OpInfo = 4`.

Следовательно:

```text
FixedStackBytes = 4 * 8 + 8 = 40
```

Handler flags отсутствуют, chain отсутствует, anomalies равны zero. Итог summary говорит не «функция безопасна», а:

- record структурно прочитан;
- declared prolog length равен 4;
- metadata описывает fixed allocation 40 bytes;
- дополнительных сохранённых registers и handlers нет;
- поддерживаемые invariants не нарушены.

## Граница доказательства

Parser может подтвердить внутреннюю согласованность metadata, но не полное соответствие реальному machine code. Для этого нужно сопоставить каждую unwind operation с prolog instructions в disassembler. Например, `ALLOC_SMALL 40` должен соответствовать изменению `RSP` на 40 bytes разрешённой prolog instruction.

Таким образом имеются три уровня:

```text
syntactic validity
-> semantic validity внутри формата
-> correspondence с фактическим кодом
```

Проект автоматизирует первые два уровня частично. Третий остаётся manual reverse-engineering task и должен быть явно назван на защите.

## Нормативные источники

- Microsoft, [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170).
- Microsoft, [x64 prolog and epilog](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-170).
- Microsoft, [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).
- Microsoft, [PE Format, `.pdata` section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

