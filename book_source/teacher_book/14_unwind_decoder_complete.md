# Том II. `unwind.c`: от таблицы функций к модели восстановления стека

## Почему Windows x64 хранит таблицу функций

Исключение может возникнуть в произвольной инструкции функции. В этот момент обычный epilog не выполнен. Значения `RSP` и nonvolatile registers отражают частично или полностью созданный stack frame.

Windows должна:

- определить, какой function range содержит текущий `RIP`;
- найти описание изменений prolog;
- восстановить caller context;
- определить наличие language-specific handler;
- продолжить поиск обработчика или stack walk.

Для nonleaf functions AMD64 image содержит function table. PE exception directory указывает на массив `RUNTIME_FUNCTION`.

## `RuntimeFunction`

```c
typedef struct RuntimeFunction {
    uint32_t begin_rva;
    uint32_t end_rva;
    uint32_t unwind_rva;
} RuntimeFunction;
```

Каждое поле 4 bytes. Размер записи 12.

Диапазон code:

```text
[BeginAddress, EndAddress)
```

`UnwindInfoAddress` указывает на `UNWIND_INFO` либо связанную encoding.

Fields являются image-relative, поэтому хранятся как RVA.

## Чтение exception directory

`unwind_read_runtime_functions` сначала обнуляет outputs:

```c
*out_rf = NULL;
*out_count = 0;
```

Если RVA и size оба zero, отсутствие таблицы считается корректным:

```c
return true;
```

Если zero только одно field, directory malformed.

Далее exception RVA преобразуется через `pe_rva_to_fileoff`.

Проверяется полный файловый диапазон:

```c
off + exception_size <= b->size
```

и structural size:

```text
size >= 12
size % 12 == 0
```

Текущая policy strict: неполный хвост отклоняет всю таблицу. Альтернативный forensic parser мог бы прочитать complete entries и сохранить remainder anomaly, но проект предпочитает однозначный contract directory.

Количество:

```c
n = exception_size / 12;
```

Для sample:

```text
0x24 / 0x0C = 3
```

## Почему reader не проверяет begin/end сразу

Функция безопасно извлекает все triples. Semantics ranges проверяются в `heuristics.c`.

Разделение позволяет сохранить malformed values в report model и агрегировать counts. Reader отвечает на вопрос «можно ли физически прочитать таблицу», heuristics — «насколько согласованы значения».

## `UnwindSummary`

Структура является нормализованным результатом декодирования:

```text
valid
version
flags
prolog_size
count_codes
frame_reg
frame_off
handler
chain
fixed_stack_bytes
pushed_nonvol_count
saved register masks
anomalies
parse_error
```

Она не сохраняет все raw slots. Подробный текст может строиться отдельно через `ops_text`.

Это design choice: массовый analysis хранит компактную summary, а `--ops` повторно декодирует выбранные entries для presentation.

## Register encoding

Unwind format кодирует general-purpose register числом `0..15`.

`unwind_reg_name` отображает:

```text
0 RAX
1 RCX
2 RDX
3 RBX
4 RSP
5 RBP
6 RSI
7 RDI
8 R8
...
15 R15
```

Unknown value возвращает `REG?`, хотя 4-bit field физически ограничен 0..15.

## Flags

Поддерживаемые:

```text
UNW_FLAG_EHANDLER  = 0x01
UNW_FLAG_UHANDLER  = 0x02
UNW_FLAG_CHAININFO = 0x04
```

`EHANDLER` указывает exception handler.

`UHANDLER` указывает termination/unwind handler.

`CHAININFO` означает, что tail содержит chained `RUNTIME_FUNCTION`.

CHAININFO не должен одновременно сочетаться с handler flags в той же record. Проект отмечает такое состояние `UA_BAD_OPERAND`.

## Вход `unwind_parse`

```c
bool unwind_parse(
    const Buf* b,
    const PeImage* img,
    uint32_t unwind_rva,
    const UnwindParseOpts* opts,
    UnwindSummary* out,
    StrBuf* ops_text,
    StrBuf* err
);
```

`b` предоставляет bytes.

`img` предоставляет mapping и `SizeOfImage`.

`unwind_rva` выбирает structure.

`opts` задаёт chain policy.

`out` получает summary.

`ops_text` optional.

`err` получает diagnostic.

## Инициализация и локализация ошибки

```c
memset(out, 0, sizeof(*out));
size_t err_start = err->len;
```

`err` может уже содержать старый текст. `err_start` позволяет `unwind_parse_fail` скопировать только diagnostic текущего вызова в `out->parse_error`.

Trailing newline удаляется, потому что JSON field должен содержать compact string.

## Options

Defaults:

```text
max_depth = 8
follow_chain = true
```

Caller может передать options. Значение depth выше 16 clamp-ится, потому что local array:

```c
uint32_t seen[16];
```

не способен хранить больше уникальных chain RVA.

## Alignment `UNWIND_INFO`

RVA должен быть 4-byte aligned:

```c
if ((unwind_rva & 3u) != 0)
    UA_ALIGNMENT
```

Нарушение не делает header физически нечитаемым, поэтому parser продолжает и сохраняет anomaly.

Это пример distinction:

```text
structurally suspicious, but decodable
```

## Mapping header

`parse_unwindinfo_header`:

1. преобразует RVA в file offset;
2. проверяет четыре bytes;
3. читает header.

Failure добавляет `UA_TRUNCATED` и возвращает false.

Термин `TRUNCATED` используется расширенно: structure физически недоступна или не помещается в file-backed range.

## Header layout

Четыре байта:

```text
byte 0: Version:3 | Flags:5
byte 1: SizeOfProlog
byte 2: CountOfCodes
byte 3: FrameRegister:4 | FrameOffset:4
```

Extraction:

```c
ver   = hdr[0] & 0x7;
flags = hdr[0] >> 3;
fr    = hdr[3] & 0x0F;
foff  = hdr[3] >> 4;
```

`FrameOffset` измеряется units of 16 bytes. Actual offset:

```text
foff * 16
```

## Version policy

Поддерживаются V1 и V2.

V3 для Intel APX имеет другую структуру и не должен интерпретироваться как V1/V2. Проект:

```c
UA_VERSION_UNKNOWN
return false
```

Test `test_unsupported_version_is_fatal` закрепляет это поведение.

Отказ лучше ложного успешного decode: неправильная версия сместила бы slots и tail, создав фиктивные handlers.

## Frame register checks

Если `frame_reg == 0`, `frame_off` должен быть zero.

Если frame register nonzero, он должен быть допустимым GPR.

После parsing codes проект также требует наличие `UWOP_SET_FPREG`, если frame register задан и record не является chained.

Несогласованность помечается `UA_BAD_OPERAND`, но structure может оставаться valid.

## CountOfCodes

`CountOfCodes` — количество двухбайтовых slots, а не логических operations.

Одна operation может занимать:

```text
1, 2 или 3 slots
```

Array физически padded до чётного числа slots, чтобы tail был 4-byte aligned:

```c
slots_even = (count + 1) & ~1
codes_bytes = slots_even * 2
```

Если `count = 1`, stored slots = 2, bytes = 4.

Второй slot является padding и не входит в semantic operation count.

## Structure slot

Первый slot operation:

```text
byte 0: CodeOffset
byte 1 low nibble: UnwindOp
byte 1 high nibble: OpInfo
```

`CodeOffset` указывает position в prolog после выполнения соответствующей operation.

Codes хранятся в порядке убывания offsets, потому что unwind применяет действия в обратном направлении.

Если очередной `CodeOffset` больше предыдущего, проект ставит:

```text
UA_CODEOFFSET_ORDER
```

Если offset больше `SizeOfProlog`:

```text
UA_CODEOFFSET_OUTSIDE
```

V2 epilog descriptors имеют другую семантику, поэтому исключаются из обычной проверки prolog offset.

## Определение длины operation

`slots_for_code` получает:

```text
version
op
opinfo
v2_seen_epilog
```

и возвращает физическое число slots.

Эта функция должна быть выполнена до чтения operands. Затем проверяется:

```c
i + slots <= count
```

Неизвестный opcode получает `UA_BAD_OPCODE`, но parser безопасно продвигается на один slot. Это позволяет собрать остальные anomalies без чтения за границей.

Если известная operation заявляет operands за CountOfCodes, parsing становится fatal.

## `UWOP_PUSH_NONVOL`

Семантика prolog:

```asm
push register
```

Stack pointer уменьшается на 8, значение register сохраняется.

Summary:

```text
fixed_stack += 8
pushed_nonvol_count += 1
register bit added to saved_nonvol_mask
```

Проект допускает некоторые volatile register operands из-за наблюдаемого real-world toolchain behavior, исключая `RSP`. Это implementation compatibility policy, а не простое повторение имени opcode.

## `UWOP_ALLOC_SMALL`

Размер:

```text
OpInfo * 8 + 8
```

Диапазон:

```text
8..128 bytes
```

Для sample slot:

```text
CodeOffset = 4
Op = 2
OpInfo = 4
```

размер:

```text
4 * 8 + 8 = 40
```

Поэтому report показывает:

```text
prolog_size = 4
fixed_stack_bytes = 40
```

## `UWOP_ALLOC_LARGE`

Имеет два modes.

Mode 0, `OpInfo == 0`:

- следующий slot содержит size / 8;
- actual size = operand * 8;
- total 2 slots.

Mode 1, `OpInfo == 1`:

- следующие два slots содержат полный 32-bit size;
- total 3 slots.

Другой `OpInfo` недопустим.

Project sanity rules отмечают использование large form для размеров, которые выглядят несогласованно с ожидаемым encoding choice. Это anomaly, не parse failure.

## `UWOP_SET_FPREG`

Указывает установку frame pointer register, заданного header.

Operation сама не добавляет fixed stack bytes. Она изменяет способ вычисления frame base.

Повторная operation или отсутствие header frame register создаёт `UA_BAD_OPERAND`.

## `UWOP_SAVE_NONVOL`

Описывает сохранение register в ранее выделенной области stack без `push`.

Следующий slot кодирует scaled offset.

Проект:

- проверяет наличие operand;
- отмечает register в mask;
- не добавляет fixed stack, потому что allocation описывается отдельной operation.

Это различие критично. `SAVE_NONVOL` сообщает расположение сохранённого значения внутри frame, но не означает дополнительное изменение `RSP`.

## `UWOP_SAVE_NONVOL_FAR`

Использует два operand slots для 32-bit offset.

Far form предназначена для больших offsets. Малое или неверно выровненное значение получает `UA_OPERAND_SANITY`.

Parser всё равно сохраняет register mask, если field декодируемо.

## XMM saves

`UWOP_SAVE_XMM128` и FAR variant описывают сохранение 128-bit XMM register.

Offsets масштабируются согласно specification, хотя compact summary проекта в основном сохраняет register mask и sanity.

Отдельный `saved_xmm_mask` не смешивает vector state с GPR.

## V1 opcodes 6 и 7

Для V1 код поддерживает observed undocumented/common encodings `SAVE_XMM` и `SAVE_XMM_FAR`. Это compatibility behavior, которое должно явно отличаться от официальных V2 meanings.

## V2 epilog descriptors

В V2 opcode 6 используется для epilog descriptors, opcode 7 — spare.

Первый descriptor может иметь short или long form; последующие описывают offsets from end.

Parser:

- определяет slot count с учётом first descriptor;
- строит readable `ops_text`;
- не применяет обычную CodeOffset check;
- продолжает декодировать последующие prolog operations.

Unit test содержит short и long records и проверяет `offset_from_end`.

## `UWOP_PUSH_MACHFRAME`

Описывает machine frame, сформированный hardware/exception mechanism.

`OpInfo` определяет наличие error code.

Summary добавляет:

```text
40 bytes без error code
48 bytes с error code
```

Другой `OpInfo` помечается `UA_BAD_OPERAND`.

## Защита суммы fixed stack

`add_fixed_stack` проверяет:

```c
UINT32_MAX - total < amount
```

При overflow:

```text
total = UINT32_MAX
UA_OPERAND_SANITY
```

Saturation сохраняет upper-bound signal и не позволяет wrap к малому размеру.

## Tail после slots

Tail начинается:

```c
after_codes = codes_off + codes_bytes;
```

`codes_bytes` уже включает padding.

Содержимое зависит от flags.

### Handler tail

При EHANDLER/UHANDLER первые 4 bytes tail — handler RVA.

Проект проверяет physical read и:

```text
handler_rva < SizeOfImage
```

Выход за image ставит `UA_HANDLER_OOB`, но read остаётся successful.

Данные после handler RVA являются language-specific. Текущая summary их не декодирует.

### Chain tail

При CHAININFO tail содержит ещё один 12-byte `RUNTIME_FUNCTION`.

Проверяются:

- `end > begin`;
- range в `SizeOfImage`;
- nonzero unwind RVA;
- unwind RVA в image.

Нарушение даёт `UA_CHAIN_INVALID`.

## Следование по chain

Если enabled, проект начинает с:

```c
cur = out->chain.unwind_rva;
```

Массив `seen[16]` хранит уже посещённые RVA. Повтор означает loop.

Внутренний recursive-like вызов:

```c
unwind_parse(... follow_chain = false)
```

декодирует один следующий record без собственного продолжения chain. Внешний цикл контролирует depth и loop detection.

Summary parent объединяется:

```text
fixed stack sum
pushed count sum
OR register masks
inherited handler
frame consistency check
```

Это compact analytical aggregation. Оно не заменяет точную реализацию `RtlVirtualUnwind` для любого instruction offset.

## `valid` и anomalies

В конце:

```c
out->valid = true;
return true;
```

Anomalies могут быть nonzero. `valid` означает, что structure была декодирована достаточно для summary, а не что metadata идеальна.

Fatal conditions:

- header unmappable/truncated;
- unsupported version;
- code array за file;
- operation operands за CountOfCodes;
- truncated handler/chain tail.

Nonfatal anomalies:

- alignment;
- bad flags/operands;
- order;
- code offset outside;
- handler OOB;
- chain invalid;
- suspicious operand form.

## `parse_error`

При failure `unwind_parse_fail`:

- устанавливает `valid = false`;
- выбирает diagnostic текущего invocation;
- удаляет newline;
- ограничивает длину 159 characters;
- null-terminates field.

Report всегда может показать конкретную причину для function.

## Сквозной sample

Runtime table:

```text
[0] 1000..1010 -> 4000
[1] 1010..1029 -> 4004
[2] 1029..1040 -> 400C
```

Для record 1:

```text
Unwind RVA 0x4004
section .xdata VA 0x4000
raw ptr 0xA00
delta 0x4
file offset 0xA04
```

Header и slot приводят к:

```text
Version 1
Flags 0
Prolog 4
Count 1
Frame register 0
ALLOC_SMALL 40
```

JSON function object сохраняет эти значения.

## Связь с heuristics

`unwind_parse` не назначает weight.

Он создаёт:

```text
us_ok[i]
us[i].anomalies
handler_rva
unwind_rva
```

`heuristics.c` считает:

- parse failures;
- anomaly-bearing records;
- placement unwind RVA;
- placement handler RVA;
- reuse.

Так decode semantics отделена от detection policy.

## Tests

`unit_unwind` строит synthetic byte buffers для точной проверки:

- alloc small;
- push nonvol;
- code offset order;
- operand sanity;
- real-world compatible operands;
- V2 epilogs;
- chain inheritance;
- invalid flags/frame;
- preserved parse error;
- unsupported V3;
- truncated handler;
- chain validation/alignment.

Synthetic tests необходимы, потому что позволяют задать отдельные bits без влияния linker.

Regression tests необходимы дополнительно, потому что проверяют полный PE path.

## Ограничения decoder

Текущий decoder:

- не выполняет полный `RtlVirtualUnwind`;
- не вычисляет caller context для заданного instruction offset;
- не декодирует language-specific handler data;
- не поддерживает V3;
- агрегирует chain эвристически;
- не сопоставляет operations с disassembly;
- сохраняет masks, но не полные offsets каждого register save в JSON summary.

Это определяет направления развития, но не нарушает заявленный contract summary analyzer.

