# Том III. `UNWIND_INFO` V3: новая модель, совместимость и план поддержки

## Почему V3 требует отдельной главы

В ранних главах курс описывает `UNWIND_INFO` V1/V2. Текущий decoder проекта
поддерживает именно эти версии. В мае 2026 года Microsoft опубликовала
preview specification `x64 Unwind Information V3`.

V3 нельзя считать небольшим добавлением одного opcode. Она сохраняет
`RUNTIME_FUNCTION` и общие `.pdata`/`.xdata` conventions, но существенно
меняет внутреннюю организацию unwind record:

- вместо V1/V2 slots появляется variable-length WOD pool;
- отдельно хранятся IP offsets;
- epilogs получают явные descriptors;
- integer register encoding расширяется до 5 bits для APX registers;
- появляется `UNW_FLAG_LARGE`;
- payload имеет собственный размер в 16-bit words.

Попытка читать V3 decoder-ом V1/V2 создаст неверные boundaries, operations и
tail offset. Поэтому controlled rejection текущей версии проекта безопаснее
ложного успешного разбора.

## Статус спецификации

Microsoft прямо обозначает V3 как preview specification. Это означает:

- структура уже документирована;
- compiler/assembler support может появляться экспериментально;
- возможны несовместимые изменения;
- production parser должен versionировать реализацию и тестовые fixtures;
- нельзя считать текущий текст неизменяемым навсегда.

На дату подготовки главы официальный источник указывает обновление
21 мая 2026 года.

## Назначение V3

V3 добавляет поддержку Intel APX, включая расширенный набор general-purpose
registers R16-R31. Она также предоставляет compiler больше свободы в prolog и
epilog и позволяет точнее описывать операции обоих направлений.

Ключевое различие:

```text
V1/V2 в основном кодируют действия prolog,
а unwind procedure восстанавливает контекст в обратном порядке.

V3 хранит общий pool operation descriptors,
на который ссылаются prolog и явные epilog descriptors.
```

## Что осталось неизменным

`.pdata` по-прежнему является отсортированным массивом 12-byte
`RUNTIME_FUNCTION`:

```text
offset 0: BeginAddress
offset 4: EndAddress
offset 8: UnwindInfoAddress
```

Все три поля остаются 32-bit RVA.

Следовательно, существующие findings function table остаются концептуально
применимыми:

- `invalid_ranges`;
- `rf_oob`;
- `unwind_rva_oob`;
- `rf_unsorted`;
- `rf_overlaps`;
- `duplicate_begin`.

Но decoder объекта по `UnwindInfoAddress` должен выбирать implementation по
version.

## Header V3

Header занимает четыре bytes.

| Byte | Bits | Поле |
|---|---|---|
| 0 | 2:0 | `Version = 3` |
| 0 | 7:3 | `Flags` |
| 1 | 7:0 | `SizeOfProlog` low byte |
| 2 | 7:0 | `PayloadWords` |
| 3 | 4:0 | `NumberOfOps` |
| 3 | 7:5 | `NumberOfEpilogs` |

Сходство размера header с V1/V2 не означает совместимость полей.

В V1/V2 byte 2 — `CountOfCodes`, а byte 3 содержит frame register и frame
offset. В V3:

```text
byte 2 = PayloadWords
byte 3 = NumberOfOps + NumberOfEpilogs
```

Старый decoder истолковал бы эти значения как slots и frame declaration.

## `PayloadWords`

`PayloadWords` задаёт число 16-bit words после header:

```text
payload_size = PayloadWords * 2
```

Payload содержит:

1. optional large-prolog extension;
2. prolog IP offsets;
3. epilog descriptors;
4. epilog IP offsets;
5. WOD pool;
6. возможный padding до полного word.

Handler RVA или chained `RUNTIME_FUNCTION` в `PayloadWords` не входят.

## Tail offset

Положение handler/chain вычисляется:

```text
tail =
align_up(sizeof(UNWIND_INFO_V3) + PayloadWords * 2, 4)
```

После tail:

- при `UNW_FLAG_EHANDLER` или `UNW_FLAG_UHANDLER` находится 4-byte
  handler RVA и language-specific data;
- при `UNW_FLAG_CHAININFO` находится 12-byte `RUNTIME_FUNCTION`.

Общий принцип tail сохранился, но его исходная длина определяется payload, а
не количеством V1/V2 slots.

## Flags V3

V3 сохраняет:

```text
UNW_FLAG_EHANDLER  = 0x01
UNW_FLAG_UHANDLER  = 0x02
UNW_FLAG_CHAININFO = 0x04
```

Добавляется:

```text
UNW_FLAG_LARGE = 0x08
```

Bit 4 зарезервирован и должен быть zero.

Decoder должен проверять:

- несовместимые combinations;
- reserved bit;
- наличие required extension;
- достаточную длину payload;
- tail bounds.

## Large prolog

Без `UNW_FLAG_LARGE` размер prolog ограничен 8-bit полем.

При `UNW_FLAG_LARGE` первый byte payload является
`UNWIND_INFO_LARGE_V3.SizeOfPrologHighByte`.

Полный размер:

```text
SizeOfProlog16 =
(SizeOfPrologHighByte << 8) | SizeOfProlog
```

Кроме того, prolog IP offsets становятся 16-bit вместо 8-bit.

Это означает, что parser должен вычислять element width из flags до чтения
массива offsets.

## Prolog IP offsets

Количество элементов равно `NumberOfOps`.

Обычная форма:

```text
NumberOfOps bytes
```

Large form:

```text
NumberOfOps * 2 bytes
```

Первый offset относится к операции, ближайшей к function body, то есть к
последней prolog instruction с unwind effect. Последний offset относится к
операции, ближайшей к function entry.

Таким образом сохраняется принцип reverse execution order.

## Epilog descriptors

`NumberOfEpilogs` кодируется тремя bits и имеет диапазон 0-7 для одного
fragment. Если epilogs больше, specification предлагает subfragments.

Каждый `EPILOG_INFO_V3` содержит:

```text
Flags          3 bits
NumberOfOps    5 bits
EpilogOffset   signed 16 bits
```

При `NumberOfOps > 0` следует extended descriptor:

- `FirstOp`;
- `IpOffsetOfLastInstruction`;
- массив IP offsets.

При `NumberOfOps == 0` descriptor наследует operation description от
предыдущего epilog. Parser должен запретить наследование без предыдущего
полного descriptor.

## Epilog offset

`EpilogOffset` является signed displacement.

Для первого descriptor:

- положительное значение считается от fragment start;
- отрицательное — от fragment tail.

Для последующих descriptors значение является delta от предыдущего epilog.

Все epilogs должны использовать одинаковое направление:

```text
либо ascending from start,
либо descending from tail
```

Нарушение sign/order policy должно стать отдельной V3 anomaly reason или
подтипом общего descriptor anomaly.

## Parent fragment transfer

Epilog flag `EPILOG_INFO_PARENT_FRAGMENT_TRANSFER` сообщает, что epilog
передаёт управление parent fragment, например через `JMP`, а не возвращается
непосредственно caller.

Для reverse engineer это важно: control transfer нельзя автоматически
интерпретировать как обычный `RET`.

## Large epilog

Flag `EPILOG_INFO_LARGE` выбирает extended descriptor с 16-bit
`IpOffsetOfLastInstruction` и 16-bit elements массива offsets.

Parser должен независимо учитывать:

- large prolog policy;
- large policy конкретного epilog.

Нельзя использовать один global element width для всего payload.

## WOD

**Winding Operation Descriptor, WOD** — variable-length packed descriptor
одной unwind operation.

WOD pool является последовательностью bytes без выравнивания между
descriptors. Размер одного WOD определяется opcode и составляет от одного до
пяти bytes.

Prolog WOD list начинается с offset zero WOD pool. Epilog использует
`FirstOp`, который является byte offset, а не порядковым номером operation.

## Почему variable-length decoding сложнее

В V1/V2 основная единица массива — двухбайтовый slot. Длина operation
выражается числом slots.

В V3:

```text
operation length = 1..5 bytes
opcode width = 3, 4, 6 или 8 bits
```

Decoder должен проверять opcode в определённом порядке. Если сначала
сравнить полный byte, можно неправильно распознать компактные opcodes,
которые используют только младшие bits.

## Порядок dispatch WOD

Безопасная логика:

1. проверить 3-bit compact opcodes;
2. проверить 4-bit opcodes;
3. проверить 6-bit `WOD_PUSH2`;
4. проверить full-byte opcodes;
5. иначе отметить invalid opcode.

Этот порядок является частью формата, а не только implementation detail.

## Основные WOD

| WOD | Размер | Смысл |
|---|---:|---|
| `WOD_SET_FPREG` | 2 | Установить frame register |
| `WOD_ALLOC_HUGE` | 5 | Большое unscaled выделение stack |
| `WOD_ALLOC_LARGE` | 3 | Выделение stack с scale 8 |
| `WOD_PUSH_CANONICAL_FRAME` | 2 | Canonical OS/hardware frame |
| `WOD_PUSH` | 1 | Push одного integer register |
| `WOD_SAVE_NONVOL_FAR` | 5 | Far save integer register |
| `WOD_SAVE_NONVOL` | 3 | Scaled save integer register |
| `WOD_PUSH_CONSECUTIVE_2` | 1 | Push двух последовательных registers |
| `WOD_ALLOC_SMALL` | 1 | Compact stack allocation |
| `WOD_SAVE_XMM128_FAR` | 5 | Far save XMM |
| `WOD_SAVE_XMM128` | 3 | Scaled save XMM |
| `WOD_PUSH2` | 2 | APX push двух arbitrary registers |

## Integer register encoding

V3 compact integer operations используют 5-bit register number:

```text
0..15  -> RAX..R15
16..31 -> R16..R31
```

Это одно из принципиальных APX-изменений. Текущий `UnwindSummary` имеет:

```c
uint16_t saved_nonvol_mask;
```

Такой mask способен представить только 16 register numbers. Для V3 он
недостаточен.

Поддержка V3 требует как минимум:

```c
uint32_t saved_nonvol_mask;
```

или отдельной extensible register-set structure.

Изменение структуры влияет на:

- `unwind.h`;
- `report.c`;
- JSON schema;
- CSV;
- HTML;
- tests;
- backward compatibility.

## `WOD_PUSH`

Первый byte:

```text
bits 2:0 = 100b
bits 7:3 = 5-bit register
```

Operation уменьшает `RSP` на 8 при исполнении prolog. При unwind register
восстанавливается из stack, а simulated `RSP` увеличивается на 8.

Parser должен проверять, допустим ли register для данной ABI role, а не
только помещается ли номер в пять bits.

## `WOD_PUSH2`

`WOD_PUSH2` занимает два bytes и кодирует два arbitrary 5-bit registers.

Stack effect:

```text
16 bytes
```

Для summary одного `pushed_nonvol_count` достаточно для количества, но masks
должны включать оба registers.

## `WOD_PUSH_CONSECUTIVE_2`

Кодирует register N и N+1.

Обязательная sanity check:

```text
N <= 30
```

Иначе второй register имел бы номер 32 вне 5-bit APX range.

## Allocation WOD

`WOD_ALLOC_SMALL`:

```text
allocation = (Size + 1) * 8
range 8..128
```

`WOD_ALLOC_LARGE`:

```text
allocation = uint16_size * 8
```

`WOD_ALLOC_HUGE`:

```text
allocation = raw uint32 byte count
```

При суммировании fixed stack bytes нужно проверять integer overflow. Даже
если individual field допустим, сумма нескольких operations может выйти за
`uint32_t`.

## Save WOD

`WOD_SAVE_NONVOL` использует 16-bit displacement со scale 8.

`WOD_SAVE_NONVOL_FAR` использует 32-bit unscaled displacement.

`WOD_SAVE_XMM128` использует scale 16.

`WOD_SAVE_XMM128_FAR` использует 32-bit unscaled displacement.

Sanity checks должны сопоставлять:

- displacement;
- stack allocation;
- alignment;
- register class;
- operation direction в prolog/epilog.

## `WOD_SET_FPREG`

Encoding включает 4-bit register и 4-bit offset.

Смысл:

```text
frame_register = RSP + offset * 16
```

В отличие от compact APX integer operations, field register здесь
документирован как 4-bit. Parser не должен автоматически расширять его до
R16-R31.

## `WOD_PUSH_CANONICAL_FRAME`

Operation описывает canonical frame, созданный hardware или OS mechanism.
Type различает варианты frame.

До появления стабильных SDK constants parser должен:

- сохранять raw type;
- распознавать документированные значения;
- неизвестное значение отмечать как unsupported/unknown;
- не вычислять stack effect по догадке.

## Fragment и chaining

V3 вводит термин **fragment** как непрерывную область machine code,
описываемую парой `RUNTIME_FUNCTION`/`UNWIND_INFO_V3`.

Одна source-level функция может иметь:

- main fragment;
- subfragments;
- chained descriptions.

Это усиливает важность различия:

```text
source function != обязательно один непрерывный runtime range
```

Findings overlap и duplicate begin должны учитывать только нормативно
допустимую fragment model, а не предполагать простое соответствие один к
одному.

## Почему текущий проект правильно отказывает V3

Текущий код:

```text
version != 1 && version != 2
-> UA_VERSION_UNKNOWN
-> parse failure
```

Это предотвращает:

- чтение `PayloadWords` как `CountOfCodes`;
- чтение `NumberOfOps/NumberOfEpilogs` как frame fields;
- неправильный tail offset;
- фиктивный handler RVA;
- выход за buffer при ложной slot length;
- ложные register masks.

С точки зрения memory safety и semantic honesty такой отказ корректен.

## Почему отказ всё равно является продуктовым ограничением

После появления корректных V3 binaries текущая версия:

- не сможет декодировать их metadata;
- создаст `unwind_parse_fail`;
- может увеличить score;
- может потребовать manual review для benign file;
- ухудшит specificity на corpus с V3.

Следовательно, V3 support является compatibility requirement, а не только
дополнительной функцией.

## Как report должен различать malformed и unsupported

Текущий aggregate finding `unwind_parse_fail` объединяет причины.

Для V3 полезно ввести явное разделение:

```text
unsupported_version
malformed_supported_version
```

На уровне per-record report:

```json
{
  "version": 3,
  "parse_status": "unsupported",
  "parse_error": "UNWIND_INFO v3 is not supported by this build"
}
```

Unsupported корректный record не должен автоматически получать тот же
severity, что truncated V1.

## План безопасной реализации V3

### Этап 1. Version dispatch

```c
switch (version) {
case 1:
case 2:
    parse_v1_v2(...);
    break;
case 3:
    parse_v3(...);
    break;
default:
    unsupported(...);
}
```

Общие tail/handler helpers можно переиспользовать только после получения
правильного version-specific payload end.

### Этап 2. Новая модель данных

Нужны:

- 32-bit integer register mask или extensible set;
- epilog summaries;
- count WOD;
- payload size;
- support status;
- version-specific anomaly flags.

Не следует перегружать поля `count_codes`, `frame_reg`, `frame_off`
несовместимой семантикой.

### Этап 3. Bounded cursor

V3 parser удобнее строить через cursor:

```text
payload_begin
payload_end
current
```

Перед каждым чтением:

```text
needed <= payload_end - current
```

WOD pool boundaries должны быть вычислены после полного прохода descriptors,
но до decoding `FirstOp`.

### Этап 4. Descriptor validation

Проверить:

- reserved flags;
- large extension;
- `NumberOfOps`;
- `NumberOfEpilogs`;
- inheritance;
- sign consistency offsets;
- range epilogs внутри fragment;
- `FirstOp` внутри WOD pool;
- WOD count и byte lengths;
- IP offset ordering;
- last instruction boundary.

### Этап 5. WOD decoding

Использовать documented dispatch order и отдельную функцию:

```c
bool v3_decode_wod(
    const uint8_t* pool,
    size_t pool_size,
    size_t offset,
    V3Wod* out,
    size_t* consumed);
```

Function не должна изменять cursor при failure.

### Этап 6. Summary

Вычислять:

- prolog stack effect;
- saved integer registers;
- saved XMM registers;
- frame register;
- epilog operation references;
- handler/chain.

При переполнении summary counter сохранять raw operation, но ставить anomaly.

### Этап 7. Reports и schema

Добавить version-aware fields без удаления V1/V2:

```text
encoding_family: "slots_v1_v2" | "wod_v3"
payload_words
prolog_operation_count
epilog_count
```

Schema version должна измениться при изменении публичного contract.

### Этап 8. Tests

Минимальный набор:

1. V3 empty payload.
2. One `WOD_ALLOC_SMALL`.
3. APX `WOD_PUSH`.
4. `WOD_PUSH2`.
5. Large prolog.
6. One full epilog.
7. Inherited epilog.
8. Large epilog.
9. Shared WOD region.
10. Handler tail.
11. Chained fragment.
12. Invalid reserved flag.
13. Truncated WOD.
14. `FirstOp` OOB.
15. Invalid inheritance.
16. Mixed epilog offset signs.
17. Register 31 consecutive-pair error.
18. Differential sample from `ml64 /unwindv3`.

### Этап 9. Corpus gate

До объявления поддержки нужны:

- compiler-generated V3 objects;
- linked PE images;
- comparison с Microsoft/LLVM tools, когда они поддерживают вывод;
- benign zero-false-positive corpus;
- mutation/fuzz seeds V3;
- backward regression V1/V2.

## Как V3 влияет на 27 findings

Без изменений остаются PE layout и function table findings.

Требуют version-aware logic:

- `unwind_parse_fail`;
- `unwind_anomalies`;
- placement findings, если parser должен получить handler;
- handler dominance;
- combo findings.

Reuse по `UnwindInfoRVA` можно считать до полного decode, но интерпретация
должна учитывать fragment sharing.

## Технически корректный ответ о V3

> Текущая версия безопасно поддерживает `UNWIND_INFO` V1/V2 и намеренно
> отказывает неизвестную V3, чтобы не интерпретировать её по старому layout.
> Microsoft опубликовала V3 как preview specification для Intel APX в мае
> 2026 года. V3 сохраняет `.pdata` и 12-byte `RUNTIME_FUNCTION`, но вводит
> `PayloadWords`, явные epilog descriptors и variable-length WOD pool.
> Поэтому поддержка требует отдельного decoder, расширенной модели registers,
> новых tests и обновления report schema. До этого корректные V3 files
> являются известной границей совместимости и могут создавать parse-failure
> signals.

## Нормативный источник

Microsoft Learn, `Exception Handling Unwind Information V3`:

`https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3?view=msvc-170`

Microsoft Learn, conventional x64 exception handling V1:

`https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170`

## Контрольные вопросы

1. Почему одинаковый размер header не делает V3 совместимой с V1/V2?
2. Что содержит `PayloadWords` и чего оно не содержит?
3. Почему WOD decoder должен проверять opcodes в определённом порядке?
4. Для чего нужны explicit epilog descriptors?
5. Почему текущего 16-bit register mask недостаточно?
6. Чем large prolog отличается от large epilog?
7. Почему unsupported V3 нельзя считать malformed автоматически?
8. Какие существующие findings остаются применимыми без изменений?
9. Какие поля JSON должны стать version-aware?
10. Какой test corpus нужен перед объявлением поддержки V3?
