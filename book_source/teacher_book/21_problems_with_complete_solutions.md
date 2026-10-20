# Том II. Глава 12. Задачи с полными решениями

## Как работать с задачами

Решение следует сначала получить самостоятельно, затем сравнить не только final number, но и последовательность проверок. В reverse engineering правильный ответ без проверяемого пути недостаточен.

## Задача 1. Little-endian field

По file offset `0x3C` находятся bytes:

```text
80 00 00 00
```

Определить 32-bit unsigned value.

### Решение

Little-endian означает, что byte с наименьшим весом хранится первым:

```text
value =
0x80 * 256^0
+ 0x00 * 256^1
+ 0x00 * 256^2
+ 0x00 * 256^3
= 0x00000080
```

Это `e_lfanew`; PE header начинается по file offset 128 decimal.

Ошибка была бы прочитать bytes как big-endian `0x80000000`, что почти наверняка вывело бы parser за file.

## Задача 2. RVA в file offset

Section:

```text
VirtualAddress   = 0x4000
VirtualSize      = 0x180
PointerToRawData = 0xA00
SizeOfRawData    = 0x200
```

Найти file offset для RVA `0x40B4`.

### Решение

Проверка нижней границы:

```text
0x40B4 >= 0x4000
```

Delta:

```text
0x40B4 - 0x4000 = 0xB4
```

Virtual span:

```text
max(0x180,0x200) = 0x200
0xB4 < 0x200
```

Raw availability:

```text
0xB4 < 0x200
```

Offset:

```text
0xA00 + 0xB4 = 0xAB4
```

Дополнительно требуется проверить:

```text
0xAB4 < file_size
```

Без file size окончательная безопасность чтения не доказана.

## Задача 3. Virtual-only address

Section:

```text
VirtualAddress = 0x5000
VirtualSize = 0x300
RawSize = 0x100
RawOffset = 0xC00
```

RVA `0x5180`. Принадлежит ли section? Есть ли byte в file?

### Решение

Delta:

```text
0x5180 - 0x5000 = 0x180
```

Virtual span:

```text
max(0x300,0x100) = 0x300
0x180 < 0x300
```

Адрес принадлежит virtual section range.

Но:

```text
0x180 >= RawSize 0x100
```

Соответствующего raw byte нет. Загрузчик может сформировать zero-filled memory, но static parser не должен читать file offset `0xD80` как часть этой section.

## Задача 4. Число runtime functions

Exception directory size `0x54`. Сколько полных AMD64 `RUNTIME_FUNCTION`?

### Решение

Entry size 12 decimal, то есть `0xC`.

```text
0x54 = 84 decimal
84 / 12 = 7
```

Remainder:

```text
84 % 12 = 0
```

Семь полных entries, incomplete tail отсутствует.

Если size был бы `0x55`, осталось бы один лишний byte, и строгая policy должна сообщить malformed directory.

## Задача 5. Range invariants

Даны entries:

```text
A [0x1000,0x1100)
B [0x1100,0x1200)
C [0x1180,0x1300)
D [0x1300,0x1300)
```

Какие нарушения?

### Решение

A и B соприкасаются:

```text
B.begin == A.end
```

Overlap отсутствует.

C:

```text
C.begin 0x1180 < B.end 0x1200
```

Overlap B/C.

D:

```text
End == Begin
```

Invalid empty range.

Если sorted overlap algorithm использует `max_end`, после C он станет `0x1300`. D begin равен `0x1300`, поэтому overlap с предыдущими отсутствует, хотя range сам invalid.

## Задача 6. Decode header

Header bytes:

```text
09 06 02 35
```

Разобрать fields.

### Решение

Byte0 `0x09 = 00001001b`.

Version — low 3 bits:

```text
001b = 1
```

Flags — high 5 bits:

```text
00001b = 1
```

То есть `UNW_FLAG_EHANDLER`.

`SizeOfProlog = 0x06 = 6`.

`CountOfCodes = 0x02 = 2 slots`.

Frame byte `0x35`:

```text
FrameRegister = low nibble = 5
FrameOffset = high nibble = 3
FrameOffsetBytes = 3 * 16 = 48
```

Register encoding 5 соответствует RBP.

После двух slots code array уже DWORD-aligned. Поскольку EHandler flag установлен, далее ожидается 32-bit HandlerRVA.

## Задача 7. `UWOP_ALLOC_SMALL`

Code slot:

```text
04 72
```

### Решение

`CodeOffset = 4`.

Second byte:

```text
low nibble 2 -> UWOP_ALLOC_SMALL
high nibble 7 -> OpInfo 7
```

Allocation:

```text
7 * 8 + 8 = 64 bytes
```

Требуется `SizeOfProlog >= 4`, иначе code-offset anomaly.

## Задача 8. `UWOP_ALLOC_LARGE`

Slots:

```text
08 01
20 00
```

### Решение

Operation byte `0x01`:

```text
UnwindOp = 1 -> UWOP_ALLOC_LARGE
OpInfo = 0
```

Следующий slot как little-endian `uint16`:

```text
20 00 -> 0x0020 = 32
```

Scale 8:

```text
32 * 8 = 256 bytes
```

Логическая operation потребила два slots: основной и operand.

## Задача 9. Code ordering

`SizeOfProlog = 8`, code offsets:

```text
8, 5, 6
```

### Решение

Каждый offset не превышает prolog size.

Но descending order нарушен:

```text
5 -> 6 увеличивается
```

Устанавливается `UA_CODEOFFSET_ORDER`.

Decoder может продолжить summary, если structure readable, но report должен отметить anomaly.

## Задача 10. Alignment tail

`CountOfCodes = 3`. Где начинается tail относительно начала `UNWIND_INFO`?

### Решение

Header 4 bytes.

Три meaningful slots:

```text
3 * 2 = 6 bytes
```

После header offset был бы:

```text
4 + 6 = 10
```

Tail должен быть DWORD-aligned. Slots округляются до четырёх:

```text
align slots = 4
4 + 4*2 = 12
```

Tail начинается по offset 12 (`0xC`) от начала record. Один padding slot занимает bytes 10–11.

## Задача 11. Score calculation

Report counters:

```text
rf_oob: 2 из 100
unwind_parse_fail: 1 из 100
unwind_exec_section: 3
handler_nonexec_section: 1
```

Рассчитать minimum score, учитывая combinations.

### Решение

`rf_oob` prevalence:

```text
2/100 = 2% > 1%
```

Weight high:

```text
+25
```

`unwind_parse_fail`:

```text
1/100 = 1%
```

Threshold strict `>1%`, поэтому low:

```text
+10
```

`unwind_exec_section`:

```text
+20
```

`handler_nonexec_section`:

```text
+15
```

Combination executable metadata + non-executable handler:

```text
+10
```

Placement + integrity, потому что executable placement и parse failure:

```text
+8
```

Total:

```text
25 + 10 + 20 + 15 + 10 + 8 = 88
```

Score clamps at 100, но здесь 88.

Verdict high suspicion, evidence strong.

## Задача 12. Confidence calculation

Для предыдущего case предположим six stored findings:

```text
4 high
2 medium
3 evidence families
hard table issue present
hard unwind issue present
```

### Решение

```text
base                  0.15
families 3*0.11      +0.33
strong 4*0.08        +0.32
medium 2*0.04        +0.08
table bonus          +0.08
unwind bonus         +0.08
raw total             1.04
```

Weakening rules не применяются из-за strong findings и multiple families.

Static confidence clamps:

```text
0.90
```

Если dynamic signals и correlation добавятся в report-level summary:

```text
0.90 + 0.10 + 0.10 = 1.10
```

Final confidence clamps at `0.98`.

Это демонстрирует engineered ceiling.

## Задача 13. Breakpoint state

Breakpoint по `0x7FF600001000` заменил original byte `0x55` на `0xCC`. Возник `EXCEPTION_BREAKPOINT`, context RIP равен `0x7FF600001001`. Какие изменения нужны?

### Решение

1. Записать `0x55` обратно по `0x...1000`.
2. Flush instruction cache.
3. Установить:

```text
RIP = 0x7FF600001000
```

4. Установить TF:

```text
EFlags |= 0x100
```

5. Сохранить pending re-arm для current thread ID.
6. `ContinueDebugEvent(..., DBG_CONTINUE)`.
7. На `EXCEPTION_SINGLE_STEP` снова записать `0xCC`.
8. Снять TF, если trace не продолжается.

Если не rewind RIP, original instruction будет пропущена. Если не re-arm, последующие hits потеряются.

## Задача 14. First-chance continuation

Target создал access violation, которое должно быть обработано его VEH. Что должен вернуть collector?

### Решение

Для ordinary exception collector должен:

```text
DBG_EXCEPTION_NOT_HANDLED
```

Это не означает, что exception останется необработанным окончательно. Status сообщает debugger layer, что он сам exception не обработал; Windows продолжит application dispatch, включая handlers.

`DBG_CONTINUE` поглотил бы exception на уровне debugger и мог не позволить VEH выполнить expected path.

## Задача 15. Dynamic function table event

На breakpoint `RtlAddFunctionTable`:

```text
RCX = 0x000001F000100000
RDX = 12
R8  = 0x000001F000000000
```

Что доказано?

### Решение

Доказано:

- execution достиг entry соответствующего API;
- на момент entry argument registers содержали указанные values;
- target пытался вызвать function с pointer, count 12 и base.

Не доказано:

- API вернул TRUE;
- pointer readable;
- table содержит 12 valid entries;
- entries sorted;
- unwind data valid;
- table использовалась exception dispatcher;
- code malicious.

Для усиления evidence нужны return observation, remote memory snapshot и последующий runtime use.

## Задача 16. Correlation

Static report:

```text
handler_writable_section = 1
representative RVA = 0x5200
```

Dynamic event:

```text
type = veh_handler_hit
module = target.exe
address = ActualBase + 0x7000
```

Можно ли утверждать exact correlation с handler `0x5200`?

### Решение

Нет. Aggregate project rule может считать suspicious handler context плюс handler hit correlated at class level, но exact addresses различаются:

```text
0x5200 != 0x7000
```

Нужно определить, был ли static finding frame handler, а dynamic event — VEH. Это разные mechanisms.

Корректный вывод:

```text
в run наблюдался handler activity при наличии suspicious static handler context,
но exact address-level identity не установлена
```

## Задача 17. Backend result

Analyzer exit code nonzero, но JSON существует и содержит:

```text
dynamic_validation.ran = true
dynamic_validation.ok = false
dynamic_validation.timed_out = true
heuristic_analysis.score = 50
```

Как сохранять job?

### Решение

Job не должен получать общий status `success`.

Рекомендуемая модель:

```text
job status = partial_failed или failed_with_report
static stage = completed
dynamic stage = timed_out
process exit code = nonzero
raw JSON = stored
findings = indexed
failure reason = dynamic timeout
```

Отбрасывать JSON нельзя: static evidence valid и dynamic partial events могут быть полезны.

Показывать пользователю complete success также нельзя.

## Задача 18. Сравнение двух runs

Run A handler address `0x7FF612345200`. Run B address `0x7FF712345200`. Module base A `0x7FF612340000`, base B `0x7FF712340000`.

### Решение

Offsets:

```text
A: 0x7FF612345200 - 0x7FF612340000 = 0x5200
B: 0x7FF712345200 - 0x7FF712340000 = 0x5200
```

Absolute VAs различаются из-за ASLR, module-relative offset совпадает. События относятся к одной позиции image, если module binary identity совпадает.

## Задача 19. Критика verdict

Report:

```text
score = 0
verdict = no_strong_static_anomalies
```

Можно ли написать заказчику «файл безопасен»?

### Решение

Нет.

Score zero означает только, что реализованные rules не нашли strong static EH/unwind anomalies. Analyzer:

- не выполняет full malware analysis;
- не проверяет все PE directories;
- не доказывает code semantics;
- может не видеть runtime-generated behavior;
- не покрывает unreachable paths.

Корректная формулировка:

```text
в поддерживаемой PE32+ AMD64 EH/unwind model структурных и placement anomalies,
покрываемых текущей heuristic policy, не обнаружено
```

## Задача 20. Проектирование нового finding

Нужно обнаруживать mismatch metadata stack allocation и machine-code prolog. Где реализовать?

### Решение

Одного изменения `heuristics.c` недостаточно. Нужен новый analysis stage:

1. Instruction decoder для x86-64.
2. Mapping function begin RVA к file bytes.
3. Decode instructions в пределах `SizeOfProlog`.
4. Вычислить фактические effects на `RSP` и nonvolatile saves.
5. Сравнить с `UnwindSummary`.
6. Создать observation model correspondence.
7. Передать counters/findings в heuristic policy.
8. Добавить JSON fields и schema version.
9. Добавить synthetic positive/negative tests.
10. Проверить compiler variants.

Instruction decoder должен быть structured library, а не ad hoc byte patterns. Иначе prefixes, alternate encodings и optimization variants создадут false results.

## Итог контроля

Если задачи решаются с пониманием, студент умеет:

- читать little-endian fields;
- переводить RVA;
- проверять section and range invariants;
- декодировать unwind header и operations;
- вручную воспроизводить score/confidence;
- объяснять breakpoint lifecycle;
- различать registration, hit и success;
- проектировать backend status;
- формулировать ограниченные выводы;
- видеть, где новый feature требует архитектурного stage, а не одной эвристики.

