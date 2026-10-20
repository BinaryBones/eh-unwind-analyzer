# Том II. Глава 10. Полный разбор `benign_richer.exe`: от bytes до assessment

## Цель сквозного разбора

Предыдущие главы объясняли modules отдельно. Здесь один реальный test binary проходит весь pipeline. Ни одно значение не предполагается: все числа взяты из фактического файла и JSON, созданного текущим release build 8 июня 2026 года.

Input:

```text
tests/samples/bin/benign_richer.exe
```

Размер:

```text
5641 bytes
```

SHA-256:

```text
8b79fe76e06a44637caa1238460b9a83c50c49d80f2f355a614cef021bacc1ec
```

Command:

```sh
build/release/eh_unwind_analyzer \
  tests/samples/bin/benign_richer.exe \
  --heuristics \
  --json /tmp/teacher_benign.json \
  --html /tmp/teacher_benign.html
```

Build platform `macos-arm64`, compiler Clang 21.0.0, mode release. Это допустимо, потому что выполняется static parsing Windows PE, а не Windows dynamic mode.

## Первые bytes

Hex dump:

```text
00000000: 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00
00000010: b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000030: 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00
```

Bytes `4d 5a` дают little-endian word `0x5A4D`, signature `MZ`.

По offset `0x3C`:

```text
80 00 00 00
```

Little-endian conversion:

```text
e_lfanew = 0x00000080
```

Следовательно, PE signature ожидается по file offset `0x80`. Parser проверяет, что этот offset и следующие headers лежат внутри 5641-byte buffer.

## PE identity

Из COFF и optional header report получает:

```text
Machine      = 0x8664
ImageBase    = 0x140000000
SizeOfImage  = 0x7000
SizeOfHeaders = 0x400
Sections     = 6
```

`0x8664` соответствует AMD64. Optional header имеет PE32+ magic, иначе parser завершил бы analysis unsupported-format error.

`SizeOfImage = 0x7000` задаёт RVA range:

```text
[0x0000, 0x7000)
```

## Alignment

```text
SectionAlignment = 0x1000
FileAlignment    = 0x0200
```

Section RVAs:

```text
0x1000
0x2000
0x3000
0x4000
0x5000
0x6000
```

Все кратны `0x1000`.

Raw offsets ненулевых raw sections:

```text
0x400
0x600
0x800
0xA00
0xC00
```

Все кратны `0x200`.

`section_misaligned = 0`.

## Sections

### `.text`

```text
RVA          0x1000
VirtualSize  0x40
RawOffset    0x400
RawSize      0x200
Flags        0x60000020
Permissions  R-X
```

Code functions находятся в `[0x1000, 0x1040)`. RawSize больше VirtualSize из-за file alignment padding.

### `.rdata`

```text
RVA          0x2000
VirtualSize  0x50
RawOffset    0x600
RawSize      0x200
Permissions  R--
```

### `.pdata`

```text
RVA          0x3000
VirtualSize  0x24
RawOffset    0x800
RawSize      0x200
Permissions  R--
```

Значимые 36 bytes содержат три `RUNTIME_FUNCTION`.

### `.xdata`

```text
RVA          0x4000
VirtualSize  0x14
RawOffset    0xA00
RawSize      0x200
Permissions  R--
```

Значимые 20 bytes содержат три unwind records.

### `.bss`

```text
RVA          0x5000
VirtualSize  0x10
RawOffset    0
RawSize      0
Permissions  RW-
```

`.bss` virtual-only. Отсутствие raw bytes корректно.

### `.idata`

```text
RVA          0x6000
VirtualSize  0x18
RawOffset    0xC00
RawSize      0x200
Permissions  R--
```

## Structural checks

Для каждой raw section:

```text
RawOffset + RawSize <= 5641
```

Для каждой virtual section:

```text
VirtualAddress + max(VirtualSize, RawSize) <= 0x7000
```

Pairwise raw и virtual intervals не пересекаются в запрещённой форме. Result:

```text
section_raw_oob = 0
section_virtual_oob = 0
section_raw_overlaps = 0
section_virtual_overlaps = 0
section_misaligned = 0
```

## Exception directory

```text
RVA  = 0x3000
Size = 0x24
```

RVA находится в `.pdata`.

Conversion:

```text
delta = 0x3000 - 0x3000 = 0
file offset = 0x800 + 0 = 0x800
```

Size `0x24 = 36`. Entry size 12:

```text
36 / 12 = 3
```

Incomplete tail отсутствует.

## Raw `.pdata` bytes

```text
00000800:
00 10 00 00  10 10 00 00  00 40 00 00
10 10 00 00  29 10 00 00  04 40 00 00
29 10 00 00  40 10 00 00  0c 40 00 00
```

Разбивка по 12 bytes.

### Entry 0

```text
00 10 00 00 -> BeginRVA  0x1000
10 10 00 00 -> EndRVA    0x1010
00 40 00 00 -> UnwindRVA 0x4000
```

Function size:

```text
0x1010 - 0x1000 = 0x10 = 16
```

### Entry 1

```text
10 10 00 00 -> 0x1010
29 10 00 00 -> 0x1029
04 40 00 00 -> 0x4004
```

Size:

```text
0x1029 - 0x1010 = 0x19 = 25
```

### Entry 2

```text
29 10 00 00 -> 0x1029
40 10 00 00 -> 0x1040
0c 40 00 00 -> 0x400C
```

Size:

```text
0x1040 - 0x1029 = 0x17 = 23
```

## Table invariants

Ranges:

```text
[0x1000,0x1010)
[0x1010,0x1029)
[0x1029,0x1040)
```

Каждый end больше begin. Все bounds внутри `SizeOfImage`. Entries sorted. Соседние ranges соприкасаются только exclusive/end boundary, overlap отсутствует. Begin values unique.

Unwind RVA:

```text
0x4000
0x4004
0x400C
```

Все nonzero и внутри image.

## Conversion unwind RVA

`.xdata`:

```text
VirtualAddress = 0x4000
RawOffset      = 0xA00
```

Conversions:

```text
0x4000 -> 0xA00 + 0x0 = 0xA00
0x4004 -> 0xA00 + 0x4 = 0xA04
0x400C -> 0xA00 + 0xC = 0xA0C
```

## Raw `.xdata` bytes

```text
00000a00:
01 00 00 00
01 04 01 00 04 42 00 00
01 04 01 00 04 42 00 00
```

### Record 0 at `0xA00`

Header:

```text
byte0 = 0x01
Version = 0x01 & 0x07 = 1
Flags   = 0x01 >> 3 = 0

SizeOfProlog = 0
CountOfCodes = 0
Frame byte   = 0
```

No code array, no handler, no chain.

Summary:

```text
v1
prolog 0
stack 0
frame none
anomalies 0
```

### Record 1 at `0xA04`

Header:

```text
01 04 01 00
```

Interpretation:

```text
Version = 1
Flags = 0
SizeOfProlog = 4
CountOfCodes = 1
FrameRegister = 0
FrameOffset = 0
```

Code slot:

```text
04 42
```

`CodeOffset = 0x04`.

Second byte nibbles:

```text
UnwindOp = low nibble 0x2 = UWOP_ALLOC_SMALL
OpInfo   = high nibble 0x4
```

Allocation:

```text
4 * 8 + 8 = 40 bytes
```

CountOfCodes odd, поэтому aligned tail находится после padding slot `00 00`. Flags zero, tail semantics нет.

### Record 2 at `0xA0C`

Bytes идентичны record 1:

```text
01 04 01 00 04 42 00 00
```

Summary также stack 40 bytes.

## Parallel arrays

Main allocates:

```text
rf[3]
us[3]
us_ok[3]
```

After decoding:

```text
us_ok = [true, true, true]
```

`us[0]` относится к `rf[0]`, и так далее. Sorting heuristic копии не нарушает эту relation.

## Heuristic aggregation

Raw counters:

```text
invalid_ranges = 0
oob = 0
unwind_oob = 0
unsorted = 0
overlaps = 0
duplicate_begins = 0
parse_fail = 0
anomalies = 0
placement = 0
handler placement = 0
```

Unwind frequency map содержит три distinct keys, frequency каждого 1:

```text
max_count = 1
unique = 3
total = 3
```

Ratios:

```text
unwind_reuse_ratio = 1/3 = 0.333333
unwind_unique_ratio = 3/3 = 1.0
```

Хотя max ratio больше 0.30, strong reuse finding требует `n > 200`. Здесь `n = 3`, поэтому finding не создаётся.

Handler count zero.

## Static assessment

Ни одно scoring rule не сработало:

```text
score = 0
suspicion = 0.0
confidence = 0.2
evidence_level = none
verdict = no_strong_static_anomalies
requires_manual_review = false
```

`details` содержит:

```text
- [info] No strong anomalies detected by heuristics.
```

## Final assessment

Dynamic mode не запрошен:

```text
runtime_evidence_level = none
dynamic_signal_count = 0
correlation = false
```

Final:

```text
final_verdict = no_strong_correlated_evidence
final_confidence = 0.2
case_strength = no_case
```

## Что именно доказал этот run

Доказано для SHA-256 указанного input и текущей implementation:

- file соответствует поддерживаемой минимальной PE32+ AMD64 model;
- шесть section headers прочитаны;
- поддерживаемые structural checks не нашли нарушений;
- exception directory содержит три полные entries;
- ranges sorted, non-overlapping и bounded;
- три unwind records decoded;
- два records описывают fixed stack allocation 40 bytes;
- parser anomalies отсутствуют;
- реализованные static heuristics не создали findings.

Не доказано:

- что binary безопасен;
- что machine code полностью соответствует metadata;
- что все PE directories корректны;
- что file будет вести себя benign при запуске;
- что в нём нет иных методов obfuscation;
- что dynamic exception behavior отсутствует.

## Как выполнить ручную correspondence check

Для functions:

```text
preferred VA 0x140001010
preferred VA 0x140001029
```

в Ghidra нужно проверить первые четыре bytes prolog. Metadata ожидает stack allocation 40 bytes. Типичная instruction:

```asm
sub rsp, 28h
```

Если фактическая instruction подтверждает это, достигается третий уровень evidence: correspondence metadata и code.

## Почему этот sample важен

Он показывает, что clean baseline не означает отсутствие metadata. Напротив, report подробно восстанавливает function ranges и stack effects, но не начисляет suspicion.

Это distinction между:

```text
наличием сложной системной структуры
и
нарушением её invariants
```

Проект ценен не только findings. Он формирует normalized map EH/unwind metadata даже для normal binary.

