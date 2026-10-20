# Том II. Глава 11. Расследование четырёх подозрительных regression samples

## Назначение samples

Regression samples созданы для контролируемой проверки rules. Они не являются коллекцией реального malware и не используются для оценки detection accuracy.

Каждый sample изменяет известное свойство `benign_richer.exe`, поэтому можно связать:

```text
изменённый факт
-> parser observation
-> finding
-> score contribution
-> manual verification
```

## `suspicious_unwind_oob.exe`

### Фактический report

```text
score = 50
confidence = 0.69
verdict = moderate_suspicion
evidence_level = strong
case_strength = strong_unconfirmed_case
```

Findings:

```text
unwind_rva_oob
severity high
affected 1
representative RVA 0x9000

unwind_parse_fail
severity high
affected 1
representative RVA 0x9000
```

### Почему `0x9000` invalid

Image size sample сохраняет `0x7000`. Допустимые RVA:

```text
[0x0000, 0x7000)
```

`0x9000 >= 0x7000`, поэтому pointer выходит за image.

### Score derivation

Один invalid pointer из трёх records:

```text
1 / 3 = 33.33%
```

Это больше threshold 1%.

Weights:

```text
unwind_rva_oob high = 25
unwind_parse_fail high = 25
total = 50
```

### Confidence derivation

Base:

```text
0.15
```

Families:

```text
table_integrity
unwind_integrity
2 * 0.11 = 0.22
```

Strong findings:

```text
2 * 0.08 = 0.16
```

Hard table bonus:

```text
+0.08
```

Unwind hard bonus:

```text
+0.08
```

Total:

```text
0.15 + 0.22 + 0.16 + 0.08 + 0.08 = 0.69
```

Weakening rules отсутствуют, потому что findings strong.

### Что проверять вручную

1. Открыть `.pdata` по raw offset.
2. Найти entry с `UnwindData = 0x9000`.
3. Проверить `SizeOfImage`.
4. Убедиться, что RVA не принадлежит section.
5. Определить, является ли это corruption, deliberate tamper или ошибка generator.
6. Исследовать function prolog без опоры на broken metadata.

### Ограниченный вывод

Один runtime function ссылается на unwind RVA вне declared image, поэтому Windows x64 unwind contract для этой записи нарушен. Намерение изменения автоматически не установлено.

## `suspicious_unwind_writable.exe`

### Фактический report

```text
score = 18
confidence = 0.34
verdict = low_suspicion
evidence_level = medium
case_strength = medium_case
```

Finding:

```text
unwind_writable_section
severity high
affected 3
representative RVA 0x4000
```

### Structural fact

Все три `UnwindRVA` остаются valid и decode succeeds. Изменено section characteristic `.xdata`: section объявлена writable.

### Score

Affected count 3, total 3. Condition:

```text
3 > 3/20
```

Integer `3/20 = 0`, поэтому high branch:

```text
weight = 18
```

### Confidence

Base `0.15`.

One family:

```text
+0.11
```

One strong finding:

```text
+0.08
```

Total `0.34`.

Weakening rules не применяются, потому что `strong_count = 1`.

### Почему score low, evidence medium

Verdict threshold:

```text
15 <= 18 < 40 -> low_suspicion
```

Evidence level:

```text
strong_count >= 1 -> medium
```

Fields не противоречат друг другу: score band low, но finding severity high enough for medium evidence level.

### Возможные benign explanations

- runtime or JIT modifies unwind records;
- custom loader changes protections;
- nonstandard toolchain;
- sample deliberately built for test.

### Manual verification

1. Проверить original `Characteristics`.
2. Запустить на Windows и запросить actual page protection.
3. Наблюдать writes к `.xdata`.
4. Проверить signatures compiler/runtime.
5. Сравнить metadata до и после execution.

### Ограниченный вывод

Все records structurally valid, но metadata размещена в writable section. Это расширяет возможность runtime modification и требует проверки, однако не доказывает tampering.

## `suspicious_section_raw_oob.exe`

### Фактический report

```text
score = 60
confidence = 0.46
verdict = moderate_suspicion
evidence_level = strong
case_strength = strong_unconfirmed_case
```

Findings:

```text
pe_section_raw_oob
high
affected 1
RVA 0x5000

pe_section_raw_overlap
medium
affected 5
RVA 0x5000

pe_section_virtual_overlap
high
affected 1
RVA 0x6000
```

### Score

```text
raw OOB          25
raw overlap      15
virtual overlap  20
total            60
```

### Confidence

All findings belong to one family `table_integrity`:

```text
base                0.15
one family         +0.11
two strong         +0.16
one medium         +0.04
total               0.46
```

Hard table bonus in implementation applies only to runtime-function hard issues, not PE section counters. Поэтому additional `+0.08` нет.

### Почему пять raw overlaps

Изменённая section raw range может стать настолько большой, что пересекает несколько других sections. Counter считает каждую pairwise collision.

Representative location показывает первый violating section, а affected count отражает число overlaps.

### Manual verification

1. Выписать raw interval каждой section.
2. Использовать формулу пересечения полуинтервалов.
3. Проверить file size.
4. Сравнить behavior Windows loader и parser.
5. Определить, какие bytes фактически shared между section descriptions.

### Ограниченный вывод

Section table внутренне противоречива: по крайней мере один raw range выходит за file и ranges пересекаются. Любая дальнейшая interpretation bytes через section mapping должна считаться потенциально неоднозначной.

## `suspicious_eh_unwind_tamper.exe`

### Фактический report

```text
score = 53
confidence = 0.54
verdict = moderate_suspicion
evidence_level = strong
case_strength = strong_unconfirmed_case
```

Findings:

```text
unwind_writable_section
high
affected 1
RVA 0x2010

handler_nonexec_section
high
affected 1
RVA 0x2000

handler_writable_section
medium
affected 1
RVA 0x2000

writable_metadata_handler_combo
high
affected 0
no representative RVA
```

### Interpretation

Одна unwind record перенаправлена в writable section near `.rdata`-like area. Handler RVA указывает на `0x2000`, который расположен в non-executable, writable section.

### Score

```text
unwind writable high       18
handler non-executable     15
handler writable           10
combined writable pattern  10
total                      53
```

### Confidence

Families:

```text
metadata_placement
```

All findings use same family in this case.

Severity:

```text
3 strong
1 medium
```

Calculation:

```text
base             0.15
one family      +0.11
three strong    +0.24
one medium      +0.04
total            0.54
```

No single-family penalty because strong findings exist.

### Why combination affected count is zero

Combination finding создаётся без `annotate_finding`. Он описывает relation между aggregate counters, а не отдельный object. Поэтому:

```text
has_location = false
affected_count = 0
```

Это data-model nuance, не отсутствие combination.

### Manual investigation

1. Найти exact `RUNTIME_FUNCTION`, указывающую `0x2010`.
2. Decode record вручную.
3. Проверить handler flags.
4. Прочитать handler RVA `0x2000`.
5. Проверить section permissions.
6. Дизассемблировать bytes по `0x2000`.
7. Если bytes не code, определить, загрузил бы Windows record и когда возник failure.
8. На Windows поставить breakpoint на actual handler VA.
9. Наблюдать, достигается ли он.
10. Проверить runtime page protection и modifications.

### Ограниченный вывод

Metadata и handler placement одновременно противоречат обычному read-only-data/executable-code layout. Сочетание является сильным static anomaly, но sample intent и runtime reachability требуют отдельного подтверждения.

## Почему все cases `unconfirmed`

Dynamic mode не запускался. Поэтому:

```text
runtime evidence = none
correlation = false
```

Strong static evidence даёт:

```text
strong_unconfirmed_case
```

Это корректное название. Статика подтверждает structural anomalies, но не runtime activation.

## Как превратить case в correlated

Для OOB record dynamic correlation может быть не достижима, если Windows loader или exception path не использует function.

Для writable handler case:

1. Запустить target в isolated Windows VM.
2. Trigger representative exception path.
3. Получить handler hit или exception flow.
4. Нормализовать address к module+RVA.
5. Связать с static representative RVA.

Если static suspicious handler context совпадает с handler hit, project summary устанавливает correlation.

## Regression test и реальное расследование

Regression test отвечает:

```text
сработало ли правило на специально созданном нарушении
```

Real investigation отвечает:

```text
почему нарушение существует в неизвестном binary и что оно делает
```

Первое автоматизировано. Второе требует reverse engineer. Проект уменьшает объём ручной работы, но не отменяет её.

