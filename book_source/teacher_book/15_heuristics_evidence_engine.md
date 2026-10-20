# Том II. Глава 6. `heuristics.c`: от структурных фактов к оценке свидетельств

## Место модуля в системе

`pe.c` и `unwind.c` отвечают на вопросы формата: какие поля присутствуют, какие значения прочитаны, нарушены ли локальные invariants. Они не должны решать, насколько совокупность наблюдений подозрительна.

`heuristics.c` получает уже построенные модели:

```c
const PeImage* img
const RuntimeFunction* rf
const UnwindSummary* us
const bool* us_ok
size_t n
```

и формирует `HeuristicReport`.

Это переход от parsing к assessment. Входные данные модуля не являются raw bytes. Они представляют нормализованные факты предыдущих этапов.

Поток данных:

```text
PE bytes
-> PeImage + structural counters
-> RuntimeFunction[]
-> UnwindSummary[] + us_ok[]
-> HeuristicReport
```

Если parser неверно извлёк поле, heuristic engine получит неверный факт. Поэтому качество assessment зависит от correctness всех предыдущих contracts.

## Что означает слово heuristic

**Heuristic**, далее эвристика, — правило практического вывода, которое использует наблюдаемые признаки, но не гарантирует единственно правильную классификацию.

Проект не содержит обученной statistical model, malware classifier или probability calibration. Все weights и thresholds заданы константами в source code. Комментарий в начале `heuristics.c` прямо называет модель conservative engineering model, а не mathematically validated classifier.

Следствия:

- `score = 70` не означает 70% вероятности вредоносности;
- `confidence = 0.8` не является частотой правильных предсказаний на независимой выборке;
- threshold `1%` не выведен из стандарта PE;
- weight `25` не является нормативным уровнем Microsoft;
- одинаковый score может быть получен разными наборами evidence.

`score` — ограниченная инженерная сумма весов. `suspicion` — её линейная нормализация `score / 100`. `confidence` — отдельная rule-based оценка полноты и взаимного подтверждения evidence.

## Выходная модель

`HeuristicReport` содержит четыре класса данных.

Первый класс — summary assessment:

```c
int score;
double suspicion;
double confidence;
bool requires_manual_review;
uint32_t evidence_families_mask;
char verdict[48];
char evidence_level[16];
```

Второй класс — counters наблюдаемых нарушений и ratios.

Третий класс — structured findings:

```c
typedef struct HeuristicFinding {
    char code[40];
    char family[32];
    char severity[16];
    char message[192];
    bool has_location;
    uint32_t representative_rva;
    size_t affected_count;
} HeuristicFinding;
```

Четвёртый класс — weakening rules, названные `mitigations` в C model:

```c
typedef struct HeuristicMitigation {
    char code[40];
    char message[192];
} HeuristicMitigation;
```

В JSON они выводятся как `weakening_rules_applied`, что точнее отражает назначение: правило не устраняет факт, а снижает confidence вывода.

## Валидация arguments и initialization

`heuristics_analyze` требует ненулевые `img`, `out`, `err`. Если `n > 0`, обязаны существовать `rf`, `us` и `us_ok`.

Затем весь output обнуляется:

```c
memset(out, 0, sizeof(*out));
```

После этого инициализируется `out->details`. Если allocation fails, функция возвращает false. Это важно для ownership: после успешного init `HeuristicReport` должен быть освобождён через `heuristics_free`.

`out->total = n`, а PE counters копируются из `PeImage`. Таким образом report сохраняет snapshot входных structural facts.

## Evidence families

Проект группирует findings в пять семейств.

`table_integrity` включает PE section structure и `RUNTIME_FUNCTION` ranges.

`unwind_integrity` включает parse failures, opcode/operand/chain anomalies и комбинации placement с metadata corruption.

`metadata_placement` включает section context unwind records и handlers.

`unwind_reuse` включает concentration одного `UnwindInfoRVA`.

`handler_dominance` включает concentration одного handler target.

Семейство представлено одним bit в `evidence_families_mask`. `heuristics_evidence_family_count` считает установленные bits.

Family count влияет на confidence, потому что независимые классы evidence считаются более убедительными, чем несколько variants одного pattern. Это engineering assumption. Реальная независимость признаков не доказана статистически.

## Frequency map

Для подсчёта повторов используется собственная небольшая hash map с open addressing и linear probing.

`HEntry` хранит:

```c
uint32_t key;
uint32_t val;
bool used;
```

Для `unwind_counts` key равен `UnwindInfoRVA`, value — числу records с этим RVA.

Для `handler_counts` key равен `HandlerRVA`, value — числу unwind records с этим handler.

Initial capacity выбирается не меньше 64. При load factor около 70% map растёт:

```text
(len + 1) * 10 >= cap * 7
```

`hmap_grow` выделяет новый array и повторно вставляет entries. Это необходимо, потому что index зависит от capacity.

Если map insertion fails после init, loop игнорирует return value:

```c
(void)hmap_inc(...)
```

Практически failure возможен главным образом при grow allocation. В таком случае frequency results могут быть неполны, но функция не сигнализирует failure. Это остаточная техническая слабость: для production-grade evidence engine следовало бы propagate OOM и не формировать potentially incomplete reuse ratios. В учебной защите это нужно назвать честно.

## Первый проход по `RUNTIME_FUNCTION`

Для каждой записи извлекаются:

```text
b = BeginRVA
e = EndRVA
u = UnwindRVA
```

### Invalid range

Если:

```text
e <= b
```

увеличивается `rf_invalid_ranges`. Первый RVA сохраняется как representative location.

`End == Begin` описывает пустой range. `End < Begin` описывает обратный range. Оба нарушают ожидаемый полуинтервал.

### Function range out of image

Если:

```text
b >= SizeOfImage || e > SizeOfImage
```

увеличивается `rf_oob`.

Для `begin` используется `>=`, потому что RVA ровно `SizeOfImage` уже находится за последним byte. Для `end` используется `>`, потому что exclusive end может быть равен верхней границе.

### Unwind RVA out of image

Если:

```text
u >= SizeOfImage || u == 0
```

увеличивается `rf_unwind_oob`.

Zero рассматривается как missing. Даже если header bytes существуют по file offset zero, `UnwindData = 0` не является поддерживаемой valid link на `UNWIND_INFO`.

### Unsorted input table

Модуль сравнивает текущий `BeginRVA` с предыдущим:

```text
current_begin < previous_begin
```

Каждое такое место считается inversion. Это не полное число инверсий математического массива; это число локальных нарушений nondecreasing order между соседними entries. Поле `rf_unsorted` и сообщение «inversions» поэтому следует понимать в реализации проекта, а не как полный inversion count `O(n²)`.

### Reuse counts

Каждый `UnwindRVA`, включая malformed values, добавляется в `unwind_counts`. Это означает, что множество zero или одинаковых OOB values может увеличить reuse ratio. Одновременно они создадут integrity findings. Combination отражает реальную концентрацию указателей, но analyst должен учитывать, что dominant key может быть invalid.

Handler добавляется только если:

```text
us_ok[i] && us[i].has_handler
```

Parse-failed record не участвует в handler dominance, потому что handler field не считается надёжно извлечённым.

## Placement unwind metadata

Для успешно decoded record проект находит section по `UnwindRVA`.

Если section отсутствует, увеличивается `unwind_unusual_section`.

Если section существует, имя оценивается двумя policy.

Строгий allowlist:

```text
.xdata
.rdata
.pdata
.gnu_xdata
.mrdata
xdata
rdata
pdata
```

Дополнительная plausible check принимает имя, содержащее case-insensitive `xdata`, `pdata` или `rdata`.

Это снижает false positives для toolchain-specific names. Но section names не являются гарантией semantics. Специально созданная executable+writable section с именем `.xdata` всё равно будет обнаружена по permissions.

Независимо от имени проверяются flags:

```text
IMAGE_SCN_MEM_EXECUTE
IMAGE_SCN_MEM_WRITE
```

Исполняемая section увеличивает `unwind_exec_section`. Writable section увеличивает `unwind_writable_section`.

Metadata обычно является read-only data. Writable или executable placement создаёт повышенный review interest, но JIT/runtime и нестандартный linker layout остаются возможными benign explanations.

## Placement handler

Если record имеет handler, проект находит section по `HandlerRVA`.

Если section отсутствует или не имеет execute flag:

```text
handler_nonexec_section++
```

Если section writable:

```text
handler_writable_section++
```

Handler — адрес code, поэтому non-executable placement противоречит ожидаемому runtime use. Writable+executable memory возможна, но нарушает распространённую W^X discipline и требует объяснения.

Здесь есть важная модельная граница. Section characteristics в файле не всегда полностью совпадают с runtime page protections после loader или защитного runtime. Поэтому static finding должен коррелироваться с dynamic memory map при серьёзном выводе.

## Parse failure и anomaly

Если `us_ok[i] == false`, увеличивается `unwind_parse_fail`.

Если parse succeeded, но `us[i].anomalies != 0`, увеличивается `unwind_anomalies`.

Эти категории различаются.

Parse failure означает, что decoder не смог надёжно завершить поддерживаемую интерпретацию record.

Anomaly означает, что summary построен, но присутствуют нарушения: неизвестная version, bad opcode, code offset order, chain issue, alignment и другие.

Разделение позволяет report сохранять partial data для anomalous-but-decodable records.

## Overlap и duplicate begin

Input table может быть unsorted, поэтому непосредственное сравнение соседей недостаточно для overlap detection. Проект создаёт `RfIdx[]`, копирует begin/end, сортирует через `qsort`, затем проходит sorted array.

`duplicate_begin`:

```text
current.begin == previous.begin
```

`overlap`:

```text
current.begin < max_end всех предыдущих records
```

Использование `max_end`, а не только previous end, корректно обнаруживает nested overlap:

```text
A = [0x1000, 0x2000)
B = [0x1100, 0x1200)
C = [0x1300, 0x1400)
```

Хотя B закончилась до C, C всё ещё пересекает A. `max_end` остаётся `0x2000`.

Sort array содержит только begin/end и не меняет original arrays. Поэтому parallel relation `rf[i] <-> us[i] <-> us_ok[i]` сохраняется.

## Ratios

После counting:

```text
unwind_reuse_ratio = max_count_same_unwind / total_records
unwind_unique_ratio = unique_unwind_rvas / total_records
handler_reuse_ratio = max_count_same_handler / handler_count
```

При denominator zero `safe_ratio` возвращает 0.

`unwind_reuse_ratio` отвечает на вопрос о концентрации наиболее частого unwind RVA. Он не равен доле всех reused records. Например, два разных RVA могут встречаться по 20% каждый; max ratio будет 20%.

`unwind_unique_ratio` отражает diversity. Значение 1.0 означает unique RVA для каждого record. Низкое значение показывает reuse, но само по себе не создаёт finding.

`handler_reuse_ratio` считается среди records, которые имеют handler, а не среди всех runtime functions. Это важное различие denominator.

## Score saturation

`add_score` вычисляет:

```text
score = clamp(score + weight, 0, 100)
```

После достижения 100 дальнейшие findings сохраняются, но числовой score не растёт. Поэтому score 100 не означает одинаковую evidence mass для всех cases. Для анализа насыщенных cases нужно читать findings, affected counts и families.

## PE structural findings и веса

Точные implementation weights:

| Finding | Weight | Severity |
|---|---:|---|
| `pe_section_raw_oob` | 25 | high |
| `pe_section_virtual_oob` | 20 | high |
| `pe_section_raw_overlap` | 15 | medium |
| `pe_section_virtual_overlap` | 20 | high |
| `pe_section_misaligned` | 8 | medium |
| `pe_exception_directory_oob` | 25 | high |

Для каждого finding сохраняется первый representative section RVA и полный affected count.

Representative RVA не означает, что только один объект нарушен. Это адрес первого найденного примера для навигации. Полный count показывает масштаб.

## Empty exception table

Если `n == 0` и image имеет непустую executable section, добавляется:

```text
code: no_runtime_functions
family: table_integrity
severity: medium
weight: 10
```

Message прямо допускает leaf-only image.

Если executable sections нет, score не начисляется. В details появляется info note о resource-only или forwarding image.

Это context-sensitive rule: одинаковое отсутствие `.pdata` оценивается по-разному в зависимости от наличия executable content.

## Процентные integrity thresholds

Для invalid ranges, function OOB, unwind RVA OOB и parse failures threshold high равен строго больше 1%:

```c
THRESHOLD_HIGH_PERCENT = 0.01;
```

Сравнение использует `>`, не `>=`.

Веса:

| Signal | Low/medium prevalence | High prevalence |
|---|---:|---:|
| invalid range | 10 | 20 |
| function OOB | 10 | 25 |
| unwind RVA OOB | 10 | 25 |
| unwind parse fail | 10 | 25 |

При высоком варианте severity становится high; иначе medium.

На малом sample один record почти всегда превышает 1%. Например, 1 из 3 равен 33.3%. Поэтому позже confidence получает small-sample penalty, если strong findings отсутствуют. Однако если finding уже high по prevalence, penalty `small_sample_size` не применяется, поскольку condition требует `strong_count == 0`.

Это демонстрирует, что score и confidence решают разные задачи.

## Unwind anomaly threshold

Для decoded records с anomaly high threshold равен строго больше 5%:

```c
THRESHOLD_UNWIND_ANOM_HIGH = 0.05;
```

Weight:

```text
10 при <= 5%
20 при > 5%
```

Severity medium или high соответственно.

## Table order findings

Точные weights:

```text
rf_unsorted      15, medium
rf_overlaps      25, high
duplicate_begin  10, medium
```

Overlap получает более высокий weight, потому что нарушает однозначность coverage ranges. Unsorted table может быть восстановлена сортировкой для анализа, но runtime contract ожидает sorted entries.

## Strong unwind reuse

Strong reuse finding появляется только если:

```text
unwind_reuse_ratio > 0.30
n > 200
```

Weight 20, severity high.

Ограничение `n > 200` защищает от малых samples, где несколько одинаковых records дали бы высокий ratio. Strict `>` означает, что ровно 200 records недостаточно, а ровно 30% не проходит.

Representative RVA равен dominant `UnwindInfoRVA`; affected count равен max frequency.

Reuse может быть legitimate из-за shared epilog/prolog patterns, chained info или runtime layout. Поэтому даже strong reuse остаётся heuristic.

## Handler dominance с benign-context suppression

Candidate требует:

```text
handler_count > 50
handler_reuse_ratio > 0.80
```

Затем проект определяет `has_static_context`: имеются ли integrity issues, placement issues или moderate reuse candidate.

Также проверяется `dominant_runtime_like`:

- dominant handler находится в section;
- section executable;
- section name code-like: `.text`, `text`, содержит `text`, `code` или `init`;
- нет non-executable handler findings.

Если handler выглядит как обычный code runtime helper и других static signals нет, finding подавляется.

Именно это проверяется unit test, где 60 entries законно используют один handler в executable `.text`: score остаётся zero. При добавлении suspicious context dominance появляется.

Если finding создаётся:

```text
weight: 15
severity: medium
family: handler_dominance
```

Это важная защита от false positive для central language runtime handlers.

## Moderate unwind reuse требует corroboration

Moderate candidate:

```text
unwind_reuse_ratio > 0.10
n > 200
```

Finding не создаётся автоматически. Требуется хотя бы один другой static signal: handler dominance, integrity issue, placement issue или anomaly.

Если strong reuse уже создан, moderate finding не добавляется.

Weight 10, severity medium.

Правило реализует принцип corroboration: умеренный repetition без context не считается самостоятельным evidence.

## Placement weights

`unwind_in_exec_section`:

```text
weight 20
severity high
```

`unwind_unusual_section`:

```text
weight 8, severity medium
weight 15, severity high, если count > n/20
```

`n/20` использует integer division. Для `n < 20`, `n/20 == 0`, поэтому любое positive count проходит high branch. Это implementation nuance. Small-sample confidence penalties могут смягчить case только если strong finding отсутствует; здесь high severity создаёт strong count и penalty не применяется. Это потенциально резкое поведение на малых samples и кандидат для будущей calibration.

`unwind_writable_section`:

```text
weight 10, severity medium
weight 18, severity high, если count > n/20
```

`handler_nonexec_section`:

```text
weight 15
severity high
```

`handler_writable_section`:

```text
weight 10
severity medium
```

## Combination findings

Модуль начисляет дополнительные weights, когда два разных свойства встречаются вместе.

### Executable unwind metadata и non-executable handler

Condition:

```text
unwind_exec_section > 0
handler_nonexec_section > 0
```

Finding:

```text
placement_exec_nonexec_handler_combo
weight 10
severity high
family metadata_placement
```

### Placement и integrity

Condition:

```text
(unwind_exec_section || handler_nonexec_section)
&&
(unwind_parse_fail || unwind_anomalies || rf_unwind_oob)
```

Finding:

```text
placement_integrity_combo
weight 8
severity medium
family unwind_integrity
```

### Reuse и dominance

Condition:

```text
unwind_reuse_ratio > 0.10
handler_dominance finding exists
```

Finding:

```text
reuse_dominance_combo
weight 8
severity medium
```

### Writable metadata и writable handler

Condition:

```text
unwind_writable_section > 0
handler_writable_section > 0
```

Finding:

```text
writable_metadata_handler_combo
weight 10
severity high
```

Combination weights intentionally double-count related raw observations in aggregate score. Это не статистически независимое суммирование; это explicit policy, что сочетание труднее объяснить benignly.

## Finding storage limit

Maximum:

```text
HEURISTICS_MAX_FINDINGS = 32
```

Если findings больше, `add_finding` продолжает добавлять human-readable line в `details` и family bit, но structured array больше не растёт.

Consequences:

- score продолжает учитывать rule;
- `details` может содержать больше findings, чем `finding_count`;
- severity counts вычисляются только по stored structured findings;
- evidence level и confidence могут недоучесть findings за пределом 32.

Текущий набор rules меньше limit в обычном run, но model limitation существует. Production version могла бы использовать dynamic array или explicit truncation flag.

## Severity counts и evidence level

High и critical считаются strong. Medium считается medium. Остальные stored findings относятся к weak.

Evidence level:

```text
strong:
  strong_count >= 2 или score >= 70

medium:
  strong_count >= 1
  или medium_count >= 2
  или score >= 30

weak:
  существует finding или score > 0

none:
  иначе
```

Evidence level не совпадает с verdict thresholds. Например, один high finding при score 15 может дать `evidence_level = medium`, но `verdict = low_suspicion`.

Это не ошибка: поля описывают разные projections. Однако пользователю необходимо объяснять обе шкалы.

## Confidence calculation

Initial:

```text
confidence = 0.15
```

Additions:

```text
+0.11 за evidence family
+0.08 за strong finding
+0.04 за medium finding
+0.08 при hard table issue
+0.08 при parse failure или unwind anomaly
```

Hard table issue:

```text
rf_invalid_ranges
rf_oob
rf_unwind_oob
rf_overlaps
```

Если `score == 0`, confidence заменяется на `0.20`. Это означает умеренную уверенность только в ограниченном выводе «сильных static anomalies не обнаружено», а не уверенность в безопасности файла.

Final confidence ограничивается:

```text
0.05 <= confidence <= 0.90
```

Static model никогда не выдаёт выше 0.90.

## Weakening rules

### `single_signal_only`

Применяется, если:

```text
finding_count == 1
strong_count == 0
```

Penalty `0.12`.

### `small_sample_size`

Применяется, если:

```text
total < 32
strong_count == 0
finding_count > 0
```

Penalty `0.06`.

### `placement_only_signal`

Применяется, если есть unusual section, но отсутствуют executable/writable placement, handler placement, range issues, parse failures и anomalies.

Penalty `0.10`.

Это правило не применится к `unwind_writable_section`, потому что writable placement рассматривается сильнее простого unusual name.

### `single_family_only`

Применяется, если:

```text
strong_finding_count == 0
family_count <= 1
finding_count > 0
```

Penalty `0.08`.

Mitigations добавляются в report после findings и не уменьшают score. Следовательно:

```text
score описывает weighted anomaly mass
confidence описывает уверенность в статическом verdict
```

## Manual review flag

`requires_manual_review` становится true, если:

- score не меньше 20;
- unwind metadata executable;
- unwind metadata writable;
- handler non-executable;
- handler writable;
- есть parse failure;
- применено хотя бы одно weakening rule.

Score 15 с единственным high placement finding также может потребовать review из-за конкретного counter. И наоборот, low score zero не требует review в автоматической модели, хотя общий reverse engineering может быть нужен по внешним причинам.

## Verdict

Thresholds:

```text
score >= 70 -> high_suspicion
score >= 40 -> moderate_suspicion
score >= 15 -> low_suspicion
иначе       -> no_strong_static_anomalies
```

Название последнего verdict выбрано осторожно. Оно не утверждает `benign`, `clean` или `safe`. Оно утверждает только отсутствие сильных anomalies в реализованном наборе static rules.

## Фактический benign sample

Для `benign_richer.exe`:

```text
total = 3
all range counters = 0
unwind_parse_fail = 0
unwind_anomalies = 0
placement counters = 0
reuse conditions не проходят n > 200
score = 0
suspicion = 0.0
confidence = 0.2
verdict = no_strong_static_anomalies
evidence_level = none
requires_manual_review = false
```

Confidence 0.2 не означает, что sample на 20% benign. Это base confidence в узком static conclusion.

## Фактический suspicious sample `suspicious_unwind_oob.exe`

Manifest требует:

```text
rf_unwind_oob = 1
unwind_parse_fail = 1
score >= 40
verdict = moderate_suspicion
case_strength = strong_unconfirmed_case
```

При малом total один OOB pointer превышает 1%, поэтому:

```text
unwind_rva_oob: +25, high
unwind_parse_fail: +25, high
```

Score достигает не менее 50. Два strong findings дают static evidence strong. Dynamic corroboration отсутствует, поэтому report-level case называется strong unconfirmed.

## Фактический suspicious sample `suspicious_unwind_writable.exe`

Manifest требует writable unwind metadata и score не менее 15. На малом sample condition `count > n/20` может выбрать high branch weight 18.

Finding говорит, что metadata находится в section с write permission. Он не доказывает tampering. Manual validation должна проверить:

- section characteristics;
- runtime memory protection;
- toolchain;
- наличие JIT/runtime scenario;
- correspondence metadata и code.

## Тесты модуля

`unit_heuristics` проверяет базовые score, placement, verdict и confidence.

`unit_heuristics_mitigations` покрывает weakening rules.

`unit_heuristics_context` проверяет benign dominance suppression, suspicious context и writable combinations.

`unit_heuristics_combos` проверяет additional weights при corroborating patterns.

`unit_core_edges` проверяет empty input, resource-only case, nested overlaps и PE structural findings.

Regression manifest связывает synthetic PE samples с ожидаемыми JSON paths.

Тесты подтверждают implementation contract. Они не валидируют weights как научно оптимальные для реального world corpus.

## Что следует улучшать в будущей версии

Наиболее значимые направления:

1. Версионировать heuristic policy отдельно от report schema и tool version.
2. Добавить calibration corpus с размеченными compiler/runtime families.
3. Публиковать score contribution каждого finding, а не только total.
4. Добавить truncation flag для fixed finding array.
5. Propagate hash-map allocation failures.
6. Исправить percentage comparison для малых `n`, используя ratio вместо `count > n/20`.
7. Отделить invalid dominant keys от valid reuse statistics.
8. Сохранять all representative locations, а не только первый.
9. Добавить explicit rationale и standard/nonstandard tag каждому finding.
10. Не называть `confidence` вероятностью до empirical calibration.

## Итоговая модель главы

`heuristics.c` не обнаруживает «зло» как бинарное свойство. Он:

```text
получает проверяемые structural observations
-> агрегирует counts и concentration
-> создаёт named findings
-> группирует findings по evidence families
-> начисляет bounded engineering score
-> оценивает rule-based confidence
-> применяет weakening rules
-> формирует осторожный verdict
-> требует manual validation там, где автоматический вывод недостаточен
```

Именно так модуль должен быть представлен заказчику и на защите: как explainable static evidence engine для EH/unwind anomalies, а не как сертифицированный malware detector.

