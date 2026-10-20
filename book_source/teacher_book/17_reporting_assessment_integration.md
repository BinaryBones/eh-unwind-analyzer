# Том II. Глава 8. `report.c`: отчёты, итоговая assessment и интеграционный контракт

## Отчёт не является форматированным `printf`

После анализа существуют несколько внутренних моделей:

```text
PeImage
RuntimeFunction[]
UnwindSummary[]
us_ok[]
HeuristicReport
DynamicReport
ReportMetadata
```

`report.c` преобразует их в четыре внешних представления:

- brief console output;
- CSV;
- JSON;
- self-contained HTML.

Это serialization boundary. Ошибка здесь может:

- потерять evidence;
- создать invalid JSON;
- внедрить untrusted text в HTML;
- нарушить report schema;
- записать частичный файл как будто он полный;
- исказить числовую semantics.

Поэтому reporting layer проверяет model bounds, metadata, encoding и atomic write.

## Brief console report

`report_print_brief` выводит:

```text
input path
machine
ImageBase
SizeOfImage
SizeOfHeaders
section count
exception directory
RUNTIME_FUNCTION count
```

Это human-readable summary для terminal. Он не содержит все functions и не предназначен как stable machine contract.

Terminal output может меняться без schema migration. Backend не должен parsing console text.

## CSV report

Обычный CSV содержит строку на runtime function:

```text
index
begin_rva
end_rva
size
unwind_rva
unwind_ver
unwind_flags
prolog_size
fixed_stack
frame_reg
frame_off
handler_rva
has_chain
anomalies
parse_error
```

При parse failure поля, которые нельзя считать надёжными, получают `NA`, а error сохраняется.

CSV escaping реализован согласно базовым правилам:

- cell с comma, quote или newline оборачивается quotes;
- internal quote удваивается.

CSV подходит для spreadsheet и простого exchange, но не выражает nested structures, typed events или null semantics так полно, как JSON.

## Ghidra CSV

При `ghidra_mode` columns:

```text
begin_rva,end_rva,name,comment
```

Name строится:

```text
sub_%08X
```

Comment содержит summary:

```text
version
flags
prolog size
stack bytes
frame register
saved GP/XMM
handler
chain
anomalies
```

Этот report создаёт bridge к Ghidra script. Он не меняет source binary и не является отдельной копией core.

## Anomaly text

Bit mask `UnwindSummary.anomalies` преобразуется в compact labels:

```text
ver
trunc
op
arg
off
chain_loop
chain_depth
handler_oob
order
operand_sanity
alignment
chain_invalid
```

Если mask zero, записывается `"0"`.

Compact text удобен в table, а numeric mask сохраняется в JSON. Consumer может использовать stable numeric bits, но для долгосрочной schema лучше также публиковать array full anomaly codes.

## Report metadata

Полный JSON/HTML требует:

```c
typedef struct ReportMetadata {
    const char* tool_version;
    const char* report_schema_version;
    const char* generated_at_utc;
    const char* input_sha256;
    uint64_t input_size;
    const char* command_line;
    const char* build_compiler;
    const char* build_platform;
    const char* build_mode;
} ReportMetadata;
```

Эти поля обеспечивают provenance.

Tool version говорит, какая implementation создала report.

Schema version говорит, как consumer должен интерпретировать JSON structure.

Generated timestamp фиксирует время serialization в UTC.

Input SHA-256 и size идентифицируют bytes.

Command line фиксирует analyzer options, но child arguments могут быть redacted.

Compiler, platform и build mode позволяют различить binaries tool.

## Metadata validation

`report_metadata_valid` требует:

- nonempty tool version;
- exact supported schema version;
- timestamp format длиной 20: `YYYY-MM-DDTHH:MM:SSZ`;
- SHA-256 length 64;
- только lowercase hex;
- nonnull command line;
- nonempty compiler/platform;
- build mode `debug` или `release`.

Проверка timestamp валидацирует syntax positions и digits, но не календарную корректность. Например, month 99 формально прошёл бы. Timestamp генерируется internally, поэтому risk ограничен, но reusable API могла бы выполнять полную date validation.

Schema version comparison strict. Старый или будущий version metadata не записывается этим writer. Это защищает от случайного mislabeled output.

## Model validation

`report_model_valid` проверяет:

- если есть sections, pointer не null;
- finding count не выше capacity;
- mitigation count не выше capacity;
- dynamic event count не выше capacity;
- trace count и requested steps не выше array capacity.

Функция не перепроверяет все semantic relationships. Она является boundary sanity guard.

## JSON escaping

Input path, error text, section names, command line и dynamic details являются untrusted strings. Они должны быть escaped.

`json_escape` обрабатывает:

```text
\  -> \\
"  -> \"
newline -> \n
carriage return -> \r
tab -> \t
control bytes -> \u00xx
```

Для bytes >= 0x80 функция проверяет valid UTF-8 sequence lengths, включая:

- исключение overlong sequences;
- исключение surrogate range;
- ограничение code points до U+10FFFF.

Valid sequence копируется целиком. Invalid byte кодируется как `\u00xx`.

Это гарантирует syntactically valid JSON string, хотя invalid multibyte source преобразуется byte-wise, а не в Unicode replacement character.

## JSON numeric representation

Addresses сериализуются strings с `0x`:

```json
"begin_rva": "0x00001010"
```

Причины:

- сохраняется hexadecimal representation;
- 64-bit VA не теряется в JavaScript number;
- адрес явно отличается от обычного count.

Counts и ratios сериализуются numbers:

```json
"score": 18,
"confidence": 0.43
```

Consumer должен знать type contract. Backend не должен преобразовывать address string в signed 32-bit integer.

## Top-level JSON model

Основные sections:

```text
input
report_metadata
image_base
size_of_image
size_of_headers
section_alignment
file_alignment
exception_directory
pe_validation
sections
heuristic_analysis          если запрошена и успешна
dynamic_validation          если dynamic был запрошен
assessment                  если есть static или dynamic report
functions
```

Optional blocks отражают выполненные stages. Отсутствие `heuristic_analysis` отличается от score zero.

## `pe_validation`

Этот block содержит parser-level structural facts:

```text
section_raw_oob
section_virtual_oob
section_raw_overlaps
section_virtual_overlaps
section_misaligned
exception_directory_oob
```

Они доступны независимо от heuristic score. Это полезно для backend, который хочет собственную policy.

## `sections`

Для каждой section:

```text
name
virtual_address
virtual_size
raw_offset
raw_size
characteristics
readable
writable
executable
```

Permissions как booleans дублируют bit field для удобства consumer. `characteristics` сохраняет original value.

## `heuristic_analysis`

Block включает:

- score, suspicion, confidence;
- manual review flag;
- verdict и evidence level;
- severity counts;
- все raw counters;
- reuse ratios;
- evidence families;
- structured findings;
- weakening rules;
- human-readable details.

Каждый finding содержит:

```text
code
family
severity
message
affected_count
representative_rva или null
representative_section
```

Для database нормализованный key — `code`, а message является display text. Business logic не должна зависеть от точной английской строки message.

## `dynamic_validation`

Block сохраняет не только successful session:

```text
enabled
ran
ok
timed_out
target_exited
target_exit_code
timeout_ms
trace_steps
counters
dynamic_signal_count
dropped_events
details
events
trace
```

Если `ok=false`, partial events всё равно могут быть значимы. Backend должен хранить session status и не отбрасывать block целиком.

Каждый event:

```text
type
module
thread_id
exception_code
first_chance
address
arg0..arg3
```

Meaning args определяется event type. Это нужно документировать в API adapter.

## Functions

Для каждой table entry JSON содержит original range, section context, parse status, decoded record и comment.

Внутренний `unwind` object:

```text
version
flags
prolog_size
count_codes
fixed_stack_bytes
frame_reg
frame_off
has_handler
handler_rva
handler_section
has_chain
anomalies
anomalies_text
chain
```

Даже при `unwind_ok=false` object присутствует с initialized partial/default values, а `unwind_error` объясняет failure.

Это упрощает schema: array shape постоянна.

## Итоговая static/dynamic correlation

`has_static_dynamic_correlation` использует две группы rules.

Первая:

```text
suspicious static handler context
&&
any unwind/VEH/VCH/UEF handler hit
```

Suspicious handler context:

- handler non-executable;
- handler writable;
- handler dominance family.

Вторая:

```text
any placement anomaly
&&
dynamic function table registration
```

Placement anomaly включает unusual/executable/writable unwind metadata или handler placement.

Correlation boolean означает совпадение агрегированных classes evidence. Она не всегда доказывает exact address identity. Поэтому detailed analyst report должен выполнять более строгий address-level join.

## Dynamic signal count

Function считает категории, а не события:

```text
unwind handler
VEH
VCH
UEF
dynamic function table
second chance
```

Registration и hit одной категории не дают два points.

Это снижает влияние repeated events и отражает diversity runtime mechanisms.

## Runtime evidence level

Handler hit относится к strong component, dynamic table call и second chance — medium, registrations и first chance — weak.

Итог `none`, `weak`, `medium`, `strong` строится rule-based. Он не учитывает benign identity handler.

## Case strength

`case_strength` комбинирует static и runtime evidence levels:

```text
strong_correlated_case
medium_correlated_case
strong_unconfirmed_case
medium_case
weak_case
no_case
```

Если есть correlation и хотя бы одна сторона strong — strong correlated.

Если нет correlation, но одна сторона strong — strong unconfirmed.

Слово case означает аналитический набор evidence, а не юридически доказанный malicious verdict.

## Final confidence

Начальная final confidence:

```text
hr->confidence, если static report есть
0.10 иначе
```

Добавляется:

```text
+0.10 если есть dynamic signals
+0.10 если есть static/dynamic correlation
```

Maximum `0.98`.

Это не Bayesian update. Runtime signal и correlation могут быть зависимы, а increments не калиброваны. Поле следует трактовать как rule-based report confidence.

## Final verdict

Если static score:

```text
>=70 high_suspicion_correlated/static
>=40 moderate_suspicion_correlated/static
>=15 low_suspicion_correlated/static
```

Если static score ниже 15, но dynamic signals существуют:

```text
runtime_signals_only
```

Иначе:

```text
no_strong_correlated_evidence
```

Dynamic events не повышают static score. Они влияют на final suffix, confidence, case strength и отдельный evidence level.

## Manual validation plan

`collect_manual_validation_steps` строит context-dependent список.

Примеры:

- проверить `.pdata` ranges в PE viewer;
- открыть suspicious `UNWIND_INFO` в hex view;
- сравнить codes с Ghidra prolog;
- проверить section permissions;
- дизассемблировать handler;
- исследовать JIT explanation;
- capture dynamic table arguments;
- single-step registered handlers;
- выполнить dynamic run при наличии только static findings.

Это сильная часть report design: output не заканчивается score, а сообщает следующий проверочный шаг.

Steps являются English display strings, не stable IDs. Для backend localization и workflow automation лучше добавить code каждому step.

## HTML security model

HTML self-contained: CSS и JavaScript встроены, external resources отсутствуют.

Content Security Policy:

```text
default-src 'none'
style-src 'unsafe-inline'
script-src 'unsafe-inline'
img-src 'none'
base-uri 'none'
form-action 'none'
```

Такой CSP запрещает network loads, images, base URL и forms. Inline style/script разрешены, потому что report содержит собственный dashboard и filter.

Все untrusted strings проходят `html_escape`:

```text
& < > " '
```

Invalid UTF-8 bytes превращаются в numeric entities.

Если path содержал `<script>`, он выводится text, а не исполняется.

## HTML sections

Dashboard показывает:

- function count;
- parse failures;
- anomalous entries;
- static score/verdict/confidence;
- dynamic status.

Далее:

- provenance;
- PE image fields;
- structural validation;
- sections;
- final assessment;
- manual plan;
- findings;
- weakening rules;
- dynamic events and log;
- filterable runtime functions.

Client-side filter работает только по уже встроенной table и не отправляет данные наружу.

## HTML status nuance

Dynamic card class green только если:

```text
dr && dr->ran && dr->ok && !dr->timed_out
```

Text различает:

```text
not requested
timed out
not run
completed
failed
```

Это предотвращает превращение «dynamic не запрошен» в «dynamic anomalies не найдены».

## Atomic file write

CSV, JSON и HTML сначала полностью строятся в `StrBuf`, затем передаются `file_write_atomic`.

Atomic strategy:

1. записать temporary file;
2. flush/close;
3. rename в final path.

Consumer либо видит старый complete file, либо новый complete file, а не partial serialization.

Atomic rename не равен полной crash durability: без directory fsync внезапное отключение питания может иметь platform-dependent outcome. Для обычного report generation гарантия достаточна, но archival evidence storage требует отдельной durability policy.

## Memory failure behavior

`StrBuf` имеет sticky `ok` state. Если append failed, дальнейшие operations не превращают truncated buffer в successful report.

Перед write проверяется:

```text
sb_ok(all working buffers)
```

Если false, final file не записывается.

Это важнее частичного convenience output: invalid JSON не должен выдаваться как report.

## JSON schema

`docs/report.schema.json` формализует expected types and required fields. Tests валидируют generated reports.

Schema version находится и в metadata, и в application constants. Изменение field contract требует:

1. обновить schema;
2. изменить schema version;
3. добавить migration/compatibility notes;
4. обновить tests;
5. уведомить backend consumer.

Нельзя silently переименовать `rf_unwind_oob`, если коллега уже сохраняет это поле в database.

## Как backend должен вызывать core

Текущее ядро предоставляет CLI executable и static library. Для другого разработчика самый безопасный initial integration:

```text
backend receives uploaded binary
-> saves immutable job input
-> starts analyzer subprocess with explicit output paths
-> enforces timeout/resource limits
-> checks process exit code
-> parses JSON
-> validates JSON schema
-> stores raw JSON and normalized indexes
```

API между frontend и backend нужен. Между backend и core отдельный network API необязателен: subprocess protocol уже является boundary.

Отдельный core service нужен только если:

- анализ выполняется на другом host;
- нужен Windows-only dynamic worker;
- требуется queue and isolation;
- много concurrent jobs;
- deployment policy запрещает запуск subprocess в backend.

## Рекомендуемая database model

Не следует разбивать каждый JSON field в таблицы до потери original report. Надёжная схема:

`analysis_job`:

```text
id
status
input_sha256
input_size
original_filename
requested_static
requested_dynamic
created_at
started_at
finished_at
tool_version
schema_version
exit_code
failure_reason
```

`analysis_report`:

```text
job_id
raw_json
json_hash
html_object_key
created_at
```

Нормализованные tables для search:

```text
finding
runtime_function
dynamic_event
section
assessment
```

Raw JSON остаётся source of truth для backward compatibility и повторной migration.

## Сравнение analyses

Сравнивать можно:

- один hash в разных tool versions;
- разные versions одного binary;
- static-only и static+dynamic runs;
- runs с разными target arguments.

Join keys:

```text
input_sha256
tool_version
schema_version
function begin_rva
finding code + representative_rva
dynamic event type + module + offset
```

Absolute runtime VA нельзя напрямую сравнивать между runs из-за ASLR. Его нужно нормализовать к module+offset или RVA.

## API adapter не должен менять core

Коллега может написать backend adapter без изменения parser/decoder:

```text
HTTP upload
-> job queue
-> subprocess execution
-> JSON schema validation
-> persistence
-> REST response
```

Core следует менять только при необходимости нового analytical field, stable library API или structured streaming. Web concerns, authentication, database transactions и UI не должны входить в C analyzer.

## Что сделано правильно

- несколько outputs для разных consumers;
- machine-readable JSON;
- provenance and hash;
- schema validation;
- UTF-8-aware escaping;
- HTML escaping and restrictive CSP;
- atomic writes;
- explicit partial dynamic status;
- structured findings and events;
- manual validation plan;
- static/dynamic assessment без изменения raw evidence.

## Что улучшить

1. Добавить explicit policy version heuristics.
2. Typed dynamic event payloads.
3. Stable codes manual steps.
4. Full anomaly code arrays.
5. Score contribution per finding.
6. JSON writer abstraction, уменьшающий риск comma errors.
7. Streaming for extremely large function tables.
8. Optional gzip or JSON Lines for events.
9. Localization layer, не меняющий machine codes.
10. Digital signing of reports для chain of custody.
11. Separate raw observation schema from assessment policy.
12. Compatibility tests against previous schema versions.

## Итог

`report.c` является публичным контрактом продукта. Он соединяет C core с analyst, Ghidra, backend, database и frontend. Полноценность проекта определяется не только тем, может ли parser прочитать `.pdata`, но и тем, может ли downstream system точно понять:

```text
что анализировалось
какой версией
какие этапы реально выполнены
какие факты обнаружены
какие выводы построены
какова их ограниченность
что проверять вручную
```

В текущем проекте этот контракт уже достаточно развит для subprocess integration. Сетевую API-прослойку можно строить вне ядра, не изменяя аналитические modules.

