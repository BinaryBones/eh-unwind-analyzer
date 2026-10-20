# Том II. `main.c`: полный жизненный цикл одного анализа

## Роль `main.c`

`main.c` не реализует формат PE или unwind encoding. Его задача — orchestration: создать правильную последовательность вызовов, сохранить результаты, сформировать requested outputs и освободить ресурсы.

Эта роль часто недооценивается. Даже корректные отдельные модули образуют некорректный продукт, если orchestration:

- вызывает их в неверном порядке;
- игнорирует failure;
- передаёт несогласованные pointers;
- создаёт отчёт до вычисления metadata;
- освобождает объект слишком рано;
- возвращает неверный exit code.

Поэтому `main.c` является формальным описанием полного user workflow.

## Входной интерфейс процесса

Сигнатура:

```c
int main(int argc, char** argv)
```

`argc` содержит число аргументов.

`argv` указывает на массив pointers на null-terminated byte strings.

Для команды:

```text
eh_unwind_analyzer benign_richer.exe --heuristics --json report.json
```

логическая модель:

```text
argc = 5
argv[0] = "eh_unwind_analyzer"
argv[1] = "benign_richer.exe"
argv[2] = "--heuristics"
argv[3] = "--json"
argv[4] = "report.json"
```

Операционная система и C runtime формируют эти значения до вызова `main`.

## Внутренняя структура `Args`

```c
typedef struct Args {
    const char* input;
    bool dump;
    bool show_ops;
    bool heuristics;
    const char* csv_path;
    const char* ghidra_csv_path;
    const char* json_path;
    const char* html_path;
    int dump_limit;
    bool follow_chain;
    int max_chain_depth;
    bool dynamic;
    uint32_t timeout_ms;
    uint32_t trace_steps;
    const char** child_argv;
    int child_argc;
} Args;
```

Эта структура является нормализованным представлением command line.

Поля `const char*` не владеют строками. Они указывают на memory, предоставленную через `argv`, и действительны в течение `main`.

Boolean fields определяют включённые режимы.

Числовые fields уже должны быть проверены по диапазонам.

`child_argv` и `child_argc` описывают arguments target после разделителя `--`.

## Почему parsing arguments отделён

Функция:

```c
static ParseResult parse_args(int argc, char** argv, Args* a)
```

обнуляет output:

```c
memset(a, 0, sizeof(*a));
```

а затем задаёт nonzero defaults:

```c
a->dump_limit = -1;
a->follow_chain = true;
a->max_chain_depth = 8;
a->timeout_ms = 15000;
a->trace_steps = 64;
```

Обнуление создаёт доказуемое начальное состояние всех optional pointers и flags. Defaults задаются явно после него.

Возвращаемый `ParseResult` различает:

```text
PARSE_OK
PARSE_HELP
PARSE_VERSION
PARSE_ERR
```

Boolean результата было бы недостаточно: help и version являются успешным завершением пользовательского запроса, а malformed CLI — ошибкой.

## Позиционный input

Если первый аргумент равен `--help` или `--version`, input file не требуется.

Иначе:

```c
a->input = argv[1];
```

Проект использует первый позиционный аргумент как путь target. Остальные аргументы до `--` должны быть известными options.

Это означает, что текущий CLI не поддерживает произвольное расположение input после options. Backend должен следовать документированному contract.

## Разделитель `--`

Option:

```text
--
```

завершает options анализатора. Все последующие strings передаются target в dynamic mode.

Пример:

```text
eh_unwind_analyzer target.exe --dynamic -- --input sample.dat
```

До separator:

```text
--dynamic
```

принадлежит анализатору.

После separator:

```text
--input sample.dat
```

принадлежит target.

Без separator невозможно однозначно определить, чья option `--input`.

## Проверка чисел

`parse_long_range` использует `strtol`.

Она проверяет:

- null/empty input;
- `ERANGE`;
- отсутствие цифр;
- наличие trailing characters;
- minimum и maximum.

Условие:

```c
end == text
```

означает, что не была распознана ни одна цифра.

Условие:

```c
*end != '\0'
```

означает, что после числа остался непотреблённый текст, например `10abc`.

Для unsigned values `parse_u32_range` дополнительно отклоняет начальный `-`, потому что `strtoul` имеет поведение, которое могло бы преобразовать отрицательную запись в большое unsigned value.

## Диапазоны options

`--max-chain-depth` допускает `1..16`.

Нижняя граница исключает бессмысленную нулевую глубину при включённом follow chain.

Верхняя граница ограничивает рекурсивную или итеративную работу на malicious chain.

`--trace-steps` допускает `0..256`. Ноль отключает trace. Верхняя граница соответствует фиксированному массиву:

```c
uint64_t trace[256];
```

CLI validation и размер модели согласованы.

`--timeout-ms` требует значение больше нуля и допускает диапазон `uint32_t`.

## Exit code CLI parsing

После:

```c
ParseResult pres = parse_args(argc, argv, &a);
```

`main` обрабатывает результат:

```c
if (pres != PARSE_OK) {
    if (pres == PARSE_VERSION) {
        print_version();
        return 0;
    }
    usage(argv[0]);
    return (pres == PARSE_HELP) ? 0 : 2;
}
```

Help и version возвращают 0. Invalid command line возвращает 2.

Различие важно для automated caller:

```text
0: запрос выполнен
1: runtime/input/output failure
2: неправильный способ вызова
```

## Чтение input

Объявляются:

```c
uint8_t* owned = NULL;
Buf b;
```

После успешного `buf_init_from_file`:

```text
owned == b.data
b.size == file size
```

но roles различаются. `owned` используется для освобождения, `b` — для чтения.

Если чтение не удалось, другие объекты ещё не созданы, поэтому cleanup минимален.

## Error buffers

Проект использует `StrBuf` для накопления подробных diagnostics:

```c
StrBuf err;
sb_init(&err, 1024);
```

В текущем `main` return value `sb_init` в некоторых местах не проверяется немедленно. `StrBuf` сохраняет `failed`, а последующие append возвращают false. Для критических output metadata проверки выполняются составным условием.

Инженерное улучшение могло бы унифицировать проверку каждого `sb_init`, но test/sanitizer coverage снижает риск незамеченного поведения.

## PE parsing

```c
PeImage img;
if (!pe_parse(&img, &b, &err)) {
    ...
    return 1;
}
```

До вызова `img` не инициализирован вызывающим кодом. Контракт `pe_parse` начинается с:

```c
memset(out, 0, sizeof(*out));
```

При failure `main` не вызывает `pe_free`, потому что parser сам освобождает локально выделенные sections на соответствующих failure paths и не возвращает успешное owned state.

При success ownership `img.sections` переходит вызывающему, и позднее требуется `pe_free`.

## Runtime function table

```c
RuntimeFunction* rf = NULL;
size_t rf_count = 0;
```

Использование null и zero перед вызовом обеспечивает определённое состояние даже при failure.

`unwind_read_runtime_functions` выделяет массив. После success:

```text
rf[0..rf_count-1]
```

доступен caller. Освобождение выполняется `free(rf)`.

Если exception directory корректно отсутствует, допустим success с `rf_count == 0`. Код последующих allocations учитывает ноль.

## Allocations для per-function state

```c
UnwindSummary* us =
    (UnwindSummary*)calloc(rf_count ? rf_count : 1,
                           sizeof(UnwindSummary));
bool* us_ok =
    (bool*)calloc(rf_count ? rf_count : 1,
                  sizeof(bool));
```

Почему при `rf_count == 0` выделяется один элемент?

Стандарт C допускает implementation-defined поведение `malloc(0)`/`calloc(0, ...)`, включая null. Проект хочет различать реальный out-of-memory и пустую таблицу, поэтому запрашивает минимум один элемент.

Логическая длина всё равно равна `rf_count`; фиктивный элемент не обрабатывается.

`calloc` обнуляет память:

- `us_ok[i]` изначально false;
- все fields `UnwindSummary` изначально zero;
- `parse_error` содержит empty string.

## Options unwind parser

```c
UnwindParseOpts uopts = {
    .max_chain_depth = a.max_chain_depth,
    .follow_chain = a.follow_chain
};
```

Designated initializers явно связывают значения с именами fields.

Эта структура отделяет policy пользователя от обязательных параметров parser. В будущем в неё можно добавить controlled options, но изменение public structure потребует проверки ABI/library use.

## Основной цикл unwind

```c
for (size_t i = 0; i < rf_count; i++) {
    StrBuf perr;
    sb_init(&perr, 256);
    bool ok = unwind_parse(
        &b,
        &img,
        rf[i].unwind_rva,
        &uopts,
        &us[i],
        a.show_ops ? &ops : NULL,
        &perr
    );
    us_ok[i] = ok;
    sb_free(&perr);
}
```

На каждой итерации:

1. выбирается `rf[i].unwind_rva`;
2. parser использует общие immutable `b` и `img`;
3. результат записывается точно в `us[i]`;
4. success записывается в `us_ok[i]`;
5. локальная diagnostic освобождается;
6. цикл продолжается независимо от failure одной записи.

`perr` не печатается в этом цикле, потому что `unwind_parse` копирует конкретную причину в `us[i].parse_error`. Локальный buffer используется для внутреннего diagnostic contract.

## Почему операции могут разбираться повторно

В первом цикле текст operations строится только при `a.show_ops`, но общий `ops` не хранит отдельный текст для всех functions.

В dump loop при необходимости `unwind_parse` вызывается повторно для конкретной записи и строит `ops2`.

Преимущество:

- не хранится большой массив текстов для всех функций;
- detailed output создаётся только для отображаемых entries.

Недостаток:

- выбранные structures разбираются второй раз.

Для CLI dump это разумный обмен memory на computation. Parser детерминирован относительно immutable input и options.

## Heuristic stage

`HeuristicReport` объявляется на stack:

```c
HeuristicReport hr;
HeuristicReport* hr_ptr = NULL;
```

Pointer остаётся null, пока анализ не завершится успешно.

После success:

```c
hr_ptr = &hr;
```

Reports получают null, если heuristics не запрошены или failed. Это позволяет сериализатору различать отсутствие этапа и заполненную модель.

Если `heuristics_analyze` failed, `exit_code` становится 1, но код может продолжить формировать другие requested outputs. Такая стратегия позволяет пользователю получить частичный результат, не скрывая failure через process status.

## Dynamic stage

`DynamicReport dr` предварительно обнуляется:

```c
memset(&dr, 0, sizeof(dr));
```

Флаг:

```c
bool dr_initialized = false;
```

нужен для корректного вызова `dynamic_report_free`. После вызова collector считается, что report прошёл init path, даже если session не ran успешно.

`dr_ptr` передаётся reports, если dynamic mode был запрошен. Тогда JSON способен показать failure/status, а не просто отсутствие блока.

## Outputs CSV

CSV writers вызываются независимо:

```c
report_write_csv(..., false, ...)
report_write_csv(..., true, ...)
```

Последний boolean выбирает full CSV или Ghidra-oriented variant.

Каждый output имеет собственный error buffer и собственную обработку. Failure одного файла устанавливает `exit_code = 1`, но не запрещает попытку создать остальные.

## Подготовка provenance

JSON и HTML требуют metadata. `main` строит:

```c
StrBuf invocation;
char timestamp[32];
char input_sha256[65];
ReportMetadata metadata;
```

Составное условие требует success всех операций:

```c
sb_init
build_invocation
app_utc_timestamp
sha256_hex
```

Только после этого:

```c
metadata_ptr = &metadata;
```

Если metadata неполна, JSON/HTML не записываются как будто полноценные. Это сохраняет report invariant: каждый полный report должен быть привязан к tool build и input hash.

## Redaction arguments target

`build_invocation` проходит исходный `argv`. При достижении `--` он не копирует последующие значения, а записывает:

```text
-- [N target arguments redacted]
```

Причина не связана с синтаксисом JSON. Target arguments могут содержать:

- credentials;
- tokens;
- персональные данные;
- внутренние пути;
- содержимое запроса.

Для воспроизводимости сохраняется факт и количество, но не значения.

## SHA-256

`sha256_hex(b.data, b.size, input_sha256)` вычисляет digest всех входных байтов.

Если файл изменится хотя бы в одном бите, ожидается другое digest. SHA-256 связывает отчёт с конкретным содержимым, но не доказывает происхождение или безопасность файла.

## JSON и HTML

Writers получают одинаковый analytical model:

```text
path
PeImage
RuntimeFunction[]
UnwindSummary[]
us_ok[]
HeuristicReport optional
DynamicReport optional
ReportMetadata
```

Различается presentation:

- JSON предназначен для machine integration;
- HTML предназначен для interactive human review.

Логические значения должны согласовываться между форматами. Unit tests проверяют оба serializers.

## Финальный cleanup

Порядок:

```c
heuristics_free
dynamic_report_free
sb_free(&ops)
free(us_ok)
free(us)
free(rf)
pe_free(&img)
sb_free(&err)
sb_free(&err2)
buf_free_owned(owned)
```

Порядок следует зависимостям. Reports уже записаны, поэтому borrowed pointers больше не используются.

`PeImage.sections` освобождается до input bytes, но мог бы освобождаться и после: sections является отдельной allocation и не указывает внутрь input. Главное — не использовать models после release.

## Полный автомат состояний `main`

```text
START
-> CLI_PARSED
-> INPUT_LOADED
-> PE_PARSED
-> RF_TABLE_READ
-> UNWIND_ATTEMPTED_FOR_ALL
-> OPTIONAL_HEURISTICS
-> OPTIONAL_DYNAMIC
-> OPTIONAL_OUTPUTS
-> CLEANUP
-> EXIT
```

Fatal transitions до построения основной модели немедленно ведут в cleanup соответствующего уровня и exit 1.

Локальные analytical failures могут позволять продолжение, но изменяют final exit code.

## Tests, относящиеся к `main`

`test_cli_contract.py` проверяет:

- help/version;
- invalid options;
- numeric ranges;
- exit codes;
- output combinations.

`run_regression_samples.py` проверяет end-to-end pipeline на шести PE.

`test_report_semantics.py` запускает CLI и проверяет отношения полей.

`test_release_metadata.py` проверяет согласованность version/schema declarations.

Mutation test многократно вызывает CLI на изменённых входах и требует controlled result вместо crash.

## Что можно улучшить

Текущий `main` является последовательным orchestration layer. Возможные улучшения:

- единый cleanup block для уменьшения повторения ранних failure paths;
- structured machine-readable error output;
- более детальные exit subcodes;
- `--quiet`;
- `--output-dir`;
- сохранение duration каждого этапа;
- явное различие `not_requested`, `failed`, `completed` для каждого stage;
- streaming или batching для очень больших reports.

Эти изменения не требуют менять предметные алгоритмы PE/unwind.

## Проверка полного понимания `main`

Читатель должен суметь для любой строки основного pipeline ответить:

1. какие объекты уже существуют;
2. кто ими владеет;
3. какие инварианты доказаны;
4. что произойдёт при failure;
5. продолжится ли анализ;
6. какой exit code сформируется;
7. какие outputs ещё могут быть созданы;
8. где объект освобождается.

