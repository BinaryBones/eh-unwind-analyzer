# Том II. `util.c`: основание безопасного parser и генерации отчётов

## Почему `util.c` является частью доказательства корректности

`pe.c` и `unwind.c` содержат предметные знания о формате. Но все их проверки бессмысленны, если базовая операция чтения способна выйти за границу или неверно собрать integer.

`util.c` формирует минимальный trusted computing base проекта на уровне пользовательского кода. Ошибка здесь распространялась бы на все последующие conclusions.

## `Buf` как read-only view

```c
typedef struct Buf {
    const uint8_t* data;
    size_t size;
} Buf;
```

`Buf` не содержит capacity, mutable pointer или ownership flag. Он описывает только доступное для чтения содержимое.

`const uint8_t*` запрещает изменение байтов через этот pointer на уровне type system C. Это shallow const: сама структура `Buf` может быть присвоена, но pointed bytes через неё не модифицируются.

`size` задаёт единственную допустимую границу. Parser не использует null terminator, потому что binary input может содержать нулевые байты в любой позиции.

## `buf_init_from_file`

Контракт:

```c
bool buf_init_from_file(
    Buf* out,
    const char* path,
    uint8_t** owned_mem
);
```

Preconditions:

- все три pointers ненулевые;
- `path` указывает на корректную C string.

Postcondition success:

```text
out->data == *owned_mem
out->size == фактическое число прочитанных байтов
*owned_mem != NULL
```

Postcondition failure:

```text
*owned_mem == NULL
нет открытого FILE
нет неосвобождённой allocation, созданной функцией
```

Функция сначала выполняет:

```c
*owned_mem = NULL;
```

Это важно для failure paths caller. Даже если открытие не удалось, caller не получает неопределённый pointer.

## Определение размера

Используются `fseek` и `ftell`. `ftell` возвращает `long`, поэтому текущая реализация имеет практическое ограничение для файлов, размер которых не представим `long` на host.

На современных 64-битных POSIX и Windows toolchains это обычно достаточно для анализируемых PE, но строгая поддержка очень больших файлов потребовала бы platform-specific 64-bit file APIs.

Отрицательный результат `ftell` считается failure:

```c
if (sz < 0) ...
```

## Пустой файл

Для размера zero:

```c
size_t alloc_size = sz > 0 ? (size_t)sz : 1u;
```

Выделяется один байт, хотя логический `Buf.size` равен нулю.

Причина: `malloc(0)` может вернуть null или уникальный pointer в зависимости от реализации. Проект хочет, чтобы failure allocation не смешивался с пустым input.

Ни один байт фиктивной allocation не считается частью input, потому что bounds определяет `size`.

## Полнота `fread`

```c
size_t rd = fread(mem, 1, (size_t)sz, f);
```

Функция требует:

```c
rd == sz
```

Частичное чтение не принимается. Если файл изменился, возник I/O error или чтение прервано, allocation освобождается.

Это сохраняет invariant: SHA-256 и parser работают с полной последовательностью заявленного размера.

## `buf_free_owned`

```c
void buf_free_owned(uint8_t* owned_mem) {
    free(owned_mem);
}
```

Отдельная wrapper function документирует ownership pair:

```text
buf_init_from_file -> buf_free_owned
```

`free(NULL)` допустим стандартом C, поэтому функция безопасна для null.

## `buf_read`

Контракт:

```c
bool buf_read(
    const Buf* b,
    size_t off,
    void* out,
    size_t len
);
```

`void* out` означает, что destination type не фиксирован интерфейсом. Функция копирует raw bytes.

Проверка:

```c
if (!b || !out) return false;
```

Даже при `len == 0` проект требует non-null `out`. Это упрощает contract.

Далее:

```c
if (off > b->size) return false;
```

`off == size` допустим только для zero-length read.

Затем:

```c
if (len > b->size - off) return false;
```

После доказательства диапазона вызывается:

```c
memcpy(out, b->data + off, len);
```

`memcpy` требует, чтобы source и destination ranges были валидны и не перекрывались. Destination предоставляется caller. Source доказан `Buf`.

## Typed read functions

`buf_read_u16` не записывает прямо в `uint16_t` из arbitrary file address:

```c
uint8_t tmp[2];
if (!buf_read(b, off, tmp, 2)) return false;
*out = le16(tmp);
```

Причины:

- file offset может быть невыровнен;
- host endianness не должен влиять;
- чтение C-object через cast может нарушать aliasing/alignment rules;
- bounds должны быть проверены до interpretation.

Такой подход немного многословнее direct cast, но создаёт переносимый parser.

## `le16`, `le32`, `le64`

`le64` строится из двух `le32`:

```c
return (uint64_t)le32(p) |
       ((uint64_t)le32(p + 4) << 32);
```

Cast к `uint64_t` выполняется до сдвига на 32. Если сдвигать 32-битное значение на 32 без расширения, операция была бы недопустимой.

Эти helpers являются pure functions: результат зависит только от входных байтов, state не изменяется.

## `StrBuf`

```c
typedef struct StrBuf {
    char* s;
    size_t len;
    size_t cap;
    bool failed;
} StrBuf;
```

`s` указывает на allocation.

`len` — число содержательных bytes без завершающего null.

`cap` — вместимость allocation в bytes.

`failed` — sticky error state.

Invariant успешного initialized buffer:

```text
s != NULL
len < cap
s[len] == '\0'
failed == false
```

Наличие null terminator позволяет передавать `s` функциям C strings, а `len` позволяет не вычислять `strlen` после каждого append.

## Почему error state sticky

Если одна операция append не смогла выделить память, дальнейшее продолжение могло бы сформировать усечённый JSON. Поэтому:

```c
if (!sb || sb->failed) return false;
```

После failure buffer остаётся failed до `sb_free`/новой initialization.

Caller может проверить итог:

```c
sb_ok(&buffer)
```

Это transactional-like property на уровне построения текста: нельзя принять partial output как complete.

## Рост capacity

`sb_reserve` увеличивает capacity:

```c
increment = newcap / 2 + 64
newcap += increment
```

Рост больше линейного снижает число `realloc` при последовательных append.

Перед сложением:

```c
if (increment > SIZE_MAX - newcap)
```

проверяется overflow.

Если geometric growth не может быть вычислен, функция использует точно `need_cap`. Затем `realloc` либо возвращает новую allocation, либо оставляет старую действительной и возвращает null. При null устанавливается `failed`.

## `sb_appendn`

Проверка required capacity:

```c
if (sb->len == SIZE_MAX ||
    n > SIZE_MAX - sb->len - 1u)
```

`+1` нужен для null terminator.

После reserve:

```c
memcpy(sb->s + sb->len, s, n);
sb->len += n;
sb->s[sb->len] = 0;
```

Invariant восстанавливается после каждой успешной операции.

## `sb_appendf`

Variadic function принимает printf format.

Первый `vsnprintf(NULL, 0, ...)` вычисляет необходимую длину. Для повторного использования аргументов создаётся `va_copy`, потому что проход `vsnprintf` изменяет состояние `va_list`.

После reserve второй `vsnprintf` пишет строку. Проверяется:

```c
wrote == need
```

Compiler attribute `format(printf, ...)` для GCC/Clang позволяет статически проверять соответствие format и аргументов.

## Атомарная запись

`file_write_atomic` создаёт temporary sibling path:

```text
<path>.tmp.<pid>
```

Пишет полное содержимое, выполняет `fflush`, закрывает stream, затем заменяет destination.

До replace существующий report остаётся неизменным. Если write failed, temp удаляется.

На Windows:

```c
MoveFileExA(
    temp_path,
    path,
    MOVEFILE_REPLACE_EXISTING |
    MOVEFILE_WRITE_THROUGH
)
```

На POSIX:

```c
rename(temp_path, path)
```

Соседнее расположение важно для атомарности rename в пределах файловой системы.

Ограничение: текущая реализация не выполняет POSIX `fsync` для file descriptor и parent directory. `fflush` переносит данные из user-space stdio buffer, но не является полной гарантией durability при system crash. Для CLI report это разумный уровень, но high-assurance storage мог бы усилить protocol.

## SHA-256

SHA-256 преобразует сообщение произвольной конечной длины в 256-bit digest.

Проект хранит результат как 64 lowercase hex characters:

```text
256 bits / 4 bits per hex digit = 64 digits
```

Плюс null terminator:

```c
char out_hex[65];
```

Digest используется для identity input bytes. Он не:

- шифрует файл;
- подтверждает автора;
- является digital signature;
- определяет maliciousness.

## Связь `util.c` с отчётом и tests

`Buf` используется всеми parsers.

`StrBuf` используется diagnostics и serializers.

Atomic writer используется CSV/JSON/HTML.

SHA-256 попадает в report metadata.

`unit_core_edges` проверяет boundary conditions.

Mutation fuzz проходит через `Buf` operations на изменённых inputs.

JSON/HTML tests косвенно проверяют `StrBuf` и atomic output.

Sanitizers проверяют memory safety на runtime test paths.

## Полная роль модуля

`util.c` обеспечивает четыре свойства всего продукта:

1. input bytes имеют явную длину;
2. каждое чтение доказывает границы;
3. многобайтные значения декодируются независимо от host layout;
4. output либо формируется полностью, либо отмечается failure.

Следующий модуль `pe.c` опирается на эти свойства и добавляет семантику формата.

