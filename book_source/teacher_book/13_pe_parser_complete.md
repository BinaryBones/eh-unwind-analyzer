# Том II. `pe.c`: построение модели PE из недоверенных байтов

## Почему PE parser выполняется раньше unwind decoder

`UNWIND_INFO` адресуется через RVA. Пока проект не прочитал section table, он не способен установить, какой file offset соответствует RVA. Поэтому `pe_parse` создаёт систему координат для всей последующей работы.

На входе функции известны только:

```text
Buf.data
Buf.size
```

На выходе должны быть известны:

```text
архитектура image
ImageBase
SizeOfImage
SizeOfHeaders
alignments
exception directory
sections
структурные counters
```

`PeImage` не является полной моделью всего PE. Проект намеренно извлекает только поля, необходимые для своего scope.

## Почему parser не использует Windows headers

`pe.h` объявляет собственные минимальные constants и структуры:

```c
#define PE_DOS_MAGIC 0x5A4D
#define PE_NT_MAGIC  0x00004550
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
```

Преимущества:

- static core компилируется на Linux и macOS;
- parser не зависит от packing C-структур Windows SDK;
- каждое поле читается с явным bounds-check;
- поддерживаемый subset виден в коде;
- анализируется файл, а не host representation.

Недостаток — offsets и constants нужно поддерживать в соответствии со спецификацией. Tests и официальная документация являются обязательной частью такого решения.

## `PeSection`

```c
typedef struct PeSection {
    char name[9];
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_ptr;
    uint32_t raw_size;
    uint32_t characteristics;
} PeSection;
```

Это нормализованная модель section header, а не byte-for-byte копия 40-байтового PE structure.

В PE имя занимает ровно 8 байт и не обязано завершаться null. В модели выделено 9:

```c
memcpy(secs[i].name, name8, 8);
secs[i].name[8] = 0;
```

Так report code безопасно использует имя как C string.

Поля relocation/line number из section header не сохраняются, потому что не используются scope проекта.

## `PeImage`

`PeImage` объединяет три класса данных.

Первый класс — identity/layout:

```text
machine
image_base
size_of_image
size_of_headers
section_alignment
file_alignment
```

Второй — предметный каталог:

```text
exception_rva
exception_size
```

Третий — результаты валидации:

```text
section_raw_oob
section_virtual_oob
section_raw_overlaps
section_virtual_overlaps
section_misaligned
exception_directory_oob
```

Parser не только извлекает поля, но и сохраняет факты о нарушениях для heuristics.

## Инициализация результата

```c
if (!out || !b || !err) return false;
memset(out, 0, sizeof(*out));
```

После `memset`:

- `out->sections == NULL`;
- counters равны нулю;
- flags false.

Поле `ok` устанавливается только в конце success path. Caller не должен использовать модель после false return.

## DOS header

PE сохраняет исторически совместимый DOS header. Первые два байта содержат `e_magic`.

При little-endian чтении байты:

```text
4D 5A
```

дают:

```text
0x5A4D
```

ASCII-представление байтов читается как `MZ`.

Функция:

```c
read_dos_lfanew
```

читает magic и 32-битное поле по file offset `0x3C`.

`e_lfanew` — file offset новой PE signature.

Почему offset PE header не зафиксирован? Между DOS header и PE header может находиться DOS stub и padding различной длины. Поэтому parser использует поле, а не предполагает значение `0x80`.

## Проверка минимального PE header range

```c
if ((size_t)lfanew + 4 + 20 > b->size)
```

`4` — размер PE signature.

`20` — размер COFF file header.

Parser доказывает, что обязательная фиксированная часть помещается в файл до чтения полей.

Теоретически сумма может переполнить `size_t`, если `size_t` 32-битный и `lfanew` близок к максимуму. Поддерживаемые современные 64-битные builds исключают это для `uint32_t lfanew`. Для абсолютно общего parser предпочтительна subtractive range check, аналогичная `buf_read`.

Фактические typed reads всё равно проходят через `buf_read`, поэтому out-of-bounds copy не происходит. Предварительная проверка формирует более точную diagnostic.

## PE signature

По `lfanew` читается:

```c
uint32_t sig;
buf_read_u32(...);
```

Ожидаемое значение:

```text
0x00004550
```

Байты:

```text
50 45 00 00
```

первые два соответствуют ASCII `PE`, следующие два равны zero.

Наличие `MZ` без корректной PE signature не делает файл поддерживаемым PE.

## COFF file header

Сразу после signature находится 20-byte COFF header.

Проект читает:

```text
offset +0: Machine
offset +2: NumberOfSections
offset +16: SizeOfOptionalHeader
```

Почему не читается timestamp? Он не нужен для PE/unwind pipeline. Минимальный parser не обязан копировать каждое поле формата.

`Machine` определяет архитектуру machine code и architecture-specific directories. Проект принимает только:

```text
0x8664 = IMAGE_FILE_MACHINE_AMD64
```

Это ранняя проверка предотвращает попытку применить AMD64 unwind decoder к ARM64 или x86.

## Optional header

Название `Optional Header` историческое. Для PE image эта структура необходима.

Её начало:

```c
size_t opthdr = filehdr + 20;
```

`SizeOfOptionalHeader` берётся из COFF header. Parser сначала доказывает:

```c
opthdr + opt_size <= file_size
```

и минимальный размер:

```c
opt_size >= 0x70
```

Смещение `0x70` является началом data directories в PE32+.

## Magic PE32+

Первые 2 байта optional header:

```text
0x10B = PE32
0x20B = PE32+
```

`PE32+` используется для 64-битных images и имеет другое layout некоторых fields. Поэтому проверка magic обязательна даже после AMD64 Machine.

Проект отклоняет PE32, а не пытается читать его по PE32+ offsets.

## Ключевые поля optional header

Offsets относительно начала PE32+ optional header:

```text
0x18 ImageBase, 8 bytes
0x20 SectionAlignment, 4
0x24 FileAlignment, 4
0x38 SizeOfImage, 4
0x3C SizeOfHeaders, 4
0x6C NumberOfRvaAndSizes, 4
```

Offsets определены PE32+ layout.

### `ImageBase`

Preferred base image. Используется для presentation и преобразования RVA в preferred VA. Static structural checks в основном работают с RVA.

### `SectionAlignment`

Выравнивание sections в virtual image.

### `FileAlignment`

Выравнивание raw section data в файле.

### `SizeOfImage`

Размер virtual image с учётом section alignment. Используется как верхняя структурная граница RVA.

### `SizeOfHeaders`

Размер области headers, отображаемой в image. Для RVA внутри этой области проект допускает прямое соответствие file offset.

### `NumberOfRvaAndSizes`

Число реально объявленных data directory entries. Нельзя обращаться к index 3, если число меньше 4.

## Фатальные проверки полей

`SizeOfImage == 0` не позволяет сформировать meaningful RVA boundary.

`SizeOfHeaders == 0` или превышение file size отклоняется. Проект требует физическое наличие всех declared headers.

Нулевой alignment недопустим, потому что modulo operation и модель размещения потеряли бы смысл.

Недостаточное число directories делает exception directory недоступным.

Эти conditions являются fatal, потому что последующий mapping не может быть надёжно выполнен.

## Data directory

Каждая standard data directory entry состоит из:

```text
VirtualAddress: 4 bytes
Size: 4 bytes
```

Exception directory имеет index 3.

Относительный offset:

```c
0x70 + 3 * 8 = 0x88
```

Parser отдельно проверяет, что вся entry помещается в фактический `opt_size`, а не только в теоретический standard layout.

Результат:

```c
exc_rva
exc_sz
```

Оба могут быть zero, что означает отсутствие directory.

Если одно zero, а второе nonzero, `pe_parse` не завершается fatal failure, но выставляет `exception_directory_oob`. Позднее strict reader отклоняет malformed pair. Такое двухуровневое поведение сохраняет `PeImage` и validation counters для отчёта, когда это возможно.

## Section table

Section headers следуют непосредственно после optional header:

```c
secthdr = opthdr + opt_size;
```

Каждый header занимает 40 байт.

Общий конец:

```c
needed = secthdr + nsects * 40;
```

должен находиться внутри файла.

Массив:

```c
calloc(nsects ? nsects : 1, sizeof(PeSection))
```

при zero sections всё равно возвращает обычную allocation. Логическое `num_sections` остаётся zero.

## Чтение section fields

Для каждой section:

```text
+0  Name[8]
+8  VirtualSize
+12 VirtualAddress
+16 SizeOfRawData
+20 PointerToRawData
+36 Characteristics
```

Все integer fields little-endian.

Если любое чтение не удалось, весь массив освобождается до return false. Ownership не передаётся caller частично.

## Virtual span policy

Проект использует:

```c
max(VirtualSize, SizeOfRawData)
```

для поиска candidate section и проверки virtual range.

Причина: реальные PE могут иметь одно из fields меньше другого из-за alignment и producer behavior. Использование maximum позволяет классифицировать RVA в расширенном logical span.

Но raw availability проверяется отдельно:

```c
delta < raw_size
```

Следовательно, membership section и наличие bytes в файле не смешиваются.

Это осознанная parser policy. Другой parser может выбирать иной span для некоторых malformed images, поэтому overlaps фиксируются как ambiguity.

## Raw OOB

Для section:

```c
raw_end = raw_ptr + raw_size
```

вычисляется в `uint64_t`.

Если `raw_size > 0` и:

```text
raw_end > file_size
```

section заявляет bytes за EOF.

Parser не прекращает работу автоматически. Он увеличивает `section_raw_oob`. Это позволяет heuristics создать finding и сохранить остальные fields.

Однако конкретное чтение через `buf_read` всё равно будет отклонено.

## Virtual OOB

```c
virtual_end = virtual_address + virtual_span
```

Если:

```text
virtual_end > SizeOfImage
```

section не помещается в declared image.

Это структурное противоречие между section table и optional header.

## Alignment

Проверяется:

```c
virtual_address % section_alignment == 0
```

и для section с raw data:

```c
raw_ptr % file_alignment == 0
```

Нарушение увеличивает `section_misaligned`.

Project rule не реализует все специальные тонкости PE для очень малых alignments как отдельную сложную policy. Поэтому finding является аналитическим сигналом и требует сверки со спецификацией/loader behavior.

## Overlap

Два полуоткрытых диапазона пересекаются, если:

```text
a_begin < b_end
и
b_begin < a_end
```

Zero-sized ranges не считаются пересекающимися.

Проект проверяет каждую новую section со всеми предыдущими. При небольшом числе sections сложность `O(s²)` приемлема и сохраняет простой проверяемый код.

Raw overlap означает, что section headers претендуют на общие file bytes.

Virtual overlap означает, что один RVA может соответствовать нескольким sections согласно выбранной span policy.

Virtual overlap особенно опасен для mapping: `pe_find_section_for_rva` возвращает первую подходящую section, а другой parser или loader может интерпретировать ambiguous image иначе.

## Exception directory boundary

Если directory не пуст:

```c
exc_end = exc_rva + exc_sz
```

вычисляется в `uint64_t`.

Anomaly выставляется, если:

- RVA zero;
- size zero;
- конец выходит за `SizeOfImage`.

На этом этапе ещё не доказывается наличие raw bytes. Это выполняет `unwind_read_runtime_functions` через `pe_rva_to_fileoff`.

## Завершение модели

Только после полного чтения sections и validation:

```c
out->ok = true;
out->sections = secs;
...
return true;
```

Ownership `secs` переходит `PeImage`.

## `pe_free`

```c
free(img->sections);
memset(img, 0, sizeof(*img));
```

Обнуление после free:

- удаляет dangling pointer из структуры;
- предотвращает случайное повторное использование старых fields;
- делает повторный `pe_free` безопасным относительно `sections == NULL`.

## `pe_find_section_for_rva`

Функция перебирает sections и проверяет:

```text
start <= RVA < end
```

`start` и `end` расширены до `uint64_t`, поэтому section у верхней границы `uint32_t` не оборачивается при сложении.

Test `test_section_range_wrap` использует:

```text
VirtualAddress = 0xFFFFFF00
VirtualSize = 0x300
```

и подтверждает корректную работу widened arithmetic.

## `pe_rva_to_fileoff`

Алгоритм:

```text
найти section
-> delta = RVA - VirtualAddress
-> доказать delta < RawSize
-> safely add RawPtr + delta
-> доказать offset < file_size
-> вернуть offset
```

Если section не найдена, проверяется headers:

```text
RVA < SizeOfHeaders
RVA < file_size
```

и используется прямое mapping.

Почему headers проверяются после sections? В корректном image их virtual ranges не должны конфликтовать. При malformed overlap chosen policy должна быть документирована. Текущий код отдаёт приоритет section membership.

## Сквозной пример `benign_richer.exe`

Report показывает:

```text
file size = 5641
ImageBase = 0x140000000
SizeOfImage = 0x7000
SizeOfHeaders = 0x400
SectionAlignment = 0x1000
FileAlignment = 0x200
Exception RVA = 0x3000
Exception Size = 0x24
```

Section `.pdata`:

```text
VirtualAddress = 0x3000
VirtualSize = 0x24
RawPtr = 0x800
RawSize = 0x200
```

Для exception RVA:

```text
delta = 0x3000 - 0x3000 = 0
file offset = 0x800 + 0 = 0x800
```

Размер `0x24` равен 36 decimal. Конец directory в файле:

```text
0x800 + 0x24 = 0x824
```

он находится внутри raw section и файла.

Section `.xdata`:

```text
VirtualAddress = 0x4000
RawPtr = 0xA00
```

Unwind RVA `0x4004`:

```text
delta = 4
file offset = 0xA04
```

Именно оттуда `unwind_parse` читает 4-byte header второй структуры.

## Переход от parser counter к finding

`pe_parse` не назначает score.

Он сохраняет:

```text
section_raw_oob = N
```

`heuristics_analyze` позднее создаёт:

```text
code = pe_section_raw_oob
family = table_integrity
severity = high
weight = 25
```

Так format layer остаётся отделён от analytical policy.

## Tests

`unit_core_edges` проверяет:

- widened section range;
- header mapping по declared size;
- empty exception directory;
- PE counters, передаваемые heuristics.

Regression sample `suspicious_section_raw_oob.exe` проверяет end-to-end:

- raw OOB;
- raw overlap;
- virtual overlap;
- score 60;
- report fields.

Mutation fuzz изменяет headers и требует controlled rejection или valid report.

## Ограничения `pe.c`

Модуль не:

- проверяет цифровую подпись;
- разбирает imports/exports;
- анализирует relocations;
- разбирает TLS;
- проверяет checksum;
- эмулирует точное loader behavior для всех malformed cases;
- поддерживает другие architectures.

Это минимальный parser, сфокусированный на exception/unwind analysis.

## Что должно быть понятно перед `unwind.c`

`pe_parse` не находит функции по machine code. Он находит exception directory по index 3 и создаёт mapping RVA-to-file-offset. Только после этого следующий модуль может прочитать массив 12-byte `RUNTIME_FUNCTION`.

