# Лекция 5. PE/COFF как контракт компоновщика, загрузчика и анализатора

## Формат файла и смысл структуры

Portable Executable, сокращённо PE, — формат образов Windows. Common Object File Format, сокращённо COFF, — связанная система структур для объектных файлов и частей PE. Название portable не означает, что конкретный EXE запускается на любой операционной системе или процессорной архитектуре. Оно означает, что общий формат способен описывать разные machine types и виды Windows images.

PE — не просто контейнер произвольных байтов. Его заголовки задают проверяемые отношения:

- где находится основной PE header;
- для какой архитектуры создан образ;
- сколько секций описано;
- как секции расположены в файле;
- по каким виртуальным адресам они должны отображаться;
- каков предпочтительный ImageBase;
- каков итоговый SizeOfImage;
- где находятся системные таблицы, включая exception directory.

Эти отношения являются контрактом между генератором файла, загрузчиком Windows и инструментами анализа. EH/Unwind Analyzer реализует ограниченного consumer этого контракта. Он не загружает образ и не исполняет его, но проверяет достаточную часть структуры, чтобы безопасно найти x64 exception metadata.

## Object file, image file и этап link

Compiler обычно создаёт object files. В них уже есть machine code, data, symbols и relocation records, но окончательные адреса ещё не назначены. **Linker**, далее компоновщик, объединяет object files и libraries, разрешает ссылки, располагает код и данные, строит import information, relocation information и другие таблицы, после чего создаёт image file.

EXE и DLL являются image files. Они предназначены для отображения загрузчиком в виртуальную память. Различие EXE и DLL выражается флагами и entry semantics, но обе категории используют PE image structure.

В проекте входной файл обязан быть PE32+ AMD64 image. PE32+ — вариант optional header для 64-разрядного адресного пространства. `Machine` должен быть `IMAGE_FILE_MACHINE_AMD64`, значение `0x8664`; optional header magic должен быть `0x20B`.

Проект намеренно не пытается применять x64 unwind decoder к PE32, ARM64 или произвольному COFF object file. Это не недостаток проверки, а граница поддерживаемого формата.

## File offset, RVA и VA как три координатные системы

**File offset** — позиция байта внутри файла на диске, отсчитываемая от нуля. Функции `buf_read`, `buf_u16le`, `buf_u32le` работают с file offsets.

**Relative Virtual Address**, сокращённо RVA, — виртуальный адрес после загрузки за вычетом base address образа. Поля `VirtualAddress` в data directories и section headers, а также адреса в `RUNTIME_FUNCTION` являются RVA.

**Virtual Address**, сокращённо VA, — адрес в виртуальном пространстве процесса. Для адреса внутри модуля:

```text
VA = ActualModuleBase + RVA
```

На диске такой же объект находится по формуле секции:

```text
delta = RVA - Section.VirtualAddress
file_offset = Section.PointerToRawData + delta
```

Формула применима только при выполнении условий принадлежности и наличия raw bytes. Нельзя вычесть `VirtualAddress` произвольной секции и считать результат правильным.

Проект проверяет, что:

```text
RVA >= section.VirtualAddress
delta < max(VirtualSize, SizeOfRawData)
delta < SizeOfRawData
PointerToRawData + delta < file_size
```

Первое условие исключает отрицательное смещение. Второе проверяет принадлежность виртуальному диапазону. Третье различает существование виртуального места и наличие соответствующего байта в файле. Четвёрто защищает от выхода за фактический входной buffer.

Секция может иметь `VirtualSize > SizeOfRawData`. Дополнительная область формируется загрузчиком, обычно с нулевым содержимым, и не имеет bytes в файле. Статический parser не должен читать её как будто она записана на диске.

## DOS header и поле e_lfanew

PE начинается с DOS-compatible header. Первые два байта содержат signature `MZ`, то есть значения `0x4D 0x5A`.

По file offset `0x3C` находится 32-разрядное поле `e_lfanew`. Оно содержит file offset PE signature. Это значение нельзя считать доверенным. Parser должен проверить, что:

- поле `e_lfanew` целиком присутствует во входе;
- вычисленный offset не выходит за размер файла;
- по этому offset доступны signature и следующие headers.

Проект использует bounded reads и safe addition, чтобы повреждённое `e_lfanew` не создавало integer overflow или out-of-bounds access.

DOS stub между DOS header и PE header для задачи проекта не имеет семантического значения. Parser не исполняет и не дизассемблирует его.

## PE signature

По offset `e_lfanew` должны лежать четыре байта:

```text
50 45 00 00
 P  E \0 \0
```

Signature отделяет DOS-compatible prefix от COFF file header. Совпадение только `MZ` недостаточно, потому что старые DOS executables и повреждённые файлы также могут начинаться с этих байтов.

## COFF file header

Сразу после PE signature находится COFF file header длиной 20 bytes. Для проекта важны:

- `Machine`;
- `NumberOfSections`;
- `SizeOfOptionalHeader`;
- `Characteristics`.

`Machine` определяет target architecture. `NumberOfSections` определяет число последующих section headers. `SizeOfOptionalHeader` задаёт фактический размер optional header и используется как граница доступа. Нельзя предполагать, что все возможные поля optional header существуют только потому, что файл имеет PE signature.

Число секций участвует в вычислении размера section table:

```text
section_table_size = NumberOfSections * 40
```

Умножение и сложение должны быть проверены до чтения. В `pe.c` все probes выполняются через безопасные функции и проверки размера `Buf`.

## Почему optional header называется optional

Название историческое. Для COFF object file этот header действительно может отсутствовать. Для PE image он обязателен. Поэтому анализатор требует его присутствия.

PE32+ optional header содержит standard fields, Windows-specific fields и data directories. Проект читает только необходимые поля:

- magic;
- `ImageBase`;
- `SectionAlignment`;
- `FileAlignment`;
- `SizeOfImage`;
- `SizeOfHeaders`;
- `NumberOfRvaAndSizes`;
- exception directory RVA и size.

Неиспользуемые поля всё равно остаются частью формата, но отсутствие их разбора означает лишь, что они не входят в аналитическую задачу инструмента.

## ImageBase

`ImageBase` — предпочтительный VA начала образа. Для PE32+ это 64-разрядное поле. Если образ загружен по этому адресу, статическая связь имеет вид:

```text
VA = ImageBase + RVA
```

При ASLR фактическая база может отличаться. Статический report сохраняет declared ImageBase, потому что анализирует file model. Dynamic collector получает actual base из `CREATE_PROCESS_DEBUG_EVENT`. Смешивать эти значения нельзя.

В `benign_richer.exe` declared ImageBase равен:

```text
0x0000000140000000
```

Например, `RVA 0x3000` соответствует preferred VA `0x140003000`, но в конкретном процессе реальный VA может быть `base_main + 0x3000`.

## SectionAlignment и FileAlignment

`SectionAlignment` задаёт выравнивание секций в памяти. `FileAlignment` задаёт выравнивание raw data в файле. Это разные пространства, поэтому значения могут различаться.

Для `benign_richer.exe`:

```text
SectionAlignment = 0x1000
FileAlignment    = 0x0200
```

Следовательно, section RVA обычно кратен 4096 bytes, а `PointerToRawData` — 512 bytes.

Проект считает section misaligned, если:

```text
VirtualAddress % SectionAlignment != 0
```

или для секции с raw content:

```text
PointerToRawData % FileAlignment != 0
```

Это structural signal. Само нарушение ещё не классифицирует назначение файла, но указывает несогласованность declared layout.

## SizeOfImage

`SizeOfImage` — размер загруженного image с учётом headers и секций, округлённый по правилам alignment. Он задаёт верхнюю границу допустимых image-relative ranges для поддерживаемой модели.

Для RVA внутри образа требуется:

```text
RVA < SizeOfImage
```

Для полуинтервала функции:

```text
BeginRVA < EndRVA
EndRVA <= SizeOfImage
```

Важно, что `EndRVA == SizeOfImage` допустим для полуинтервала: последний включённый byte находится по адресу `SizeOfImage - 1`.

Проект не использует размер файла как замену `SizeOfImage`. File layout и virtual layout различаются.

## SizeOfHeaders

`SizeOfHeaders` задаёт размер заголовочной области image. RVA, попадающий в headers и имеющий file-backed byte, может отображаться непосредственно:

```text
file_offset = RVA
```

при условии:

```text
RVA < SizeOfHeaders
RVA < file_size
```

Это отдельная ветвь `pe_rva_to_fileoff`. Не все RVA обязаны принадлежать section data.

## Data directories

В optional header находится массив `IMAGE_DATA_DIRECTORY`. Каждая запись содержит:

```c
DWORD VirtualAddress;
DWORD Size;
```

Несмотря на имя поля `VirtualAddress`, для обычных image data directories это RVA. Exception directory является записью с индексом 3.

Перед чтением directory parser обязан проверить:

- `NumberOfRvaAndSizes` достаточно велико;
- `SizeOfOptionalHeader` включает нужную запись;
- сама запись лежит внутри файла.

Microsoft отдельно указывает, что directory RVA не обязан совпадать с началом секции и что инструменты не должны полагаться только на section name. Поэтому проект находит directory по RVA, а не ищет обязательную секцию с именем `.pdata`.

## Section header

Каждый section header имеет размер 40 bytes и описывает одну секцию. Проект сохраняет:

```c
typedef struct PeSection {
    char name[9];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_ptr;
    uint32_t characteristics;
} PeSection;
```

Имя в PE занимает максимум восемь bytes и не обязано иметь завершающий zero. Parser копирует восемь bytes в массив длиной девять и добавляет terminator, чтобы получить безопасную C string.

`VirtualAddress` — RVA начала секции. `VirtualSize` — значимый размер в memory model. `SizeOfRawData` и `PointerToRawData` описывают file-backed bytes. `Characteristics` содержат flags назначения и permissions.

Для эвристик особенно важны:

```text
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ    = 0x40000000
IMAGE_SCN_MEM_WRITE   = 0x80000000
```

Проект не превращает section name в разрешение. Разрешение берётся из `Characteristics`. Имя используется только как дополнительный layout context.

## Почему parser использует max(VirtualSize, RawSize)

Разные toolchains и linker layouts могут описывать границу секции неидентично. Для определения того, к какой секции относится RVA, проект использует:

```text
span = max(VirtualSize, SizeOfRawData)
```

Это policy parser. Она позволяет распознать RVA в raw tail, если raw size больше declared virtual size. Но для фактического чтения всё равно требуется `delta < RawSize`.

Таким образом разделяются два вопроса:

1. к какой секции относится адрес в принятой модели;
2. существует ли соответствующий byte в файле.

Это разделение необходимо для корректной диагностики virtual-only и malformed ranges.

## Structural validation секций

`pe_parse` не прекращает анализ при каждой подозрительной секции. Он собирает counters:

- `section_raw_oob`;
- `section_virtual_oob`;
- `section_raw_overlaps`;
- `section_virtual_overlaps`;
- `section_misaligned`;
- `exception_directory_oob`.

**Raw out of bounds** означает:

```text
PointerToRawData + SizeOfRawData > file_size
```

**Virtual out of bounds** означает:

```text
VirtualAddress + max(VirtualSize, RawSize) > SizeOfImage
```

**Raw overlap** означает пересечение двух file ranges. **Virtual overlap** означает пересечение двух RVA ranges. Пересечение проверяется симметричной формулой полуинтервалов:

```text
a_begin < b_end && b_begin < a_end
```

Parser сохраняет counters в `PeImage`, а `heuristics_analyze` превращает их в structured findings. Это хороший пример разделения уровней: parser устанавливает факт структуры, heuristic engine оценивает его аналитическую значимость.

## Exception directory

Для AMD64 exception directory содержит массив `RUNTIME_FUNCTION`. Размер каждой записи равен 12 bytes:

```text
BeginAddress  : 4 bytes
EndAddress    : 4 bytes
UnwindData    : 4 bytes
```

Все три значения image-relative. Directory size должен быть совместим с записью фиксированной длины. Проект использует строгую policy: неполный хвост directory считается ошибкой целостности, а не молча игнорируется.

Для `benign_richer.exe`:

```text
Exception RVA  = 0x3000
Exception Size = 0x24
```

`0x24 = 36`, следовательно:

```text
36 / 12 = 3 RUNTIME_FUNCTION entries
```

Directory RVA `0x3000` попадает в `.pdata`. Если `.pdata` имеет:

```text
VirtualAddress  = 0x3000
PointerToRawData = 0x0800
```

то:

```text
delta = 0x3000 - 0x3000 = 0
file_offset = 0x0800 + 0 = 0x0800
```

Именно с file offset `0x800` parser начинает читать три записи.

## Связь `.pdata` и `.xdata`

`RUNTIME_FUNCTION.UnwindData` указывает RVA `UNWIND_INFO`. В типичном MSVC layout table entries находятся в `.pdata`, а unwind records — в `.xdata`. Однако section names не являются нормативным условием поиска.

В исследуемом sample одна запись указывает:

```text
UnwindData RVA = 0x4004
```

Если `.xdata` имеет:

```text
VirtualAddress   = 0x4000
PointerToRawData = 0x0A00
```

то:

```text
delta = 0x4004 - 0x4000 = 0x4
file_offset = 0x0A00 + 0x4 = 0x0A04
```

По `0xA04` начинается header соответствующего `UNWIND_INFO`. Следующая лекция объясняет его семантику как программу обратного преобразования prolog.

## Loader contract и parser contract

Windows loader и EH/Unwind Analyzer имеют разные задачи. Loader должен создать исполнимый image или отклонить его. Analyzer должен безопасно извлечь сведения даже из повреждённого или подозрительного файла и предоставить локализованные diagnostics.

Поэтому parser contract строже в одних местах и уже в других:

- он поддерживает только PE32+ AMD64;
- он не разрешает imports и relocations;
- он не исполняет TLS callbacks;
- он проверяет все reads по file bounds;
- он сохраняет structural anomalies вместо безусловленного продолжения;
- он не считает section name источником истины;
- он не заменяет static file model поведением реального loader.

Успешный `pe_parse` означает, что минимальная поддерживаемая модель PE извлечена безопасно. Это не означает, что Windows обязательно загрузит файл, что все directories корректны или что файл безопасен.

## Что должен уметь доказать студент

После этой лекции необходимо уметь без механического заучивания вывести:

1. почему `RVA` нельзя использовать как file offset;
2. почему actual module base отличается от declared ImageBase;
3. почему принадлежность секции не гарантирует наличие raw byte;
4. почему directory ищется по RVA, а не по имени `.pdata`;
5. почему parser counters являются фактами, а score появляется только на следующем уровне;
6. как из exception directory size получить число `RUNTIME_FUNCTION`;
7. как вручную преобразовать `UnwindData RVA` в file offset.

## Нормативный источник

Microsoft, [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Документ описывает DOS header, PE signature, COFF header, optional header, data directories, section table, RVA, VA, file pointer и exception table. При работе с проектом следует учитывать оговорку Microsoft: спецификация предназначена для разработки инструментов, но не гарантируется как исчерпывающая во всех деталях.

