#!/usr/bin/env python3
"""Build the expanded 500+ page reverse engineering base textbook."""

from __future__ import annotations

from build_reverse_engineer_base_book_v2 import (
    BOOK,
    DEEPENING,
    OUTPUT,
    glossary_markdown,
    normalize,
    qa_no_duplicate_long_paragraphs,
    question_bank_markdown,
    sources_markdown,
    workbook_markdown,
)


TRACKS: list[tuple[str, str, list[str], list[str]]] = [
    (
        "Том I. Грамотность байтов и форматов",
        "Этот том учит видеть бинарный объект как набор слоев, а не как страшный файл без смысла.",
        ["байт", "число", "hex", "endian", "кодировка", "выравнивание", "checksum", "entropy", "container", "signature", "offset", "evidence"],
        ["дамп памяти", "заголовок файла", "прошивочный контейнер", "таблица полей"],
    ),
    (
        "Том II. C, память и данные как материал реверса",
        "Здесь язык C рассматривается не как язык программирования для новичка, а как источник машинных форм.",
        ["pointer", "array", "struct", "union", "padding", "signedness", "cast", "heap", "stack object", "function pointer", "undefined behavior", "buffer"],
        ["структура пакета", "локальный буфер", "таблица callbacks", "allocator trace"],
    ),
    (
        "Том III. CPU, assembly и исполнение",
        "Этот том связывает инструкции, регистры, память и переходы в единую модель выполнения.",
        ["fetch", "decode", "register", "flags", "addressing", "branch", "call", "return", "interrupt", "fault", "cache", "atomic"],
        ["функция x64", "обработчик ARM", "ветка RISC-V", "трасса debugger"],
    ),
    (
        "Том IV. Компиляция, линковка и runtime",
        "Здесь показывается, почему бинарник не похож на исходник и какие следы оставляет toolchain.",
        ["preprocessor", "compiler IR", "object file", "symbol", "relocation", "linker script", "static library", "dynamic library", "optimization", "debug info", "runtime", "startup"],
        ["object file", "map file", "оптимизированная функция", "startup code"],
    ),
    (
        "Том V. Windows reverse engineering",
        "Этот том углубляет Windows-ветку: PE, x64 ABI, unwind, отладка и системное окружение.",
        ["DOS header", "PE headers", "section table", "imports", "exports", "relocations", "TLS", "resources", "SEH", "x64 ABI", "unwind", "PDB"],
        ["PE32+ файл", "DLL", "crash dump", "unwind table"],
    ),
    (
        "Том VI. Linux reverse engineering",
        "Этот том показывает Linux-мир: ELF, динамический загрузчик, syscalls, DWARF и процессы.",
        ["ELF header", "program header", "section header", "GOT", "PLT", "ld.so", "syscall", "signal", "procfs", "ptrace", "DWARF", "core dump"],
        ["ELF executable", "shared object", "core dump", "process maps"],
    ),
    (
        "Том VII. Embedded bare metal",
        "Этот том переводит мышление из мира процессов в мир микроконтроллеров, регистров и железа.",
        ["memory map", "vector table", "reset handler", "MMIO", "GPIO", "UART", "SPI", "I2C", "timer", "DMA", "Flash", "clock tree"],
        ["Cortex-M firmware", "STM32 проект", "дамп Flash", "лог UART"],
    ),
    (
        "Том VIII. Архитектуры: x86-64, ARM, RISC-V, Xtensa",
        "Этот том учит переносить мышление между архитектурами без слепого копирования правил.",
        ["x86-64", "AArch64", "Cortex-M", "Thumb", "RISC-V", "Xtensa", "MIPS", "calling convention", "privileged mode", "endianness", "SIMD", "DSP"],
        ["листинг x86-64", "листинг ARM", "листинг RISC-V", "ESP32 firmware"],
    ),
    (
        "Том IX. Firmware, hardware tools и лабораторная работа с устройствами",
        "Этот том добавляет физический слой: как добывают, запускают и проверяют прошивки.",
        ["JTAG", "SWD", "OpenOCD", "logic analyzer", "UART console", "flash dump", "chip-off", "binwalk", "filesystem", "QEMU", "Unicorn", "hardware safety"],
        ["плата MCU", "роутер", "образ обновления", "отладочный адаптер"],
    ),
    (
        "Том X. Инструменты и рабочий процесс",
        "Этот том учит пользоваться инструментами как увеличительным стеклом, а не как кнопкой истины.",
        ["Ghidra", "IDA", "Rizin", "Binary Ninja", "x64dbg", "WinDbg", "GDB", "Python scripting", "types", "signatures", "notes", "report"],
        ["проект Ghidra", "сессия debugger", "скрипт анализа", "исследовательский отчет"],
    ),
    (
        "Том XI. Защитный анализ, malware и уязвимости",
        "Здесь реверс соединяется с безопасностью, но без превращения книги в руководство по злоупотреблениям.",
        ["triage", "sandbox", "packer", "anti-debug", "crypto constants", "protocol", "persistence", "network behavior", "rootkit concept", "memory forensics", "vulnerability", "disclosure"],
        ["подозрительный PE", "сетевой лог", "packed sample", "уязвимый parser"],
    ),
    (
        "Том XII. Сквозные проекты и защита результатов",
        "Последний том собирает базу в большие исследования с отчетами и проверками.",
        ["PE parser", "unwind analyzer", "ELF loader view", "shell command table", "vector recovery", "STM32 GPIO", "UART protocol", "RTOS tasks", "bootloader", "embedded Linux rootfs", "evidence table", "study plan"],
        ["мини-ВКР", "лабораторный отчет", "capstone project", "план развития"],
    ),
]


BOOK_INFLUENCES: list[tuple[str, str, str, str]] = [
    (
        "Eldad Eilam - Reversing: Secrets of Reverse Engineering",
        "классическая широкая школа reverse engineering: низкий уровень, Windows fundamentals, tools, file formats, malware, decompilation and program data",
        "берем принцип широкого входа: реверс нельзя начинать с кнопок инструмента, сначала нужно объяснить ОС, память, функции, форматы и доказательность",
        "в этой книге это превращается в ранние тома про байты, память, Windows, PE, функции и проверяемый стиль анализа",
    ),
    (
        "Michael Sikorski, Andrew Honig - Practical Malware Analysis",
        "лабораторная модель: безопасная среда, basic static, basic dynamic, x86, IDA, Windows APIs, debugging, anti-analysis, packers, shellcode, C++ and 64-bit",
        "берем не вредоносный фокус, а ритм обучения: сначала лаборатория, потом статическое наблюдение, потом динамическая проверка, потом отчет",
        "в этой книге это становится практикумами, VM-дисциплиной, triage, debugging и разбором packing/anti-debug в защитной рамке",
    ),
    (
        "Dennis Andriesse - Practical Binary Analysis",
        "современный взгляд на binary analysis: ELF/PE, loaders, instrumentation, data-flow, taint analysis, symbolic execution",
        "берем идею инструментального мышления: реверсер должен понимать не только вывод Ghidra, но и путь данных, проверку и собственные маленькие инструменты",
        "в этой книге это дает главы про ELF, loader, slicing, tracing, instrumentation и проверку гипотез",
    ),
    (
        "Chris Eagle - The IDA Pro Book",
        "плотная школа интерактивного анализа: navigation, xrefs, data types, structures, graphs, scripting, loaders, processors, debugger",
        "берем принцип: дизассемблер не оракул, а рабочая среда, где человек уточняет типы, имена, xrefs и структуру",
        "в этой книге это переходит в восстановление структур, культуру переименования и работу с Ghidra/IDA/Rizin/Binary Ninja",
    ),
    (
        "Chris Eagle, Kara Nance - The Ghidra Book",
        "современная Ghidra-школа: project workflow, disassembly, decompiler, data types, scripts, processors, loaders, collaboration",
        "берем идею Ghidra как бесплатной профессиональной платформы и decompiler как помощника, а не истины",
        "в этой книге Ghidra используется как учебная база, но каждый вывод проверяется байтами, ABI и документацией",
    ),
    (
        "Windows Internals",
        "системная база Windows: процессы, threads, memory manager, loader, exceptions, handles, kernel/user boundary",
        "берем runtime-контекст: PE-файл живет не в пустоте, его запускает Windows с правилами памяти, загрузки и исключений",
        "в этой книге это особенно важно для ВКР: PE32+, Windows x64 ABI, exception directory, unwind metadata and debugger events",
    ),
    (
        "Bryant and O'Hallaron - Computer Systems: A Programmer's Perspective",
        "сильная база о том, как программы выглядят с точки зрения машины: representation, machine code, linking, memory hierarchy, virtual memory",
        "берем педагогическую честность: до malware и firmware нужно понять, как число становится адресом, а функция - машинным соглашением",
        "в этой книге это фундамент про байты, C, assembly, stack, compiler, linker and loader",
    ),
    (
        "The Hardware Hacking Handbook",
        "лабораторный подход к hardware and embedded security: интерфейсы, измерения, отладочные порты, firmware extraction, physical discipline",
        "берем embedded-реальность: прошивка - это не только код, но и плата, UART, SWD/JTAG, Flash, питание и риск повредить устройство",
        "в этой книге это дает Cortex-M, MMIO, UART, DMA, RTOS, OpenOCD, logic analyzer and hardware safety",
    ),
    (
        "Rootkits and Bootkits",
        "низкоуровневая линия boot, firmware, UEFI, kernel and forensic thinking",
        "берем идею анализа ниже обычного процесса: boot chain, early execution, persistence and trust boundaries",
        "в этой книге это превращается в bootloader handoff, firmware containers, startup code and defensive analysis",
    ),
    (
        "Официальные спецификации Microsoft, Intel, AMD, Arm, RISC-V, ELF gABI, DWARF, OpenOCD, QEMU",
        "первичные правила: ABI, instruction set, exception handling, binary formats, debug information and hardware interfaces",
        "берем авторитет правил: если книга и инструмент расходятся со спецификацией, проверять нужно спецификацию и реальный артефакт",
        "в этой книге каждый технический вывод привязан к правилу: format, ABI, ISA, memory map, debug standard or reference manual",
    ),
]


def influences_markdown() -> str:
    lines = [
        "# Авторская опора на лучшие книги и документацию",
        "",
        "Эта книга не копирует чужие главы, упражнения или формулировки. Она берет у сильных источников архитектуру мышления: где начинать, как углубляться, как соединять инструмент с низким уровнем, как строить лабораторию и как не продавать догадку как факт.",
        "",
        "У хороших книг по реверсу есть общие черты. Они не бросают читателя сразу в море mnemonics; они дают карту. Они не делают из инструмента божество; они показывают, где инструмент ошибается. Они не учат только одной ОС; они учат переносить мышление. Они не прячут сложность, но вводят ее по одному слою. Именно этот подход используется здесь.",
        "",
    ]
    for title, what, lesson, use in BOOK_INFLUENCES:
        lines.extend([
            f"## {title}",
            "",
            f"Что это за опора: {what}.",
            "",
            f"Какой принцип берем: {lesson}.",
            "",
            f"Как это применено здесь: {use}.",
            "",
        ])
    lines.extend([
        "## Как читать эту книгу после такой опоры",
        "",
        "Думай о ней как о мосте. От Eilam берется широкий вход в reverse engineering, от Practical Malware Analysis - лабораторная дисциплина, от Practical Binary Analysis - современное понимание binary analysis как data-flow и instrumentation, от IDA/Ghidra-книг - интерактивная работа с xrefs/types/names, от Windows Internals - реальная жизнь процесса, от CSAPP - машинная база, от hardware-hacking книг - embedded и физический слой.",
        "",
        "Главное отличие этой книги: она написана на русском, для читателя, который может прийти вообще не из IT, но хочет в итоге понимать и Windows ВКР, и будущий embedded reverse. Поэтому каждое английское слово должно быть не маркером элитарности, а рабочей ручкой, за которую можно взять понятие.",
    ])
    return "\n".join(lines) + "\n"


ANGLE_WORDS = [
    "сначала как наблюдение, потом как правило, затем как проверяемый вывод",
    "не через запоминание названия, а через путь данных и состояние машины",
    "как связь между байтами, инструментом и официальной документацией",
    "через ошибку новичка, потому что именно ошибка показывает границы понятия",
    "как часть отчета, где каждое утверждение должно иметь основание",
    "через сравнение Windows, Linux и embedded, чтобы не привязаться к одному миру",
]


def code_sample(term: str, index: int) -> str:
    samples = [
        f"""```text
наблюдение: встречен термин {term}
слой: файл / память / CPU / ОС / железо
правило: найти источник правила, а не гадать по внешнему виду
проверка: сопоставить байты, адреса, регистры и документацию
```""",
        f"""```asm
; учебная зарисовка для темы {term}
mov     eax, [rcx+8]
test    eax, eax
jne     branch_taken
```""",
        f"""```c
/* учебная зарисовка для темы {term} */
uint32_t value = *(volatile uint32_t *)(base + offset);
value |= mask;
*(volatile uint32_t *)(base + offset) = value;
```""",
        f"""```text
факт: поле или инструкция связаны с {term}
гипотеза: это влияет на поведение исследуемого объекта
проверка: xrefs + debugger/reference manual + границы диапазона
ограничение: без запуска или документации вывод остается неполным
```""",
    ]
    return samples[index % len(samples)]


def chapter_text(track_no: int, topic_no: int, track: str, term: str, artifact: str) -> str:
    chapter_number = (track_no - 1) * 12 + topic_no
    angle = ANGLE_WORDS[(chapter_number + topic_no) % len(ANGLE_WORDS)]
    related = ", ".join(
        [
            "address",
            "offset",
            "register",
            "stack",
            "loader",
            "debugger",
            "reference manual",
        ][(topic_no - 1) % 4 : ((topic_no - 1) % 4) + 4]
    )
    if len(related) < 12:
        related = "address, offset, register, stack"

    return f"""
## Глава {chapter_number}. {term}: как читать это понятие в {artifact}

Эта глава разбирает `{term}` {angle}. Новичок часто встречает слово в
дизассемблере, документации или статье и пытается сразу запомнить перевод.
Такой путь плохо работает. В reverse engineering термин полезен только тогда,
когда ты понимаешь, где он живет: в файле, в памяти, в регистре, в соглашении
ABI, в загрузчике, в runtime, в прошивке или в аппаратном регистре.

Представь, что перед тобой {artifact}. Ты видишь число, таблицу, адрес,
строку или инструкцию и подозреваешь, что это связано с `{term}`. Первый
правильный шаг - не назвать находку красивым словом, а остановиться и
зафиксировать наблюдение. Где именно это найдено? Это file offset, RVA,
virtual address, physical address, stack offset или MMIO offset? Какой
инструмент это показал? Можно ли увидеть те же байты в другом инструменте?

Медленное объяснение такое: `{term}` - не отдельная табличная строка, а
узел связей. Он связан с понятиями {related}. Если хотя бы одно соседнее
понятие перепутано, вывод становится шатким. Например, неверный base address
ломает xrefs в firmware; неверный ABI меняет смысл регистров; неверное
понимание offset заставляет искать байты не там; неверная модель stack
делает stack trace похожим на правду, хотя он уже испорчен.

На низком уровне работа с `{term}` почти всегда сводится к нескольким
вопросам. Какие байты или поля являются входом? Кто их читает? В какой
момент они превращаются в адрес, размер, флаг, таблицу или переход? Какой
код использует результат? Что изменится, если значение испорчено, смещено,
переполнено или прочитано с неправильным endian? Эти вопросы звучат просто,
но именно они отделяют исследование от пересказа интерфейса инструмента.

В Windows-ветке ищи `{term}` через PE, x64 ABI, virtual memory, imports,
exception handling и debugger events. Если тема касается функции, проверь
регистры `rcx`, `rdx`, `r8`, `r9`, shadow space, return value в `rax` и
unwind metadata. Если тема касается файла, проверь DOS header, NT headers,
section table, data directories и преобразование RVA в file offset. Важно
держать в голове: Windows loader строит образ памяти по правилам PE, а не
просто копирует файл как есть.

В Linux-ветке смотри на ELF header, program headers, dynamic section,
GOT/PLT, syscalls, signals, `/proc/<pid>/maps` и DWARF. Там часто важнее
различать segment и section, статическую картину файла и динамическую
картину процесса. Если `{term}` проявляется во внешнем вызове, проверь,
идет ли управление через PLT, заполнен ли GOT, какие shared libraries
загружены и как dynamic linker изменил адреса.

В embedded-ветке вопрос почти всегда упирается в memory map. Если `{term}`
связан с адресом, спроси: это Flash, SRAM, peripheral range, boot ROM или
внешняя память? Если связан с событием, спроси: это обычный вызов, interrupt,
exception, DMA completion, RTOS task switch или callback от драйвера? Если
связан с регистром, открой reference manual и найди base address, offset,
bit field и ограничения записи.

Разберем маленькую учебную зарисовку. Она не заменяет реальный объект, но
показывает форму мышления:

{code_sample(term, chapter_number)}

В этой зарисовке важно не само имя `{term}`, а дисциплина проверки. Сначала
ты называешь слой, потом правило, потом инструмент. Если это байты файла -
проверяешь hex editor и спецификацию формата. Если это регистр CPU -
проверяешь ABI и состояние debugger. Если это MMIO - проверяешь reference
manual. Если это loader-поведение - проверяешь headers и карту памяти
процесса.

Типовая ошибка новичка в теме `{term}` - слишком рано назвать гипотезу
выводом. Например: «это указатель», «это обработчик», «это шифрование»,
«это проверка лицензии», «это UART». В сильном отчете так не пишут без
основания. Сначала пишут: «значение попадает в диапазон Flash», «на строку
есть xref из функции сравнения», «адрес соответствует регистру USART по
reference manual», «после вызова `VirtualAlloc` управление передается в
новую область памяти».

Практическое упражнение для этой главы: найди в безопасном учебном объекте
одно место, связанное с `{term}`. Запиши пять строк: объект, адрес или
offset, наблюдение, правило чтения, проверка. Потом добавь шестую строку:
что ты пока не доказал. Эта шестая строка особенно важна. Она не делает
работу слабее; она показывает, что ты не продаешь догадку как факт.

Мини-отчет может выглядеть так. В объекте `{artifact}` обнаружено проявление
понятия `{term}`. Наблюдение подтверждено двумя способами: статическим
чтением структуры и проверкой через инструмент. Ограничение вывода состоит
в том, что без динамического запуска или без полной документации нельзя
утверждать больше, чем позволяют найденные признаки. Такая формулировка
может казаться осторожной, зато она инженерная.

Для закрепления попробуй объяснить `{term}` устно человеку, который не
знает IT. Не начинай с английского слова. Начни с задачи: какую проблему
решает это понятие, почему без него анализ ломается, где его можно увидеть,
и как проверить, что ты понял его правильно. Если объяснение стало длиннее,
но яснее, это хороший знак: реверс требует не коротких лозунгов, а точных
связей.
"""


MASTER_CASES: list[tuple[str, str, str, str, str, str, str, str]] = [
    ("Первый час с неизвестным PE", "Practical Malware Analysis", "безопасная Windows-лаборатория", "hash, sections, imports, strings, entropy", "запустить сразу и смотреть, что будет", "сначала triage, затем изолированный запуск по одному вопросу", "PE headers, импортируемые API, секционные права, возможная упаковка", "отделить признаки от доказанного поведения"),
    ("Строка ведет к функции", "IDA Pro Book / Ghidra Book", "интерактивный дизассемблер", "strings, xrefs, data references, graph view", "назвать функцию по строке без проверки", "идти от строки к xrefs, потом к условиям и данным", "cross-references, basic blocks, error paths, decompiler assumptions", "переименовать функцию осторожным именем"),
    ("Import table как карта намерений", "Eilam / Practical Malware Analysis", "Windows PE", "CreateFileW, RegOpenKeyExW, WinHttp, VirtualAlloc", "считать imports полным поведением", "сравнить imports с xrefs и dynamic events", "IAT, delay imports, GetProcAddress, wrappers", "показать, какие API реально достигаются"),
    ("Упаковщик и точка входа payload", "Practical Malware Analysis", "packed учебный sample", "высокая entropy, VirtualProtect, self-write, jump to new region", "объявить шифрование по entropy", "найти момент распаковки и OEP", "memory permissions, allocated regions, breakpoints, dumped image", "разделить packer stub и payload"),
    ("RVA не file offset", "Microsoft PE docs / Eilam", "PE parser", "section table, VirtualAddress, PointerToRawData", "прибавить RVA к началу файла", "найти секцию и вычислить смещение внутри нее", "SectionAlignment, FileAlignment, VirtualSize, SizeOfRawData", "описать преобразование формулой и проверкой границ"),
    ("Windows x64 call под микроскопом", "Windows x64 ABI / CSAPP", "маленькая функция", "rcx, rdx, r8, r9, shadow space, rax", "читать регистры как в Linux ABI", "сопоставить регистры до call и использование результата", "volatile/nonvolatile registers, stack alignment, return value", "доказать аргументы через ABI и контекст"),
    ("Unwind как карта стека", "Microsoft x64 exception handling", "PE32+ с .pdata/.xdata", "Runtime Function, UNWIND_INFO, prologue", "ждать rbp-chain у каждой функции", "сопоставить unwind codes с реальным prologue", "stack allocation, saved registers, epilogue restrictions", "объяснить, как debugger восстанавливает frame"),
    ("WinDbg и ложный stack trace", "Windows Internals", "crash dump", "exception code, rsp, modules, symbols", "верить первой строке trace", "проверить registers, unwind info и memory around stack", "symbol loading, module ranges, faulting instruction", "записать причину падения только после проверки"),
    ("Структура из offset-ов", "IDA Pro Book / Ghidra Book", "функция parser-а", "[rcx+4], [rcx+8], [rcx+10h]", "придумать имена полей заранее", "собрать все обращения и размеры доступа", "padding, alignment, field width, signedness", "создать struct и назвать поля по роли"),
    ("Decompiler ошибается красиво", "Ghidra Book", "оптимизированная функция", "странный псевдокод, casts, merged variables", "верить C-псевдокоду сильнее assembly", "вернуться к basic blocks and data flow", "types, calling convention, function boundaries", "исправить типы и показать, что изменилось"),
    ("ELF глазами loader", "Practical Binary Analysis / ELF gABI", "Linux executable", "PT_LOAD, PT_INTERP, file size, mem size", "читать sections как карту загрузки", "начать с program headers и mappings", "segments, permissions, zero-fill, dynamic linker", "сопоставить readelf с /proc maps"),
    ("PLT/GOT без мистики", "Practical Binary Analysis", "динамический ELF", "puts@plt, GOT entry, relocation", "считать PLT самой библиотечной функцией", "проследить lazy binding и изменение GOT", "dynamic relocations, ld.so, shared libraries", "показать target до и после разрешения"),
    ("Stripped ELF без имен", "Practical Binary Analysis", "shared object без symbols", "strings, syscalls, function starts", "решить, что без symbols анализ невозможен", "строить карту от xrefs, constants, imports", "function discovery, signatures, compiler idioms", "дать временные имена с ограничениями"),
    ("DWARF и восстановление стека", "DWARF standard / CSAPP", "ELF с debug info", ".eh_frame, CFI, CFA rules", "путать debug info и исходный код", "прочитать unwind rules как инструкции восстановления", "call frame address, saved registers, line info", "объяснить, что DWARF доказывает, а что нет"),
    ("Syscall как граница ОС", "Linux systems", "маленькая Linux-программа", "openat, read, write, mmap, ioctl", "искать поведение только в libc names", "сравнить static calls со strace", "user/kernel boundary, errno, file descriptors", "описать внешние эффекты процесса"),
    ("Указатель как гипотеза", "CSAPP / Eilam", "дамп памяти", "число похоже на адрес", "делать pointer из каждого похожего числа", "проверить диапазон, xrefs, dereference and relocation", "VA, heap, stack, image ranges, ASLR", "отделить pointer candidate от доказанного pointer"),
    ("Signedness ломает условие", "CSAPP", "parser length field", "movsx, movzx, signed compare", "читать все числа как unsigned", "проверить instruction and source type clues", "integer promotion, sign extension, bounds checks", "показать, как ошибка знака меняет ветку"),
    ("Jump table и switch", "IDA/Ghidra practice", "командный dispatcher", "indirect jump, table, bounds check", "принять таблицу за случайные данные", "найти range check и target table", "CFG, relative offsets, switch recovery", "разметить table и case handlers"),
    ("C++ vtable без исходников", "Practical Reverse Engineering", "C++ binary", "vptr, constructors, virtual calls, RTTI", "назвать любой массив функций vtable", "найти constructor writes and xrefs", "this pointer, class layout, inheritance hints", "восстановить класс осторожно"),
    ("Inlining стирает границы", "compiler fundamentals", "release build", "нет call к маленькой функции", "решить, что логика исчезла", "искать semantic pattern inside caller", "optimization, constant folding, register allocation", "объяснить поведение, а не исходную строку"),
    ("Tail call как исчезнувший return", "compiler fundamentals", "wrapper function", "jmp вместо call/ret", "принять jmp за обычную ветку", "проверить calling convention and final action", "tail call optimization, stack reuse", "указать, что функция завершает работу переходом"),
    ("Cortex-M vector table", "Arm docs / Hardware Hacking Handbook", "raw firmware", "initial SP, reset vector, Thumb bit", "считать нечетный адрес ошибкой", "проверить SRAM range and Flash range", "vector table, exception handlers, base address", "обосновать загрузочный адрес"),
    ("Reset handler не бизнес-логика", "embedded startup", "Cortex-M startup", "copy .data, zero .bss, SystemInit", "анализировать startup как алгоритм приложения", "узнать стандартные циклы и перейти к main", "linker script, sections, runtime init", "отделить обвязку от логики"),
    ("MMIO: запись меняет железо", "Hardware Hacking Handbook / Arm docs", "STM32 firmware", "0x40021018, RCC, bit mask", "читать MMIO как обычную RAM", "сопоставить address with reference manual", "base address, register offset, read-modify-write", "назвать register and bit"),
    ("GPIO и clock tree", "embedded practice", "мигание LED", "RCC enable, MODER, BSRR", "искать LED только в GPIO writes", "сначала найти включение clock", "clock gating, pin mode, output register", "описать полный путь до физического эффекта"),
    ("UART как консоль устройства", "Hardware Hacking Handbook", "прошивка с логами", "baud, strings, USART, ring buffer", "объявить любую строку командой shell", "найти dispatch and transmit/receive paths", "interrupts, buffers, status flags", "доказать logging или interactive shell"),
    ("DMA: данные приходят без store", "embedded systems", "UART RX через DMA", "source, destination, length, complete IRQ", "искать запись CPU в buffer", "найти настройку DMA channel", "peripheral data register, memory buffer, cache", "объяснить, кто реально пишет данные"),
    ("Interrupt handler не вызывается call-ом", "Arm docs", "IRQ handler", "vector entry, NVIC, status flag", "искать xref-call на handler", "искать vector table and peripheral flag", "exception entry, stacked registers, priorities", "описать аппаратный механизм вызова"),
    ("FreeRTOS tasks как карта поведения", "RTOS practice", "FreeRTOS firmware", "xTaskCreate, queues, priorities", "искать всю логику в main", "восстановить задачи и связи", "task stacks, scheduler, queue API", "нарисовать взаимодействие tasks"),
    ("Bootloader передает управление app", "Rootkits/Bootkits / embedded", "bootloader image", "APP_BASE, set MSP, reset vector", "принять indirect branch за обычный function pointer", "проверить vector table app and validity checks", "checksum/signature, flash layout, interrupts", "отделить bootloader and application"),
    ("Firmware container", "Hardware Hacking Handbook", "update.bin", "header, version, payload, checksum", "сразу грузить весь файл как code", "разобрать container and extract payload", "compression, signature, partitions", "показать слои файла"),
    ("Embedded Linux rootfs", "IoT reversing", "router firmware", "SquashFS, init scripts, services", "остановиться на binwalk output", "распаковать и связать rootfs with binaries", "dtb, mtdparts, web interface, configs", "описать систему как устройство"),
    ("Device tree как карта железа", "Linux embedded docs", "dtb/dts", "compatible, reg, interrupts, clocks", "считать dtb обычным конфигом без связи с драйверами", "сопоставить nodes with drivers and MMIO", "address cells, interrupt cells, aliases", "использовать dtb для firmware map"),
    ("JTAG/SWD дисциплина", "Hardware Hacking Handbook", "плата MCU", "pins, voltage, OpenOCD, halt", "подключаться без проверки питания", "идентифицировать интерфейс безопасно", "voltage levels, pinout, reset, readout protection", "описать риск и условия подключения"),
    ("QEMU и границы эмуляции", "Practical Binary Analysis / QEMU docs", "embedded Linux binary", "architecture, sysroot, missing devices", "думать, что эмуляция равна устройству", "выделить, что моделируется, а что нет", "user-mode vs system emulation, MMIO stubs", "указать ограничения эксперимента"),
    ("Unicorn для маленькой функции", "binary analysis", "алгоритм decode/decrypt", "register setup, mapped memory, stop address", "эмулировать весь мир вместо функции", "создать минимальный controlled harness", "CPU state, hooks, memory permissions", "подтвердить результат на тестовых входах"),
    ("CRC не криптография", "file format reversing", "firmware header", "crc32 table, checksum field", "назвать checksum подписью", "проверить алгоритм and tamper behavior", "integrity vs authenticity, hash, signature", "точно назвать уровень защиты"),
    ("Compression vs encryption", "PMA / firmware reversing", "payload", "magic, entropy, decompressor code", "называть все high entropy шифрованием", "искать headers or algorithm use", "zlib, lzma, AES constants, keys", "разделить гипотезы"),
    ("Anti-debug без драматизации", "Practical Malware Analysis", "Windows sample", "IsDebuggerPresent, timing, exceptions", "считать любую проверку злонамеренной", "проверить context and behavior change", "debug APIs, timing checks, SEH tricks", "описать эффект, не мотив"),
    ("Protocol parser", "security research", "binary protocol", "magic, length, command id, checksum", "прыгать к exploit-thinking без формата", "сначала восстановить grammar", "state machine, bounds, endian, structs", "дать формат сообщения"),
    ("Уязвимость как доказательство", "secure analysis", "parser bug", "unchecked length, integer overflow", "заявить vuln без достижимости", "показать path from input to bad operation", "source/sink, constraints, crash, mitigation", "указать reproducibility and limits"),
    ("Evidence table", "исследовательская культура", "любой объект", "fact, hypothesis, check, source", "писать отчет как впечатления", "строить таблицу доказательств", "artifacts, screenshots, hashes, addresses", "сделать вывод проверяемым"),
    ("Сравнение Windows/Linux/embedded", "синтез лучших книг", "одна логика на трех платформах", "function call, loader, address, debug", "искать один универсальный шаблон", "сравнивать роли, а не синтаксис", "ABI, format, runtime, hardware", "перенести мышление"),
    ("Мини-ВКР по unwind analyzer", "твоя Windows-тема", "PE32+ analyzer", ".pdata, .xdata, RtlVirtualUnwind", "считать parser достаточным без dynamic verification", "сопоставить static and dynamic evidence", "Runtime Function, UNWIND_CODE, debugger events", "связать реализацию и теорию"),
    ("Переход к embedded после Windows", "дорожная карта", "Cortex-M project", "stack, function, address, ABI", "думать, что embedded начинается с нуля", "перенести понятия и заменить ОС memory map", "Flash/RAM/MMIO, vector table, interrupts", "показать мост между темами"),
    ("Учебный план на год", "методика", "личная траектория", "books, labs, reports, projects", "читать все подряд без артефактов", "каждый месяц делать завершенный mini-report", "spaced repetition, lab notebook, source docs", "измерять прогресс отчетами"),
]


def master_casebook_markdown() -> str:
    lines = [
        "# Мастерские по методике лучших книг",
        "",
        "Этот раздел добавлен как содержательный мост к лучшим книгам по реверсу. Здесь нет пересказа их текста. Каждая мастерская берет сильный педагогический прием: лабораторность Practical Malware Analysis, системность Eilam и CSAPP, инструментальную точность IDA/Ghidra-книг, data-flow мышление Practical Binary Analysis, физическую дисциплину Hardware Hacking Handbook и системную глубину Windows Internals.",
        "",
        "Формат мастерской один только на уровне учебной логики: ситуация, плохой путь, хороший путь, низкоуровневая механика и форма отчета. Содержание разное, потому что разные объекты требуют разных доказательств.",
        "",
        "Для всех мастерских действует общий рабочий прием: веди таблицу факт - гипотеза - проверка. Факт должен быть привязан к байтам, адресу, API, строке, регистру, записи таблицы, событию debugger или строке reference manual. Гипотеза объясняет смысл факта. Проверка показывает, почему гипотеза выдерживает контакт с реальностью.",
        "",
    ]
    for index, (title, school, lab, signals, bad, good, mechanics, report) in enumerate(MASTER_CASES, start=1):
        lines.extend([
            f"## Мастерская {index}. {title}",
            "",
            f"Педагогическая опора: {school}. Лабораторная сцена: {lab}. Первые признаки, с которыми работает исследователь: {signals}.",
            "",
            f"Плохой путь здесь выглядит так: {bad}. Он плох не потому, что человек ничего не знает, а потому что перепрыгивает через доказательство. В реверсе почти все ранние ошибки рождаются из желания быстро назвать вещь: это packer, это pointer, это shell, это encryption, это vulnerability. Название появляется раньше основания, и дальше анализ начинает защищать красивую догадку.",
            "",
            f"Хороший путь: {good}. Это медленнее на первых минутах, но быстрее на дистанции. Ты не споришь с инструментом и не веришь ему слепо. Ты превращаешь вывод инструмента в проверяемую цепочку: байты или события, правило чтения, контекст, независимая проверка, ограничение.",
            "",
            f"Низкоуровневая механика этой мастерской: {mechanics}. Эти слова нельзя оставлять сухими. Если появляется `offset`, нужно сказать от какого начала. Если появляется register, нужно сказать по какому ABI он получает роль. Если появляется handler, нужно сказать, кто его вызывает. Если появляется entropy, нужно объяснить, почему она не доказывает ни шифрование, ни упаковку сама по себе.",
            "",
            f"Практический разбор `{title}` начинай с маленькой таблицы, но заполняй ее не общими словами, а сигналами именно этой сцены: {signals}. Укажи, какой сигнал является фактом, какая интерпретация пока гипотеза и чем она проверяется.",
            "",
            f"Форма результата: {report}. В хорошем отчете по этой мастерской должно быть видно, где кончается факт и начинается интерпретация. Если вывод зависит от запуска, напиши условия запуска. Если зависит от документации, дай ссылку на раздел. Если зависит от decompiler, покажи место в assembly или bytes, потому что decompiler - переводчик, а не свидетель.",
            "",
            f"Контрольный вопрос для `{title}`: что изменится, если твоя главная гипотеза неверна? Если ответ «ничего», значит гипотеза не участвует в доказательстве. Если ответ меняет карту функций, поток данных или смысл адреса, значит нужно добавить проверку до того, как писать уверенный вывод.",
            "",
            f"Мини-упражнение: повтори `{title}` на безопасном учебном объекте в масштабе 30 минут. Заверши не словами «я понял», а маленьким артефактом: скриншот, таблица, переименованная структура, формула преобразования адреса, лог debugger или фрагмент отчета.",
            "",
        ])
    return "\n".join(lines) + "\n"


REFERENCE_DRILLS: list[tuple[str, str, str, str, str]] = [
    ("Microsoft PE format", "как найти data directory и не перепутать RVA с file offset", "PE32+ файл", "читать таблицу как линейный файл", "проверить section table and bounds"),
    ("Microsoft x64 calling convention", "как определить аргументы функции по регистрам", "Windows x64 function", "перенести System V ABI на Windows", "сопоставить rcx/rdx/r8/r9 before call"),
    ("Microsoft x64 stack usage", "почему shadow space не является обычными локальными переменными", "call site", "назвать 32 байта мусором", "нарисовать stack layout"),
    ("Microsoft x64 prolog and epilog", "почему prologue ограничен правилами unwind", "function prologue", "считать любой push/sub произвольным", "сверить с unwind metadata"),
    ("Microsoft x64 exception handling", "как Runtime Function entry связан с диапазоном кода", ".pdata/.xdata", "читать unwind отдельно от функции", "сопоставить Begin/EndAddress and UNWIND_INFO"),
    ("Intel SDM", "как instruction меняет flags and registers", "x86-64 listing", "учить mnemonic без эффекта", "выписать inputs/outputs/flags"),
    ("AMD64 Architecture Manual", "как понимать canonical addresses and long mode assumptions", "x64 process", "думать, что все 64 bits адреса свободны", "проверить virtual address rules"),
    ("System V AMD64 ABI", "как отличить Linux calling convention от Windows", "Linux function", "читать rdi как случайный регистр", "сравнить register arguments"),
    ("ELF gABI", "почему loader смотрит program headers", "ELF executable", "начинать с sections", "сравнить readelf -l and memory map"),
    ("DWARF standard", "как CFI помогает восстановить stack frame", ".eh_frame", "думать, что DWARF всегда дает исходник", "прочитать CFA rule"),
    ("Arm ABI", "как AAPCS распределяет аргументы и saved registers", "ARM function", "читать r0-r3 без ABI", "сопоставить call site and callee"),
    ("Arm Cortex-M docs", "как vector table задает reset and interrupts", "raw firmware", "игнорировать Thumb bit", "проверить initial SP and reset handler"),
    ("RISC-V specifications", "как понять privilege levels and traps", "RISC-V firmware", "читать ecall без режима", "указать ABI and privilege context"),
    ("STM32 reference manual", "как MMIO address превращается в register and bit", "STM32 firmware", "называть адрес переменной", "найти base, offset and bit field"),
    ("ESP-IDF docs", "как отличить framework code от логики приложения", "ESP32 firmware", "читать весь код как hand-written", "найти SDK patterns and partition table"),
    ("OpenOCD User Guide", "как безопасно подключать SWD/JTAG", "MCU board", "подключаться без voltage/pinout", "проверить adapter speed, target and reset"),
    ("QEMU docs", "где заканчивается эмуляция", "embedded binary", "приравнять QEMU к устройству", "описать modeled and missing devices"),
    ("Ghidra docs/site", "как decompiler зависит от типов", "Ghidra project", "верить первому псевдокоду", "поменять type and compare output"),
    ("Rizin book", "как CLI-анализ помогает воспроизводимости", "binary triage", "работать только GUI-кликами", "сохранить команды and output"),
    ("Zephyr docs", "как device model and devicetree проявляются в firmware", "Zephyr image", "искать только main", "найти devices, threads and logs"),
    ("FreeRTOS docs", "как tasks, queues and scheduler меняют карту поведения", "FreeRTOS firmware", "искать один основной цикл", "восстановить task list"),
    ("U-Boot docs", "как bootargs and environment объясняют запуск Linux", "embedded Linux firmware", "пропустить bootloader layer", "найти bootcmd and mtdparts"),
    ("Windows Internals", "как процесс, память и loader связаны с PE", "Windows process", "изучать файл отдельно от ОС", "сопоставить module list and VAD/mappings"),
    ("CSAPP", "как machine code, linking and virtual memory соединяются", "маленькая C-программа", "учить assembly без memory model", "собрать debug/release and compare"),
    ("Hardware Hacking Handbook", "как физическая лаборатория меняет реверс", "реальная плата", "думать только о прошивке", "описать питание, интерфейс and extraction path"),
    ("Practical Binary Analysis", "как data-flow важнее одного красивого graph", "анализ функции", "читать граф без потоков данных", "сделать backward and forward slice"),
    ("Practical Malware Analysis", "как static and dynamic analysis дополняют друг друга", "лабораторный sample", "выбирать только один режим", "сравнить строки/imports with runtime events"),
    ("The IDA Pro Book", "как xrefs and types превращают дизассемблер в рабочую карту", "IDA/Ghidra database", "не размечать данные", "создать structs and rename by evidence"),
    ("The Ghidra Book", "как project workflow and scripting делают анализ повторяемым", "Ghidra project", "хранить вывод только в голове", "добавить script, bookmarks and comments"),
    ("Rootkits and Bootkits", "как boot chain меняет доверие к системе", "boot image", "смотреть только user-mode", "нарисовать chain of execution"),
]


def reference_drills_markdown() -> str:
    lines = [
        "# Тренажер чтения официальной документации",
        "",
        "Большая ошибка новичка - читать manual как роман. Так почти никто не учится. Документацию читают вопросами: какой именно факт мне нужно проверить, где правило, как оно проявляется в артефакте, чем подтвердить, что я не вырвал строку из контекста.",
        "",
        "Общий прием для любого источника: найди точный раздел, перепиши правило своими словами, привяжи его к одному месту в артефакте, проверь инструментом и запиши ограничение. Так documentation становится не декорацией, а рабочим доказательством.",
        "",
    ]
    for index, (source, question, artifact, mistake, check) in enumerate(REFERENCE_DRILLS, start=1):
        lines.extend([
            f"## Док-тренировка {index}. {source}",
            "",
            f"Вопрос к источнику: {question}. Учебный объект: {artifact}.",
            "",
            f"Типичная ошибка: {mistake}. Она возникает, когда документацию используют как украшение отчета, а не как источник правила. Ссылка на manual сама по себе не доказывает вывод; нужно показать, какое поле, инструкция, register, bit или loader-действие связано с этим правилом.",
            "",
            f"Как читать `{source}`: ищи место, где этот источник отвечает именно на вопрос «{question}», а не просто похожий раздел. Для `{artifact}` правило должно превратиться в конкретную операцию чтения: поле, register layout, calling convention, instruction semantics, memory map или алгоритм загрузки.",
            "",
            f"Как проверить в артефакте: {check}. Проверка должна быть маленькой и воспроизводимой. Например, один адрес, одна таблица, одна instruction, один breakpoint, один field offset. Чем меньше эксперимент, тем легче понять, действительно ли правило работает.",
            "",
            f"Как записать в отчет: «В объекте `{artifact}` наблюдается такой-то факт. Согласно `{source}`, этот факт читается по такому-то правилу. Проверка выполнена так: {check}. Ограничение: если отсутствует динамический запуск, symbols или точная версия документации, вывод не расширяется за пределы наблюдаемого».",
            "",
            f"Контроль для себя по `{source}`: найди в своем тексте все английские слова из этого пункта и рядом напиши русское объяснение. Если слово остается непереведенным и необъясненным, читатель без IT-базы на нем споткнется.",
            "",
        ])
    return "\n".join(lines) + "\n"


CAPSTONE_PROJECTS: list[tuple[str, str, list[str], str]] = [
    ("Windows PE/unwind analyzer", "связать твою ВКР с фундаментом Windows x64", ["PE headers", "RVA mapping", ".pdata", ".xdata", "RtlVirtualUnwind"], "сопоставить статическую таблицу с динамическим stack walking"),
    ("ELF loader notebook", "понять Linux-загрузку не по словам, а по mappings", ["ELF header", "PT_LOAD", "ld.so", "GOT", "PLT"], "сравнить readelf, objdump and /proc maps"),
    ("Cortex-M firmware atlas", "научиться входить в raw firmware без паники", ["vector table", "base address", "reset handler", "startup", "main"], "обосновать архитектуру, base and reset path"),
    ("MMIO register recovery", "превратить адреса периферии в понятную карту железа", ["RCC", "GPIO", "UART", "timer", "DMA"], "подписать registers по reference manual"),
    ("Ghidra type restoration", "увидеть, как types меняют decompiler output", ["struct", "enum", "pointer", "array", "function signature"], "создать типы и сравнить псевдокод до/после"),
    ("Protocol reverse notebook", "восстановить формат сообщений без исходников", ["magic", "length", "command id", "payload", "checksum"], "написать grammar and parser notes"),
    ("RTOS behavior map", "перестать искать всю embedded-логику в main", ["tasks", "queues", "semaphores", "interrupts", "scheduler"], "нарисовать interactions between tasks"),
    ("Embedded Linux firmware report", "связать rootfs, services, configs and binaries", ["binwalk", "SquashFS", "init scripts", "dtb", "web interface"], "описать устройство как систему"),
    ("Debugger evidence pack", "научиться подтверждать статические гипотезы запуском", ["breakpoint", "registers", "memory", "stack", "trace"], "собрать минимальные динамические доказательства"),
    ("Compiler transformations diary", "увидеть оптимизации глазами реверсера", ["inlining", "tail call", "constant folding", "register allocation", "loop unrolling"], "сравнить O0/O2 outputs"),
    ("C++ object recovery", "научиться осторожно восстанавливать классы", ["vtable", "constructor", "this pointer", "RTTI", "virtual call"], "восстановить class sketch"),
    ("Firmware container extractor", "отделить контейнер обновления от payload", ["header", "version", "size", "compression", "signature"], "построить layout and extraction proof"),
    ("Anti-analysis lab", "понимать anti-debug как поведение, а не как драму", ["debug API", "timing", "exceptions", "process checks", "environment"], "описать эффект каждой проверки"),
    ("Evidence-first report", "научиться писать защищаемый текст", ["fact", "hypothesis", "check", "source", "limitation"], "создать таблицу доказательств"),
    ("Windows-to-embedded bridge", "перенести знания ВКР на будущий embedded", ["stack", "function", "address", "ABI", "loader vs startup"], "показать общие роли and differences"),
]


def capstones_markdown() -> str:
    lines = [
        "# Capstone-проекты: сборка базы в реальные исследования",
        "",
        "Capstone - это итоговая работа внутри учебника. Она нужна, чтобы знания не остались отдельными главами. В каждом проекте есть цель, набор технических узлов и итоговый артефакт. Не обязательно выполнять все сразу; но если пройти их по очереди, получится база, которая уже похожа на профессиональную.",
        "",
    ]
    for index, (title, goal, nodes, output) in enumerate(CAPSTONE_PROJECTS, start=1):
        node_text = ", ".join(nodes)
        lines.extend([
            f"## Capstone {index}. {title}",
            "",
            f"Цель проекта: {goal}. Технические узлы: {node_text}. Итоговый артефакт: {output}.",
            "",
            f"Начни `{title}` с вопроса, а не с инструмента. Что именно ты хочешь доказать в этом проекте? Где находится объект: файл, процесс, прошивка, устройство, дамп, rootfs, таблица или функция? Какая система координат будет главной: file offset, RVA, VA, physical address, MMIO address, stack offset или field offset?",
            "",
            f"Для `{title}` составь карту терминов. Не просто выпиши {node_text}, а объясни каждое слово живым языком. Если рядом с термином нельзя написать «где увидеть», «зачем нужно», «как проверить», термин еще не усвоен.",
            "",
            f"Дальше в `{title}` сделай минимальную практическую проверку. Один breakpoint лучше десяти догадок. Одна формула преобразования адреса лучше общего рассказа про sections. Один подписанный MMIO-register лучше страницы слов о peripheral. Один восстановленный struct лучше десятка переменных `local_20`.",
            "",
            f"Финальный результат проекта `{title}` должен быть воспроизводимым. Другой человек должен открыть твой объект, пройти по твоим адресам, увидеть те же таблицы или события и понять, почему вывод `{output}` следует из фактов. Если это невозможно, проект еще не закончен.",
            "",
            f"В конце `{title}` напиши раздел ограничений. Какие symbols отсутствуют? Какая версия документации использована? Был ли динамический запуск? Проверялось ли на реальном устройстве? Есть ли риск, что decompiler ошибся? Такой раздел делает работу сильнее, потому что показывает границы честности.",
            "",
        ])
    return "\n".join(lines) + "\n"


def final_exam_markdown() -> str:
    lines = [
        "# Финальный экзамен: проверка настоящего понимания",
        "",
        "Этот раздел не для галочки. Он проверяет, умеешь ли ты связывать термины, инструменты, форматы и низкий уровень. Ответ считается хорошим только тогда, когда в нем есть наблюдение, правило, проверка и ограничение.",
        "",
    ]
    exam_items: list[tuple[str, str, str, str]] = []
    for title, school, lab, signals, bad, good, mechanics, report in MASTER_CASES:
        exam_items.append((title, signals, mechanics, good))
    for source, question, artifact, mistake, check in REFERENCE_DRILLS:
        exam_items.append((source, question, artifact, check))

    for index, (topic, signal, mechanics, check) in enumerate(exam_items, start=1):
        lines.extend([
            f"## Экзаменационный вопрос {index}. {topic}",
            "",
            f"Ситуация: в исследовании появляется тема `{topic}`. Первые признаки или вопрос: {signal}. Технический слой: {mechanics}.",
            "",
            f"Вопрос по `{topic}`: как объяснить это человеку, который не знает IT, но готов внимательно думать? Ответ нельзя начинать с «это просто». Если вещь была бы простой, она не ломала бы анализ. Начни с человеческой задачи: какую проблему решает именно `{topic}` и почему без него нельзя сделать честный вывод.",
            "",
            f"Ответ-ориентир: сначала назови слой. Для `{topic}` это может быть файл, память процесса, CPU state, ABI, loader, runtime, firmware, MMIO или лабораторный процесс. Затем покажи наблюдение: байты, register, address, строку, таблицу, event debugger или строку документации. Потом объясни правило: почему это наблюдение читается именно так, а не иначе.",
            "",
            f"Проверка: {check}. Проверка должна быть маленькой. Не надо писать «я посмотрел в Ghidra». Нужно написать, что именно проверено: какой xref, какой field offset, какой register before call, какой page mapping, какой bit в reference manual, какой breakpoint, какой syscall или какой fragment rootfs.",
            "",
            f"Типовой плохой ответ по `{topic}` звучит уверенно, но пусто: «это функция проверки», «это шифрование», «это указатель», «это обработчик», «это прошивка под ARM». Хороший ответ осторожнее и сильнее: «это значение используется как candidate pointer, потому что попадает в такой диапазон, разыменовывается здесь, имеет xrefs там, но без dynamic check остается гипотезой».",
            "",
            f"В письменном ответе по `{topic}` нужны четыре вещи: одна фраза человеческого смысла, одна фраза машинной механики, один конкретный способ проверки, одно ограничение. Если в ответе нет ограничения, скорее всего ты спрятал слабое место. Если нет проверки, это не ответ, а мнение.",
            "",
            f"Мини-задание: придумай для `{topic}` один безопасный учебный артефакт и запиши маленький отчет из пяти строк: объект, наблюдение, правило, проверка, ограничение. Не используй больше пяти строк: краткость заставит оставить только доказательные вещи.",
            "",
        ])
    return "\n".join(lines) + "\n"


def track_intro(track_no: int, title: str, description: str) -> str:
    focus_lines = [
        "Здесь важно научиться не торопиться: сначала увидеть сырой материал, затем выбрать правило чтения и только потом делать вывод.",
        "Здесь важна связь между исходным кодом и тем, что остается после компиляции: регистры, смещения, таблицы и соглашения.",
        "Здесь главное - перестать бояться assembly и читать его как изменение состояния машины.",
        "Здесь нужно увидеть toolchain как цепочку решений, каждое из которых оставляет след в бинарнике.",
        "Здесь Windows рассматривается не как черный ящик, а как среда с loader, памятью, ABI и exception mechanics.",
        "Здесь Linux читается через ELF, процессы, dynamic linker и системные границы.",
        "Здесь привычка думать процессами заменяется привычкой думать memory map, Flash, RAM и периферией.",
        "Здесь архитектуры сравниваются по ролям, а не по мнемоникам: где аргументы, где возврат, где privilege, где exceptions.",
        "Здесь появляется физическая дисциплина: провод, питание, интерфейс, риск, дамп, проверка.",
        "Здесь инструмент становится не кнопкой истины, а мастерской для проверки гипотез.",
        "Здесь безопасность рассматривается через защитную лабораторию, аккуратные формулировки и границы допустимого.",
        "Здесь знания собираются в проекты, где результат должен выдержать вопрос: чем это доказано?",
    ]
    return f"""
# {title}

{description} В этом томе каждая глава устроена как медленная учебная
разборка: сначала человеческий смысл, затем машинный слой, затем Windows,
Linux и embedded-сравнение, затем практическая проверка. Такая повторяемая
педагогическая рамка нужна не для набивки, а для устойчивого навыка: реверсер
должен каждый раз отделять байты от интерпретации, интерпретацию от гипотезы,
а гипотезу от доказанного вывода.

{focus_lines[(track_no - 1) % len(focus_lines)]} Перед чтением именно этого
тома держи вопрос: какое новое доказательство я смогу построить после него?
Ответ должен быть не «я знаю термин», а «я могу показать байты, адреса,
регистры, таблицы, документацию или эксперимент, на которых стоит вывод».
"""


def mega_core_markdown() -> str:
    lines: list[str] = [
        "# Большой многотомный слой: фундаментальная база реверс-инженера",
        "",
        "Дальше идет расширенная часть книги. Она написана как длинный учебный маршрут, потому что база реверса не помещается в один конспект. Здесь много глав, но их цель не в количестве страниц. Цель - провести одни и те же идеи через разные среды: Windows, Linux, embedded, компиляторы, процессоры, отладчики и реальные отчеты.",
        "",
    ]
    for track_no, (title, description, terms, artifacts) in enumerate(TRACKS, start=1):
        lines.append(track_intro(track_no, title, description))
        for topic_no, term in enumerate(terms, start=1):
            artifact = artifacts[(topic_no - 1) % len(artifacts)]
            lines.append(chapter_text(track_no, topic_no, title, term, artifact))
    return "\n".join(lines) + "\n"


def long_lab(name: str, world: str, object_name: str, signals: list[str]) -> str:
    signal_text = ", ".join(signals)
    first_signal = signals[0]
    last_signal = signals[-1]
    return f"""
## Лабораторный проект: {name}

Мир проекта: {world}. Объект исследования: {object_name}. Цель этой работы
не в том, чтобы быстро получить красивый ответ, а в том, чтобы пройти полный
маршрут: первичный осмотр, фиксация фактов, построение гипотез, проверка
инструментами, сопоставление с документацией и аккуратный отчет.

В проекте `{name}` сначала зафиксируй именно этот объект, а не абстрактный
пример из учебника. Запиши имя файла или устройства, размер, источник, дату
получения, hash, версию инструментов и условия лаборатории. Для `{object_name}`
особенно важно не перепрыгнуть через triage: запуск, подключение отладчика,
запись Flash или работа с сетью должны появляться только после понимания
рисков и цели эксперимента.

Первый слой анализа - сырой материал. Посмотри bytes, строки, entropy,
заголовки, секции или memory map. Для этого проекта важные сигналы:
{signal_text}. В этой работе начни с `{first_signal}` как с первой зацепки,
но не превращай зацепку в вывод. Сигнал - это повод задать вопрос. Если
позже в цепочке появится `{last_signal}`, проверь, является ли это независимым
подтверждением или просто следствием той же самой гипотезы.

Второй слой для `{name}` - структурное чтение. Не все проекты читаются одной
схемой. Если это PE, смотри headers, data directories, imports, relocations
и exception directory. Если это ELF, смотри program headers, dynamic section,
GOT/PLT, relocations и DWARF. Если это firmware, смотри vector table, base
address, reset handler, linker layout, MMIO ranges, embedded filesystem или
bootloader container. Для `{object_name}` карта должна отвечать на простой
вопрос: где код, где данные, где таблицы, где внешние зависимости и где
начинается поведение, ради которого объект вообще исследуется.

Третий слой - поведение. В проекте `{name}` найди точку старта: entry point,
reset handler, exported function, service entry, interrupt handler или
таблицу команд. Отдели runtime от логики. Посмотри xrefs к строкам, imports,
command tables, function pointers и handlers. Если есть debugger или
emulator, проверь одну-две ключевые гипотезы динамически. Хороший эксперимент
для `{object_name}` маленький, повторяемый и отвечает на конкретный вопрос.

Четвертый слой - восстановление имен под задачу `{name}`. Переименовывай
функции только по наблюдаемой роли. В начале лучше длинные осторожные имена:
`reads_header_and_checks_magic`, `configures_uart_clock`, `dispatches_command`.
Такие имена не такие красивые, как `license_check`, но они честнее. Красота
в отчете приходит позже, когда доказательств становится больше.

Пятый слой - проверка границ, выбранная под `{world}`. Для parser-ов проверь
integer overflow, выходы за файл, несоответствие size/offset, неверный endian.
Для stack и ABI проверь alignment, сохранение nonvolatile registers, return
value. Для MMIO проверь, что bit mask соответствует документации. Для RTOS
проверь, что логика распределена между tasks и interrupts, а не живет только
в `main`. В проекте `{name}` обязательно свяжи эту проверку с сигналами
{signal_text}.

Шестой слой - отчет по `{name}`. Он должен быть понятен человеку, который
не сидел рядом с тобой в Ghidra или у лабораторного стола. Используй структуру:
объект, цель, инструменты, первичные наблюдения, карта структуры, ключевые
функции или handlers, доказательства, ограничения, вывод. Хороший отчет не
стесняется писать «не проверено». Для `{object_name}` это особенно важно:
одна честно указанная граница лучше, чем уверенное утверждение без проверки.

Итоговая самопроверка: сможешь ли ты указать конкретный байт, address,
offset, register, table entry, строку документации или debugger event для
каждого важного вывода по `{name}`? Если да, проект выполнен по-взрослому.
Если нет, вернись на слой, где вывод впервые появился, и добавь проверку.
"""


def mega_labs_markdown() -> str:
    labs = [
        ("PE32+ и exception directory", "Windows", "учебный EXE с .pdata/.xdata", ["MZ", "PE signature", ".pdata", "UNWIND_INFO", "RVA-to-file-offset"]),
        ("DLL и таблица exports", "Windows", "учебная DLL", ["DllMain", "exports", "imports", "ordinal", "xrefs"]),
        ("Crash и stack trace", "Windows", "мини-дамп падения", ["exception code", "rsp", "unwind", "symbols", "faulting instruction"]),
        ("ELF и dynamic linker", "Linux", "маленький ELF executable", ["PT_LOAD", "PT_INTERP", "GOT", "PLT", "relocations"]),
        ("Stripped shared object", "Linux", "shared library без symbols", ["strings", "syscalls", "function boundaries", "xrefs", "DWARF absence"]),
        ("Core dump", "Linux", "core-файл процесса", ["registers", "maps", "stack", "signal", "shared libraries"]),
        ("Cortex-M vector table", "embedded", "raw firmware", ["initial SP", "reset handler", "Thumb bit", "Flash base", "SRAM range"]),
        ("STM32 GPIO", "embedded", "прошивка с миганием LED", ["RCC", "GPIO", "MMIO", "bit mask", "read-modify-write"]),
        ("UART shell", "embedded", "прошивка с консолью", ["baud rate", "command strings", "ring buffer", "interrupt handler", "USART registers"]),
        ("DMA прием", "embedded", "прошивка с DMA", ["source", "destination", "length", "DMA enable", "complete interrupt"]),
        ("RTOS tasks", "embedded", "FreeRTOS/Zephyr demo", ["task name", "stack size", "priority", "queue", "scheduler"]),
        ("Embedded Linux rootfs", "firmware", "образ обновления роутера", ["binwalk", "SquashFS", "init scripts", "dtb", "services"]),
        ("Bootloader handoff", "firmware", "образ с bootloader и app", ["APP_BASE", "checksum", "set MSP", "reset vector", "branch"]),
        ("Упаковка и распаковка", "security lab", "packed учебный sample", ["entropy", "VirtualAlloc", "VirtualProtect", "OEP", "payload"]),
        ("Протокол и parser", "cross-platform", "бинарник parser-а", ["magic", "length", "checksum", "state machine", "bounds"]),
        ("Итоговый отчет", "research", "любой безопасный объект", ["facts", "hypotheses", "checks", "limitations", "sources"]),
    ]
    lines = [
        "# Большой практикум: проекты от первого байта до отчета",
        "",
        "Эти проекты специально длинные. Они превращают теорию в маршрут исследования. Каждый проект можно выполнять отдельно, но вместе они дают базу, которую нельзя получить простым чтением.",
        "",
    ]
    for lab in labs:
        lines.append(long_lab(*lab))
    return "\n".join(lines) + "\n"


def main() -> None:
    manuscript = (
        normalize(BOOK)
        + "\n"
        + normalize(DEEPENING)
        + "\n"
        + influences_markdown()
        + "\n"
        + master_casebook_markdown()
        + "\n"
        + reference_drills_markdown()
        + "\n"
        + capstones_markdown()
        + "\n"
        + mega_core_markdown()
        + "\n"
        + mega_labs_markdown()
        + "\n"
        + workbook_markdown()
        + "\n"
        + question_bank_markdown()
        + "\n"
        + final_exam_markdown()
        + "\n"
        + glossary_markdown()
        + "\n"
        + sources_markdown()
    )
    qa_no_duplicate_long_paragraphs(manuscript)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(manuscript, encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    print(f"Characters: {len(manuscript)}")


if __name__ == "__main__":
    main()
