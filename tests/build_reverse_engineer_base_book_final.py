#!/usr/bin/env python3
"""Build the final broad reverse-engineering textbook revision."""

from __future__ import annotations

from textwrap import dedent

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
from build_reverse_engineer_base_book_mega import (
    TRACKS,
    capstones_markdown,
    influences_markdown,
    master_casebook_markdown,
    mega_labs_markdown,
    reference_drills_markdown,
)


ADDITIONAL_TRACKS: list[tuple[str, str, list[str], list[str]]] = [
    (
        "Том XIII. Mach-O, Apple и мобильная среда",
        "Этот том закрывает Apple-ветку: Mach-O, dyld, подписи, Objective-C, Swift и ограничения мобильной платформы.",
        [
            "Mach-O header",
            "load command",
            "segment/section",
            "dyld",
            "codesign",
            "entitlements",
            "Objective-C runtime",
            "Swift metadata",
            "iOS sandbox",
            "IPA",
            "arm64e/PAC",
            "crash log",
        ],
        ["Mach-O binary", "iOS application bundle", "macOS dylib", "Apple crash report"],
    ),
    (
        "Том XIV. Android, ART, JNI и мобильный Linux",
        "Этот том связывает Android как Linux-систему, managed-runtime, native-библиотеки и мобильную лабораторию.",
        [
            "APK",
            "DEX",
            "ART",
            "OAT/VDEX",
            "JNI",
            "Binder IPC",
            "SELinux",
            "A/B update",
            "boot image",
            "native library",
            "Frida on Android",
            "logcat",
        ],
        ["APK package", "Android native library", "system image", "instrumented test device"],
    ),
    (
        "Том XV. Managed runtimes: .NET, JVM, bytecode",
        "Этот том объясняет, почему не весь реверс начинается с native assembly: иногда главный слой - байткод, метаданные и JIT.",
        [
            "managed code",
            "IL",
            "metadata token",
            "assembly manifest",
            ".NET JIT",
            "GC",
            "Java class file",
            "JVM operand stack",
            "constant pool",
            "verification",
            "reflection",
            "obfuscator",
        ],
        [".NET assembly", "Java class file", "managed crash", "decompiler output"],
    ),
    (
        "Том XVI. Kernel, drivers, UEFI и boot chain",
        "Этот том аккуратно вводит уровни ниже обычного процесса: firmware, загрузку ОС, kernel-mode и драйверные границы.",
        [
            "UEFI",
            "DXE driver",
            "PEI",
            "ACPI table",
            "kernel mode",
            "driver object",
            "IRP",
            "IOCTL",
            "Linux kernel module",
            "sysfs/debugfs",
            "eBPF",
            "Secure Boot",
        ],
        ["UEFI image", "Windows driver", "Linux kernel module", "boot log"],
    ),
    (
        "Том XVII. Защита, obfuscation и автоматизированный анализ",
        "Этот том показывает защитные техники и инструменты анализа без превращения учебника в инструкцию по вредоносной эксплуатации.",
        [
            "packer",
            "anti-debug",
            "control-flow flattening",
            "opaque predicate",
            "string encryption",
            "VM-based obfuscation",
            "YARA",
            "capa",
            "Frida",
            "fuzzing",
            "symbolic execution",
            "taint analysis",
        ],
        ["defensive lab sample", "analysis rule", "instrumentation script", "coverage report"],
    ),
    (
        "Том XVIII. Hardware security и полевые системы",
        "Этот том расширяет embedded-реверс до физического мира: сигналы, память, шины, питание, отладочные порты и доверенная загрузка.",
        [
            "side channel",
            "fault injection",
            "glitching",
            "logic analyzer",
            "oscilloscope",
            "SPI Flash",
            "JTAG boundary scan",
            "CAN bus",
            "radio firmware",
            "boot ROM",
            "TrustZone",
            "secure element",
        ],
        ["hardware target", "logic trace", "firmware dump", "board-level report"],
    ),
]


SOURCE_MATRIX: list[tuple[str, str, str, str]] = [
    ("Microsoft PE/COFF specification", "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format", "PE, COFF, RVA, VA, sections, imports, exports, relocations", "Любой вывод о PE-поле сверять с именем поля, размером, границей секции и правилом RVA-to-file-offset."),
    ("Microsoft x64 calling convention", "https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170", "Windows x64 ABI, регистры аргументов, shadow space, volatile/nonvolatile", "Аргументы и возвращаемые значения подтверждать состоянием регистров до call и после return."),
    ("Microsoft x64 exception handling", "https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170", ".pdata, .xdata, RUNTIME_FUNCTION, UNWIND_INFO", "Unwind-вывод проверять сопоставлением prologue, unwind codes и диапазона функции."),
    ("System V ABI / ELF gABI", "https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html", "ELF object files, program loading, dynamic linking", "В Linux начинать загрузочную модель с program headers, а не с красивых section names."),
    ("x86-64 psABI", "https://gitlab.com/x86-psABIs/x86-64-ABI", "System V AMD64 ABI, Linux/macOS register calling convention", "Не переносить Windows-регистры аргументов на Linux: проверять ABI перед чтением вызова."),
    ("DWARF Standards Committee", "https://dwarfstd.org/", "debug info, CFI, CFA, line info, DIE", "Debug/unwind-данные читать как правила восстановления состояния, а не как гарантированный исходный код."),
    ("Intel Software Developer Manuals", "https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html", "x86/x64 ISA, paging, exceptions, instruction semantics", "Смысл инструкции проверять по ISA, особенно флаги, порядок операций с памятью и привилегированное поведение."),
    ("Arm Architecture Reference Manual", "https://developer.arm.com/documentation/ddi0487/latest/", "AArch64 architecture, exceptions, registers", "Для ARM не угадывать по x86-привычкам: проверять режим, набор инструкций и уровень исключения."),
    ("Arm Cortex-M documentation", "https://developer.arm.com/documentation/", "Cortex-M vector table, exceptions, NVIC, memory map", "Reset vector, Thumb bit и interrupt handlers проверять по архитектурному руководству и reference manual конкретного устройства."),
    ("RISC-V ratified specifications", "https://riscv.org/specifications/ratified/", "RISC-V ISA, privileged architecture, extensions", "Всегда указывать ISA profile/extensions, иначе смысл инструкции может быть неполным."),
    ("Apple Mach-O documentation", "https://developer.apple.com/documentation/kernel/mach-o", "Mach-O, load commands, Apple binary format", "Для Apple-бинарника начинать с magic, CPU type и load commands, затем смотреть контекст dyld и code signing."),
    ("Android runtime and Dalvik / ART", "https://source.android.com/docs/core/runtime", "Android runtime, DEX, ART, managed/native boundary", "В Android разделять Java/Kotlin bytecode, результат работы ART, JNI native code и поведение Binder."),
    ("Microsoft .NET managed code", "https://learn.microsoft.com/en-us/dotnet/standard/managed-code", ".NET managed code, runtime services, CLR", "Managed-бинарник проверять через metadata, IL и поведение runtime/JIT, а не только через native dump."),
    ("Oracle Java SE specifications", "https://docs.oracle.com/javase/specs/", "Java Language Specification and JVM Specification", "JVM-вывод проверять по class file, constant pool, operand stack и модели verifier."),
    ("UEFI Forum specifications", "https://uefi.org/specifications", "UEFI, ACPI, Platform Initialization, boot services", "Boot-chain выводы привязывать к фазе PEI/DXE/BDS и текущей версии UEFI/PI."),
    ("OpenOCD User Guide", "https://openocd.org/doc/html/index.html", "JTAG, SWD, flash programming, debug adapters", "Hardware debug действия описывать через adapter, target, reset strategy и flash command."),
    ("QEMU System Emulation docs", "https://www.qemu.org/docs/master/system/", "system emulation, machine model, devices", "Эмуляцию не считать реальным железом: явно писать, какая machine/device model проверялась."),
    ("Frida documentation", "https://frida.re/docs/home/", "dynamic instrumentation, hooks, process inspection", "Instrumentation-вывод подтверждать тем, где именно стоит hook и какие arguments/events он зафиксировал."),
    ("YARA documentation", "https://yara.readthedocs.io/en/stable/", "pattern rules, strings, modules, conditions", "YARA-правило доказывает совпадение признаков, а не полное поведение; это triage, а не verdict."),
    ("Mandiant capa documentation", "https://mandiant.github.io/capa/", "capability extraction from executable files", "capa помогает найти возможности, но rule match нужно проверять в дизассемблере и явно описывать ограничения вывода."),
    ("angr documentation", "https://docs.angr.io/", "symbolic execution, CFG, program state", "Symbolic execution требует модели входов, памяти и external calls; без модели результат ограничен."),
    ("LLVM libFuzzer documentation", "https://llvm.org/docs/LibFuzzer.html", "coverage-guided fuzz testing", "Fuzzing доказывает найденные падения и достигнутое coverage, но не доказывает отсутствие ошибок."),
]


TERM_CONNECTIONS: list[tuple[str, str, str, str, str]] = [
    ("offset", "смещение от начала выбранного объекта", "file offset, RVA, stack offset, field offset, MMIO offset", "сначала назови систему координат, потом число", "Путают offset с адресом и ищут байты не там."),
    ("address", "номер места в адресном пространстве", "VA, physical address, MMIO, base address, ASLR", "проверь, кто задает карту: loader, MMU, linker script или reference manual", "Считают любое похожее число указателем."),
    ("register", "быстрая ячейка внутри CPU", "ABI, instruction, flags, debugger, interrupt context", "смотри значение до инструкции и после нее", "Читают register без учета calling convention."),
    ("stack", "область памяти для возвратов, локальных данных и временного состояния", "call, return, frame, unwind, interrupt stack", "рисуй изменение SP/RSP по инструкциям", "Думают, что stack всегда имеет красивую цепочку rbp."),
    ("function", "участок кода с договором входа и выхода", "ABI, prologue, epilogue, return value, side effects", "проверяй входы, выходы и измененную память", "Называют функцию по одной строке."),
    ("ABI", "договор между кодом, compiler, linker и OS", "registers, stack alignment, calling convention, object format", "выбери ABI до чтения вызова", "Переносят правила Windows на Linux или ARM."),
    ("loader", "механизм, который превращает файл в образ памяти", "sections, segments, relocations, imports, permissions", "сравни файл, memory map и specification", "Считают, что файл копируется в память один к одному."),
    ("runtime", "код и правила, которые обслуживают программу вокруг ее логики", "startup, libc, CRT, GC, exceptions, scheduler", "отделяй стандартную обвязку от предметной логики", "Анализируют startup как будто это алгоритм приложения."),
    ("MMIO", "память-похожий доступ к регистрам устройства", "base address, register offset, bit field, volatile", "проверяй manual и side effect", "Читают peripheral register как обычную RAM."),
    ("unwind", "правила восстановления стека после call/exception", ".pdata, .xdata, CFI, CFA, saved registers", "сопоставляй metadata с prologue/epilogue", "Ждут frame pointer там, где compiler его убрал."),
    ("bytecode", "инструкции виртуальной машины, а не native CPU", "IL, DEX, JVM, verifier, JIT", "сначала читай virtual machine model, потом native output", "Сразу ищут x64 assembly и пропускают metadata."),
    ("hook", "контролируемая точка наблюдения или перехвата", "Frida, debugger breakpoint, API trace, inline patch", "записывай место, аргументы, момент и ограничения", "Думают, что hook показывает все поведение программы."),
]


def profile_for(term: str, track: str, artifact: str) -> dict[str, str]:
    key = term.lower()
    joined = f"{key} {track.lower()} {artifact.lower()}"

    if any(word in joined for word in ["pe", "rva", "pdata", "xdata", "unwind", "seh", "pdb", "imports", "exports", "relocations", "tls", "resources", "dos header", "section table"]):
        return {
            "world": "Windows/PE",
            "plain": f"`{term}` в Windows-мире надо читать как часть договора между файлом PE, загрузчиком Windows, компоновщиком и отладчиком. Это не просто поле в hex editor: поле получает смысл только после того, как loader построил image, применил relocations, подготовил imports и права доступа к страницам памяти.",
            "where": f"Ищи `{term}` в заголовках PE, section table, data directories, import/export tables, exception directory, символах PDB или в памяти процесса. Один и тот же байт может иметь file offset на диске и другой RVA в загруженном образе.",
            "relations": "Главные соседи: file offset, RVA, VA, ImageBase, SectionAlignment, loader, x64 ABI, exception handling и debugger symbols.",
            "low": "На низком уровне Windows не исполняет EXE как плоский файл. Loader читает headers, создает memory mappings, задает page protections, исправляет адреса через relocation records, заполняет таблицы imports и передает управление entry point. Если речь об unwind, debugger и exception dispatcher используют metadata, а не угадывают стек по красивой форме кода.",
            "verify": "Проверка: показать поле в PE, пересчитать RVA-to-file-offset, сравнить с отображением в памяти, затем подтвердить xrefs или debugger event. Для unwind - сопоставить RUNTIME_FUNCTION range, UNWIND_INFO и реальный prologue.",
            "mistake": "Типовая ошибка: прочитать число из файла как виртуальный адрес или назвать import полным поведением программы.",
        }

    if any(word in joined for word in ["elf", "got", "plt", "ld.so", "syscall", "signal", "procfs", "ptrace", "dwarf", "core dump", "program header", "section header"]):
        return {
            "world": "Linux/ELF",
            "plain": f"`{term}` в Linux надо читать через разницу между файлом ELF и живым процессом. ELF хранит материал для загрузки, связывания и отладки, но поведение процесса появляется только после того, как kernel и dynamic linker построят отображения памяти.",
            "where": f"Ищи `{term}` в ELF header, program headers, dynamic section, relocation tables, GOT/PLT, `.eh_frame`, DWARF sections, `/proc/<pid>/maps`, strace/logs или core dump.",
            "relations": "Главные соседи: segment, section, relocation, symbol, dynamic linker, shared object, syscall, signal, CFI и process memory map.",
            "low": "На низком уровне kernel загружает loadable segments, dynamic linker разрешает зависимости, relocations меняют адреса, GOT становится таблицей фактических целей, PLT служит переходным механизмом, а syscalls переводят выполнение из user-mode в kernel boundary. Sections часто полезны для анализа, но loader живет прежде всего program headers.",
            "verify": "Проверка: сравнить представление `readelf`/`objdump` с `/proc/<pid>/maps`, увидеть relocation, target в GOT, syscall trace или правило DWARF/CFI. Не ограничиваться именем секции.",
            "mistake": "Типовая ошибка: принять section layout за точную карту памяти процесса или перепутать PLT-stub с настоящей library function.",
        }

    if any(word in joined for word in ["cortex", "mmio", "gpio", "uart", "spi", "i2c", "dma", "flash", "clock", "vector", "reset", "rtos", "freertos", "zephyr", "jtag", "swd", "openocd", "logic", "chip-off", "firmware", "bootloader"]):
        return {
            "world": "embedded/bare metal",
            "plain": f"`{term}` в embedded - это часть связи между прошивкой, memory map и физическим устройством. Здесь нет привычного процесса с loader-ом ОС: есть Flash, RAM, периферия, interrupt vectors и startup code.",
            "where": f"Ищи `{term}` в raw firmware, vector table, linker script, startup code, device reference manual, SVD-файле, MMIO addresses, interrupt handlers, logic analyzer trace или OpenOCD session.",
            "relations": "Главные соседи: base address, Flash/SRAM ranges, reset handler, interrupt, peripheral register, bit field, volatile, DMA и clock tree.",
            "low": "На низком уровне CPU берет начальные значения из vector table, переходит в reset handler, runtime копирует `.data` и очищает `.bss`, затем firmware настраивает clocks и peripheral registers. Запись по адресу MMIO может не просто менять число в памяти, а включать тактирование, запускать DMA, очищать interrupt flag или менять состояние ножки микроконтроллера.",
            "verify": "Проверка: обосновать architecture и base address, показать address range в reference manual, связать register offset и bit mask, затем подтвердить behavior trace, emulator, debugger или controlled hardware observation.",
            "mistake": "Типовая ошибка: читать MMIO как RAM, забывать clock enable или считать нечетный Thumb-address ошибкой.",
        }

    if any(word in joined for word in ["mach-o", "dyld", "codesign", "entitlements", "objective-c", "swift", "ios", "ipa", "arm64e", "pac", "crash log"]):
        return {
            "world": "Apple/Mach-O",
            "plain": f"`{term}` в Apple-среде живет между Mach-O format, dynamic loader `dyld`, code signing, Objective-C/Swift metadata и sandbox rules. Это слой, где структура файла тесно связана с политикой платформы.",
            "where": f"Ищи `{term}` в Mach-O header, load commands, segments, sections, symbol tables, Objective-C metadata, Swift descriptors, entitlement plist, crash log и контексте dyld shared cache.",
            "relations": "Главные соседи: magic, CPU type, load command, segment, dylib dependency, code signature, sandbox, Objective-C selector, Swift type metadata и arm64e pointer authentication.",
            "low": "На низком уровне Mach-O говорит loader-у, какие segments отобразить, какие libraries нужны, где находятся symbols и rebasing/binding information. На iOS добавляются подписи, entitlements и sandbox: бинарник анализируется не только как код, а как подписанный application bundle с политикой платформы.",
            "verify": "Проверка: прочитать Mach-O header/load commands, связать адрес с segment mapping, проверить dependency или selector xref и четко отделить факт из файла от runtime/dyld behavior.",
            "mistake": "Типовая ошибка: переносить PE/ELF-модель без учета load commands, dyld shared cache и code signing.",
        }

    if any(word in joined for word in ["apk", "dex", "art", "oat", "vdex", "jni", "binder", "selinux", "a/b", "android", "logcat"]):
        return {
            "world": "Android",
            "plain": f"`{term}` в Android надо читать как часть системы, где APK содержит resources и DEX, ART исполняет managed code, JNI соединяет его с native libraries, а Binder связывает процессы.",
            "where": f"Ищи `{term}` в APK structure, AndroidManifest, DEX methods, native `.so`, ART/OAT/VDEX artifacts, Binder interfaces, SELinux denials, logcat output и device partitions.",
            "relations": "Главные соседи: package, manifest, permission, DEX, ART, JNI boundary, Binder IPC, SELinux, native ABI и system image.",
            "low": "На низком уровне Java/Kotlin method может закончиться native call через JNI, native library исполняется уже как ELF, а внешний эффект часто проходит через Binder service. Поэтому Android-reverse требует держать сразу несколько карт: managed code, native code, IPC, filesystem и platform policy.",
            "verify": "Проверка: связать manifest permission с actual call path, DEX method с native symbol, Binder transaction с service, а logcat/event trace - с controlled action.",
            "mistake": "Типовая ошибка: анализировать APK как обычный ZIP или `.so` как весь Android behavior.",
        }

    if any(word in joined for word in ["managed", "il", "metadata", "manifest", ".net", "jit", "gc", "java", "jvm", "class file", "constant pool", "verification", "reflection", "bytecode", "obfuscator"]):
        return {
            "world": "managed runtime",
            "plain": f"`{term}` относится к миру, где программа сначала описана не native-инструкциями CPU, а байткодом, metadata и runtime rules. CPU все равно исполняет машинный код, но важный смысл может жить уровнем выше - в metadata, type system, verifier или JIT.",
            "where": f"Ищи `{term}` в IL или JVM bytecode, metadata tables, constant pool, assembly manifest, class descriptors, method signatures, reflection calls, JIT output и runtime exceptions.",
            "relations": "Главные соседи: bytecode, verifier, metadata token, type system, JIT, GC, reflection, exception model и native interop.",
            "low": "На низком уровне runtime проверяет или загружает metadata, строит типы, подготавливает method body, иногда компилирует hot code в native, перемещает objects через GC и скрывает многие детали платформы за правилами virtual machine. Поэтому decompiler может показать почти исходный код, но obfuscator и reflection способны перенести смысл в metadata и runtime decisions.",
            "verify": "Проверка: сопоставить decompiler output с bytecode, metadata token, method signature и runtime behavior. Для JIT/interop отдельно указать, где managed world переходит в native world.",
            "mistake": "Типовая ошибка: думать, что managed binary проще native только потому, что decompiler output выглядит читаемым.",
        }

    if any(word in joined for word in ["uefi", "dxe", "pei", "acpi", "kernel", "driver", "irp", "ioctl", "module", "sysfs", "debugfs", "ebpf", "secure boot"]):
        return {
            "world": "kernel/boot",
            "plain": f"`{term}` относится к слоям, где код работает до обычного пользовательского процесса или ниже него. Здесь цена ошибки выше: другой privilege level, другой memory model, другой способ входа и другой набор доказательств.",
            "where": f"Ищи `{term}` в UEFI images, boot logs, ACPI tables, driver entry points, dispatch tables, IOCTL handlers, kernel modules, sysfs/debugfs nodes, eBPF programs и secure boot policy.",
            "relations": "Главные соседи: privilege, firmware phase, boot service, runtime service, kernel object, device object, request packet, ioctl code, module init и trust chain.",
            "low": "На низком уровне цепочка загрузки постепенно передает управление от firmware к bootloader и затем к kernel. Код драйвера не вызывается как обычная функция из `main`: его дергает kernel через зарегистрированные точки входа, структуры запросов и обратные вызовы. UEFI-образы и kernel-артефакты могут использовать знакомые форматы вроде PE/ELF, но контекст их исполнения не пользовательский режим.",
            "verify": "Проверка: назвать phase или privilege level, entry point, dispatch mechanism, request structure и documented boundary. Для UEFI - сверить image type/phase; для driver - показать handler и request flow.",
            "mistake": "Типовая ошибка: читать драйвер как обычную программу или забывать privilege boundary.",
        }

    if any(word in joined for word in ["packer", "anti-debug", "flattening", "opaque", "encryption", "obfuscation", "yara", "capa", "frida", "fuzzing", "symbolic", "taint"]):
        return {
            "world": "defensive analysis",
            "plain": f"`{term}` - это инструмент или техника анализа защищенного/запутанного поведения. В учебнике это рассматривается defensive: цель - понять и описать behavior, а не научить злоупотреблению.",
            "where": f"Ищи `{term}` в entropy changes, unusual control flow, API traces, instrumentation hooks, YARA/capa matches, fuzzing crashes, symbolic states, taint propagation и anti-analysis checks.",
            "relations": "Главные соседи: triage, hypothesis, instrumentation, coverage, rule match, behavior evidence, limitation и report discipline.",
            "low": "На низком уровне защитные техники ломают привычную прямую дорогу от bytes к псевдокоду, похожему на исходный текст. Packer может создавать code at runtime, obfuscation скрывает control/data flow, anti-debug меняет поведение под наблюдением, fuzzing перебирает входы, symbolic execution рассуждает о путях, а taint analysis отслеживает влияние данных.",
            "verify": "Проверка: формулировать узкий вопрос, фиксировать версию инструмента и входные данные, подтверждать rule/hook/crash/path вручную там, где возможно, и явно писать, чего эта техника не доказывает.",
            "mistake": "Типовая ошибка: выдавать tool result за окончательный вывод или путать detection с explanation.",
        }

    if any(word in joined for word in ["side channel", "fault", "glitch", "logic analyzer", "oscilloscope", "spi flash", "boundary", "can bus", "radio", "boot rom", "trustzone", "secure element"]):
        return {
            "world": "hardware security",
            "plain": f"`{term}` переносит реверс из файла в физический мир. Здесь доказательство может быть не только инструкцией, но и сигналом на линии, формой импульса, дампом памяти, реакцией платы или записью логического анализатора.",
            "where": f"Ищи `{term}` в board photos, pinout, datasheets, bus traces, SPI flash dumps, JTAG/SWD configuration, oscilloscope captures, boot ROM behavior, TrustZone transitions и secure element communication.",
            "relations": "Главные соседи: voltage, clock, reset, bus protocol, timing, flash layout, debug port, threat model, safety и repeatability.",
            "low": "На низком уровне устройство - не абстрактная программа. Питание, reset, clock, timing на шине и protection fuses определяют, что вообще можно наблюдать. Side-channel видит косвенную утечку, fault injection пытается нарушить вычисление, а hardware trace требует калибровки до интерпретации.",
            "verify": "Проверка: записать setup, wiring, voltage, clock, sample rate, firmware version, commands и repeated measurements. Без воспроизводимости hardware observation остается подсказкой, а не доказательством.",
            "mistake": "Типовая ошибка: считать единичный trace доказательством или игнорировать риск повредить устройство.",
        }

    if any(word in joined for word in ["x86", "aarch64", "arm", "risc-v", "xtensa", "mips", "thumb", "simd", "dsp", "calling convention", "privileged mode", "endianness"]):
        return {
            "world": "CPU/architecture",
            "plain": f"`{term}` относится к архитектуре - набору правил, по которым процессор понимает инструкции, регистры, адреса, исключения и иногда privilege levels.",
            "where": f"Ищи `{term}` в disassembly, register view, ABI docs, exception vectors, instruction manual, compiler output и emulator traces.",
            "relations": "Главные соседи: instruction set, register file, flags/status register, memory addressing, ABI, exception model, privilege и endianness.",
            "low": "На низком уровне CPU снова и снова берет instruction bytes, декодирует их, читает registers/memory, выполняет операцию, обновляет state и выбирает следующий address. Разные ISA families решают одни и те же роли по-разному, поэтому сильный реверсер сравнивает роли, а не только mnemonics.",
            "verify": "Проверка: объяснить instruction semantics, затронутые registers, memory operands, flags/status effects и ABI role. Для cross-architecture work надо указать точный mode и ISA extension.",
            "mistake": "Типовая ошибка: искать x86-pattern в ARM или читать Thumb/AArch64/RISC-V без проверки mode и ABI.",
        }

    if any(word in joined for word in ["compiler", "linker", "runtime", "startup", "optimization", "symbol", "relocation", "object file", "static library", "dynamic library", "debug info", "preprocessor", "ir"]):
        return {
            "world": "toolchain",
            "plain": f"`{term}` относится к дороге от исходного текста до исполняемого артефакта. Reverse engineering видит не исходник, а следы решений compiler, assembler, linker и runtime.",
            "where": f"Ищи `{term}` в object files, symbols, relocation records, map files, debug info, startup code, optimized functions, library calls и generated metadata.",
            "relations": "Главные соседи: translation unit, IR, object file, symbol, relocation, section, linker script, runtime init и optimization.",
            "low": "На низком уровне compiler удаляет лишнее, объединяет похожее, встраивает функции, меняет порядок и специализирует code. Linker соединяет object files, разрешает symbols, применяет relocations, размещает sections и может выбросить неиспользованные части. Runtime готовит memory и language environment до того, как логика программы станет видимой.",
            "verify": "Проверка: сравнить O0/O2 там, где это возможно, посмотреть relocations, symbols и map file, узнать startup patterns и не восстанавливать исходные строки там, где optimization намеренно стерла форму исходника.",
            "mistake": "Типовая ошибка: считать every missing call доказательством исчезновения логики, хотя compiler мог встроить функцию или заменить вызов на tail-call.",
        }

    if any(word in joined for word in ["ghidra", "ida", "rizin", "binary ninja", "x64dbg", "windbg", "gdb", "python scripting", "types", "signatures", "notes", "report", "debugger"]):
        return {
            "world": "tools/workflow",
            "plain": f"`{term}` - это часть рабочего процесса. Инструмент помогает видеть и проверять, но он не несет ответственности за вывод вместо исследователя.",
            "where": f"Ищи `{term}` в disassembler project, debugger session, script output, type database, signature matches, trace logs и report tables.",
            "relations": "Главные соседи: hypothesis, xrefs, types, decompiler assumptions, breakpoint, trace, notes, reproducibility и evidence table.",
            "low": "На низком уровне tool строит модель из bytes: дизассемблирует, угадывает функции, распространяет типы, разрешает references и рисует представления. Каждый шаг может быть неполным. Задача исследователя - улучшать модель и сохранять цепочку от наблюдения к выводу.",
            "verify": "Проверка: повторить ключевое наблюдение в другом view или tool там, где это возможно, сохранить addresses, версии инструментов, before/after screenshots или text extracts и объяснить, почему переименованная функция заслуживает свое имя.",
            "mistake": "Типовая ошибка: написать «Ghidra показала» вместо объяснения bytes, references и правил, на которых держится claim.",
        }

    return {
        "world": "general reverse engineering",
        "plain": f"`{term}` - это не пароль в закрытый клуб, а рабочее имя для наблюдаемой роли. Чтобы термин стал понятным, нужно связать его с object, address, rule и verification.",
        "where": f"Ищи `{term}` в текущем артефакте: file bytes, memory map, registers, function graph, data table, runtime event или documentation.",
        "relations": f"Главные соседи для `{term}`: bytes, address, offset, type, function, control flow, data flow, tool output и source document.",
        "low": f"На низком уровне `{term}` должен свестись к изменению состояния: какие bytes читаются, какой register меняется, какой memory address используется, какая branch выбирается, какой внешний объект затрагивается или какая table entry интерпретируется.",
        "verify": f"Проверка `{term}`: записать одно observation, одно rule, одну independent check и одно limitation.",
        "mistake": f"Типовая ошибка в теме `{term}`: запомнить слово, но не знать, где оно живет и как доказывается.",
    }


def artifact_for(term: str, artifacts: list[str], topic_no: int) -> str:
    key = term.lower()
    if any(word in key for word in ["sysfs", "debugfs", "ebpf", "linux kernel"]):
        return "Linux kernel module"
    if any(word in key for word in ["irp", "ioctl", "driver object"]):
        return "Windows driver"
    if any(word in key for word in ["uefi", "dxe", "pei", "acpi", "secure boot"]):
        return "UEFI image"
    if any(word in key for word in ["apk", "dex", "art", "jni", "binder", "selinux", "logcat"]):
        return "Android application"
    if any(word in key for word in ["mach-o", "dyld", "codesign", "objective-c", "swift", "ios", "ipa", "arm64e", "crash log"]):
        return "Apple binary или application bundle"
    if any(word in key for word in ["yara", "capa", "frida", "fuzzing", "symbolic", "taint", "anti-debug", "packer"]):
        return "defensive analysis lab sample"
    if any(word in key for word in ["side channel", "fault", "glitch", "oscilloscope", "spi flash", "can bus", "radio", "trustzone", "secure element"]):
        return "hardware target"
    return artifacts[(topic_no - 1) % len(artifacts)]


def revised_term_chapter(track_no: int, topic_no: int, track: str, term: str, artifact: str) -> str:
    chapter_number = (track_no - 1) * 12 + topic_no
    profile = profile_for(term, track, artifact)
    opener = [
        "В этой главе мы не заучиваем термин, а приручаем его: смотрим, какую проблему он решает and где его можно проверить руками.",
        "Хороший реверсер начинает не с перевода слова, а с вопроса: какое состояние машины стоит за этим словом?",
        "Этот термин полезен только тогда, когда он превращается в адрес, поле, таблицу, регистр, событие or ограничение отчета.",
        "Если слово кажется страшным, его надо разложить на три части: где лежит, кто читает, что меняется после чтения.",
    ][(chapter_number + len(term)) % 4]
    practice_kind = [
        "нарисуй маленькую карту: байты -> правило чтения -> поведение -> доказательство",
        "составь таблицу из четырех строк: наблюдение, источник правила, проверка, ограничение",
        "объясни термин человеку без IT-базы, не используя английское слово в первой фразе",
        "найди одно место в учебном объекте and докажи только один узкий вывод",
    ][chapter_number % 4]

    return dedent(
        f"""
        ## Глава {chapter_number}. {term}: понятие без тумана

        {opener} Контекст этой главы - {profile['world']}. Учебный артефакт:
        `{artifact}`. Мы будем читать `{term}` не как отдельную карточку из
        словаря, а как узел в сети понятий.

        ### Человеческий смысл

        {profile['plain']} Простыми словами: термин нужен, чтобы не путать
        разные уровни реальности. Есть байты как материал, есть правило чтения,
        есть работающий код, есть внешняя среда, а есть наш отчет. Если все это
        назвать одним словом «программа», анализ быстро станет мутным.

        Представь, что ты впервые открыл `{artifact}`. Ты еще не обязан знать
        все тонкости. Твоя первая задача скромнее: понять, в каком слое живет
        `{term}`. Это слой файла? памяти? процессора? соглашения вызова? ОС?
        виртуальной машины? железа? Чем точнее ответ, тем меньше магии.

        ### Где это увидеть

        {profile['where']} В хорошем исследовании рядом с термином всегда стоит
        конкретная координата: offset, RVA, VA, physical address, register name,
        field offset, function address, trace event, rule match or строка
        документации. Термин без координаты похож на ярлык без привязки.

        В `{artifact}` запиши не «нашел `{term}`», а «нашел вот это значение,
        вот здесь, таким инструментом, и оно похоже на `{term}` по таким
        причинам». Слово «похоже» здесь важное. На первом проходе мы строим
        кандидат, not final truth.

        ### Связи с другими понятиями

        Для `{term}` здесь важно: {profile['relations']} Если одно соседнее понятие понято неверно,
        ломается и `{term}`. Например, неверный base address портит xrefs,
        неверный ABI портит чтение аргументов, неверный endian портит числа,
        неверное понимание loader-а портит карту памяти, а неверная модель
        runtime заставляет принять служебный код за предметную логику.

        Поэтому объяснение термина должно отвечать на четыре вопроса:
        зачем он нужен, где он виден, кто им пользуется, and что меняется,
        если его прочитать неправильно. Это и есть взаимосвязь, а не сухой
        перевод.

        ### Что происходит ниже интерфейса

        Для `{term}` низкий механизм такой: {profile['low']} Обрати внимание: «низкий уровень» не означает
        «обязательно assembly». Низкий уровень означает ближайший проверяемый
        механизм. Для PE это поля and loader. Для ABI - registers and stack.
        Для embedded - memory map and peripheral registers. Для JVM/.NET -
        bytecode, metadata and runtime. Для hardware - signal, voltage, timing
        and repeated measurement.

        В реальном реверсе `{term}` становится понятным, когда ты можешь
        провести цепочку: байты or событие -> правило -> изменение состояния ->
        наблюдаемое следствие. Если цепочка обрывается, это нормально, но
        обрыв надо честно записать.

        ### Как проверять

        Для `{term}` проверка строится так: {profile['verify']} Проверка должна быть маленькой. Большая фраза
        «я проанализировал» ничего не доказывает. Сильнее выглядит одна
        точная фраза: «по offset `0x...` находится поле такого размера; по
        спецификации оно значит это; пересчет дает такой адрес; xref ведет
        в такую функцию; динамическая проверка подтверждает такую ветку».

        Если dynamic check невозможен, это не провал. Тогда пишется:
        «динамически не проверялось». Честная граница делает вывод сильнее,
        потому что читатель понимает, где факт, где гипотеза and где план
        следующей проверки.

        ### Типовая ошибка

        В теме `{term}` типовой сбой такой: {profile['mistake']} Еще одна частая ошибка - оставлять английский
        термин без разжевывания. Если в тексте есть `{term}`, рядом должно
        быть русское объяснение: что это такое, зачем нужно, где видно,
        с чем связано, как проверить, and какую ошибку предотвращает.

        Не бойся длинного объяснения именно для `{term}`. Для новичка короткое
        определение часто бесполезно. Лучше одна живая страница, где термин связан с байтами,
        памятью, инструментом and отчетом, чем строка словаря, после которой
        человек все равно не понимает, что делать.

        ### Мини-практика

        Для `{term}` в объекте `{artifact}` сделай упражнение: {practice_kind}.
        Обязательные пять строк результата: объект, координата, наблюдение,
        правило, проверка. Шестая строка - ограничение. Например: «не проверено
        на реальном устройстве», «нет symbols», «неизвестна версия compiler»,
        «нет dynamic trace».

        После этого попробуй объяснить `{term}` устно. Начни не с английского
        слова, а с задачи: «это нужно, чтобы...». Потом покажи место, где оно
        живет. Потом скажи, чем оно связано с соседними понятиями. Если слушатель
        может повторить смысл своими словами, глава сработала.
        """
    ).strip() + "\n"


def revised_core_markdown() -> str:
    lines = [
        "# Новая фундаментальная редакция: термины, связи и проверяемая глубина",
        "",
        "Эта часть заменяет прежний слабый многотомный слой. Ее задача - не раздувать страницы, а дать большую, связанную карту реверса: от байта до loader-а, от ABI до unwind, от PE/ELF до Mach-O, Android, managed runtimes, UEFI, drivers, embedded and hardware security.",
        "",
        "Правило чтения простое: каждое английское слово нужно приручить. Сначала человеческий смысл, затем слой, затем связи, затем низкий механизм, затем проверка. Пока термин нельзя объяснить так, он еще не стал знанием.",
        "",
    ]
    seen_terms: set[str] = set()
    for track_no, (title, description, terms, artifacts) in enumerate(list(TRACKS) + ADDITIONAL_TRACKS, start=1):
        lines.extend([
            f"# {title}",
            "",
            description,
            "",
            "В этом томе главы сохраняют одинаковую учебную логику, но не повторяют один и тот же текст: каждый термин разбирается через свою среду, свои соседние понятия and свой способ проверки.",
            "",
        ])
        for topic_no, term in enumerate(terms, start=1):
            term_key = term.casefold()
            if term_key in seen_terms:
                lines.extend([
                    f"## Повторный узел: {term}",
                    "",
                    f"`{term}` уже разобран выше. В этом томе он остается важной связкой, но повторять главу дословно не нужно: вернись к первому разбору and примени его к контексту `{title}`.",
                    "",
                ])
                continue
            seen_terms.add(term_key)
            artifact = artifact_for(term, artifacts, topic_no)
            lines.append(revised_term_chapter(track_no, topic_no, title, term, artifact))
            lines.append("")
    return "\n".join(lines) + "\n"


def term_network_markdown() -> str:
    lines = [
        "# Карта терминов: как английские слова связываются в одну систему",
        "",
        "Этот раздел нужен, чтобы читатель не утонул в английских словах. В реверсе почти все термины пришли из документации, ABI, ISA, toolchain and operating systems. Их нельзя просто перевести один к одному. Нужно понять роль слова в системе.",
        "",
        "Ниже - не сухой глоссарий. Это сеть. Каждый термин объясняется через соседей: с чем его чаще всего путают, где он появляется and какая проверка превращает слово в знание.",
        "",
    ]
    for index, (term, meaning, related, check, mistake) in enumerate(TERM_CONNECTIONS, start=1):
        lines.extend([
            f"## Узел {index}. {term}",
            "",
            f"`{term}` - это {meaning}. Если сказать еще проще, это способ не потерять координаты в низкоуровневом материале.",
            "",
            f"Связан с: {related}. Эти соседи важны потому, что реверсер почти никогда не видит термин в одиночестве. Например, address без memory map опасен, stack без ABI неполон, MMIO без reference manual почти бессмыслен, а bytecode без runtime model легко обманет красивым decompiler output.",
            "",
            f"Как проверять: {check}. Проверка должна быть написана так, чтобы другой человек смог повторить ее на том же объекте.",
            "",
            f"Типовая ошибка: {mistake} Исправление всегда одно: назвать систему координат, источник правила and границу вывода.",
            "",
        ])
    lines.extend([
        "## Как пользоваться картой",
        "",
        "Когда встречаешь новый термин, не спрашивай только «как это переводится?». Спроси: где это живет, кто это создает, кто это читает, какой инструмент это показывает, какая документация задает правило, and что сломается, если я ошибусь. Такой вопрос превращает словарь в инженерное мышление.",
        "",
    ])
    return "\n".join(lines)


def authored_deep_chapters_markdown() -> str:
    chapters: list[tuple[str, str]] = [
        (
            "Как функция рождается из исходного кода и исчезает в оптимизации",
            """
            Новичок часто думает, что функция в исходнике обязана стать функцией в бинарнике. Это удобная фантазия, но compiler не обязан сохранять наш человеческий порядок. Его задача - получить эквивалентное поведение в рамках языка, ABI and выбранных оптимизаций.

            На `-O0` compiler часто сохраняет форму, похожую на учебник: prologue, stack frame, локальные переменные, call, return. На `-O2` та же логика может раствориться: маленькая функция inline-ится в caller, условие превращается в conditional move, цикл разворачивается, константа вычисляется заранее, а tail call заменяет call/ret на прямой jump. Для реверсера это не «компилятор украл функцию», а нормальная реальность.

            Поэтому в отчете лучше писать не «в бинарнике нет функции X», а «отдельной function boundary for X не наблюдается; поведение, похожее на X, возможно встроено в caller; подтверждение: такие-то constants, такие-то data-flow dependencies, такой-то output». Это взрослая формулировка. Она признает, что reverse engineering восстанавливает поведение, not source code as a photograph.

            Практический прием: сравни две сборки маленькой программы - debug and release. Посмотри, как исчезают stack variables, как register allocation меняет имена, как inlining убирает call. После такой практики decompiler перестает казаться оракулом and становится удобным, но проверяемым черновиком.
            """,
        ),
        (
            "Почему decompiler красиво ошибается",
            """
            Decompiler пытается поднять assembly обратно в похожий на C текст. Это мощная помощь, но не машина истины. Он угадывает function boundaries, types, signedness, calling convention, stack variables, structures and control flow. Если один слой угадан неверно, псевдокод может выглядеть уверенно and быть неправильным.

            Самая коварная ошибка - красивый `if` or `struct`, который выглядит правдоподобно. Читатель расслабляется: «раз похоже на C, значит можно читать как C». Но decompiler мог объединить две разные переменные, принять unsigned compare за signed, потерять side effect volatile access, перепутать calling convention or поставить неверный тип pointer-а.

            Рабочий ритуал такой: когда псевдокод важен для вывода, вернись к assembly around key decision. Посмотри actual branch instruction, width of load/store, sign extension, register source, memory address and call target. Затем поправь types в инструменте and проверь, стал ли псевдокод лучше. Хороший реверсер не воюет с decompiler-ом, а обучает его.

            В отчете не надо писать «decompiler says». Пиши: «псевдокод после уточнения типов соответствует такой-то ветке assembly; ключевой факт подтверждается instruction X and value Y». Так текст становится проверяемым.
            """,
        ),
        (
            "От PE ВКР к embedded: что переносится, а что нет",
            """
            Твоя ВКР живет в Windows PE/unwind-мире, но будущий embedded reverse не начинается с нуля. Переносится главное: дисциплина координат, уважение к формату, осторожность с инструментом, проверка ABI and умение писать доказательный отчет.

            В Windows ты учишься отличать file offset, RVA and VA. В embedded похожая привычка превращается в различение Flash address, SRAM address, MMIO address, boot ROM and file offset raw dump-а. В Windows loader строит image по PE headers. В bare-metal startup and linker script задают layout; sometimes no OS loader exists. В Windows unwind metadata помогает восстановить stack. В Cortex-M exception frame and vector table помогают понять вход в handler.

            Разница тоже огромная. В Windows внешний мир доступен через API, handles, system calls, DLLs and process memory. В embedded внешний мир часто сидит в регистрах периферии: один bit может включить clock, очистить interrupt flag or начать передачу DMA. Здесь нельзя анализировать только код; нужно читать reference manual and sometimes наблюдать сигнал на линии.

            Вывод: Windows-база не мешает embedded, она дает позвоночник. Но привычки надо адаптировать. Вместо «какая DLL импортируется?» спрашиваешь «какой peripheral range используется?». Вместо «какой process mapping?» - «какая memory map MCU?». Вместо «какой API call?» - «какой register write and какой bit field?».
            """,
        ),
        (
            "Форматы файлов как договоры, а не контейнеры",
            """
            PE, ELF, Mach-O, DEX, class file and firmware container - это не просто коробки с байтами. Формат файла - договор между producer and consumer. Producer: compiler, linker, packer, build system, firmware vendor. Consumer: loader, runtime, debugger, update service, bootloader or analysis tool.

            Когда ты читаешь формат, спрашивай: кто будет использовать это поле? Loader? Dynamic linker? Debugger? Signature verifier? Boot ROM? Если поле никем не используется in the execution path, оно может быть полезно для анализа, но не объясняет поведение напрямую.

            Например, section names in PE can help analyst, but loader relies on section headers and data directories. ELF sections useful for linkers and tools, while process loading depends on program headers. Mach-O load commands tell dyld how to map and bind. Android APK is a ZIP-like package, but behavior spans manifest, DEX, resources, native libraries and platform services.

            Сильный разбор формата всегда заканчивается картой: где metadata, где code, где data, где imports/exports, где relocations, где debug info, где signature, где payload. После карты можно честно идти к поведению.
            """,
        ),
        (
            "Как писать отчет, который выдерживает защиту",
            """
            Отчет реверсера - это не пересказ приключений в Ghidra. Это цепочка доказательств. В хорошей цепочке есть объект, вопрос, метод, наблюдение, правило чтения, проверка, вывод and ограничение.

            Плохая фраза: «функция проверяет лицензию». Хорошая фраза: «функция at VA ... получает строку from ..., сравнивает ее with ..., при несовпадении идет в error path; динамически проверено breakpoint-ом before conditional branch; ограничение: не проверены альтернативные branches». Видишь разницу: первая просит поверить, вторая показывает дорогу.

            Особенно важно объяснять термины. Если ты пишешь `RVA`, рядом должно быть понятно: это address relative to image base, not file offset. Если пишешь `ABI`, поясни, что это договор о registers, stack and return values. Если пишешь `MMIO`, скажи, что address-like access touches hardware register, not ordinary RAM.

            Хороший отчет не боится слов «вероятно», «кандидат», «не проверено». Эти слова не слабость. Они показывают, что ты различаешь факт and hypothesis. На защите это выглядит сильнее, чем уверенность без доказательств.
            """,
        ),
        (
            "Автоматизация без самообмана: YARA, capa, Frida, fuzzing",
            """
            Современный реверс нельзя делать только глазами. Но автоматизация опасна, если человек перестает понимать, что именно доказал инструмент. YARA находит byte/string patterns and module conditions. capa ищет capabilities through rules over code features. Frida observes and modifies runtime behavior at chosen hooks. Fuzzing explores inputs and finds crashes. Symbolic execution reasons about paths under a model.

            Ни один из этих инструментов не говорит: «истина найдена». Они дают signals. Signal must become evidence. Если YARA rule matched, надо показать, какие strings or byte patterns matched and why they matter. Если capa found capability, надо открыть function and проверить features. Если Frida hook captured argument, надо описать hook point and conditions. Если fuzzer found crash, надо сохранить input, stack trace, build flags and minimization.

            Автоматизация особенно полезна для ширины: быстро отфильтровать corpus, найти suspicious functions, собрать traces, проверить many inputs. Глубина все равно приходит через ручную проверку ключевых выводов.

            В учебной книге это важно проговорить отдельно, потому что новичок часто либо боится инструментов, либо верит им слишком сильно. Правильная середина: инструмент - усилитель внимания, not replacement for thinking.
            """,
        ),
        (
            "Kernel и driver: почему это не обычная программа",
            """
            User-mode программа обычно имеет понятный вход: process starts, loader prepares image, entry point runs, APIs cross into OS. Driver and kernel module живут иначе. Их вызывает kernel через registered callbacks, request structures, device objects, interrupt paths and synchronization rules.

            В Windows driver может иметь DriverEntry, dispatch routines, IOCTL handlers и unload routine. В Linux module обычно имеет init/exit, file operations, sysfs/debugfs nodes, netfilter hooks или platform driver callbacks. UEFI image может исполняться на boot phase, где services и memory model отличаются от обычного runtime операционной системы.

            Главная ошибка новичка - искать `main`. Его может не быть. Нужно искать registration: где код сообщает системе «вот мои handlers». После этого анализ идет от external request to handler to side effects. Для IOCTL нужно понять code, input buffer, output buffer, access method and boundary checks. Для kernel module - какие user-controlled data reach kernel code and how errors are returned.

            Этот раздел в книге должен оставаться безопасным: цель - понимать архитектуру and писать защитный анализ, а не давать рецепты злоупотреблений. Но фундамент без kernel/driver слоя был бы неполным.
            """,
        ),
        (
            "Managed code: когда главный смысл живет в metadata",
            """
            .NET and JVM ломают привычку думать только native assembly. В managed world важнейшие факты могут жить в metadata, class descriptors, constant pool, IL/bytecode, attributes, reflection strings and runtime services.

            В .NET method has metadata token, signature, IL body, references to types and assemblies. CLR/JIT later turns IL into native code, but reverse engineer often gets more meaning from IL and metadata than from raw machine code. In Java class file constant pool stores names, descriptors, method references and literals; JVM operand stack model differs from register machine.

            Obfuscator может переименовать identifiers, спрятать strings, заменить simple control flow, move calls into reflection or dynamic loading. Но metadata and runtime constraints still leave traces. Поэтому анализ managed binary starts with structure: assemblies/classes, methods, metadata, resources, dependencies, entry points, then dynamic behavior.

            В отчете важно писать, на каком уровне сделан вывод: IL/bytecode, metadata, JIT native code или runtime trace. Смешивать эти уровни нельзя.
            """,
        ),
    ]
    lines = [
        "# Авторские глубокие главы: без шаблона и с живой связкой",
        "",
        "Эти главы добавлены как редакторская проходка поверх терминов. Они закрывают места, где одной карточки понятия мало: compiler transformations, decompiler assumptions, перенос Windows-базы в embedded, отчетность, automation and managed/kernel layers.",
        "",
    ]
    for index, (title, body) in enumerate(chapters, start=1):
        lines.extend([f"## Авторская глава {index}. {title}", "", dedent(body).strip(), ""])
    return "\n".join(lines) + "\n"


def fact_matrix_markdown() -> str:
    lines = [
        "# Матрица проверки фактов и источников",
        "",
        "Эта матрица нужна, чтобы книга не выглядела как набор уверенных утверждений без опоры. Она не заменяет документацию, но показывает, куда возвращаться, когда в исследовании появляется конкретный вопрос.",
        "",
        "| Источник | Ссылка | Что проверять | Как превращать в доказательство |",
        "|---|---|---|---|",
    ]
    for title, url, scope, check in SOURCE_MATRIX:
        lines.append(f"| {title} | {url} | {scope} | {check} |")
    lines.extend([
        "",
        "## Как читать матрицу",
        "",
        "Если источник официальный, это еще не означает, что любой вывод автоматически доказан. Нужно показать связь: конкретное поле, конкретный register, конкретный instruction, конкретный loader step, конкретный trace. Документация дает правило; артефакт дает наблюдение; исследователь связывает их проверкой.",
        "",
        "Если источник не официальный, например книга or tool documentation, его роль другая. Книга дает педагогическую модель and практический маршрут. Tool documentation explains tool behavior. Но нормативное правило binary format, ABI, ISA or platform policy лучше сверять с primary documentation.",
        "",
    ])
    return "\n".join(lines) + "\n"


def living_exam_markdown() -> str:
    return dedent(
        """
        # Финальная проверка понимания: не тест, а разговор с материалом

        Финальная проверка в этой редакции устроена не как длинный список одинаковых вопросов. Она похожа на защиту мини-исследования. Возьми любой безопасный объект: маленький PE, ELF, Mach-O, APK, .NET assembly, Cortex-M firmware, rootfs or driver-like учебный sample. Не выбирай вредоносный объект, если лаборатория не готова and нет законного основания.

        ## Задание 1. Карта объекта

        Опиши объект так, чтобы человек без IT-базы понял, что перед ним. Потом добавь инженерные координаты: формат, размер, hash, architecture, expected loader/runtime, entry point or reset vector, code/data regions, external dependencies. Если есть английские термины, рядом дай русское объяснение.

        ## Задание 2. Один путь исполнения

        Найди один путь: entry -> функция -> решение -> внешний эффект. Для Windows это может быть import/API/event. Для Linux - syscall or library call. Для embedded - MMIO write or interrupt. Для managed - method call through bytecode/runtime. Для Android - DEX/JNI/Binder path. Не надо покрывать все. Надо доказать один путь хорошо.

        ## Задание 3. Одна структура данных

        Восстанови одну структуру: PE table, ELF relocation, C struct, packet, command table, vector table, vtable, metadata table or MMIO register layout. Объясни field offsets, sizes, endian, signedness, alignment and validation. Если чего-то не знаешь, напиши limitation.

        ## Задание 4. Один динамический or экспериментальный факт

        Подтверди одну статическую гипотезу через debugger, emulator, trace, log, hook, fuzz input, hardware measurement or controlled run. Если запуск невозможен, напиши why and what static evidence remains. В инженерном тексте честное «не запускалось» лучше, чем притворная уверенность.

        ## Задание 5. Мини-отчет

        Итоговый отчет должен иметь семь разделов: объект, вопрос, метод, наблюдения, правила чтения, проверки, ограничения. Запрещенная фраза: «инструмент показал, значит так и есть». Разрешенная фраза: «инструмент показал X; по документации Y это читается так; я проверил Z; ограничение W».

        Если ты можешь выполнить эти пять заданий для PE из ВКР and затем повторить логику для простого firmware, книга дала фундамент. Если нет, возвращайся не к объему страниц, а к узкому месту: адреса, ABI, loader, runtime, embedded memory map, tool discipline or report writing.
        """
    ).strip() + "\n"


def editorial_audit_markdown() -> str:
    return dedent(
        """
        # Редакторская заметка к этой версии

        В этой редакции исправлена главная слабость предыдущей сборки: большой повторяющийся слой заменен новым ядром. Теперь объем строится не вокруг одинаковых абзацев, а вокруг расширенной карты терминов and областей: Windows PE/unwind, Linux ELF, embedded bare metal, CPU architectures, toolchain, tools, malware-defense workflow, Mach-O/Apple, Android, managed runtimes, UEFI, drivers, obfuscation, automated analysis and hardware security.

        Книга все равно не должна притворяться последним словом во всех областях. Reverse engineering слишком широк. Но теперь она честнее выполняет роль фундаментального труда: дает новичку вход, объясняет английские термины, показывает связи, учит проверять факты and связывает твою Windows-ВКР with future embedded reverse.

        Важное правило для дальнейшего развития: если добавляется новый термин, нельзя просто вставить его в список. Нужно добавить пять вещей: человеческое объяснение, слой существования, соседние понятия, низкий механизм and проверку. Иначе термин снова станет туманом.
        """
    ).strip() + "\n"


LANGUAGE_POLISH_REPLACEMENTS: list[tuple[str, str]] = [
    ("not final truth", "не окончательная истина"),
    ("write one observation", "запиши одно наблюдение"),
    ("one independent check", "одну независимую проверку"),
    ("one limitation", "одно ограничение"),
    ("one rule", "одно правило"),
    ("finally", "наконец"),
    ("source-like pseudocode", "псевдокод, похожий на исходный текст"),
    ("model from bytes", "модель из байтов"),
    (" and ", " и "),
    (" and\n", " и\n"),
    ("\nand ", "\nи "),
    (" or ", " или "),
    (" or\n", " или\n"),
    ("\nor ", "\nили "),
    (" not ", " не "),
    (" not\n", " не\n"),
    ("\nnot ", "\nне "),
    (" with ", " с "),
    (" with\n", " с\n"),
    ("\nwith ", "\nс "),
    (" without ", " без "),
    (" through ", " через "),
    (" before ", " до "),
    (" after ", " после "),
    ("which ", "какой "),
    ("where ", "где "),
]


def polish_language(text: str) -> str:
    for old, new in LANGUAGE_POLISH_REPLACEMENTS:
        text = text.replace(old, new)
    return text


def main() -> None:
    manuscript = (
        normalize(BOOK)
        + "\n"
        + normalize(DEEPENING)
        + "\n"
        + editorial_audit_markdown()
        + "\n"
        + influences_markdown()
        + "\n"
        + master_casebook_markdown()
        + "\n"
        + authored_deep_chapters_markdown()
        + "\n"
        + reference_drills_markdown()
        + "\n"
        + capstones_markdown()
        + "\n"
        + revised_core_markdown()
        + "\n"
        + term_network_markdown()
        + "\n"
        + mega_labs_markdown()
        + "\n"
        + workbook_markdown()
        + "\n"
        + question_bank_markdown()
        + "\n"
        + living_exam_markdown()
        + "\n"
        + glossary_markdown()
        + "\n"
        + fact_matrix_markdown()
        + "\n"
        + sources_markdown()
    )
    manuscript = polish_language(manuscript)
    qa_no_duplicate_long_paragraphs(manuscript)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(manuscript, encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    print(f"Characters: {len(manuscript)}")


if __name__ == "__main__":
    main()
