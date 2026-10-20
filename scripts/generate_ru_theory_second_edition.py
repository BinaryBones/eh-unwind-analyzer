# -*- coding: utf-8 -*-
from __future__ import annotations

import re
import shutil
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
TEACHER_DIR = ROOT / "book_source" / "teacher_book"
RU_DIR = ROOT / "docs" / "ru"
THEORY_DIR = RU_DIR / "теория 2"
TMP_DIR = ROOT / "tmp" / "pdfs" / "theory_second_edition_real"

PDF_PATH = THEORY_DIR / "EH_Unwind_Analyzer_Теоретическая_база_с_нуля_RU.pdf"
MD_PATH = THEORY_DIR / "EH_Unwind_Analyzer_Теоретическая_база_с_нуля_RU.md"

FONT = "ArialRU"
FONT_BOLD = "ArialRU-Bold"
FONT_ITALIC = "ArialRU-Italic"
CODE_FONT = "ConsolasRU"


@dataclass(frozen=True)
class Concept:
    name: str
    ru: str
    plain: str
    strict: str
    project: str
    neighbor: str
    check: str


@dataclass(frozen=True)
class FindingInfo:
    code: str
    family: str
    meaning: str
    theory: str
    manual: str


CONCEPTS = [
    Concept("байт", "byte", "минимальный кусок файла, который можно адресовать и показать в hex viewer", "8 бит данных; именно из байтов состоят PE headers, секции, машинные инструкции и unwind metadata", "Buf в проекте хранит исследуемый EXE как массив байтов", "file offset, hex, parser", "открыть EXE в hex viewer и найти первые байты MZ"),
    Concept("шестнадцатеричная запись", "hex", "способ писать байты и адреса компактно", "система счисления с основанием 16, где одна цифра кодирует 4 бита", "отчеты печатают RVA, VA, offsets и sizes как 0x1000, 0x7100, 0x140000000", "byte, address, RVA", "перевести 0x10, 0x100 и 0x1000 в десятичные числа"),
    Concept("файловое смещение", "file offset", "координата байта от начала файла на диске", "целое число, показывающее позицию в raw file representation", "нужно, чтобы безопасно читать структуру после перевода RVA в offset", "RVA, section, raw size", "вычислить offset = PointerToRawData + (RVA - VirtualAddress)"),
    Concept("RVA", "Relative Virtual Address", "адрес внутри образа без учета того, куда Windows загрузила файл", "image-relative coordinate; RVA прибавляется к loaded ImageBase для получения VA", "RUNTIME_FUNCTION и UNWIND_INFO используют RVA", "VA, ImageBase, section", "найти RVA в отчете и перейти в Ghidra как ImageBase + RVA"),
    Concept("VA", "Virtual Address", "адрес в памяти конкретного запущенного процесса", "координата внутри virtual address space после загрузки image", "dynamic log показывает VA обработчиков, breakpoints и API", "RVA, ASLR, process", "сравнить loaded base в runtime log и адрес handler"),
    Concept("секция PE", "section", "именованный диапазон файла и памяти с ролью и правами", "section header задает virtual range, raw backing, name и characteristics", "анализатор проверяет .text, .pdata, .xdata и необычные секции", "permissions, raw size, virtual size", "открыть таблицу Sections в HTML-отчете"),
    Concept("права секции", "permissions", "ответ на вопрос: можно ли область читать, писать или исполнять", "битовые признаки секции R, W, X в PE characteristics", "writable или executable placement для unwind metadata влияет на findings", "section, metadata placement, handler", "найти RW или R-X секцию и объяснить риск"),
    Concept("PE", "Portable Executable", "формат Windows EXE и DLL", "контракт между компоновщиком, загрузчиком Windows и инструментами анализа", "pe.c строит модель PE без запуска target", "headers, sections, data directories", "найти DOS header, PE signature и section table"),
    Concept("каталог данных", "data directory", "таблица ссылок на важные области PE", "массив RVA/size пар в OptionalHeader", "exception directory index 3 ведет к RUNTIME_FUNCTION table", "OptionalHeader, exception directory, RVA", "найти Exception Directory и проверить его размер"),
    Concept("каталог исключений", "exception directory", "указатель на таблицу функций для обработки исключений x64", "data directory, который для AMD64 описывает массив RUNTIME_FUNCTION", "если каталог выходит за image, появляется pe_exception_directory_oob", ".pdata, RUNTIME_FUNCTION, SizeOfImage", "сравнить directory RVA/size с секциями"),
    Concept("RUNTIME_FUNCTION", "runtime function entry", "строка таблицы: где начинается функция, где кончается и где ее unwind info", "три 32-битных image-relative поля: BeginAddress, EndAddress, UnwindInfoAddress", "главный объект таблицы Runtime functions в отчете", "UNWIND_INFO, .pdata, function range", "выбрать строку Runtime functions и объяснить begin/end/unwind RVA"),
    Concept("UNWIND_INFO", "unwind metadata", "рецепт, как восстановить стек функции при исключении", "структура Windows x64 с version, flags, prolog size, unwind codes и optional handler/chained info", "unwind.c декодирует структуру и проверяет границы", "prolog, stack frame, handler", "сравнить Version/flags и Handler в отчете"),
    Concept("стек", "stack", "область памяти для истории вызовов функций", "LIFO-память потока с return address, saved registers и local variables", "unwind metadata нужна, чтобы идти от текущего кадра к предыдущему", "call, ret, stack frame", "нарисовать stack до call, после call и после prolog"),
    Concept("кадр стека", "stack frame", "кусок стека, принадлежащий одной функции", "логическая область с адресом возврата, сохраненными регистрами и локальными данными", "UNWIND_INFO описывает, как восстановить прошлый frame", "RSP, prolog, epilog", "найти sub rsp в disassembly и объяснить выделение frame"),
    Concept("ABI", "Application Binary Interface", "правила общения функций на машинном уровне", "соглашение о регистрах аргументов, сохранении регистров и выравнивании стека", "Windows x64 ABI объясняет смысл unwind codes", "registers, prolog, stack alignment", "объяснить shadow space и 16-byte alignment"),
    Concept("исключение", "exception", "событие, которое ломает обычный ход выполнения", "механизм Windows для ошибок, breakpoints и dispatch к обработчикам", "dynamic mode собирает exception events", "SEH, VEH, handler", "найти first chance и second chance в runtime log"),
    Concept("обработчик", "handler", "код, которому дают шанс обработать исключение", "function или callback, связанный с dispatch исключения", "handler target может быть в UNWIND_INFO, VEH или UEF", "VEH, UEF, handler dominance", "перейти в Ghidra по handler address"),
    Concept("статический анализ", "static analysis", "чтение файла без запуска", "исследование bytes, headers, tables и metadata как данных", "основной режим analyzer строит findings", "parser, findings, report", "запустить analyzer без --dynamic"),
    Concept("динамическая проверка", "dynamic validation", "наблюдение за target при запуске", "Debug API создает процесс, ловит events, ставит breakpoints и собирает runtime evidence", "dynamic_win.c фиксирует registrations, exceptions и handler hits", "debug event, runtime evidence, timeout", "запустить --dynamic и сравнить Runtime log с static findings"),
    Concept("finding", "признак", "структурированное сообщение о низкоуровневом факте", "code, family, severity, affected count, representative RVA и message", "heuristics.c превращает наблюдения parser в findings", "score, confidence, evidence", "найти finding в JSON и объяснить его без слова 'вредоносно'"),
    Concept("confidence", "уверенность интерпретации", "насколько устойчиво объяснение найденных фактов", "инженерная оценка, а не статистическая вероятность", "assessment использует confidence вместе со score и evidence level", "score, mitigation, case strength", "объяснить, почему confidence не равен вероятности malware"),
    Concept("Ghidra", "Ghidra", "инструмент, где байты становятся кодом, функциями и комментариями", "reverse engineering suite с disassembly, decompiler, labels и bookmarks", "Ghidra CSV помогает перейти от report к адресам", "disassembly, function, manual validation", "импортировать target и перейти к ImageBase + RVA"),
]

FINDINGS = [
    FindingInfo("pe_section_raw_oob", "table_integrity", "секция заявляет raw range за пределами файла", "PE section header должен указывать на реально существующие байты", "сравнить PointerToRawData + SizeOfRawData с размером файла"),
    FindingInfo("pe_section_virtual_oob", "table_integrity", "виртуальный диапазон секции выходит за image", "loader строит image по SectionAlignment и SizeOfImage", "сравнить VirtualAddress + VirtualSize с SizeOfImage"),
    FindingInfo("pe_section_raw_overlap", "table_integrity", "две секции пересекаются в raw file", "один байт файла не должен неоднозначно принадлежать двум секциям", "отсортировать raw ranges и найти пересечение"),
    FindingInfo("pe_section_virtual_overlap", "table_integrity", "две секции пересекаются в виртуальном image", "RVA должен иметь однозначный section context", "отсортировать virtual ranges и найти пересечение"),
    FindingInfo("pe_section_misaligned", "table_integrity", "секция нарушает ожидаемое выравнивание", "FileAlignment и SectionAlignment задают сетку размещения", "проверить адреса и размеры секций на кратность alignment"),
    FindingInfo("pe_exception_directory_oob", "table_integrity", "exception directory выходит за допустимые границы", "каталог исключений должен быть mappable в секции/image", "перевести directory RVA в file offset и проверить size"),
    FindingInfo("no_runtime_functions", "table_integrity", "в x64 image нет runtime function entries", "non-leaf x64 code обычно требует unwind metadata", "сначала понять, есть ли исполняемый non-leaf код"),
    FindingInfo("invalid_ranges", "table_integrity", "BeginAddress и EndAddress образуют невозможные диапазоны", "диапазон функции должен иметь begin < end", "найти строки с нулевым или отрицательным размером"),
    FindingInfo("rf_oob", "table_integrity", "runtime function range выходит за image или code context", "функция должна ссылаться на существующий код", "сравнить begin/end с секциями и SizeOfImage"),
    FindingInfo("unwind_rva_oob", "table_integrity", "UnwindInfoAddress не указывает на валидное место", "RUNTIME_FUNCTION должен вести к читаемой UNWIND_INFO", "проверить Unwind RVA через section mapping"),
    FindingInfo("rf_unsorted", "table_integrity", "таблица функций не отсортирована по begin", "Windows ожидает упорядоченный поиск function entries", "отсортировать begin values и найти нарушение"),
    FindingInfo("rf_overlaps", "table_integrity", "диапазоны функций пересекаются", "один адрес кода не должен принадлежать двум разным function entries", "сравнить соседние begin/end после сортировки"),
    FindingInfo("duplicate_begin", "table_integrity", "несколько записей начинаются с одного адреса", "BeginAddress должен идентифицировать диапазон", "найти одинаковые BeginAddress"),
    FindingInfo("unwind_parse_fail", "unwind_integrity", "UNWIND_INFO не удалось корректно разобрать", "layout структуры должен помещаться в доступные байты", "открыть bytes UNWIND_INFO и проверить header/codes/tail"),
    FindingInfo("unwind_anomalies", "unwind_integrity", "UNWIND_INFO разобран, но содержит необычные свойства", "unwind codes должны согласовываться с prolog/frame", "сравнить unwind operations с disassembly prolog"),
    FindingInfo("unwind_reuse_moderate", "unwind_reuse", "несколько функций повторно используют один UnwindInfoRVA", "reuse бывает нормальным, но требует контекста", "проверить, насколько похожи функции и есть ли другие signals"),
    FindingInfo("unwind_reuse_strong", "unwind_reuse", "слишком много функций используют одну unwind запись", "массовая централизация metadata может скрывать pattern", "посчитать долю функций с одинаковым UnwindInfoRVA"),
    FindingInfo("handler_dominance", "handler_dominance", "один handler обслуживает слишком много функций", "обработчик может быть runtime helper или центральный dispatcher", "перейти к handler и оценить его роль"),
    FindingInfo("unwind_in_exec_section", "metadata_placement", "unwind metadata лежит в executable section", "metadata обычно read-only data, а не код", "проверить section permissions для Unwind RVA"),
    FindingInfo("unwind_unusual_section", "metadata_placement", "unwind metadata лежит в необычной секции", "секция .xdata ожидаема, но .weird требует объяснения", "сравнить section name с нормальными PE conventions"),
    FindingInfo("unwind_writable_section", "metadata_placement", "unwind metadata лежит в writable section", "изменяемая metadata опаснее неизменяемой", "проверить W permission у секции"),
    FindingInfo("handler_nonexec_section", "metadata_placement", "handler указывает в неисполняемую область", "handler должен быть кодом", "сопоставить handler RVA с section permissions"),
    FindingInfo("handler_writable_section", "metadata_placement", "handler находится в writable section", "исполняемый код в writable области повышает риск", "найти section для handler target"),
    FindingInfo("placement_exec_nonexec_handler_combo", "metadata_placement", "сочетание подозрительного placement и handler context", "комбинации важнее одиночного факта", "проверить обе стороны: metadata и handler"),
    FindingInfo("placement_integrity_combo", "unwind_integrity", "placement подтверждается structural integrity проблемой", "сильный case появляется при согласовании разных слоев", "связать section anomaly с parse/range anomaly"),
    FindingInfo("reuse_dominance_combo", "unwind_reuse", "reuse metadata связан с доминирующим handler", "централизация двух разных объектов усиливает гипотезу", "посчитать reuse и dominance в одном отчете"),
    FindingInfo("writable_metadata_handler_combo", "metadata_placement", "writable metadata и writable handler усиливают друг друга", "изменяемость данных и кода создает сильный сигнал", "проверить permissions для обоих RVA"),
]

LABS = [
    ("Первое знакомство с PE", "открыть Sections, найти .text, .pdata, .xdata и объяснить роль каждой"),
    ("Адреса без путаницы", "взять один RVA, найти его section, file offset и VA при известном ImageBase"),
    ("RUNTIME_FUNCTION руками", "выбрать строку таблицы и объяснить begin, end, size, unwind RVA"),
    ("UNWIND_INFO без магии", "прочитать version, flags, prolog size и понять, есть ли handler"),
    ("Статика против динамики", "сравнить static finding с Runtime log и не смешивать их"),
    ("Ghidra как проверка", "перейти по representative RVA и посмотреть surrounding disassembly"),
    ("Confidence без самообмана", "объяснить, почему высокий score не равен доказательству вредоносности"),
    ("Прочерк в Anomalies/error", "понять разницу между локальной строкой функции и агрегированным finding"),
    ("Timeout в динамике", "объяснить, почему timeout ограничивает наблюдение, но не отменяет static facts"),
    ("Защитный ответ", "сформулировать вывод: факт, адрес, проверка, ограничение"),
]

STUDY_MODULES = [
    (
        "Как думать о бинарнике до открытия Ghidra",
        "Новичок часто хочет сразу нажать Analyze и получить ответ. В реверс-инжиниринге это почти всегда слишком быстро. Сначала нужно принять простую мысль: бинарник не является текстом программы, который кто-то аккуратно подписал для человека. Это набор байтов, созданный компилятором, компоновщиком и иногда вручную измененный человеком или инструментом. Поэтому первая работа аналитика - не угадать смысл, а восстановить уровни представления.",
        "В этой теме полезно разделить четыре слоя: файл на диске, образ после загрузки, исполняемый процесс и аналитический отчет. Файл живет в координатах file offset. Загруженный образ живет в RVA и VA. Процесс добавляет реальные адреса, потоки, исключения и API-вызовы. Отчет analyzer собирает эти наблюдения и превращает их в проверяемые утверждения.",
        "Типичная ошибка - говорить 'по адресу 0x7100 лежит плохой код', не уточнив, это file offset, RVA или VA. Для защиты проекта такая неточность опасна: оппонент может попросить показать этот адрес в Ghidra или hex viewer, и без слоя координат ответ рассыпается.",
        "Практическая проверка: возьми один отчет, выпиши из него ImageBase, representative RVA и секцию. Затем отдельно покажи, как этот RVA превращается в VA при запуске и как он превращается в file offset при чтении байтов из файла."
    ),
    (
        "Почему PE - это договор, а не просто формат",
        "Документация Microsoft описывает PE/COFF как структуру исполняемых файлов и объектных файлов Windows. Но для учебника важнее увидеть смысл: PE - это договор между тем, кто собрал файл, и тем, кто будет его загружать. В договоре сказано, где заголовки, где таблица секций, где каталоги данных, какие области нужно отобразить в память и какие права у этих областей.",
        "Когда analyzer читает PE, он ведет себя как строгий проверяющий договора. Он не запускает программу и не верит ей на слово. Он смотрит, можно ли найти PE signature, согласуются ли размеры, попадают ли директории в образ, можно ли перевести RVA в file offset, не указывает ли таблица на область, которой в файле нет.",
        "Связь с проектом прямая: без PE parser все последующие проверки бессмысленны. Нельзя декодировать UNWIND_INFO, пока не доказано, что адрес этой структуры действительно отображается в байты файла. Нельзя уверенно говорить о секции, пока section table не прочитана и не проверена.",
        "Практическая проверка: в HTML-отчете открой блок Sections и найди .text, .pdata, .xdata или необычную секцию. Для каждой запиши Virtual address, Virtual size, Raw offset, Raw size и Permissions. После этого объясни, какая часть существует на диске, а какая появляется как память процесса."
    ),
    (
        "Как не перепутать file offset, RVA и VA",
        "Три адреса - главный экзамен на зрелость в этой теме. File offset отвечает на вопрос 'где байт лежит в файле'. RVA отвечает на вопрос 'где объект находится внутри образа относительно ImageBase'. VA отвечает на вопрос 'где объект оказался в адресном пространстве конкретного процесса'. Это не три названия одного и того же, а три разные системы координат.",
        "Microsoft PE Format отдельно определяет RVA и VA именно потому, что файл на диске и память процесса устроены по-разному. Секция может иметь один размер на диске и другой размер в памяти. Между секциями могут быть выравнивания. ASLR может изменить фактическую базу загрузки. Поэтому прямое сравнение offset и runtime address без перевода - ошибка.",
        "В EH/Unwind Analyzer это особенно важно для RUNTIME_FUNCTION. BeginAddress, EndAddress и UnwindInfoAddress являются image-relative значениями. Отчет показывает их как RVA, а динамический лог может показывать VA. Если увидеть только числа и не понять слой, можно решить, что статический и динамический анализ расходятся, хотя они говорят об одном объекте.",
        "Практическая проверка: выбери функцию из таблицы Runtime functions. Вычисли VA = loaded base + Begin RVA. Потом найди секцию, куда попадает Begin RVA, и вычисли file offset = PointerToRawData + (RVA - VirtualAddress). Если все три точки совпали в отчете, Ghidra и hex viewer, координаты освоены."
    ),
    (
        "Секции и права как язык намерений",
        "Секция PE - это не папка и не красивое имя. Это диапазон байтов и памяти с ролью, размерами и правами. Обычно .text исполняется и читается, .rdata читается, .data читается и пишется, .pdata содержит runtime function table, .xdata содержит unwind metadata. Такие имена не являются магией, но они образуют культурную норму Windows x64.",
        "Аномалия начинается там, где структура нарушает ожидание. Если unwind metadata оказывается в writable section, это не автоматически вредоносность, но это повод спросить: почему данные, от которых зависит раскрутка стека и обработка исключений, находятся там, где программа может их менять? Если секция с metadata называется странно, это снова вопрос к намерению и устойчивости.",
        "Проект не должен кричать 'malware' только потому, что секция необычна. Он должен сказать точнее: unwind section unusual, unwind section writable, code section unusual, handler outside image или другой конкретный факт. Сила отчета не в громкости вывода, а в проверяемости наблюдения.",
        "Практическая проверка: найди строку с Anomalies/error в Runtime functions. Если там написано unwind section unusual или writable, перейди в таблицу Sections и покажи, что именно в правах или имени секции вызвало признак."
    ),
    (
        "x64 ABI как правила дорожного движения для функций",
        "Calling convention, или соглашение о вызовах, отвечает на вопрос: как одна функция вызывает другую так, чтобы обе стороны поняли друг друга. На Windows x64 первые аргументы обычно передаются через RCX, RDX, R8 и R9, вызывающая сторона резервирует shadow space, стек должен оставаться выровненным, а часть регистров имеет правила сохранения.",
        "Без ABI невозможно серьезно читать disassembly. Инструкция call сама по себе говорит только о переходе. Но ABI объясняет, где искать аргументы перед call, почему рядом есть sub rsp, зачем сохраняются nonvolatile registers и почему эпилог должен восстанавливать стек аккуратно.",
        "Unwind metadata тоже вырастает из ABI. Windows должна уметь восстановить состояние потока при исключении. Для этого ей нужно знать, что prolog сделал со стеком и регистрами. Поэтому UNWIND_INFO - это не украшение, а сжатое описание действий функции, важных для безопасного движения назад по стеку.",
        "Практическая проверка: в Ghidra открой простую функцию, найди prolog и epilog. Отметь, где меняется RSP, какие регистры сохраняются, и сравни это с Stack size или unwind actions в отчете analyzer."
    ),
    (
        "Prolog, epilog и unwindability",
        "Microsoft x64 documentation использует слово unwindability: код должен быть описуемым для механизма раскрутки стека. Prolog - начало функции, где выделяется stack frame и сохраняются регистры. Epilog - конец, где состояние возвращается. Для обычного чтения кода это технические детали, но для исключений это жизненно важная карта.",
        "Если исключение произошло внутри функции, Windows должна понять, как перейти к вызывающей функции. Она не может просто угадать старый RSP. Ей нужна UNWIND_INFO. Там записано, сколько байтов выделено на стеке, какие регистры сохранены, где есть обработчик и есть ли chained info.",
        "Аномалии unwind metadata часто означают, что эта карта странная: не туда указывает RVA, плохо декодируется структура, handler выглядит подозрительно, таблица перекрывается, entry не отсортированы или metadata лежит в необычном месте. Это не теоретические придирки, а вопросы к способности Windows и инструментов корректно понимать функцию.",
        "Практическая проверка: выбери функцию со статусом OK и функцию со статусом Failed. Сравни их Version/flags, Stack, Handler и Anomalies/error. Хорошая защита начинается с такого контраста."
    ),
    (
        "RUNTIME_FUNCTION как оглавление функций для Windows",
        "На x64 Windows многие функции описываются строками RUNTIME_FUNCTION. Каждая строка содержит BeginAddress, EndAddress и UnwindInfoAddress. Это похоже на оглавление: откуда докуда функция и где лежит инструкция для раскрутки стека. Но в отличие от обычного оглавления, ошибка здесь влияет на обработку исключений.",
        "Если Begin >= End, диапазон бессмысленен. Если таблица не отсортирована, поиск может стать неоднозначным. Если диапазоны перекрываются, один адрес может претендовать на несколько функций. Если UnwindInfoAddress указывает за пределы образа, analyzer не может безопасно прочитать структуру.",
        "Статический анализ проекта начинается именно с таких инвариантов. Он не пытается доказать намерение автора. Он проверяет договор: таблица должна быть читаемой, диапазоны должны иметь смысл, указатели должны попадать в образ, декодер должен иметь достаточно байтов.",
        "Практическая проверка: открой Runtime functions в отчете и отсортируй взглядом Begin/End. Найди размер функции, section, unwind RVA и статус. Если есть finding table_integrity, объясни его через конкретную строку таблицы."
    ),
    (
        "UNWIND_INFO как сжатая биография stack frame",
        "UNWIND_INFO хранит версию, flags, размер prolog, количество unwind codes и дополнительные поля. Если есть EHANDLER или UHANDLER, после unwind codes появляется handler RVA. Если есть CHAININFO, структура ссылается на другую RUNTIME_FUNCTION. Эти поля выглядят сухо, но вместе они рассказывают, как функция вошла в свое состояние.",
        "Новичок часто спрашивает: почему нельзя просто посмотреть disassembly? Можно, но disassembly показывает инструкции, а UNWIND_INFO показывает, что Windows считает официальной картой восстановления. Если эти два взгляда расходятся, это и есть аналитически интересное место.",
        "Проект декодирует UNWIND_INFO осторожно: проверяет границы, версию, flags, выравнивание, количество кодов, наличие хвостовых полей. Поэтому parse failure - это не 'программа не понравилась', а конкретная проблема чтения структуры по правилам формата.",
        "Практическая проверка: найди функцию с EHANDLER или UHANDLER. Покажи handler RVA, секцию handler и объясни, почему наличие обработчика меняет смысл строки в таблице."
    ),
    (
        "SEH, VEH, UEF и цепочка обработки исключения",
        "Exception handling в Windows - это не одна кнопка. Есть структурированная обработка исключений, vectored exception handlers, unhandled exception filter, runtime function tables и диспетчер исключений. В проекте особенно важны API AddVectoredExceptionHandler, SetUnhandledExceptionFilter, RtlAddFunctionTable и RtlInstallFunctionTableCallback.",
        "Динамический анализ не заменяет статический. Он отвечает на другой вопрос: происходило ли во время запуска то, что статически выглядело подозрительно или важным? Например, был ли зарегистрирован обработчик, была ли добавлена runtime function table, случилось ли exception event, попал ли breakpoint в handler.",
        "Если в динамическом отчете Runtime table calls = 2, это значит, что процесс реально вызвал API, связанные с динамическими таблицами функций. Если Handler hits > 0, это значит, что выполнение дошло до обработчика. Это сильнее, чем просто наличие адреса в PE, но все равно зависит от выбранного пути запуска и timeout.",
        "Практическая проверка: открой Runtime log и выдели строки с RtlAddFunctionTable, RtlInstallFunctionTableCallback, AddVectoredExceptionHandler или SetUnhandledExceptionFilter. Потом найди соответствующие счетчики в Dynamic validation."
    ),
    (
        "Статика и динамика как две половины доказательства",
        "Static analysis читает файл без запуска. Его сила в полноте структуры: можно увидеть секции, таблицы, директории, metadata и много функций сразу. Его слабость в том, что он не знает, какой путь выполнения реально активируется. Dynamic validation запускает процесс под наблюдением. Его сила в фактах поведения. Его слабость в неполноте: один запуск не обязан пройти все ветви.",
        "Поэтому лучший вывод выглядит не как 'статика против динамики', а как корреляция. Статика говорит: в файле есть необычное размещение unwind metadata. Динамика говорит: во время запуска был зарегистрирован handler или добавлена runtime function table. Вместе они дают более сильный рассказ: структура необычна, и runtime действительно касается механизма исключений.",
        "Если динамика молчит, это не отменяет статическую аномалию. Возможно, путь выполнения не дошел до нужного кода, timeout был коротким, sample требует аргументы или событие возникает только при определенных условиях. В отчете поэтому есть слова confidence, instrumentation complete, dropped events и timeout.",
        "Практическая проверка: для combo sample открой static HTML и dynamic HTML рядом. Найди один и тот же адрес, секцию или handler. Сформулируй вывод в две строки: что видно в файле и что подтвердилось при запуске."
    ),
    (
        "Почему finding не равен обвинению",
        "Finding - это обнаруженный признак. Verdict - итоговая оценка. Suspicion score - числовая мера подозрительности. Confidence - уверенность в том, что наблюдения достаточно сильны. Эти слова нельзя смешивать. Один finding может быть важным, но не окончательным. Несколько независимых finding с динамическим подтверждением дают гораздо более сильную позицию.",
        "Хороший реверсер не стремится звучать страшно. Он стремится звучать точно. Вместо 'тут вирус' он говорит: 'в этой функции unwind metadata находится в writable section; таблица содержит такой-то handler; динамический запуск показал регистрацию такого-то обработчика; поэтому кейс требует ручной проверки и имеет такую-то уверенность'.",
        "Именно поэтому отчеты проекта сохраняют details. Пользователь должен видеть не только карточку Final assessment, но и строки Static findings, Runtime functions, Runtime log, Manual validation plan. Если отчет нельзя проверить руками, он превращается в черный ящик.",
        "Практическая проверка: выбери один high finding и напиши его как научное утверждение: объект, адрес, нарушенное правило, способ проверки, ограничение вывода. Это лучшая форма ответа на защите."
    ),
    (
        "Ghidra как микроскоп, а не оракул",
        "Ghidra помогает разметить функции, увидеть disassembly, decompiler output, references, sections и memory map. Но она не заменяет мышление. Если Ghidra назвала область code, это полезный сигнал, но не математическое доказательство. Если decompiler построил C-подобный код, это удобная реконструкция, а не исходник автора.",
        "Для проекта Ghidra особенно полезна как место ручной проверки representative RVA. Analyzer говорит: проблема около этого адреса. Ghidra позволяет перейти к адресу, увидеть окружающие инструкции, проверить, похожа ли область на функцию, есть ли handler, какие references ведут к адресу.",
        "Правильный порядок такой: сначала читаешь отчет и понимаешь, что именно проверяется; потом открываешь Ghidra с конкретным вопросом. Неправильный порядок: открыть Ghidra без вопроса и пытаться глазами найти 'что-то странное' во всем бинарнике.",
        "Практическая проверка: импортируй sample, дождись анализа, перейди к ImageBase + RVA из отчета. Если адрес попал внутрь функции, сравни границы Ghidra с Begin/End из Runtime functions. Если не попал, объясни, почему разметка могла отличаться."
    ),
    (
        "Как читать Runtime log без паники",
        "Runtime log выглядит шумно, потому что debugger видит много технических событий. CREATE_PROCESS сообщает о запуске процесса. API resolved говорит, что analyzer нашел адрес функции в модуле. BP set говорит, что breakpoint установлен. Handler hit означает попадание в обработчик. Timeout означает, что наблюдение остановлено по времени.",
        "Не каждая строка - сенсация. Например, сообщение о том, что API resolved but module not present yet, часто означает порядок загрузки модулей, а не провал анализа. Breakpoint failures важны, если они не ноль: тогда часть наблюдения могла не сработать. Dropped events важны, если событий больше, чем collector успел сохранить.",
        "Главное - связывать лог со счетчиками сверху. Exceptions, Handler hits, Runtime table calls, Instrumentation complete, Module coverage дают быстрый обзор. Runtime log затем объясняет, откуда эти числа взялись.",
        "Практическая проверка: возьми динамический отчет, выпиши пять строк Runtime log и напротив каждой напиши: это событие запуска, установка наблюдения, регистрация API, попадание в обработчик или ограничение эксперимента."
    ),
    (
        "Как устроен pipeline проекта от команды до HTML",
        "Командная строка запускает analyzer с путем к PE и опциями. main собирает конфигурацию, util читает файл безопасно, pe parser строит модель образа, unwind decoder проходит runtime function table, heuristics engine превращает факты в findings, dynamic collector при необходимости запускает процесс под debugger, report writer сохраняет JSON/CSV/HTML.",
        "Эта цепочка важна для доверия к результату. Если отчет пишет 'unwind RVA out of bounds', нужно понимать, на каком этапе это обнаружено. Это не HTML придумал текст. Это результат проверки адреса в PE model и попытки безопасно получить байты UNWIND_INFO.",
        "Разделение слоев помогает отлаживать проект. Ошибка parser не должна маскироваться как dynamic failure. Ошибка dynamic instrumentation не должна уничтожать статические finding. Ошибка report rendering не должна менять смысл evidence.",
        "Практическая проверка: открой исходники src и найди места, которые соответствуют словам parser, decoder, heuristics, dynamic, report. После этого прочитай один finding в JSON и покажи, какой слой проекта его породил."
    ),
    (
        "Как защищать вывод перед преподавателем",
        "На защите важно не засыпать слушателя терминами, а провести его по маршруту доказательства. Начинай с объекта: какой бинарник, какая команда анализа, какой отчет. Затем назови главный факт: например, необычная unwind section или runtime table registration. Потом покажи адрес и таблицу. Затем объясни, почему это необычно по правилам Windows x64.",
        "Следующий шаг - ручная проверка. Открой Ghidra или HTML, покажи representative RVA, section, permissions, handler или runtime log. Если есть динамика, скажи, что именно произошло во время запуска. Если динамика неполная, честно назови timeout или incomplete instrumentation.",
        "Хороший ответ звучит спокойно: 'я не утверждаю больше, чем вижу; вот байты, вот структура, вот правило, вот наблюдение runtime, вот ограничение'. Такая позиция выглядит профессиональнее, чем попытка объявить любой странный бинарник вредоносным.",
        "Практическая проверка: подготовь трехминутный рассказ по одному combo sample. В нем должны быть команда запуска, static finding, dynamic signal, Ghidra address и финальная осторожная формулировка."
    ),
]


STUDY_MODULES.extend([
    (
        "Как читать Microsoft Learn как инженер, а не как словарь",
        "Официальная документация Microsoft обычно написана компактно. Она сообщает структуру, поля, ограничения и поведение API, но не обязана разжевывать путь новичка. Поэтому читать ее нужно не линейно, а с вопросом. Если открыт PE Format, вопрос такой: какое поле помогает мне перейти от байтов файла к образу? Если открыт x64 exception handling, вопрос такой: какая структура объясняет строку Runtime functions в отчете?",
        "В проекте документация Microsoft является не украшением библиографии, а основанием инвариантов. PE Format объясняет RVA, VA, sections и data directories. x64 Calling Convention объясняет регистры, стек и shadow store. x64 Exception Handling объясняет RUNTIME_FUNCTION, UNWIND_INFO и flags. Debugging Events объясняет, почему dynamic collector видит CREATE_PROCESS, EXCEPTION_DEBUG_EVENT и EXIT_PROCESS.",
        "Ошибка новичка - цитировать документацию, не связывая ее с наблюдением. На защите мало сказать 'Microsoft пишет про RVA'. Нужно показать: вот RVA из отчета, вот секция, вот формула перевода, вот почему это поле читается именно так.",
        "Практическая проверка: открой один абзац Microsoft Learn и перепиши его в четыре формы: простыми словами, технически точно, как проверку в analyzer, как вопрос для Ghidra."
    ),
    (
        "Зачем реверсеру Intel manuals, даже если проект про Windows",
        "Windows задает формат PE и правила unwind metadata, но инструкции выполняет процессор. Поэтому под PE и ABI всегда лежит архитектура: регистры, стек, call, ret, условные переходы, исключения, флаги. Intel Software Developer Manuals нужны не для того, чтобы читать их от первой до последней страницы, а чтобы понимать, где искать строгий смысл инструкции или поведения процессора.",
        "Когда Ghidra показывает disassembly, она переводит байты в инструкции. Но значение инструкции все равно определяется архитектурой. Например, изменение RSP важно не потому, что analyzer так решил, а потому что стек и соглашение о вызовах завязаны на RSP. Сохранение регистра важно потому, что ABI определяет, кто должен сохранить значение.",
        "Ошибка новичка - думать, что decompiler output важнее инструкций. Decompiler помогает читать, но если вопрос касается prolog, epilog, stack frame или handler transfer, иногда нужно вернуться к disassembly и понимать инструкции буквально.",
        "Практическая проверка: в Ghidra выбери функцию, найди первые пять инструкций, и для каждой напиши не перевод на C, а эффект на регистры, стек или управление."
    ),
    (
        "Дизайн эксперимента: почему один запуск не закрывает вопрос",
        "Динамический анализ соблазняет простым ощущением реальности: программа ведь запущена, значит мы увидели правду. На самом деле мы увидели только один путь выполнения при конкретных аргументах, окружении, timeout, правах и состоянии системы. Поэтому dynamic validation нужно читать как эксперимент, а не как всевидящую камеру.",
        "В EH/Unwind Analyzer это отражается в полях instrumentation complete, timeout, dropped events, breakpoint failures, module coverage. Эти поля не второстепенные. Они говорят, насколько хорошо был поставлен эксперимент. Если breakpoint failures равны нулю, доверие к наблюдению выше. Если timeout достигнут, нужно честно сказать, что процесс не завершил полный путь.",
        "Ошибка новичка - считать отсутствие handler hit доказательством отсутствия handler behavior. Возможно, исключение не было сгенерировано, ветка не сработала, программа ждала ввод или sample требует специальных условий.",
        "Практическая проверка: запусти один и тот же sample с разными timeout значениями и сравни Runtime log. Запиши, какие выводы устойчивы, а какие зависят от запуска."
    ),
    (
        "JSON, HTML и CSV как разные формы одного доказательства",
        "HTML удобен для чтения глазами. JSON удобен для точной проверки полей и автоматизации. CSV удобен для импорта в Ghidra или таблицы. Это не три разных результата, а три представления одной модели анализа. Хороший инженер умеет перейти между ними без потери смысла.",
        "Если в HTML видно finding, в JSON должны быть поля, по которым этот finding появился. Если CSV экспортирует begin, end, name или comment для Ghidra, эти значения должны соответствовать тем же RVA и функциям. Когда форматы расходятся, это не косметика, а риск доверия к инструменту.",
        "Ошибка новичка - читать только красивую карточку Final assessment. Карточка нужна для обзора, но доказательство живет ниже: Static findings, Runtime functions, Runtime log, sections, manual validation plan.",
        "Практическая проверка: для одного отчета найди один и тот же finding в HTML и JSON. Потом, если есть CSV для Ghidra, проверь, какой адрес или комментарий он должен добавить в проект."
    ),
    (
        "Воспроизводимость: команда важнее впечатления",
        "Настоящий технический результат должен воспроизводиться. Поэтому рядом с отчетом всегда должна быть команда запуска analyzer, путь к binary, набор опций, версия инструмента и понимание, debug это сборка или release. Без команды невозможно отличить уверенный результат от случайного скриншота.",
        "В проекте это особенно важно для динамики. Опции --dynamic, --timeout-ms, --html, --json, --csv и путь к sample определяют, что именно будет собрано. Если в презентации показывается dynamic validation, нужно уметь заново запустить ту же проверку и объяснить, почему появились те же счетчики.",
        "Ошибка новичка - хранить только HTML и забыть команду. На защите преподаватель может попросить повторить анализ. Если команда готова, это выглядит уверенно. Если команда потеряна, даже хороший отчет кажется менее надежным.",
        "Практическая проверка: рядом с каждым показательным отчетом запиши одну строку PowerShell-команды, которая его воспроизводит. Проверь, что пути с пробелами взяты в кавычки."
    ),
    (
        "Как превратить техническую аномалию в понятный рассказ",
        "Техническая аномалия сама по себе может быть сухой: writable unwind section, runtime table call, handler hit, parse failure. Рассказ появляется, когда ты объясняешь, почему это важно, где это видно, как это проверено и чего это не доказывает. Именно этот переход превращает набор признаков в дипломную работу.",
        "Хороший рассказ имеет структуру: объект исследования, нормальное ожидание, наблюдаемое отклонение, статическое доказательство, динамическое подтверждение или его отсутствие, ручная проверка, ограничение вывода. Такая структура понятна даже человеку, который не пишет C каждый день.",
        "Ошибка новичка - начинать с самого сложного термина. Лучше сначала сказать: 'Windows хранит карту восстановления стека. В этом бинарнике часть этой карты лежит необычно и при запуске регистрируется обработчик. Сейчас покажу, где это видно'. После такой фразы слушатель готов к RUNTIME_FUNCTION и UNWIND_INFO.",
        "Практическая проверка: возьми один finding и произнеси его в трех версиях: для одногруппника, для преподавателя, для инженера-реверсера. В каждой версии смысл должен быть один, меняется только глубина терминов."
    ),
])


SOURCE_GUIDE = [
    (
        "Microsoft PE/COFF Specification",
        "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
        "формат PE/COFF, file pointer, RVA, VA, section headers, OptionalHeader, data directories",
        "главы о файле, секциях, RVA-to-file-offset и exception directory",
    ),
    (
        "Microsoft x64 calling convention",
        "https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention",
        "Windows x64 ABI, регистры аргументов, shadow store, stack alignment, unwindability",
        "главы о CPU, stack frame, prolog/epilog и связи ABI с unwind metadata",
    ),
    (
        "Microsoft x64 exception handling",
        "https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64",
        "RUNTIME_FUNCTION, UNWIND_INFO, unwind codes, chained info, language-specific handlers",
        "центральные главы о .pdata/.xdata и логике EH/Unwind Analyzer",
    ),
    (
        "Microsoft RtlAddFunctionTable",
        "https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable",
        "динамические function tables для generated code",
        "разделы о dynamic validation и runtime table calls",
    ),
    (
        "Microsoft RtlInstallFunctionTableCallback",
        "https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlinstallfunctiontablecallback",
        "callback-модель function table для very dynamic code",
        "разделы о callback-based unwind tables и динамических событиях",
    ),
    (
        "Microsoft Debugging Events and Debugging Functions",
        "https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events",
        "CREATE_PROCESS, LOAD_DLL, EXCEPTION, EXIT_PROCESS и цикл debugger events",
        "главы о dynamic_win.c, breakpoints, timeout и runtime evidence",
    ),
    (
        "Microsoft VEH and UEF APIs",
        "https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler",
        "AddVectoredExceptionHandler, SetUnhandledExceptionFilter, порядок вызова handlers",
        "разделы о handler registration, handler hits и динамическом подтверждении",
    ),
    (
        "Intel 64 and IA-32 Architectures Software Developer's Manuals",
        "https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html",
        "архитектурная база инструкций, регистров, памяти и исключений x86/x64",
        "вводные главы о машинной инструкции, регистрах, стеке и дизассемблировании",
    ),
    (
        "NSA Ghidra Software Reverse Engineering Framework",
        "https://github.com/NationalSecurityAgency/ghidra",
        "Ghidra как SRE framework: disassembly, decompilation, graphing, scripting",
        "главы о Ghidra workflow, CSV import и ручной проверке адресов",
    ),
    (
        "Practical Malware Analysis, No Starch Press",
        "https://nostarch.com/malware",
        "педагогическая модель: basic static, basic dynamic, disassembly, debugging, labs",
        "структура практикумов и идея учить анализ через повторяемые лабораторные сценарии",
    ),
    (
        "Eldad Eilam, Reversing: Secrets of Reverse Engineering",
        "https://en.wikipedia.org/wiki/Reversing:_Secrets_of_Reverse_Engineering",
        "широкая дисциплина reversing: low-level software, Windows fundamentals, tools, file formats",
        "логика перехода от основ к applied reversing и юридически осторожным выводам",
    ),
    (
        "Dennis Yurichev, Reverse Engineering for Beginners",
        "https://beginners.re/",
        "стиль разжевывания assembly, compiler output и практических примеров для начинающих",
        "живой тон объяснения, когда сложная низкоуровневая тема подается через маленькие наблюдения",
    ),
]


def clean(text: str) -> str:
    replacements = {
        "\ufeff": "",
        "\u00a0": " ",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "вЂ”": "-",
        "вЂ“": "-",
        "вЂ™": "'",
        "вЂњ": '"',
        "вЂќ": '"',
        "В«": '"',
        "В»": '"',
        "«": '"',
        "»": '"',
        "├": "|-",
        "└": "`-",
        "─": "-",
        "²": "^2",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont(FONT, r"C:\Windows\Fonts\arial.ttf"))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, r"C:\Windows\Fonts\arialbd.ttf"))
    pdfmetrics.registerFont(TTFont(FONT_ITALIC, r"C:\Windows\Fonts\ariali.ttf"))
    pdfmetrics.registerFont(TTFont(CODE_FONT, r"C:\Windows\Fonts\consola.ttf"))
    pdfmetrics.registerFont(TTFont("ConsolasRU-Bold", r"C:\Windows\Fonts\consolab.ttf"))
    pdfmetrics.registerFontFamily(FONT, normal=FONT, bold=FONT_BOLD, italic=FONT_ITALIC, boldItalic=FONT_BOLD)
    pdfmetrics.registerFontFamily(CODE_FONT, normal=CODE_FONT, bold="ConsolasRU-Bold", italic=CODE_FONT, boldItalic="ConsolasRU-Bold")


def styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontName=FONT_BOLD, fontSize=24, leading=30, alignment=TA_CENTER, textColor=colors.HexColor("#0f172a"), spaceAfter=10),
        "subtitle": ParagraphStyle("subtitle", parent=base["BodyText"], fontName=FONT, fontSize=12.2, leading=17, alignment=TA_CENTER, textColor=colors.HexColor("#334155"), spaceAfter=8),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=FONT_BOLD, fontSize=20.5, leading=27, textColor=colors.HexColor("#0f172a"), spaceBefore=11, spaceAfter=10, keepWithNext=True),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=FONT_BOLD, fontSize=16.0, leading=21.5, textColor=colors.HexColor("#1d4ed8"), spaceBefore=13, spaceAfter=8, keepWithNext=True),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName=FONT_BOLD, fontSize=13.6, leading=18.5, textColor=colors.HexColor("#0f766e"), spaceBefore=10, spaceAfter=6, keepWithNext=True),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName=FONT, fontSize=12.8, leading=20.0, firstLineIndent=15, alignment=TA_JUSTIFY, spaceAfter=8),
        "body0": ParagraphStyle("body0", parent=base["BodyText"], fontName=FONT, fontSize=12.8, leading=20.0, firstLineIndent=0, alignment=TA_JUSTIFY, spaceAfter=8),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontName=FONT, fontSize=10.6, leading=15.0, alignment=TA_LEFT, spaceAfter=4),
        "note": ParagraphStyle("note", parent=base["BodyText"], fontName=FONT_ITALIC, fontSize=11.6, leading=17.0, leftIndent=8, rightIndent=8, firstLineIndent=0, alignment=TA_JUSTIFY, textColor=colors.HexColor("#334155"), spaceBefore=6, spaceAfter=9),
        "bullet": ParagraphStyle("bullet", parent=base["BodyText"], fontName=FONT, fontSize=12.0, leading=17.6, leftIndent=12, firstLineIndent=0, spaceAfter=5),
        "code": ParagraphStyle("code", parent=base["BodyText"], fontName=CODE_FONT, fontSize=9.0, leading=11.4, leftIndent=7, rightIndent=7, backColor=colors.HexColor("#f1f5f9"), borderPadding=5, spaceBefore=4, spaceAfter=8),
    }


def xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def inline_markup(text: str) -> str:
    text = xml_escape(clean(text))
    parts = re.split(r"(`[^`]+`|\*\*[^*]+\*\*)", text)
    out: list[str] = []
    for part in parts:
        if part.startswith("`") and part.endswith("`"):
            out.append(f'<font name="{CODE_FONT}">{part[1:-1]}</font>')
        elif part.startswith("**") and part.endswith("**"):
            out.append(f'<b>{part[2:-2]}</b>')
        else:
            out.append(part)
    return "".join(out)


def para(text: str, st: dict[str, ParagraphStyle], style: str = "body") -> Paragraph:
    return Paragraph(inline_markup(text), st[style])


def heading(text: str, st: dict[str, ParagraphStyle], level: int):
    return Paragraph(inline_markup(text), st[f"h{min(level, 3)}"])


def note_box(title: str, text: str, st: dict[str, ParagraphStyle]) -> Table:
    data = [[Paragraph(f"<b>{xml_escape(title)}</b><br/>{inline_markup(text)}", st["small"])]]
    table = Table(data, colWidths=[144 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def wrap_code_line(line: str, width: int = 78) -> list[str]:
    if len(line) <= width:
        return [line]
    chunks: list[str] = []
    current = line
    while len(current) > width:
        cut = current.rfind(" ", 0, width)
        if cut < 30:
            cut = width
        chunks.append(current[:cut])
        current = "    " + current[cut:].lstrip()
    chunks.append(current)
    return chunks


def code_flowable(lines: Iterable[str], st: dict[str, ParagraphStyle]):
    wrapped: list[str] = []
    for line in lines:
        wrapped.extend(wrap_code_line(line.rstrip()))
    return Preformatted("\n".join(wrapped), st["code"])


def markdown_to_story(md: str, st: dict[str, ParagraphStyle]):
    story = []
    code_lines: list[str] | None = None
    paragraph: list[str] = []

    def flush_paragraph():
        nonlocal paragraph
        if paragraph:
            text = clean(" ".join(paragraph))
            if text:
                story.append(para(text, st))
            paragraph = []

    def flush_code():
        nonlocal code_lines
        if code_lines is not None:
            story.append(code_flowable(code_lines, st))
            code_lines = None

    for raw_line in md.splitlines():
        line = raw_line.rstrip()
        if line.startswith("```"):
            if code_lines is None:
                flush_paragraph()
                code_lines = []
            else:
                flush_code()
            continue
        if code_lines is not None:
            code_lines.append(line)
            continue
        if not line.strip():
            flush_paragraph()
            continue
        if line.startswith("#"):
            flush_paragraph()
            level = len(line) - len(line.lstrip("#"))
            title = line[level:].strip()
            if level == 1 and story:
                story.append(PageBreak())
            story.append(heading(title, st, level))
            continue
        stripped = line.strip()
        if stripped.startswith(("- ", "* ")):
            flush_paragraph()
            story.append(para("- " + stripped[2:], st, "bullet"))
            continue
        if re.match(r"^\d+[.)]\s+", stripped):
            flush_paragraph()
            story.append(para(stripped, st, "bullet"))
            continue
        if stripped.startswith(">"):
            flush_paragraph()
            story.append(para(stripped.lstrip("> "), st, "note"))
            continue
        paragraph.append(line)
    flush_paragraph()
    flush_code()
    return story


def on_page(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#0f172a"))
    canvas.rect(0, A4[1] - 16 * mm, A4[0], 16 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont(FONT_BOLD, 8.4)
    canvas.drawString(18 * mm, A4[1] - 10 * mm, "EH/Unwind Analyzer - теоретическая база с нуля")
    canvas.setFont(FONT, 8.2)
    canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 10 * mm, f"стр. {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.setFont(FONT, 7.5)
    canvas.drawString(18 * mm, 10 * mm, "связный лекционный учебник")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, "третье переработанное издание")
    canvas.restoreState()


def build_pdf(md: str, pdf_path: Path) -> int:
    register_fonts()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    st = styles()
    story = []
    story.append(Spacer(1, 35 * mm))
    story.append(Paragraph("EH/Unwind Analyzer", st["title"]))
    story.append(Paragraph("Теоретическая база с нуля", st["title"]))
    story.append(Paragraph("Третье переработанное издание: цельный лекционный учебник по PE, адресам, Windows x64 EH/Unwind, статике, динамике, отчетам и Ghidra", st["subtitle"]))
    story.append(Spacer(1, 10 * mm))
    story.append(note_box("Как читать эту версию", "Это не набор одинаковых уроков. Материал построен как университетский курс: от простого опыта работы с файлом до строгого анализа unwind metadata и защиты выводов. Читай медленно, связывай термины между собой и проверяй каждый важный тезис на отчете или в Ghidra.", st))
    story.append(PageBreak())
    story.extend(markdown_to_story(md, st))

    doc = BaseDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=28 * mm,
        rightMargin=28 * mm,
        topMargin=27 * mm,
        bottomMargin=25 * mm,
        title="EH/Unwind Analyzer - теоретическая база с нуля",
        author="EH/Unwind Analyzer project",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=on_page)])
    doc.build(story)
    return len(PdfReader(str(pdf_path)).pages)


def assert_supported_glyphs(md: str) -> None:
    bad = {}
    for ch in md:
        if ord(ch) <= 127:
            continue
        name = unicodedata.name(ch, "")
        if "CYRILLIC" in name or ch in "ёЁ":
            continue
        bad[ch] = bad.get(ch, 0) + 1
    if bad:
        details = ", ".join(f"U+{ord(ch):04X} {ch!r} x{count}" for ch, count in sorted(bad.items()))
        raise RuntimeError(f"unsupported non-cyrillic glyphs in manuscript: {details}")


def source_chapters() -> list[Path]:
    return sorted(TEACHER_DIR.glob("*.md"))


TERM_EXPLAIN = {
    "byte": ("байт", "минимальная единица данных в файле", "Байт сам по себе не имеет смысла, пока мы не знаем, является ли он частью инструкции, числа, строки, поля PE или служебного выравнивания."),
    "file offset": ("файловое смещение", "позиция байта от начала файла на диске", "Это координата hex viewer. Она нужна, когда мы доказываем, что структура действительно читается из файла."),
    "RVA": ("относительный виртуальный адрес", "адрес внутри загруженного образа относительно ImageBase", "RVA связывает PE-таблицы с памятью, но еще не является реальным адресом процесса."),
    "VA": ("виртуальный адрес", "адрес в памяти конкретного процесса", "VA получается из ImageBase и RVA; именно такие адреса часто видны в debugger и Ghidra."),
    "PE": ("Portable Executable", "формат исполняемых файлов Windows", "PE задает договор между файлом, компоновщиком, загрузчиком Windows и инструментом анализа."),
    "section": ("секция PE", "именованный диапазон файла и памяти с правами доступа", "Секция объясняет, почему одни байты исполняются, другие читаются как данные, а третьи выглядят необычно."),
    "metadata": ("метаданные", "данные, описывающие другие данные или код", "В EH/Unwind метаданные управляют тем, как Windows понимает функции и раскручивает стек."),
    "ABI": ("двоичный интерфейс приложения", "правила вызова функций, регистров, стека и выравнивания", "Без ABI нельзя понять prolog, epilog, stack frame и смысл UNWIND_INFO."),
    "stack": ("стек", "память потока для вызовов функций и временного состояния", "Стек связывает call/return, локальные данные, сохраненные регистры и обработку исключений."),
    "frame": ("кадр стека", "участок стека, принадлежащий конкретной функции", "Unwind metadata нужна, чтобы восстановить предыдущий frame при исключении."),
    "RUNTIME_FUNCTION": ("запись таблицы функций времени выполнения", "тройка BeginAddress, EndAddress и UnwindInfoAddress", "Эта запись говорит Windows, где находится функция и где лежит ее карта раскрутки."),
    "UNWIND_INFO": ("информация раскрутки стека", "структура Windows x64 с описанием prolog, stack operations, flags и handler", "Она объясняет системе, как безопасно вернуться к вызывающему кадру."),
    "handler": ("обработчик исключения", "код или callback, которому может быть передано управление", "Handler надо проверять как адрес кода: где он лежит, исполняема ли секция, достигался ли он динамически."),
    "static analysis": ("статический анализ", "чтение файла без запуска", "Он силен структурной полнотой, но не доказывает, какой путь выполнения реально произойдет."),
    "dynamic validation": ("динамическая проверка", "наблюдение процесса при запуске", "Она дает runtime-факты, но зависит от аргументов, timeout, окружения и покрытого пути."),
    "finding": ("признак", "названный проверяемый факт анализа", "Finding не является приговором; он должен иметь адрес, правило, evidence и ограничение вывода."),
    "confidence": ("уверенность", "инженерная оценка силы свидетельств", "Это не процент вредоносности, а мера согласованности найденных фактов."),
    "Ghidra": ("среда реверс-инжиниринга", "инструмент для disassembly, decompiler, memory map и ручной проверки", "Ghidra нужна не как оракул, а как микроскоп для проверки конкретного RVA."),
    "debugger": ("отладчик", "инструмент управления процессом и получения debug events", "В динамике debugger позволяет увидеть exception events, breakpoints и handler hits."),
    "runtime log": ("журнал выполнения", "последовательность событий, собранных во время запуска", "Лог нужно читать как эксперимент: что наблюдалось, что не наблюдалось и какие были ограничения."),
    "JSON": ("структурированный отчет", "машиночитаемый формат полей анализа", "JSON помогает проверить точные поля без влияния HTML-верстки."),
    "HTML": ("читаемый отчет", "страница для просмотра результатов человеком", "HTML удобен для демонстрации, но доказательство надо уметь сверять с JSON."),
}


LECTURE_BLUEPRINTS = [
    ("С нуля: зачем реверсеру вообще думать слоями", "переход от обычного файла к системе договоров", ["byte", "file offset", "PE", "section", "finding"]),
    ("От исходного текста к работающему процессу", "как идея программиста превращается в машинный код и память процесса", ["ABI", "stack", "VA", "debugger", "runtime log"]),
    ("Данные, память и адреса без путаницы", "почему file offset, RVA и VA нельзя смешивать", ["file offset", "RVA", "VA", "section", "Ghidra"]),
    ("Процессор, функция, стек и соглашение вызовов", "как CPU, ABI и stack frame делают функцию понятной", ["ABI", "stack", "frame", "UNWIND_INFO", "handler"]),
    ("Windows: процесс, поток, исключение", "как операционная система видит выполнение и особые события", ["debugger", "runtime log", "handler", "dynamic validation", "confidence"]),
    ("PE как карта загрузчика Windows", "как секции и каталоги данных связывают файл с памятью", ["PE", "section", "RVA", "metadata", "RUNTIME_FUNCTION"]),
    ("Каталог исключений и таблица RUNTIME_FUNCTION", "почему Windows нужен каталог функций для обработки исключений x64", ["RUNTIME_FUNCTION", "UNWIND_INFO", "RVA", "section", "finding"]),
    ("UNWIND_INFO как язык восстановления стека", "почему prolog, flags и handler превращаются в структуру", ["UNWIND_INFO", "ABI", "stack", "frame", "handler"]),
    ("Метод реверс-инжиниринга: от наблюдения к выводу", "как не прыгать от странности к обвинению", ["static analysis", "dynamic validation", "finding", "confidence", "Ghidra"]),
    ("Архитектура EH/Unwind Analyzer", "как проект превращает файл в проверяемый отчет", ["PE", "metadata", "finding", "JSON", "HTML"]),
    ("Командная строка и воспроизводимость", "почему команда запуска является частью доказательства", ["static analysis", "dynamic validation", "JSON", "HTML", "runtime log"]),
    ("Безопасное чтение байтов", "почему parser обязан быть недоверчивым", ["byte", "file offset", "RVA", "section", "metadata"]),
    ("PE-парсер как строгий переводчик", "как байты становятся моделью секций и каталогов", ["PE", "section", "RVA", "file offset", "finding"]),
    ("Декодер unwind-метаданных Windows x64", "как анализатор читает RUNTIME_FUNCTION и UNWIND_INFO", ["RUNTIME_FUNCTION", "UNWIND_INFO", "handler", "metadata", "confidence"]),
    ("Эвристики: почему признак не равен приговору", "как структурные факты превращаются в осторожную оценку", ["finding", "confidence", "static analysis", "metadata", "handler"]),
    ("Динамический сборщик: что реально подтверждает запуск", "как отладчик видит процесс, события, точки останова и срабатывания обработчиков", ["dynamic validation", "debugger", "runtime log", "handler", "confidence"]),
    ("Отчет как форма доказательства", "почему HTML удобен, а JSON строг", ["HTML", "JSON", "finding", "confidence", "Ghidra"]),
    ("Нормальные контрольные образцы", "зачем показывать обычные файлы рядом с подозрительными", ["static analysis", "dynamic validation", "confidence", "finding", "HTML"]),
    ("Подозрительные образцы и ручная проверка", "как построить сильный рассказ по одному бинарнику", ["finding", "RVA", "Ghidra", "handler", "runtime log"]),
    ("Задачи с решениями как тренировка мышления", "как переходить от вопроса к проверке без скачков", ["RVA", "section", "UNWIND_INFO", "JSON", "Ghidra"]),
    ("Глоссарий как карта, а не список слов", "почему термин надо связывать с действием", ["byte", "RVA", "VA", "PE", "finding"]),
    ("Свидетельства и покрытие наблюдения", "как понять силу и неполноту наблюдений", ["confidence", "dynamic validation", "runtime log", "finding", "JSON"]),
    ("Система 27 признаков", "как признаки вырастают из PE, unwind metadata и runtime behavior", ["finding", "RUNTIME_FUNCTION", "UNWIND_INFO", "section", "handler"]),
    ("Точность, валидация и эксперимент", "почему один запуск не является всей истиной", ["dynamic validation", "confidence", "runtime log", "static analysis", "HTML"]),
    ("Совместимость и будущие версии unwind metadata", "как поддерживать новые форматы без ложных выводов", ["UNWIND_INFO", "metadata", "RUNTIME_FUNCTION", "finding", "confidence"]),
]


SOURCE_RU_TITLES = {
    "Microsoft PE/COFF Specification": "Спецификация PE/COFF Microsoft: как Windows понимает исполняемый файл",
    "Microsoft x64 calling convention": "Соглашение о вызовах Microsoft x64: как функции договариваются между собой",
    "Microsoft x64 exception handling": "Обработка исключений Microsoft x64: почему существуют RUNTIME_FUNCTION и UNWIND_INFO",
    "Microsoft RtlAddFunctionTable": "RtlAddFunctionTable: как программа добавляет таблицу функций во время выполнения",
    "Microsoft RtlInstallFunctionTableCallback": "RtlInstallFunctionTableCallback: как Windows запрашивает таблицу функций через обратный вызов",
    "Microsoft Debugging Events and Debugging Functions": "События отладки Microsoft: как отладчик наблюдает процесс",
    "Microsoft VEH and UEF APIs": "VEH и UEF API Microsoft: как программа регистрирует обработчики исключений",
    "Intel 64 and IA-32 Architectures Software Developer's Manuals": "Руководства Intel по архитектуре x64: что реально делает процессор",
    "NSA Ghidra Software Reverse Engineering Framework": "Ghidra от NSA: среда ручной проверки адресов, кода и данных",
    "Practical Malware Analysis, No Starch Press": "Practical Malware Analysis: традиция статического и динамического разбора",
    "Eldad Eilam, Reversing: Secrets of Reverse Engineering": "Eldad Eilam, Reversing: широкий взгляд на низкоуровневый анализ",
    "Dennis Yurichev, Reverse Engineering for Beginners": "Dennis Yurichev, Reverse Engineering for Beginners: путь новичка через ассемблер и компилятор",
}


SOURCE_RU_EXPLAIN = {
    "Microsoft PE/COFF Specification": (
        "Этот документ важен не как ссылка для библиографии, а как основа всей координатной системы проекта. Он объясняет, почему исполняемый файл Windows состоит из заголовков, секций и каталогов данных, а не является просто набором команд процессора.",
        "Для EH/Unwind Analyzer особенно важны три идеи: файл на диске отличается от образа в памяти, адреса требуют перевода, а каталог исключений ведет к служебным таблицам x64. Без этой базы невозможно честно объяснить, почему один адрес можно найти в HTML-отчете, в Ghidra и в байтах файла.",
        "Официальное название источника: Microsoft PE/COFF Specification.",
    ),
    "Microsoft x64 calling convention": (
        "Соглашение о вызовах объясняет, как функции передают аргументы, кто сохраняет регистры, почему стек должен быть выровнен и зачем существует область, которую часто называют теневым местом под аргументы. Это правила поведения функций на машинном уровне.",
        "Unwind-метаданные нельзя понять отдельно от этих правил. Если функция изменила стек или сохранила регистр, Windows должна знать, как восстановить состояние при исключении. Поэтому соглашение о вызовах является не соседней темой, а фундаментом для UNWIND_INFO.",
        "Официальное название источника: Microsoft x64 calling convention.",
    ),
    "Microsoft x64 exception handling": (
        "Эта документация связывает исключение, стек, диапазон функции и служебные структуры Windows x64 в один механизм. Она показывает, зачем таблица RUNTIME_FUNCTION хранит начало функции, конец функции и адрес UNWIND_INFO.",
        "Именно отсюда берется строгий смысл проверок проекта. Если запись выходит за границы, если UNWIND_INFO не декодируется, если флаги ведут к странному обработчику, анализатор не фантазирует, а проверяет нарушение ожидаемого договора Windows x64.",
        "Официальное название источника: Microsoft x64 exception handling.",
    ),
    "Microsoft RtlAddFunctionTable": (
        "Эта функция показывает, что таблица функций может появиться не только из .pdata внутри файла. Программа может зарегистрировать таблицу во время выполнения, и Windows начнет учитывать ее при раскрутке стека.",
        "Для динамики проекта это принципиально: статический отчет видит файл, а динамический запуск может увидеть регистрацию runtime-таблицы. Такое событие важно не потому, что оно автоматически вредоносно, а потому что оно меняет карту функций во время работы процесса.",
        "Официальное имя API: RtlAddFunctionTable.",
    ),
    "Microsoft RtlInstallFunctionTableCallback": (
        "Этот API идет еще дальше: таблица функций может предоставляться через обратный вызов. То есть Windows при необходимости обращается к коду программы, чтобы получить сведения о функциях.",
        "Для учебника это хороший пример динамического поведения: часть картины может отсутствовать в статическом файле и появляться только при запуске. Поэтому проект отслеживает не только байты, но и события регистрации таблиц.",
        "Официальное имя API: RtlInstallFunctionTableCallback.",
    ),
    "Microsoft Debugging Events and Debugging Functions": (
        "Документация по событиям отладки объясняет, как внешний наблюдатель получает сообщения о создании процесса, загрузке модулей, исключениях и завершении. Это язык, на котором динамический сборщик разговаривает с Windows.",
        "Когда в отчете появляются CREATE_PROCESS, EXCEPTION или EXIT_PROCESS, это не произвольные строки лога. Это следы событий отладочного интерфейса. Поэтому динамический отчет надо читать как протокол эксперимента, а не как вторую версию статической таблицы.",
        "Официальная группа источников: Debugging Events and Debugging Functions.",
    ),
    "Microsoft VEH and UEF APIs": (
        "Vectored Exception Handler и Unhandled Exception Filter описывают два способа зарегистрировать код, который участвует в обработке исключений. На русском их удобно называть векторным обработчиком и фильтром необработанного исключения.",
        "Для проекта это важно потому, что обработчик является исполняемым адресом. Если он зарегистрирован, находится в необычной секции или реально срабатывает, это уже не абстрактный термин, а конкретное наблюдение, которое можно показать в отчете и Ghidra.",
        "Официальные имена API: AddVectoredExceptionHandler и SetUnhandledExceptionFilter.",
    ),
    "Intel 64 and IA-32 Architectures Software Developer's Manuals": (
        "Windows задает формат PE и правила исключений, но сами инструкции выполняет процессор. Руководства Intel объясняют регистры, стек, переходы, вызовы функций, возврат и эффекты инструкций.",
        "Без этой базы можно неправильно читать дизассемблер. Например, изменение RSP является не просто строкой в Ghidra, а изменением вершины стека. Сохранение регистра важно потому, что соглашение о вызовах назначает ответственность за его восстановление.",
        "Официальное название источника: Intel 64 and IA-32 Architectures Software Developer's Manuals.",
    ),
    "NSA Ghidra Software Reverse Engineering Framework": (
        "Ghidra нужна в книге как инструмент ручной проверки, а не как безошибочный судья. Она помогает перейти к адресу, увидеть инструкции, секцию, ссылки и приблизительную модель функции.",
        "Если отчет показывает representative RVA или адрес обработчика, Ghidra помогает проверить, что там находится. Но границы функций, восстановленный C-подобный код и имена, которые предлагает инструмент, надо воспринимать как результат анализа, а не как исходную истину.",
        "Официальное название инструмента: NSA Ghidra Software Reverse Engineering Framework.",
    ),
    "Practical Malware Analysis, No Starch Press": (
        "Эта книга важна прежде всего методикой. Она учит разделять базовый статический анализ, базовый динамический анализ, дизассемблирование, отладку и лабораторную проверку.",
        "В этом учебнике взята не чужая формулировка, а педагогическая логика: сначала наблюдение, потом инструмент, потом эксперимент, потом осторожный вывод. Именно так надо читать отчеты EH/Unwind Analyzer.",
        "Название источника: Practical Malware Analysis.",
    ),
    "Eldad Eilam, Reversing: Secrets of Reverse Engineering": (
        "Эта книга полезна широтой взгляда: реверс-инжиниринг не сводится к одной кнопке дизассемблера. Это восстановление смысла программы через форматы файлов, Windows, машинный код, инструменты и ручную проверку.",
        "В нашем учебнике этот подход проявляется в том, что PE, стек, исключения, Ghidra и отчеты не разбросаны по отдельным островам. Они собираются в одну цепочку доказательства.",
        "Название источника: Reversing: Secrets of Reverse Engineering.",
    ),
    "Dennis Yurichev, Reverse Engineering for Beginners": (
        "Этот источник полезен тем, что уважает новичка. Он показывает, как постепенно привыкнуть к ассемблеру, машинному представлению и следам компилятора.",
        "Для текущей книги это особенно важно: читатель должен не заучить аббревиатуры, а начать видеть, как высокоуровневая программа превращается в байты, адреса, функции и служебные структуры Windows.",
        "Название источника: Reverse Engineering for Beginners.",
    ),
}


def source_title_ru(title: str) -> str:
    return SOURCE_RU_TITLES.get(title, title)


def source_paragraphs_ru(title: str, url: str, gives: str, used_for: str) -> list[str]:
    paragraphs = list(SOURCE_RU_EXPLAIN.get(title, ()))
    if not paragraphs:
        paragraphs = [
            f"Этот источник используется как техническая опора для тем: {gives}.",
            f"В книге он связан с такими разделами: {used_for}.",
            f"Официальное название источника: {title}.",
        ]
    paragraphs.append(f"Ссылка для самостоятельной проверки: {url}")
    return paragraphs


def polish_common_language(md: str) -> str:
    replacements = [
        ("reverse engineering", "реверс-инжиниринг"),
        ("malware analysis", "анализ вредоносного ПО"),
        ("static analysis", "статический анализ"),
        ("Static analysis", "Статический анализ"),
        ("dynamic validation", "динамическая проверка"),
        ("Dynamic validation", "Динамическая проверка"),
        ("dynamic event", "динамическое событие"),
        ("Dynamic event", "Динамическое событие"),
        ("static HTML", "статический HTML"),
        ("dynamic HTML", "динамический HTML"),
        ("runtime behavior", "поведение во время выполнения"),
        ("runtime evidence", "свидетельства времени выполнения"),
        ("runtime events", "события времени выполнения"),
        ("Runtime events", "События времени выполнения"),
        ("runtime function table", "таблица функций времени выполнения"),
        ("function table entry", "запись таблицы функций"),
        ("function tables", "таблицы функций"),
        ("Function tables", "Таблицы функций"),
        ("runtime functions", "функции времени выполнения"),
        ("Runtime functions", "Функции времени выполнения"),
        ("runtime log", "журнал выполнения"),
        ("Runtime log", "Журнал выполнения"),
        ("file offset", "файловое смещение"),
        ("File offset", "Файловое смещение"),
        ("runtime address", "адрес во время выполнения"),
        ("runtime", "время выполнения"),
        ("Runtime", "Время выполнения"),
        ("section table", "таблица секций"),
        ("Section table", "Таблица секций"),
        ("section headers", "заголовки секций"),
        ("section", "секция"),
        ("Section", "Секция"),
        ("data directories", "каталоги данных"),
        ("Exception handling", "Обработка исключений"),
        ("exception handling", "обработка исключений"),
        ("vectored exception", "векторные обработчики исключений"),
        ("unhandled exception filter", "фильтр необработанного исключения"),
        ("static report", "статический отчет"),
        ("Static report", "Статический отчет"),
        ("dynamic report", "динамический отчет"),
        ("Dynamic report", "Динамический отчет"),
        ("dynamic run", "динамический запуск"),
        ("Dynamic run", "Динамический запуск"),
        ("static facts", "статические факты"),
        ("static finding", "статический признак"),
        ("Static finding", "Статический признак"),
        ("stack frame", "кадр стека"),
        ("Stack frame", "Кадр стека"),
        ("shadow store", "теневое место для аргументов"),
        ("instrumentation complete", "полнота инструментирования"),
        ("Instrumentation complete", "Полнота инструментирования"),
        ("dropped events", "потерянные события"),
        ("Dropped events", "Потерянные события"),
        ("dropped", "потерянные"),
        ("confidence", "уверенность"),
        ("Confidence", "Уверенность"),
        ("combo", "комбинированный"),
        ("Combo", "Комбинированный"),
        ("memory map", "карта памяти"),
        ("Memory map", "Карта памяти"),
        ("references", "ссылки"),
        ("References", "Ссылки"),
        ("reference", "ссылка"),
        ("Reference", "Ссылка"),
        ("callback", "обратный вызов"),
        ("Callback", "Обратный вызов"),
        ("target", "целевая программа"),
        ("Target", "Целевая программа"),
        ("metadata", "метаданные"),
        ("Metadata", "Метаданные"),
        ("handler hits", "срабатывания обработчиков"),
        ("Handler hits", "Срабатывания обработчиков"),
        ("handler hit", "срабатывание обработчика"),
        ("handler transfer", "передача управления обработчику"),
        ("handler behavior", "поведение обработчика"),
        ("handlers", "обработчики"),
        ("Handlers", "Обработчики"),
        ("handler", "обработчик"),
        ("Handler", "Обработчик"),
        ("findings", "признаки"),
        ("Findings", "Признаки"),
        ("finding", "признак"),
        ("Finding", "Признак"),
        ("samples", "образцы"),
        ("Samples", "Образцы"),
        ("sample", "образец"),
        ("Sample", "Образец"),
        ("timeout", "тайм-аут"),
        ("Timeout", "Тайм-аут"),
        ("breakpoints", "точки останова"),
        ("Breakpoints", "Точки останова"),
        ("breakpoint", "точка останова"),
        ("Breakpoint", "Точка останова"),
        ("coverage", "покрытие"),
        ("Coverage", "Покрытие"),
        ("evidence", "свидетельства"),
        ("Evidence", "Свидетельства"),
        ("score", "оценка"),
        ("Score", "Оценка"),
        ("decompiler output", "вывод декомпилятора"),
        ("Decompiler output", "Вывод декомпилятора"),
        ("disassembly", "дизассемблерное представление"),
        ("Disassembly", "Дизассемблерное представление"),
        ("debugger events", "события отладчика"),
        ("debug events", "события отладки"),
        ("Debug events", "События отладки"),
        ("debugger", "отладчик"),
        ("Debugger", "Отладчик"),
        ("process", "процесс"),
        ("Process", "Процесс"),
        ("events", "события"),
        ("Events", "События"),
        ("parser", "парсер"),
        ("Parser", "Парсер"),
        ("decoder", "декодер"),
        ("Decoder", "Декодер"),
        ("analyzer", "анализатор"),
    ]
    for old, new in replacements:
        pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(old) + r"(?![A-Za-z0-9_])")
        md = pattern.sub(new, md)
    return md


def explain_term(term: str) -> str:
    ru, short, deep = TERM_EXPLAIN[term]
    return (
        f"Термин `{term}` в этой книге читается так: по-русски - {ru}. "
        f"Короткий смысл: {short}. {deep} "
        f"Важно не просто запомнить английское слово, а сразу привязать его к действию: "
        f"где это поле видно в отчете, каким адресом оно выражено и как его проверить руками."
    )


def term_deep_dive(term: str, lecture_title: str) -> str:
    ru, short, deep = TERM_EXPLAIN[term]
    return "\n\n".join([
        (
            f"Разберем `{term}` глубже. Русская опора - {ru}. Если убрать технический шум, "
            f"то перед нами {short}. Но простого перевода мало: термин должен отвечать на вопрос, "
            "где объект находится, кто его создал, кто его использует и как его проверить."
        ),
        (
            f"В рамках лекции '{lecture_title}' этот термин связан с общей цепочкой анализа. "
            f"{deep} Если термин встречается в отчете, его надо сразу перевести в русский инженерный вопрос: "
            "какое поле отчета я читаю, какой адрес или диапазон за ним стоит, и что изменится, если это поле неверно."
        ),
        (
            "Строгая привычка такая: сначала назвать тип объекта, потом систему координат, потом владельца. "
            "Для адреса нужно уточнить файловое смещение, RVA или VA. Для секции - права и диапазон. "
            "Для обработчика - исполняемость адреса и факт достижения во время запуска."
        ),
        (
            "Связь с EH/Unwind Analyzer проявляется в том, что проект не работает с абстрактными словами. "
            "Он читает байты, строит модель PE, переводит адреса, декодирует unwind-метаданные, создает признак "
            "и показывает человеку доказуемые детали. Поэтому объяснение термина должно заканчиваться ссылкой "
            "на таблицу отчета, JSON-поле, адрес в Ghidra или строку динамического журнала."
        ),
        (
            f"Проверка понимания по термину `{term}` простая: найди один пример в отчете, перепиши его по-русски "
            "и добавь фразу 'я могу подтвердить это через ...'. Если вместо многоточия получается назвать конкретный "
            "HTML-блок, JSON-поле, Ghidra-адрес или строку журнала выполнения, термин стал рабочим знанием."
        ),
        (
            "Теперь свяжем это со слоями. В файле на диске объект существует как байты и смещения. "
            "В загруженном образе он получает место в карте PE и может выражаться через RVA. "
            "В процессе он может проявиться как виртуальный адрес, событие отладки или срабатывание обработчика. "
            "Один термин может проходить через все эти слои, и именно поэтому его нельзя читать как отдельное слово."
        ),
        (
            "Для Windows важен не красивый перевод, а соблюдение договора. Если объект относится к PE, "
            "он должен согласовываться с заголовками, секциями и каталогами данных. Если он относится к x64 unwind, "
            "он должен согласовываться с диапазоном функции, стеком, прологом и правилами обработки исключений. "
            "Если он относится к динамике, его надо читать как наблюдение конкретного запуска с конкретными ограничениями."
        ),
        (
            "Маршрут ручной проверки всегда похож на маленькое расследование. Сначала найди объект в HTML, "
            "чтобы увидеть человеческое объяснение. Затем открой JSON, чтобы проверить точные поля без влияния верстки. "
            "После этого перейди в Ghidra по адресу или секции и посмотри, что находится вокруг. "
            "Если есть динамический отчет, сравни его журнал с тем, что предполагала статика."
        ),
        (
            "Типичная ошибка выглядит так: человек узнает термин, но пропускает вопрос о границах. "
            "Граница может быть файловой, адресной, секционной, временной или доказательной. "
            "Файловая граница отвечает на вопрос, есть ли нужные байты. Адресная - правильно ли переведена координата. "
            "Секционная - какие права и роль у области. Временная - проявилось ли это при запуске. "
            "Доказательная - можно ли на основании этого делать сильный вывод."
        ),
    ])


def project_lecture_chapter(number: int, title: str, focus: str, terms: list[str]) -> str:
    out = [f"# Том III. Лекция {number}. {title}"]
    out.append(
        f"Эта лекция нужна, чтобы разобрать тему '{focus}' не как перечень английских названий, "
        "а как связный участок инженерной картины. Сначала мы говорим простым языком, затем "
        "переходим к строгим структурам Windows и только после этого связываем тему с EH/Unwind Analyzer."
    )
    out.append(
        "Главный принцип такой: любой низкоуровневый термин должен иметь три опоры. "
        "Первая - человеческий смысл, то есть зачем эта вещь существует. Вторая - точная техническая форма, "
        "то есть поле, структура, адрес или событие. Третья - проверка, которую можно выполнить в отчете, JSON, "
        "Ghidra или debugger. Если хотя бы одной опоры нет, термин остается пустым английским словом."
    )
    out.append("## Термины лекции простыми словами")
    for term in terms:
        out.append(explain_term(term))
        out.append(term_deep_dive(term, title))
    out.append("## Как эта тема работает внутри Windows и PE")
    out.append(
        f"В теме '{title}' важно видеть не отдельные детали, а цепочку. Файл на диске содержит байты. "
        "PE-заголовки объясняют, какие байты станут секциями. Секции получают виртуальные адреса и права. "
        "На x64 часть кода связывается с таблицами `RUNTIME_FUNCTION`, а эти таблицы ведут к `UNWIND_INFO`. "
        "Когда происходит исключение или отладчик ловит событие, Windows опирается не на догадку, а на эти "
        "формальные описания. Поэтому любая аномалия в таблицах, адресах или размещении metadata является "
        "поводом для внимательного анализа."
    )
    out.append(
        "Новичку легко потеряться, потому что одни и те же числа путешествуют между слоями. "
        "Например, значение может быть RVA в таблице, VA в Ghidra, file offset в hex viewer и строкой в JSON. "
        "Глубокое понимание начинается там, где ты перестаешь говорить просто 'адрес' и каждый раз уточняешь, "
        "в каком пространстве координат находишься."
    )
    out.append(
        "Чтобы это стало не теорией ради теории, представь один полный путь. Сначала файл лежит на диске, "
        "и мы можем открыть его как последовательность байтов. Затем PE-заголовки говорят, какие области "
        "станут секциями. Затем загрузчик Windows создает image в памяти. Затем процессор исполняет код, "
        "а ABI задает правила вызова функций. Затем при исключении Windows ищет function table entry и "
        "читает unwind metadata. Analyzer идет по этой же цепочке снаружи и проверяет, где она выглядит "
        "согласованной, а где возникает разрыв."
    )
    out.append(
        "Такой путь важен еще и потому, что он защищает от ложных выводов. Если видеть только последнюю "
        "карточку verdict, можно решить, что инструмент просто выдает оценку. Но внутри оценки лежит "
        "много маленьких проверок: границы секций, отображение RVA, корректность структуры, права памяти, "
        "наличие handler, runtime events и ограничения эксперимента. Чем больше этих проверок ты можешь "
        "объяснить словами, тем меньше книга похожа на список терминов."
    )
    out.append("## Как это проявляется в EH/Unwind Analyzer")
    out.append(
        "В проекте эта тема проходит через несколько этапов. Сначала parser читает PE и проверяет, можно ли "
        "доверять размерам, секциям и каталогам. Потом unwind decoder пытается прочитать таблицы функций и "
        "metadata. Затем heuristics engine называет проверяемые факты признаками. Если включена динамика, "
        "collector запускает процесс под наблюдением и собирает runtime-события. Наконец report writer "
        "показывает это человеку в HTML и JSON."
    )
    out.append(
        "Смысл такого pipeline не в том, чтобы заменить человека. Он нужен, чтобы быстро поднять факты, "
        "которые человек затем проверяет. Analyzer может сказать: 'вот finding, вот affected count, вот RVA, "
        "вот секция, вот runtime log'. Человек должен объяснить, почему это важно и где границы вывода."
    )
    out.append(
        "Поэтому в учебном чтении проекта всегда держи две колонки. В первой колонке - что сделал инструмент: "
        "прочитал, декодировал, сравнил, зарегистрировал событие, сформировал отчет. Во второй колонке - что "
        "должен сделать человек: проверить адрес, открыть секцию, сравнить Ghidra, прочитать JSON, назвать "
        "ограничение. Если есть только первая колонка, получается черный ящик. Если есть только вторая, теряется "
        "автоматизация. Сила проекта в их соединении."
    )
    out.append("## Типичная ошибка и правильное рассуждение")
    out.append(
        "Типичная ошибка - увидеть английское имя поля и начать повторять его как заклинание. "
        "Например, сказать '`UNWIND_INFO` неправильный' недостаточно. Нужно сказать: какая функция ссылается "
        "на эту metadata, какой RVA используется, в какую секцию он попадает, что именно не декодируется или "
        "выглядит необычно, и можно ли подтвердить это динамически."
    )
    out.append(
        "Правильное рассуждение идет медленнее, но сильнее. Сначала объект: таблица, секция, handler или событие. "
        "Потом координата: file offset, RVA или VA. Потом правило: что ожидает PE/Windows x64. Потом наблюдение: "
        "что именно нарушено. Потом проверка: где это видно в отчете и Ghidra. В конце ограничение: чего этот "
        "факт еще не доказывает."
    )
    out.append("## Мини-лекция для защиты")
    out.append(
        "Если эту тему нужно объяснить преподавателю за одну минуту, начни не с английского термина, а с роли. "
        f"Скажи: 'В этой части проекта я проверяю {focus}. Это важно, потому что Windows должна понимать, "
        "где находится функция, как восстановить стек и куда передавать управление при исключении. Если структура "
        "или адреса выглядят необычно, analyzer фиксирует не приговор, а проверяемый признак'."
    )
    out.append(
        "Затем покажи один адрес и один отчет. Не надо показывать всю книгу. Достаточно одной цепочки: "
        "HTML summary -> Static findings -> Runtime functions -> JSON field -> Ghidra address. "
        "Когда слушатель видит эту цепочку, английские слова перестают быть шумом и становятся инструментами."
    )
    out.append("## Самопроверка")
    out.append(
        "Ответь письменно на три вопроса. Что в этой теме является объектом анализа? В какой системе координат "
        "он записан? Какая ручная проверка подтверждает, что analyzer не выдумал вывод? Если ответы получились "
        "конкретными, лекция усвоена. Если ответы общие, вернись к терминам и найди адрес, секцию или событие."
    )
    return "\n\n".join(out)


def chapter_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return clean(line[2:])
    return fallback


def chapter_headings(text: str) -> list[str]:
    heads = []
    for line in text.splitlines():
        if line.startswith("## "):
            heads.append(clean(line[3:]))
    return heads[:8]


def lecture_bridge(title: str, headings: list[str], index: int) -> str:
    focus = ", ".join(headings[:4]) if headings else "основные понятия главы"
    return f"""
## Перед лекцией: зачем нужна эта глава

Эта глава отвечает за участок карты: {title}. В ней важны темы: {focus}. Читай ее не как отдельный конспект, а как часть маршрута от байтов PE к проверяемому выводу.

Перед чтением держи один вопрос: какой объект здесь появляется, кто его создает, в каких координатах он живет и как его проверить в отчете, Ghidra или исходном коде проекта?
"""


def after_chapter_reflection(title: str, index: int) -> str:
    return f"""
## После лекции: как связать главу с проектом

После главы "{title}" проверь себя коротко: назови один объект из главы, его адресный слой, поле отчета и ручной способ проверки. Если не получается, вернись к примеру и восстанови цепочку от байта до вывода.
"""


def concept_chapter() -> str:
    out = ["# Том II. Живой словарь: термины не отдельно, а во взаимосвязи"]
    out.append("""
Технический словарь часто пугает новичка тем, что каждое слово кажется отдельной дверью в новую комнату. В реверс-инжиниринге это ощущение особенно сильное: byte, RVA, VA, section, handler, unwind metadata, exception directory, confidence. Но на самом деле эти слова образуют цепочку. Одно понятие подает руку следующему.

Поэтому ниже термины объясняются не как сухой глоссарий. Каждый термин получает простой смысл, строгий смысл, место в проекте, соседние понятия и ручную проверку. Это не справочник для заучивания. Это тренажер связного мышления.
""")
    for i, c in enumerate(CONCEPTS, 1):
        out.append(f"## {i}. {c.name} ({c.ru})")
        out.append(f"{c.name.capitalize()} сначала надо понять по-человечески: {c.plain}. В этот момент не нужно стесняться простого объяснения. Хороший преподаватель всегда начинает с него, потому что без простого образа строгая формула остается чужой.")
        out.append(f"Строго говоря, это {c.strict}. Здесь важно не только определение, но и границы применимости. Почти все ошибки новичка связаны с тем, что он переносит смысл термина в неправильный слой: файл, image, процесс, отчет или Ghidra.")
        out.append(f"В EH/Unwind Analyzer этот термин появляется так: {c.project}. Значит, когда ты видишь его в коде или отчете, надо сразу спросить: из какого слоя пришло это значение, какая функция проекта его создала и какая функция потом ему доверяет.")
        out.append(f"Соседние понятия: {c.neighbor}. Эти связи важнее голого перевода. Например, если термин связан с адресами, нужно сразу отличать file offset, RVA и VA. Если связан с exception handling, нужно вспомнить стек, frame и handler.")
        out.append(f"Ручная проверка: {c.check}. Это превращает термин из слова в действие. Реверс-инженер не просто говорит 'я знаю, что такое {c.ru}', а показывает, где это находится и как проверить.")
    return "\n\n".join(out)


def findings_chapter() -> str:
    out = ["# Том IV. Почему 27 признаков имеют смысл: теория, доказательство и осторожность вывода"]
    out.append("""
Признак в этом проекте - не приговор и не ярлык "malware". Это аккуратно названный низкоуровневый факт. Хорошая инженерная культура начинается с того, что мы не преувеличиваем смысл факта. Мы говорим: вот что наблюдается; вот в какой семье evidence это находится; вот почему оно необычно; вот как проверить руками; вот какие ограничения у вывода.

Эта глава связывает признаки с теорией. Она не заменяет отдельный учебник по признакам, а показывает, почему признаки вообще вырастают из PE, секций, RUNTIME_FUNCTION, UNWIND_INFO, handlers и dynamic evidence.
""")
    for i, f in enumerate(FINDINGS, 1):
        out.append(f"## {i}. {f.code}")
        out.append(f"Что наблюдается: {f.meaning}. Это нужно читать как техническое утверждение, а не эмоциональный вывод. Если в отчете есть {f.code}, сначала найди affected count, representative RVA и message.")
        out.append(f"Теоретическая опора: {f.theory}. Семья evidence: `{f.family}`. Семья показывает, какой слой проверяется: целостность таблиц, декодирование unwind metadata, placement, reuse или handler model.")
        out.append(f"Как проверять: {f.manual}. После этого желательно открыть HTML/JSON и Ghidra. В HTML удобно увидеть итоговую таблицу, в JSON - точные поля, в Ghidra - код и контекст.")
        out.append("Как говорить на защите: 'анализатор обнаружил проверяемый структурный факт; я показываю адрес или диапазон, объясняю нарушенный инвариант, затем подтверждаю или ослабляю вывод ручной проверкой'. Такая формулировка честнее и сильнее, чем резкое заявление без доказательства.")
    return "\n\n".join(out)


def deep_foundation_chapter() -> str:
    sections = [
        (
            "Программа как слои договоров",
            "Когда человек без подготовки впервые слышит слово 'бинарник', оно звучит как черный ящик. На самом деле бинарник становится понятным, если смотреть на него как на цепочку договоров. Исходный код договаривается с компилятором о смысле функций и данных. Компилятор договаривается с процессором о машинных инструкциях. Компоновщик договаривается с загрузчиком Windows о формате PE. Операционная система договаривается с программой о памяти, потоках, исключениях и соглашении вызовов. Реверс-инженер входит в эту цепочку с обратной стороны и восстанавливает, какие договоры видны в готовом файле.",
            "EH/Unwind Analyzer занимается не всей программой сразу. Его область уже и точнее: он изучает то место, где PE, Windows x64 ABI и механизм исключений встречаются в runtime function table и unwind metadata. Это узкая тема, но она глубоко связана с фундаментом. Нельзя понять UNWIND_INFO, если не понимать стек. Нельзя понять стек, если не понимать функцию. Нельзя понять функцию, если не понимать соглашение вызовов. Нельзя понять адрес handler, если путать RVA и VA.",
            "Поэтому правильное чтение отчета начинается не с verdict. Verdict - это конец маршрута. Начало маршрута - вопрос: какой договор сейчас проверяется? Если проверяется PE layout, мы говорим о секциях, размерах, raw offset и RVA. Если проверяется function table, мы говорим о begin, end и unwind RVA. Если проверяется динамика, мы говорим о реальном запуске, debug events, API calls и handler hits. Глубина появляется тогда, когда эти слои не смешиваются.",
            "Проверка понимания простая: попробуй объяснить один и тот же адрес тремя способами. В файле это смещение от начала байтов. В PE image это RVA относительно ImageBase. В запущенном процессе это VA. Если эти три объяснения не путаются, значит ты уже вышел из режима 'черный ящик' и начал думать как реверс-инженер."
        ),
        (
            "Почему байты не равны смыслу",
            "Байт сам по себе ничего не говорит. Один и тот же байт может быть частью инструкции, числом, символом строки, полем структуры, padding или случайным мусором. Смысл появляется только из контекста. В PE этот контекст задают заголовки и секции. В коде этот контекст задают инструкции и поток управления. В unwind metadata этот контекст задают правила Windows x64 exception handling.",
            "Например, число 0x1000 может быть RVA начала секции, размером, константой в коде или частью машинной инструкции. Если аналитик видит число и сразу делает вывод, он гадает. Если аналитик спрашивает, кто владеет этим числом и в какой структуре оно находится, он анализирует. Именно поэтому проект сначала строит модель PE, а только потом читает exception directory и runtime functions.",
            "Через эту мысль становится понятной роль parser. Parser не 'ищет вирус'. Parser делает более скромную и важную работу: он превращает сырые байты в проверяемые структуры, не доверяя входу. Если размер секции выходит за файл, parser должен заметить. Если RVA нельзя перевести в file offset, decoder не имеет права читать дальше. Это не бюрократия, а безопасность анализа.",
            "Практический навык: когда видишь любое поле в отчете, не называй его сразу 'подозрительным'. Сначала назови его тип: байты, offset, RVA, VA, размер, флаг, имя секции, адрес handler, событие dynamic log. Потом скажи, из какой структуры оно пришло. Только после этого можно обсуждать нормальность или аномальность."
        ),
        (
            "Функция, стек и причина существования unwind metadata",
            "Функция в исходном коде кажется простой: есть имя, аргументы, тело и return. В бинарнике функция становится соглашением о переходе управления и состоянии процессора. Инструкция call кладет адрес возврата, функция может выделить место на стеке, сохранить регистры, вызвать другие функции и затем вернуть управление. Все это должно быть сделано так, чтобы вызывающая и вызываемая стороны не разрушили состояние друг друга.",
            "Стек нужен как рабочая память вызовов. Там лежат адреса возврата, локальные данные, сохраненные регистры и иногда аргументы. Но стек не является самодокументирующимся. Если исключение происходит внутри функции, Windows должна понять, как вернуться к предыдущему кадру. Она не может просто 'посмотреть глазами'. Ей нужна формальная карта того, что функция успела сделать со стеком и регистрами.",
            "Эта карта и есть unwind metadata. UNWIND_INFO описывает prolog, размер стека, сохранения регистров и наличие обработчика. RUNTIME_FUNCTION говорит, для какого диапазона кода эта карта действует. Поэтому runtime function table - это не второстепенная таблица. Это инфраструктура, без которой корректная обработка исключений и stack unwinding на x64 становятся ненадежными.",
            "Отсюда понятно, почему аномалии в этой области важны. Если unwind RVA указывает за пределы образа, карта не читается. Если metadata лежит в writable section, возникает вопрос, можно ли ее менять во время выполнения. Если handler указывает в non-executable область, это противоречит ожиданию о коде обработчика. Это не магические признаки, а нарушения вокруг механизма восстановления управления."
        ),
        (
            "PE как карта между диском и памятью",
            "Файл на диске и программа в памяти не совпадают один к одному. PE описывает, как Windows должна превратить файл в image: какие секции загрузить, куда они попадут, какие права получат, где лежат импорты, релокации, ресурсы и exception directory. Поэтому PE - это карта перехода между двумя мирами: raw file и virtual memory.",
            "Секция имеет raw offset и raw size для файла, а также virtual address и virtual size для памяти. Эти пары легко перепутать. Если аналитик открывает hex viewer, он находится в мире file offsets. Если он открывает Ghidra с ImageBase, он чаще всего находится в мире virtual addresses. Если он читает RUNTIME_FUNCTION, он работает с RVA. Один и тот же объект надо уметь переносить между этими мирами.",
            "EH/Unwind Analyzer делает такой перенос постоянно. Когда он видит UnwindInfoAddress, он должен понять, какая секция содержит этот RVA, можно ли отобразить его в file offset, достаточно ли байтов осталось до конца области, какие права у секции и как это соотносится с ожиданиями Windows. Если на любом шаге возникает противоречие, появляется конкретный finding.",
            "Глубокое понимание PE начинается с простой дисциплины: никогда не говорить 'адрес' без уточнения. Говори file offset, RVA или VA. Говори section и range. Говори raw size или virtual size. Тогда отчет перестает быть набором чисел и превращается в проверяемую карту."
        ),
        (
            "Статический анализ как чтение договора",
            "Статический анализ не запускает программу. Это не недостаток, а особенность метода. Он читает то, что записано в файле: заголовки, секции, таблицы, metadata, строки, импорты, диапазоны функций. Его сила в том, что он видит структуру целиком и не зависит от того, прошла ли программа нужную ветку во время запуска.",
            "Но статический анализ не должен выдавать себя за поведенческое доказательство. Если metadata необычна, это факт файла. Если handler лежит вне ожидаемой секции, это факт размещения. Если runtime table не отсортирована, это факт структуры. Эти факты сильны, но они не равны утверждению 'при запуске обязательно произойдет такое-то действие'.",
            "Проект поэтому разделяет static findings и dynamic validation. Static findings говорят: в PE есть проверяемое нарушение или необычность. Dynamic validation говорит: во время конкретного запуска были такие-то события. Когда эти два слоя поддерживают друг друга, вывод становится сильнее. Когда динамика молчит, статический факт не исчезает, но его надо формулировать осторожнее.",
            "Хорошая фраза для защиты: 'Статически я вижу нарушение такого-то инварианта. Это не приговор, а структурный факт. Дальше я проверяю, есть ли runtime-события, которые усиливают вывод, и показываю ручную проверку в Ghidra или JSON'."
        ),
        (
            "Динамическая проверка как эксперимент",
            "Динамика кажется убедительной, потому что программа реально запускается. Но любой запуск - это эксперимент с условиями. Есть аргументы командной строки, текущая папка, права, загруженные DLL, timeout, путь выполнения, случайность и состояние системы. Один запуск не покрывает всю программу. Он показывает только то, что произошло в данном сценарии.",
            "Debug API Windows позволяет наблюдать события процесса: создание процесса, загрузку DLL, исключения, завершение, точки останова. EH/Unwind Analyzer использует это, чтобы увидеть регистрацию обработчиков, вызовы runtime table API и попадания в handler. Это ценно, потому что такие события уже не просто лежат в файле, а происходят во время выполнения.",
            "Но динамический отчет надо читать вместе с его ограничениями. Timeout reached означает, что эксперимент остановлен по времени. Breakpoint failures говорят, что часть точек наблюдения могла не установиться. Dropped events говорят, что collector мог не сохранить все события. Instrumentation complete показывает, насколько наблюдение завершено. Эти поля не мелочь, а научная честность.",
            "Поэтому правильный вывод звучит так: 'В этом запуске наблюдались такие-то события'. Неправильный вывод звучит так: 'В программе больше ничего нет'. Реверс-инженер силен не громкостью утверждения, а точностью границ."
        ),
        (
            "Ghidra как место ручной проверки",
            "Ghidra не является волшебным судьей. Это мощная среда reverse engineering: disassembly, decompiler, memory map, functions, references, scripts. Она помогает человеку увидеть код и данные, но ее результат тоже является анализом, а не исходной истиной. Разметка функции может отличаться от RUNTIME_FUNCTION. Decompiler может упростить или неверно восстановить намерение. Поэтому Ghidra надо использовать с вопросом.",
            "В этом проекте главный вопрос к Ghidra обычно такой: где находится representative RVA из отчета и что вокруг него видно? Если отчет говорит о handler, нужно перейти к адресу handler. Если отчет говорит об unwind metadata, нужно посмотреть секцию и связанные диапазоны. Если отчет говорит о странной секции, нужно открыть memory map и проверить права.",
            "Правильный workflow: сначала отчет формулирует вопрос, затем Ghidra помогает проверить контекст. Неправильный workflow: открыть весь бинарник и бесцельно искать 'что-то страшное'. Ручная проверка должна быть адресной. У нее есть вход: RVA, section, finding code, handler или runtime event. У нее есть выход: подтверждение, ослабление или уточнение вывода.",
            "На защите это выглядит сильно: 'Вот строка отчета. Вот RVA. Вот расчет адреса для Ghidra. Вот окружающий disassembly или memory map. Вот почему это подтверждает или уточняет finding'. Такой показ превращает инструмент из черного ящика в проверяемую систему."
        ),
        (
            "От признака к доказательству",
            "Признак - это не обвинение. Признак - это наблюдение, которому дали имя. Например, `unwind_parse_fail` говорит, что UNWIND_INFO не удалось корректно разобрать. `rf_unsorted` говорит, что порядок runtime function entries нарушает ожидание. `handler_nonexec_section` говорит, что обработчик связан с областью без executable permission. В каждом случае важно не имя признака, а цепочка доказательства.",
            "Цепочка доказательства состоит из нескольких звеньев. Первое - объект: какая функция, секция, таблица или handler. Второе - координата: RVA, VA или file offset. Третье - правило: какой инвариант Windows/PE/x64 ожидается. Четвертое - наблюдение: что именно нарушено. Пятое - проверка: где это видно в HTML, JSON, Ghidra или runtime log. Шестое - ограничение: чего этот факт не доказывает.",
            "Если хотя бы одно звено пропущено, вывод становится слабым. Если нет координаты, нечего проверять. Если нет правила, непонятно, почему это аномалия. Если нет ограничения, вывод звучит как преувеличение. Поэтому хороший отчет должен не только ставить score, но и показывать details, affected count, representative RVA, Runtime functions и Manual validation plan.",
            "Финальный навык реверс-инженера - говорить спокойно. Не 'это точно вредонос'. А 'это необычное размещение unwind metadata; оно затрагивает такие-то функции; динамический запуск показал такие-то события; ручная проверка должна подтвердить такие-то адреса; уверенность ограничена такими-то условиями'. Это и есть инженерная глубина."
        ),
    ]
    out = ["# Том I. Фундамент: от байтов к доказательству"]
    out.append("""
Эта глава написана как длинная вводная лекция для человека, который раньше не занимался reverse engineering. Ее задача - не перечислить термины, а собрать картину. В центре книги находится EH/Unwind Analyzer, но понять его можно только через общую систему: файл, процессор, память, PE, загрузчик Windows, ABI, исключения, unwind metadata, static analysis, dynamic validation и ручную проверку.

Читать эту главу надо медленно. Каждый раздел отвечает на вопрос "почему это вообще существует?". Почему у файла есть секции? Почему адресов несколько? Почему функции нужен стек? Почему Windows хранит unwind metadata? Почему finding не равен verdict? Если эти вопросы проясняются, дальнейшие главы перестают быть набором сложных слов.
""")
    for i, (title, *paragraphs) in enumerate(sections, 1):
        out.append(f"## {i}. {title}")
        out.extend(paragraphs)
        out.append("Короткая самопроверка: сформулируй этот раздел одним предложением, затем найди в отчете проекта поле или таблицу, где эта идея становится видимой.")
    out.append("""
## Итог фундаментальной главы

После этой главы у тебя должна появиться главная мысль: реверс-инжиниринг не является гаданием по непонятным байтам. Это восстановление договоров. PE договаривается с Windows о загрузке. ABI договаривается о вызовах функций. Unwind metadata договаривается о восстановлении стека. Analyzer проверяет, где эти договоры выполнены, нарушены или выглядят необычно. Человек затем проверяет самые важные места руками.

Если держать эту рамку, даже сложные слова становятся рабочими. RVA - это не страшная аббревиатура, а координата внутри image. RUNTIME_FUNCTION - не просто строка таблицы, а связь диапазона кода с картой восстановления. UNWIND_INFO - не мусорная структура, а инструкция для раскрутки стека. Dynamic log - не шум, а дневник эксперимента. Ghidra - не оракул, а микроскоп для проверки адресного вопроса.
""")
    return "\n\n".join(out)


def deep_unwind_mechanics_chapter() -> str:
    topics = [
        (
            "Почему исключение - это не просто ошибка",
            "В бытовом смысле исключение часто воспринимается как 'что-то сломалось'. В системном смысле exception - это механизм передачи управления при особом событии. Событие может быть ошибкой доступа к памяти, делением на ноль, breakpoint, single step, программно сгенерированным исключением или ситуацией, которую runtime использует как часть своего поведения.",
            "Для реверс-инженера важно не путать событие и смысл. Сам факт exception не доказывает вредоносность. Debugger тоже использует exceptions. Защитные механизмы и антиотладка тоже используют exceptions. Обычный runtime может использовать обработку исключений легально. Поэтому analyzer считает не эмоцию, а структуру: где зарегистрирован handler, какая таблица функций существует, какой код был достигнут при запуске.",
            "Windows должна решить, кому передать управление после exception. Для этого она использует контекст потока, адрес инструкции, таблицы функций, обработчики и правила поиска. Если программа x64 имеет функции с изменением стека, система должна уметь правильно подняться по кадрам. Поэтому исключение сразу связывает CPU context, stack, ABI и unwind metadata.",
            "В отчете это проявляется двумя путями. Статически analyzer читает таблицы, которые Windows будет использовать. Динамически analyzer наблюдает события, которые реально произошли. Глубина анализа появляется тогда, когда ты понимаешь, какая часть относится к потенциальной карте поведения, а какая - к фактическому запуску."
        ),
        (
            "Контекст потока и точка остановки мира",
            "Когда exception происходит, поток имеет конкретное состояние: регистры, RSP, RIP, flags, память стека. Это состояние называют context. Оно важно потому, что обработчик должен понять, где выполнение остановилось и как можно продолжить, завершить или передать управление дальше.",
            "На x64 адрес текущей инструкции и состояние стека определяют, какую RUNTIME_FUNCTION нужно искать. Если RIP находится внутри диапазона BeginAddress-EndAddress, Windows получает соответствующий UnwindInfoAddress. Без этой связи невозможно аккуратно понять, как восстановить предыдущий frame.",
            "Debugger видит exception как debug event. Это не то же самое, что обычный printf в программе. Потоки процесса приостанавливаются, debugger получает событие, решает, что делать, и затем продолжает процесс. Поэтому dynamic collector работает в мире событий и синхронизации, а не просто читает лог программы.",
            "В отчете Runtime log каждая строка про exception, breakpoint или handler hit связана с этим механизмом. Если ты читаешь лог как обычный текст, он кажется шумом. Если читаешь его как историю остановок и продолжений потока, он становится понятным."
        ),
        (
            "Поиск функции по RIP",
            "RUNTIME_FUNCTION table нужна, чтобы по адресу инструкции найти описание функции. Представь библиотечный каталог: если ты знаешь номер страницы, тебе нужно понять, в какой главе эта страница находится. BeginAddress и EndAddress задают диапазон. UnwindInfoAddress говорит, где лежит инструкция по восстановлению.",
            "Если таблица отсортирована, поиск может быть быстрым и однозначным. Если диапазоны перекрываются, один RIP может попадать сразу в несколько описаний. Если begin больше или равен end, диапазон не имеет смысла. Если UnwindInfoAddress не отображается в файл, статический analyzer не может безопасно прочитать карту.",
            "Эти нарушения не являются декоративными. Они касаются самого механизма поиска. Поэтому признаки вроде rf_unsorted, rf_overlap, rf_bad_range и unwind_rva_oob имеют смысл не как набор ругательств, а как проверка пригодности таблицы для надежного объяснения кода.",
            "Ручная проверка в Ghidra здесь проста: возьми BeginAddress, прибавь ImageBase, перейди к адресу и посмотри, есть ли там код. Затем сравни границы функции Ghidra с EndAddress. Если они расходятся, объясни источник каждого взгляда."
        ),
        (
            "Что именно хранит UNWIND_INFO",
            "UNWIND_INFO можно представить как компактную инструкцию для обратного движения по функции. Она не хранит исходный код. Она хранит сведения, важные для восстановления состояния: версию, флаги, размер prolog, количество unwind codes, описание операций со стеком и регистрами, а иногда handler или chained info.",
            "Prolog важен потому, что именно там функция обычно меняет RSP и сохраняет nonvolatile registers. Если exception случился после prolog, Windows должна знать, как отменить эти действия. Если exception случился внутри prolog, правила становятся еще аккуратнее. Поэтому unwind codes имеют порядок и смысл, а не являются произвольным массивом.",
            "Flags меняют хвост структуры. EHANDLER или UHANDLER означают, что после unwind codes есть адрес обработчика. CHAININFO означает, что структура ссылается на другую RUNTIME_FUNCTION. Если parser не учитывает flags, он будет читать не те байты как не те поля. Поэтому decoder должен быть строгим.",
            "В проекте parse failure важен именно здесь. Он говорит: по указанному адресу структура не была прочитана как корректная UNWIND_INFO по ожидаемым правилам. Это не 'не понравилось', а конкретный сбой декодирования."
        ),
        (
            "Handler как код, а не просто число",
            "Handler RVA в отчете - это не абстрактный номер. Это адрес кода или callback, которому система может передать управление в процессе обработки exception. Поэтому вокруг handler появляются вопросы: попадает ли он в image, в какую секцию попадает, исполняемая ли эта секция, не доминирует ли один handler над большим числом функций, не выглядит ли reuse слишком концентрированным.",
            "Если handler указывает за пределы image, это серьезный структурный вопрос. Если handler находится в non-executable section, возникает конфликт с ожиданием исполняемого кода. Если handler находится в writable section, возникает вопрос изменяемости. Если один handler обслуживает слишком много функций, это может быть легальным runtime-паттерном, но также может быть признаком обфускации или необычной схемы.",
            "Dynamic validation усиливает этот слой, когда handler реально достигается. Handler hit говорит, что breakpoint на handler сработал. Но даже тут надо смотреть контекст: какое exception было, first chance или second chance, какой поток, какой адрес, завершился ли процесс нормально или аварийно.",
            "На защите handler надо показывать не словами, а маршрутом: handler RVA в отчете, секция и permissions, переход в Ghidra, строка Runtime log при динамическом подтверждении. Тогда число становится доказательством."
        ),
        (
            "Динамические function tables",
            "Не все функции обязаны быть описаны только статической .pdata в файле. Windows поддерживает динамические function tables через API вроде RtlAddFunctionTable и RtlInstallFunctionTableCallback. Это нужно, например, для JIT, runtime-generated code и сложных сред выполнения. Но для анализа это важный runtime-сигнал.",
            "Если процесс вызывает RtlAddFunctionTable, он сообщает Windows о таблице функций во время выполнения. Если вызывает RtlInstallFunctionTableCallback, он может устанавливать callback для получения function table information. Это легально, но аналитически интересно, потому что карта unwind поведения становится частично динамической.",
            "Статический анализ может не увидеть всю такую карту заранее. Он видит файл. Динамический collector может увидеть сам факт регистрации. Поэтому Runtime table calls в отчете имеет особый вес: это не просто странное поле PE, а runtime-действие вокруг механизма unwind.",
            "Правильный вывод не должен преувеличивать: вызов RtlAddFunctionTable не делает программу вредоносной. Но если он совпадает с необычным static placement, handler activity или обфускационной структурой, корреляция становится сильной."
        ),
        (
            "Почему writable unwind metadata настораживает",
            "Metadata обычно воспринимается как описание, а не как исполняемое поведение. Но в системах низкого уровня описание может управлять поведением. Если Windows использует metadata для восстановления стека и поиска handler, то изменение metadata способно менять то, как система понимает выполнение.",
            "Writable section означает, что область может быть изменена во время выполнения. Это не всегда зло: бывают runtime-паттерны, packer, loader, JIT, самописные схемы. Но для unwind metadata writable placement необычен, потому что карта восстановления стека обычно должна быть стабильной частью образа.",
            "Поэтому finding `unwind_section_writable` надо объяснять осторожно. Он не говорит 'это malware'. Он говорит: 'данные, от которых зависит unwind/exception interpretation, находятся в изменяемой области'. Дальше нужен контекст: кто пишет в эту область, есть ли dynamic table calls, есть ли handler hits, есть ли признаки обфускации.",
            "Ручная проверка: открыть Sections, найти секцию Unwind RVA, проверить permissions, затем открыть Runtime functions и посмотреть, сколько функций ссылаются на эту область. Если много функций, finding затрагивает не одну строку, а общий участок metadata."
        ),
        (
            "Как читать итоговую оценку без самообмана",
            "Final assessment удобен, но опасен, если читать только его. Verdict, confidence, static/runtime evidence и cross-layer correlation являются сжатием большого анализа. Сжатие помогает обзорно, но не заменяет доказательство.",
            "Если final confidence высокое, спроси: за счет чего? Есть ли high severity findings? Есть ли dynamic signals? Есть ли handler hits или runtime table calls? Есть ли manual validation plan? Если confidence среднее, спроси, чего не хватает: динамического подтверждения, полной instrumentation, большего числа независимых признаков или ручной проверки.",
            "Хороший инженер не прячет uncertainty. Он показывает, почему вывод имеет именно такую силу. Если есть только статика, он говорит 'структурно подозрительно'. Если есть статика и динамика, он говорит 'структурно необычно и runtime-подтверждено в таком-то сценарии'. Если есть timeout, он не делает вывод о полном поведении.",
            "Так отчет становится учебным инструментом. Он не заменяет мышление, а заставляет пройти правильный маршрут: факт, адрес, правило, проверка, ограничение, вывод."
        ),
    ]
    out = ["# Том I-A. Windows x64 EH/Unwind: как механизм работает изнутри"]
    out.append("""
Этот раздел углубляет центральную тему проекта. Если фундаментальная глава объясняет общую картину, то здесь мы медленно разбираем именно EH/Unwind: исключение, контекст потока, поиск функции, UNWIND_INFO, handler, динамические таблицы и итоговую оценку. Цель - чтобы слова из отчета перестали быть ярлыками и стали понятными частями одного механизма.
""")
    for i, (title, *paragraphs) in enumerate(topics, 1):
        out.append(f"## {i}. {title}")
        out.extend(paragraphs)
        out.append("Проверка на практике: найди в любом отчете проекта поле, которое соответствует этой теме, и объясни его без слова 'просто'. Если объяснение требует адрес, покажи RVA и секцию.")
    return "\n\n".join(out)


def deep_common_mistakes_chapter() -> str:
    mistakes = [
        (
            "Путать странность с вредоносностью",
            "Необычная секция, writable metadata или handler reuse не равны слову malware. Это признаки, которые требуют проверки. Если сразу назвать их вредоносностью, защита станет слабее: достаточно одного легального примера JIT, packer или нестандартного runtime, чтобы формулировка выглядела грубой.",
            "Правильная фраза: 'обнаружен структурный признак, который необычен для ожидаемой схемы Windows x64 unwind metadata; он повышает подозрительность и требует ручной проверки'. Такая фраза точнее и профессиональнее."
        ),
        (
            "Смешивать координаты",
            "Самая частая техническая ошибка - говорить 'адрес' без уточнения. File offset, RVA и VA живут в разных слоях. Отчет может дать RVA, Ghidra показать VA, hex viewer открыть file offset. Если не сделать перевод, можно показать преподавателю не то место.",
            "Правильная дисциплина: рядом с каждым числом пиши его тип. `0x7100 RVA`, `file offset 0x900`, `VA 0x140007100`. Тогда даже сложный отчет становится проверяемым."
        ),
        (
            "Верить decompiler вместо механизма",
            "Decompiler удобен, но он восстанавливает C-подобное представление. Для EH/Unwind темы иногда важнее disassembly, prolog, stack adjustment, section permissions и metadata. Если decompiler молчит про handler, это не значит, что handler metadata не существует.",
            "Правильная проверка: сначала смотри таблицу Runtime functions и UNWIND_INFO, затем disassembly вокруг адреса, и только потом decompiler как удобное объяснение логики."
        ),
        (
            "Игнорировать нормальные samples",
            "Если показывать только подозрительные бинарники, создается впечатление, что инструмент всегда находит тревогу. Нормальный benign sample нужен как контроль. Он показывает, как выглядит спокойная таблица, OK-статусы и отсутствие strong anomalies.",
            "Правильная демонстрация: сначала коротко показать benign report, затем перейти к combo sample. Контраст делает подозрительный пример понятнее."
        ),
        (
            "Считать timeout отрицательным доказательством",
            "Если динамика завершилась timeout, это не значит, что события отсутствуют. Это значит, что в данном временном окне они не были достигнуты или процесс не завершился. Timeout ограничивает вывод, а не отменяет статические факты.",
            "Правильная формулировка: 'динамический запуск не дал подтверждения в выбранных условиях; статический finding остается структурным наблюдением'."
        ),
        (
            "Читать только верхнюю карточку отчета",
            "Final assessment помогает быстро сориентироваться, но не содержит всего доказательства. Настоящая проверка находится ниже: Static findings, Runtime functions, Runtime log, Analysis details, Manual validation plan.",
            "Правильный порядок: сначала карточка, потом конкретный finding, потом affected object и representative RVA, потом ручная проверка."
        ),
        (
            "Не отличать parser failure от плохой программы",
            "Parse failure говорит о том, что analyzer не смог корректно прочитать структуру по ожидаемым правилам. Причина может быть в повреждении, обфускации, неподдержанном варианте, нехватке байтов или ошибке инструмента. Это не автоматический verdict.",
            "Правильная проверка: открыть bytes по RVA, проверить границы секции, version/flags/count fields и сравнить с документацией Microsoft по x64 exception handling."
        ),
        (
            "Защищать вывод без команды воспроизведения",
            "Отчет без команды запуска похож на скриншот без эксперимента. Для диплома важно показать воспроизводимость: какой analyzer, какой sample, какие опции, какой timeout, какие выходные файлы.",
            "Правильная привычка: рядом с каждым показательным HTML держать PowerShell-команду, которая пересоздает JSON/HTML и при необходимости dynamic report."
        ),
        (
            "Ждать аномалию в каждой строке Runtime functions",
            "Если общий finding относится к секции или общей области metadata, он может затрагивать десятки функций, но не обязан превращать каждую строку Runtime functions в уникальную ошибку. Строка может быть OK как декодированная структура, но при этом ссылаться на секцию, которая в целом необычна.",
            "Правильное чтение: смотри и верхние Static findings, и колонку Anomalies/error, и section summary. Если аномалия общая для секции, объясняй ее как свойство размещения, а не как отдельную поломку каждой функции."
        ),
        (
            "Путать affected count с числом разных причин",
            "Affected count показывает, сколько объектов затронуто признаком. Это не обязательно число разных аномалий. Один плохой UnwindInfoRVA может затронуть одну функцию, а одна writable unwind section может затронуть много функций сразу.",
            "Правильный ответ: сначала назови finding code, затем affected count, затем объясни, является ли причина локальной для одной строки или общей для секции/таблицы."
        ),
        (
            "Считать confidence процентом истины",
            "Confidence в отчете - инженерная оценка силы evidence, а не математическая вероятность того, что файл вредоносный. Если написано 69%, это не значит 'на 69 процентов malware'. Это значит, что совокупность признаков имеет такую расчетную силу в модели проекта.",
            "Правильная формулировка: 'confidence отражает силу и согласованность найденных свидетельств; окончательный вывод требует ручной проверки и контекста sample'."
        ),
        (
            "Не сверять HTML с JSON",
            "HTML удобен, но при споре лучше иметь JSON. В JSON поля не спрятаны версткой: finding code, severity, affected, representative RVA, dynamic events и counts можно проверить точно. Если защита требует строгости, JSON сильнее скриншота.",
            "Правильная проверка: для одного finding найди его в HTML, затем найди соответствующий объект в JSON и сравни code, message, RVA и affected count."
        ),
        (
            "Готовить GitHub и презентацию без чистоты артефактов",
            "Даже хороший проект выглядит слабее, если рядом лежат временные PNG, старые candidates, мусорные build-cache файлы и случайные отчеты без назначения. Для презентации и GitHub нужна чистая структура: исходники, тесты, docs, reports-примеры, scripts и понятный README.",
            "Правильная привычка: перед загрузкой проверить временные папки, убрать промежуточные PDF-render PNG, оставить только воспроизводимые документы и примеры, которые ты реально можешь объяснить."
        ),
    ]
    out = ["# Том I-B. Типичные ошибки новичка: как не разрушить сильный анализ"]
    out.append("""
Эта глава нужна потому, что глубокое понимание проявляется не только в знании терминов, но и в умении не делать ложных скачков. Реверс-инженер постоянно удерживает границы вывода: где факт, где интерпретация, где подтверждение, где ограничение эксперимента. Ошибки ниже встречаются часто, и каждая из них может испортить даже хороший отчет.

На защите эти ошибки обычно проявляются в форме простых вопросов. "Почему вы называете это аномалией?" "Где этот адрес в Ghidra?" "Почему динамика ничего не показала?" "Почему affected count такой большой?" "Что означает confidence?" Если отвечать на такие вопросы общими словами, работа кажется сырой. Если отвечать через слой, адрес, правило и проверку, даже сложная тема становится убедительной.

Поэтому ниже каждая ошибка дана в двух формах: как выглядит слабое рассуждение и как его заменить сильным. Не надо заучивать формулировки дословно. Надо усвоить ход: остановиться, назвать объект, уточнить координату, объяснить правило, показать проверку и только потом делать вывод.
""")
    for i, (title, bad, good) in enumerate(mistakes, 1):
        out.append(f"## Ошибка {i}. {title}")
        out.append(bad)
        out.append(good)
        out.append("Мини-практика: открой один отчет и найди место, где эту ошибку легко совершить. Затем сформулируй корректный вариант ответа.")
    out.append("## Контрольные вопросы преподавателя")
    out.append("Вопрос: 'Почему вы уверены, что это именно unwind-анализ, а не общий антивирусный сканер?' Ответ: потому что объект анализа ограничен конкретными структурами Windows x64: PE exception directory, RUNTIME_FUNCTION, UNWIND_INFO, handler RVA, section placement и runtime exception/table events. Инструмент не ищет сигнатуры malware. Он проверяет договоры вокруг EH/Unwind.")
    out.append("Вопрос: 'Почему статический признак важен, если динамика его не подтвердила?' Ответ: статический признак является фактом структуры файла. Динамика проверяет только конкретный путь выполнения при конкретных условиях. Отсутствие runtime-события ослабляет поведенческий вывод, но не удаляет структурное наблюдение.")
    out.append("Вопрос: 'Почему один handler на много функций подозрителен?' Ответ: сам по себе reuse может быть легальным. Подозрительность появляется, когда концентрация handler сочетается с необычным placement, writable metadata, странной секцией или dynamic behavior. Поэтому важно говорить не о количестве само по себе, а о совокупности evidence.")
    out.append("Вопрос: 'Что вы делаете, если Ghidra показывает не те границы функции?' Ответ: я разделяю источники. Analyzer читает PE runtime function metadata. Ghidra строит свою function model по disassembly и эвристикам. Я сравниваю оба взгляда, проверяю bytes, section, prolog и references, а не выбираю один инструмент как абсолютную истину.")
    out.append("Вопрос: 'Как доказать воспроизводимость?' Ответ: показать команду запуска, input sample, версию analyzer, опции static/dynamic, timeout, пути HTML/JSON/CSV и затем заново получить тот же тип отчета. Для динамики я дополнительно называю ограничения запуска.")
    out.append("Вопрос: 'Где здесь место человека?' Ответ: analyzer поднимает структурные и runtime-факты, но человек связывает их с контекстом, проверяет адреса в Ghidra, читает JSON, сравнивает benign и suspicious samples и формулирует ограниченный вывод. Поэтому проект является инструментом поддержки reverse engineering, а не заменой эксперта.")
    return "\n\n".join(out)


def language_bridge_chapter() -> str:
    out = ["# Том II-A. Англоязычные термины: как переводить, понимать и объяснять"]
    out.append("""
В реверс-инжиниринге невозможно полностью убрать английские слова: документация Microsoft, Ghidra, имена структур и API написаны по-английски. Но плохой учебник оставляет их как список. Хороший учебник делает другое: рядом с английским термином дает русский смысл, техническую роль, типичную ошибку и способ проверки.

Эта глава нужна как мост. Ее задача - чтобы слова `runtime`, `handler`, `metadata`, `finding`, `confidence`, `section`, `RVA` не висели в воздухе. После каждого термина ты должен уметь сказать: что это значит по-русски, где это видно в проекте, почему это важно и как это проверить.
""")
    for i, term in enumerate(TERM_EXPLAIN.keys(), 1):
        ru, short, deep = TERM_EXPLAIN[term]
        out.append(f"## {i}. {term}: {ru}")
        out.append(
            f"Переводить `{term}` надо не одним словом, а смыслом. В этой книге рабочий русский вариант - {ru}. "
            f"Коротко: {short}. {deep}"
        )
        out.append(
            "Когда этот термин появляется в отчете, не оставляй его английским ярлыком. Сразу добавь русское "
            "объяснение: какой объект назван, какой слой анализа затронут, какая проверка нужна. Именно так "
            "английская документация превращается в понятный ответ на русском языке."
        )
        out.append(
            f"Фраза для защиты: 'Термин `{term}` я использую не как непереведенное слово, а как название "
            f"конкретного объекта. По-русски это {ru}; в проекте это проверяется через отчет, JSON и ручной "
            "переход к адресу или событию'."
        )
    out.append("""
Главное правило этой главы: английский термин допустим, если сразу раскрыт по-русски и связан с проверкой. Если слово нельзя привязать к адресу, полю отчета, секции, событию или ручному действию, значит оно пока не объяснено.
""")
    return "\n\n".join(out)


def whole_system_story_chapter() -> str:
    topics = [
        ("От файла на диске к образу в памяти", "Файл на диске кажется неподвижным, но Windows читает его как инструкцию к построению образа. PE-заголовки объясняют, какие диапазоны байтов станут секциями, какие права получат эти секции и где искать служебные каталоги. Это первый большой переход: байты перестают быть просто байтами и становятся частями образа.", "Если этот переход не понять, дальше начинается путаница. Человек видит число и не знает, является ли оно смещением в файле, RVA или адресом в памяти. Поэтому любой анализ EH/Unwind начинается с дисциплины адресов. Нельзя декодировать metadata, пока не понятно, где она физически лежит и как она попадает в image."),
        ("От образа к функции", "Функция в бинарнике не имеет красивой рамки, как в исходном коде. Ее границы восстанавливаются через disassembly, symbol information, metadata или эвристики. На Windows x64 важную роль играет RUNTIME_FUNCTION: она задает диапазон кода и ссылку на UNWIND_INFO.", "Именно здесь проект становится специализированным. Он не пытается понять всю бизнес-логику программы. Он спрашивает: как Windows будет понимать функции, если произойдет исключение? Где начинается диапазон, где заканчивается, и где лежит инструкция по восстановлению стека?"),
        ("От функции к стеку", "Каждая функция оставляет след в стеке. Она может выделить место под локальные данные, сохранить регистры, вызвать другие функции и вернуть управление. ABI задает правила, чтобы разные функции могли взаимодействовать без разрушения состояния.", "Unwind metadata существует потому, что при исключении система должна пройти этот путь назад. Если функция изменила RSP, Windows должна знать, как вернуть прежнее состояние. Поэтому UNWIND_INFO является не абстрактной таблицей, а кратким описанием того, как функция обращается со стеком."),
        ("От стека к исключению", "Исключение останавливает обычный ход выполнения. У системы появляется вопрос: кто должен обработать событие и как безопасно восстановить состояние? Для ответа нужны context, RIP, stack, function table и handler. Это не одна структура, а цепочка решений.", "Если в этой цепочке поврежден адрес, странно размещена metadata или handler указывает в подозрительную область, analyzer фиксирует не эмоцию, а нарушение условий, при которых цепочка должна быть понятной."),
        ("От статического факта к динамическому событию", "Статический анализ видит карту, записанную в файле. Динамический анализ видит отдельное путешествие по этой карте. Карта может содержать необычность, даже если конкретный запуск до нее не дошел. И наоборот, запуск может показать регистрацию dynamic function table, которую статическая карта не описывает полностью.", "Поэтому сильный вывод строится на сопоставлении: что лежит в файле, что произошло при запуске, где эти два слоя подтверждают друг друга, а где остаются ограничениями эксперимента."),
        ("От finding к человеческому выводу", "Finding является названием наблюдения. Он нужен, чтобы не писать каждый раз длинное описание нарушения. Но finding не должен становиться ярлыком без смысла. За ним всегда должны стоять объект, адрес, правило и проверка.", "Хороший отчет помогает человеку пройти этот путь: Final assessment дает обзор, Static findings дают список фактов, Runtime functions дают строки таблицы, Runtime log показывает события, Manual validation plan говорит, что проверить руками."),
        ("От Ghidra к доказательству", "Ghidra превращает байты в карту кода и данных, но она не является последней инстанцией. Ее сила в том, что она помогает человеку проверить конкретный вопрос: что находится по этому адресу, как выглядит surrounding disassembly, где секция и какие есть references.", "Если отчет говорит о representative RVA, Ghidra дает способ показать это место. Если отчет говорит о handler, Ghidra помогает увидеть код. Если Ghidra не согласна с границами функции, это не конец анализа, а начало сравнения двух моделей."),
        ("От документации к своей речи", "Документация Microsoft точна, но написана не как учебник для нулевого читателя. Она задает поля, структуры и API. Задача студента - превратить эту точность в понятную речь: сначала русское объяснение, потом английский термин, потом техническое поле, потом пример из проекта.", "Именно так литература и документация становятся частью диплома. Не надо пересказывать Microsoft Learn абзацами. Надо показать, что правила из документации объясняют, почему analyzer проверяет именно эти поля и почему finding имеет технический смысл."),
        ("От отчета к презентации", "Презентация не должна показывать все 500 страниц. Она должна показать маршрут мышления. Один benign sample нужен как контроль. Один combo sample нужен как главный рассказ. Один переход в Ghidra нужен как ручное подтверждение. Одна команда запуска нужна как воспроизводимость.", "Если все это есть, проект выглядит зрелым. Он не обещает невозможного, не делает вид, что один запуск знает все поведение, и не прячет детали. Он показывает инструмент, метод и границы вывода."),
        ("От новичка к реверс-инженеру", "Рост в реверс-инжиниринге происходит не тогда, когда человек запоминает больше страшных слов. Рост происходит тогда, когда он учится задавать точные вопросы. Что я вижу? Где это лежит? Кто это создал? Кто это использует? Как проверить? Чего это не доказывает?", "EH/Unwind Analyzer является хорошей учебной темой именно потому, что заставляет удерживать много слоев сразу: файл, PE, память, ABI, стек, исключения, metadata, статический отчет, динамический запуск и Ghidra. Когда эти слои складываются, появляется настоящее понимание."),
    ]
    out = ["# Том II-B. Сквозной рассказ: как вся система складывается в одну картину"]
    out.append("""
Эта глава написана как единая лекция без таблиц и списков. Ее цель - собрать разрозненные термины в последовательную историю. Если предыдущие главы объясняли детали, здесь мы идем по всей цепочке целиком: файл, память, функция, стек, исключение, metadata, отчет, Ghidra и защита результата.
""")
    for i, (title, p1, p2) in enumerate(topics, 1):
        out.append(f"## {i}. {title}")
        out.append(p1)
        out.append(p2)
        out.append(
            "Проверь понимание этого шага на любом отчете проекта: найди одно поле, которое относится к теме, "
            "и произнеси его смысл по-русски. Если в объяснении остался только английский термин, значит шаг "
            "надо перечитать и привязать к адресу, секции, событию или ручной проверке."
        )
    out.append("""
Итог этой главы простой: теория нужна не для украшения диплома, а для того, чтобы не делать ложных скачков. Сильный реверс-инженер не угадывает смысл бинарника. Он восстанавливает цепочку договоров, проверяет каждый переход и честно говорит, где вывод силен, а где требует дополнительного эксперимента.
""")
    return "\n\n".join(out)


def study_path_chapter() -> str:
    out = ["# Том V. Учебный маршрут: как из терминов собрать профессию"]
    out.append("""
Эта глава добавлена не для объема, а для связности. В длинной технической теме легко выучить отдельные слова и все равно не понимать, что делать перед реальным бинарником. Здесь каждый модуль устроен как маленькая лекция: сначала человеческий смысл, потом строгая связь с Windows и PE, потом типичная ошибка, потом упражнение, которое можно выполнить руками.

Маршрут намеренно идет от мышления к проверке. Реверс-инжиниринг начинается не с инструмента, а с дисциплины вопроса. Что я сейчас вижу: байты, адрес, секцию, функцию, обработчик, событие debugger или итоговую оценку? Какой слой создал это значение? Какой другой инструмент может подтвердить или ослабить вывод? Если эти вопросы становятся привычкой, Ghidra, Microsoft documentation и отчеты проекта перестают быть разрозненными окнами и складываются в одну систему.

Читай эту главу как набор лекций перед практикой. После каждого модуля лучше открыть один реальный отчет из `reports`, один sample из набора combo и один исходный файл проекта. Тогда теория сразу получает опору в конкретных адресах, таблицах и командах.
""")
    for i, (title, meaning, relation, mistake, practice) in enumerate(STUDY_MODULES, 1):
        out.append(f"## Модуль {i}. {title}")
        out.append(meaning)
        out.append(relation)
        out.append(mistake)
        out.append(practice)
        out.append("Контрольный вопрос: можешь ли ты объяснить этот модуль двумя способами - сначала человеку без подготовки, а потом технически точно, используя слова PE, RVA, section, ABI, UNWIND_INFO, handler, static finding или dynamic event там, где они действительно нужны? Если оба объяснения сходятся, тема стала рабочей, а не заученной.")
    out.append("""
## Как пользоваться этим маршрутом перед защитой

Перед защитой не надо перечитывать всю книгу подряд в панике. Возьми один показательный бинарник, лучше combo sample, и пройди по модулям как по чек-листу. Сначала назови слой наблюдения. Потом найди PE-секцию и адрес. Потом объясни, что говорит x64 ABI и unwind model. Потом покажи static finding. Затем открой dynamic report и проверь, был ли runtime signal. В конце сформулируй осторожный вывод.

Если в каком-то месте рассказ ломается, это не провал, а указатель на пробел. Например, если ты не можешь объяснить, почему dynamic timeout не отменяет static finding, вернись к модулю про статику и динамику. Если путаются адреса, вернись к file offset, RVA и VA. Если Ghidra показывает не то, что ожидалось, вернись к мысли, что инструмент - микроскоп, а не оракул.

Такой способ подготовки хорош тем, что он тренирует не память, а движение мысли. На реальной защите ценят именно это: способность спокойно связать байты, формат, механизм Windows, вывод analyzer и ручную проверку.
""")
    return "\n\n".join(out)


def beginner_theory_bridge_chapter() -> str:
    topics = [
        (
            "Что такое программа до того, как она стала EXE",
            "Для человека программа обычно начинается с исходного текста: функций, переменных, условий и комментариев. Для компьютера такой текст сам по себе еще не является исполняемой программой. Между текстом и запуском стоит цепочка превращений: компилятор переводит идеи в машинные инструкции, компоновщик собирает части вместе, а загрузчик Windows готовит образ к выполнению в памяти.",
            "Новичок часто думает, что EXE - это просто программа в сжатом виде. Это неверная картина. EXE ближе к контейнеру с инструкциями, данными, таблицами, адресами, правилами загрузки и служебной информацией. В этом контейнере есть не только то, что написал программист, но и то, что нужно операционной системе: где начинается код, где данные, какие библиотеки нужны, какие диапазоны функций существуют, как восстанавливать стек при исключении.",
            "Для EH/Unwind Analyzer это главный стартовый тезис. Проект исследует не намерения автора программы напрямую, а следы, которые остались в исполняемом файле и во время запуска. Поэтому первая зрелая привычка реверс-инженера - не спрашивать сразу 'что программа хотела сделать', а спрашивать 'какой слой я сейчас вижу и по каким правилам он устроен'.",
        ),
        (
            "Почему бинарник нельзя читать как обычный текст",
            "Текстовая книга хранит буквы, и человек сразу видит слова. Бинарник хранит байты, а смысл байта зависит от места и контекста. Один и тот же набор байтов может быть числом, частью инструкции, адресом, строкой, выравниванием или полем структуры. Поэтому реверс-инжиниринг начинается не с чтения, а с разметки: нужно понять, где какой слой данных начинается и заканчивается.",
            "Формат PE помогает внести порядок. Он говорит: вот заголовки, вот таблица секций, вот каталог данных, вот место, где можно найти таблицу исключений. Но даже формат не отменяет осторожность. Файл может быть поврежден, намеренно изменен, необычно собран или просто не похож на учебный пример. Значит, анализатор обязан проверять границы, размеры и перевод адресов, а не верить каждому полю.",
            "Когда в отчете написано, что адрес выходит за границы или структура не декодируется, это не эмоция инструмента. Это результат дисциплины чтения бинарника: сначала проверить, что байты действительно доступны, потом понять, какая структура там ожидается, и только потом делать вывод о подозрительности.",
        ),
        (
            "Файл, образ и процесс: три состояния одного объекта",
            "Один и тот же EXE можно увидеть в трех состояниях. Первое состояние - файл на диске. Здесь все измеряется смещениями от начала файла. Второе состояние - образ, который Windows подготовила для выполнения. Здесь важны адреса внутри образа, секции, права и база загрузки. Третье состояние - живой процесс. Здесь появляются потоки, реальные виртуальные адреса, загруженные библиотеки, исключения, обработчики и события отладки.",
            "Путаница между этими состояниями разрушает анализ. Если число выглядит как адрес, еще не ясно, адрес это в файле, в образе или в процессе. Если в статическом отчете указан RVA, его нужно переводить в координаты Ghidra и при необходимости в файловое смещение. Если в динамическом логе указан адрес во время выполнения, нужно помнить о базе загрузки и ASLR.",
            "Учебная картина такая: файл дает устойчивые байты, образ дает системную карту, процесс дает наблюдение поведения. Статика сильна тем, что видит всю доступную структуру файла. Динамика сильна тем, что показывает, что реально произошло в конкретном запуске. Ни один слой не отменяет другой.",
        ),
        (
            "Компилятор, компоновщик и загрузчик как три автора следов",
            "В реверс-инжиниринге важно понимать, что многие байты в программе написал не человек вручную. Компилятор выбрал инструкции и построил пролог функции. Компоновщик разложил секции и служебные таблицы. Загрузчик Windows отобразил секции в память, применил необходимые настройки и подготовил процесс. Поэтому бинарник является результатом работы нескольких участников.",
            "Если проект находит необычную секцию или странную unwind-структуру, это не означает автоматически злой умысел. Нужно спросить, кто мог создать этот след. Иногда это компилятор, иногда упаковщик, иногда защитный инструмент, иногда ручная модификация, иногда тестовый sample из лабораторного набора. Сильный анализ не угадывает автора, а собирает признаки.",
            "Для защиты диплома это особенно важно. Формулировка 'анализатор нашел вредоносность' слабая. Формулировка 'анализатор нашел нарушение ожидаемой структуры Windows x64 unwind metadata, указал адрес, секцию и проверяемое основание' намного сильнее и честнее.",
        ),
        (
            "Что такое функция в бинарнике",
            "В исходном коде функция видна глазами: есть имя, фигурные скобки и тело. В бинарнике таких удобных границ может не быть. Функция становится диапазоном инструкций, который нужно восстановить по символам, дизассемблированию, служебным таблицам, соглашению о вызовах и контексту.",
            "На Windows x64 важную роль играет таблица RUNTIME_FUNCTION. Она дает системный взгляд: от какого адреса до какого адреса находится функция и где лежит UNWIND_INFO. Ghidra может строить свою разметку функций по инструкциям и эвристикам. Иногда эти взгляды совпадают, иногда расходятся. Расхождение не нужно прятать, его нужно объяснять.",
            "EH/Unwind Analyzer работает именно с тем, как Windows должна понимать диапазоны функций для обработки исключений. Поэтому он не заменяет весь анализ программы, но очень хорошо подсвечивает отдельный критичный слой: официальную карту функций и восстановления стека.",
        ),
        (
            "Стек как память разговора между функциями",
            "Стек можно представить как рабочую тетрадь потока выполнения. Когда функция вызывается, там появляются адрес возврата, временные данные, сохраненные регистры и место для локальной работы. Когда функция завершается, стек должен вернуться в согласованное состояние. Если этого не происходит, выполнение ломается.",
            "На x64 стек особенно важен для исключений. Исключение может произойти не в удобный момент, а внутри функции, после изменения указателя стека и сохранения регистров. Windows должна понять, как аккуратно перейти назад к вызывающей функции. Для этого ей нужна не догадка, а карта действий функции.",
            "Этой картой и является UNWIND_INFO. Она не описывает всю логику функции. Она описывает только то, что важно для восстановления состояния: какие операции со стеком и регистрами были сделаны, есть ли обработчик, есть ли цепочка к другой записи. Поэтому маленькая служебная структура может иметь большое значение.",
        ),
        (
            "Исключение как управляемый сбой, а не просто ошибка",
            "Слово 'исключение' легко понять бытово: что-то пошло не так. Но в Windows исключение является управляемым событием. Система получает контекст потока, смотрит, где произошло событие, ищет подходящую информацию о функции и решает, кому дать шанс обработать ситуацию.",
            "Существуют разные участники этого процесса: структурированная обработка исключений, векторные обработчики, фильтр необработанного исключения, таблицы функций времени выполнения. Они не являются одной и той же вещью. Одни связаны с диапазонами функций и unwind-метаданными, другие регистрируются как callback и участвуют в маршруте обработки.",
            "Динамический отчет проекта ценен потому, что может увидеть не только статическую структуру, но и факты регистрации или срабатывания. Если виден RtlAddFunctionTable, значит программа во время выполнения добавляла таблицу функций. Если виден AddVectoredExceptionHandler, значит регистрировался векторный обработчик. Эти наблюдения нужно читать как события эксперимента.",
        ),
        (
            "Почему метаданные бывают важнее видимого кода",
            "Новичок часто хочет смотреть только дизассемблер и декомпилятор. Это понятно: инструкции похожи на действие, а таблицы кажутся скучными. Но операционная система часто принимает решения именно по служебным данным. Если метаданные говорят, что диапазон функции один, а код выглядит иначе, перед нами уже важное аналитическое место.",
            "Unwind-метаданные находятся между кодом и системой. Они объясняют Windows, как безопасно восстановить состояние при исключении. Поэтому ошибка в них может привести не только к красивой строке в отчете, но и к реальному изменению поведения обработки исключений.",
            "Проект выбран удачно для обучения именно потому, что заставляет уважать служебные структуры. Реверс-инженер учится видеть не только 'что делает код', но и 'что система считает истинной картой этого кода'.",
        ),
        (
            "Статика и динамика как два вида доказательства",
            "Статический анализ читает файл без запуска. Он похож на изучение чертежа: можно внимательно проверить структуру, размеры, адреса, таблицы и секции. Динамическая проверка запускает процесс и наблюдает события. Она похожа на эксперимент: можно увидеть регистрацию обработчика, исключение, точку останова, завершение процесса или тайм-аут.",
            "Ни статика, ни динамика не являются абсолютной истиной по одиночке. Статика может показать потенциальную проблему, которая в данном запуске не проявилась. Динамика может не пройти нужную ветку, не получить нужные аргументы или остановиться по тайм-ауту. Поэтому хороший вывод всегда говорит, какой слой дал свидетельство.",
            "В идеальном демонстрационном примере статика и динамика встречаются. Статика показывает необычное размещение, поврежденную структуру или подозрительный обработчик. Динамика показывает регистрацию таблицы, установку обработчика или срабатывание при исключении. Тогда рассказ становится сильным: файл и запуск указывают на один механизм.",
        ),
        (
            "Что значит доказательство в учебном реверсе",
            "В математике доказательство строится по строгим правилам. В инженерном анализе бинарника доказательство тоже должно быть дисциплинированным, но оно часто состоит из свидетельств разной силы. Есть факт байтов, факт адреса, факт секции, факт декодирования, факт события во время запуска и факт ручной проверки в Ghidra.",
            "Слабый рассказ прыгает сразу к выводу. Сильный рассказ идет цепочкой: вот бинарник, вот команда запуска, вот отчет, вот таблица, вот адрес, вот почему он необычен, вот как это связано с документацией Windows, вот что подтвердила или не подтвердила динамика, вот что видно в Ghidra, вот ограничение вывода.",
            "Такой стиль важен не только для защиты диплома. Это профессиональная привычка реверс-инженера: не делать вид, что инструмент знает все, а показывать, на чем держится каждое утверждение.",
        ),
        (
            "Почему английские термины нельзя просто выкинуть",
            "Технический мир Windows, Ghidra и официальной документации использует английские имена. Полностью убрать их нельзя: RUNTIME_FUNCTION, UNWIND_INFO, RtlAddFunctionTable и AddVectoredExceptionHandler являются официальными названиями структур и API. Если заменить их только русскими словами, потеряется связь с документацией и инструментами.",
            "Но плохая подача оставляет эти слова как стену. Хорошая подача делает мост: сначала русский смысл, затем официальное имя, затем роль в проекте, затем способ проверки. Например, не просто 'UNWIND_INFO', а 'служебная структура Windows x64, которая описывает, как восстановить стек функции при исключении'.",
            "Поэтому в этой книге английский термин должен быть не украшением и не списком, а адресом к точному объекту. Если термин нельзя объяснить по-русски и показать в отчете, значит он еще не стал знанием.",
        ),
        (
            "Как из этого рождается профессия",
            "Реверс-инженер растет не за счет количества открытых окон, а за счет точности вопросов. Что я вижу сейчас: байты, секцию, адрес, функцию, метаданные, событие запуска или итоговую оценку? Кто создал этот объект: компилятор, компоновщик, загрузчик, Windows, сама программа или анализатор? Как проверить это вторым способом?",
            "Когда такие вопросы становятся привычкой, инструменты перестают быть магией. Visual Studio собирает бинарник, PowerShell воспроизводит команду, анализатор строит отчет, Ghidra помогает проверить адрес, JSON сохраняет точные поля, HTML помогает показать результат человеку.",
            "Именно поэтому теория здесь не отделена от проекта. Она нужна, чтобы каждый столбец отчета, каждое поле UNWIND_INFO и каждая строка динамического лога попадали в одну картину.",
        ),
    ]
    out = ["# Том 0-A. Большая вводная теория: как из программы получается объект анализа"]
    out.append("""
Эта глава добавлена как медленный вход в предмет. Она не требует, чтобы читатель уже знал ассемблер, Windows API или формат PE. Ее задача - собрать в голове первую цельную карту: от обычной программы к исполняемому файлу, от файла к памяти, от памяти к процессу, от процесса к исключению, от исключения к unwind-метаданным, от метаданных к отчету и ручной проверке.

Читать ее нужно не как справочник, а как лекцию. Здесь важны связи. Байты важны не сами по себе, а потому что из них строятся структуры. Адреса важны не сами по себе, а потому что переводят нас между файлом, образом и процессом. Ghidra важна не сама по себе, а потому что помогает проверить конкретный адресный вопрос. Отчет важен не сам по себе, а потому что превращает низкоуровневые факты в воспроизводимую форму.
""")
    for i, (title, p1, p2, p3) in enumerate(topics, 1):
        out.append(f"## {i}. {title}")
        out.append(p1)
        out.append(p2)
        out.append(p3)
        out.append(
            "Проверь себя после этого раздела: попробуй объяснить его без английских слов, а затем добавь только те официальные имена, "
            "которые действительно нужны для поиска в документации, отчете или Ghidra. Если без английского слова смысл исчезает, "
            "значит надо вернуться к русскому объяснению и укрепить связь с конкретным объектом."
        )
    out.append("""
Главный итог вводной теории такой: реверс-инжиниринг не начинается с героического угадывания. Он начинается с уважения к слоям. Сначала мы понимаем, где лежат байты. Потом понимаем, как Windows превращает их в образ. Потом понимаем, как функция живет в стеке. Потом понимаем, как исключение заставляет систему искать карту восстановления. Потом читаем отчет и проверяем самое важное руками. Так из хаоса терминов получается профессия.
""")
    return "\n\n".join(out)


def source_method_chapter() -> str:
    out = ["# Том 0. Как сформировано оглавление: источники, традиция и границы этой книги"]
    out.append("""
Фундаментальный учебник нельзя строить только из желания "объяснить поподробнее". Нужно понимать, на каких источниках держится предмет. У этой книги есть три опоры. Первая - официальная документация Microsoft и Intel, потому что PE, x64 ABI, unwind metadata, Debug API и exception handling являются системными контрактами. Вторая - классическая литература по reverse engineering и malware analysis, потому что там выработана педагогика: от статического наблюдения к динамическому, от инструмента к выводу, от байта к смыслу. Третья - исходный код EH/Unwind Analyzer, потому что книга должна объяснять не абстрактный PE вообще, а конкретный проект и его отчеты.

Важно: эта книга не пересказывает чужие главы и не копирует защищенные тексты. Она использует источники как карту темы. Официальная документация дает точные определения и ограничения. Книги по реверсу дают порядок обучения и практический стиль. Проект дает живой предмет: парсер, декодер, эвристики, динамический сборщик, отчеты, Ghidra CSV и regression samples.
""")
    out.append("## Источники и как они повлияли на книгу")
    for title, url, gives, used_for in SOURCE_GUIDE:
        out.append(f"### {source_title_ru(title)}")
        for paragraph in source_paragraphs_ru(title, url, gives, used_for):
            out.append(paragraph)
    out.append("""
## Почему главы идут именно в таком порядке

Лучшие учебники не начинают с самого красивого результата. Они начинают с того, без чего результат будет магией. Поэтому здесь сначала идут байты, числа, файл, память и адреса. Потом появляется PE как договор между компоновщиком и загрузчиком. Потом - x64 ABI, потому что без стека, регистров, prolog и epilog невозможно понять unwind metadata. Только после этого есть смысл говорить о RUNTIME_FUNCTION, UNWIND_INFO, handlers, chained info и dynamic function tables.

После системной базы идет метод reverse engineering: как смотреть на бинарник, чем отличается static analysis от dynamic validation, зачем нужен Ghidra, почему finding не является приговором. Затем книга переходит к самому проекту: как src/main.c запускает pipeline, как util.c защищает чтение, как pe.c строит модель PE, как unwind.c декодирует metadata, как heuristics.c превращает факты в evidence, как dynamic_win.c наблюдает runtime и как report.c делает вывод проверяемым.

Такой порядок выбран сознательно. Если раньше времени дать человеку 27 признаков, он будет заучивать названия. Если сначала дать ему file offset, RVA, section, stack frame, UNWIND_INFO и evidence, признаки становятся естественным следствием.

## Как читать источники после этой книги

Официальная документация Microsoft написана точно, но не обязана быть учебником для нулевого читателя. Она говорит, как устроено поле или API, но не всегда объясняет, почему новичок путается. Книги по reverse engineering часто дают широкий опыт, но не фокусируются на конкретном EH/Unwind Analyzer. Поэтому эта книга выполняет роль моста: она подготавливает язык, карту и вопросы, после которых Microsoft Learn, Intel manuals и Ghidra docs читаются уже не как стена терминов, а как знакомая техническая территория.
""")
    return "\n\n".join(out)


def lab_chapter(rounds: int) -> str:
    out = ["# Том VI. Практикум: как читать бинарник, отчет и Ghidra как одну историю"]
    out.append("""
Практикум нужен не для количества страниц. Он нужен, чтобы теория стала привычкой. Ниже идут семинарские разборы. Они похожи не формой, а дисциплиной: каждый раз мы начинаем с факта, удерживаем слои отдельно и заканчиваем ручной проверкой.

Главное правило практикума: не пытайся сразу доказать вредоносность. Сначала докажи, что ты правильно понял объект. Где он лежит? Какой у него адрес? Кто его создал? Кто его использует? Какая граница нарушена? Чем это видно во втором инструменте?
""")
    for i in range(rounds):
        title, task = LABS[i % len(LABS)]
        concept = CONCEPTS[(i * 3) % len(CONCEPTS)]
        finding = FINDINGS[(i * 5) % len(FINDINGS)]
        out.append(f"## Семинар {i + 1}. {title}: {concept.name} и {finding.code}")
        out.append(f"Начнем с простой ситуации. У тебя есть отчет analyzer и бинарник. Тема семинара - {task}. Не открывай сразу все окна подряд. Сначала назови объект исследования: в этой задаче это `{concept.name}` и признак `{finding.code}`.")
        out.append(f"Первый слой - файл. Здесь важно понять, где физически лежат байты. Для `{concept.name}` базовая проверка такая: {concept.check}. Если на этом этапе перепутать файл и image, все последующие адреса станут шаткими.")
        out.append(f"Второй слой - PE image. Нужно найти секцию, права, virtual range и связь с exception directory или runtime functions. Признак `{finding.code}` относится к семье `{finding.family}`, поэтому он подсказывает, в какую часть отчета смотреть первой.")
        out.append(f"Третий слой - человеческая проверка. Для выбранного признака ручная проверка звучит так: {finding.manual}. После этого можно идти в Ghidra, но уже не вслепую: у тебя есть адрес, контекст и вопрос.")
        out.append("Четвертый слой - аккуратный вывод. Формулируй не 'это точно плохо', а 'это необычно по такой причине, подтверждается такими полями, требует такой проверки, ограничение такое'. Именно эта осторожность делает реверс-инженера сильным.")
    return "\n\n".join(out)


def capstone_chapter() -> str:
    out = ["# Том VII. Финальный экзамен: четыре сквозных разбора от байта до защиты"]
    out.append("""
Финальная глава нужна для того, чтобы собрать книгу в одно движение. До этого мы отдельно говорили о PE, адресах, ABI, RUNTIME_FUNCTION, UNWIND_INFO, признаках, Ghidra, статике и динамике. Но на практике перед тобой будет не отдельный термин, а бинарник и вопрос: что с ним не так, насколько этому можно верить и как это объяснить другому человеку.

Ниже четыре сквозных разбора. Это не новые признаки и не повтор таблиц. Это тренировка маршрута мышления. Каждый раз мы начинаем с команды и отчета, затем переходим к статическому факту, затем ищем динамическую поддержку, затем открываем Ghidra или ручную проверку, затем формулируем осторожный вывод. Именно так техническое наблюдение превращается в защищаемый результат.
""")
    cases = [
        (
            "Статическая аномалия без динамического подтверждения",
            "Представь sample, где static report показывает unwind section unusual и writable placement, но dynamic validation дает нули по handler hits. Слабый ответ звучал бы так: 'динамика ничего не нашла, значит аномалии нет'. Сильный ответ другой: static finding остается фактом структуры файла; динамический запуск лишь не прошел путь, где эта структура проявилась поведением.",
            "В таком разборе первым делом нужно показать section table. Где находится unwind RVA? Какие permissions у секции? Почему это необычно по сравнению с .pdata/.xdata? Затем нужно открыть Runtime functions и показать, какие строки затронуты. Если Anomalies/error заполнен для многих функций, объясни, что finding относится не к каждой функции как отдельному злому действию, а к общей области metadata, которую используют эти функции.",
            "Динамический отчет читать нужно честно. Если Exceptions = 0, Handler hits = 0, Runtime table calls = 0, это не отрицание статического факта. Это описание данного запуска. Проверь timeout, instrumentation complete, breakpoint failures и module coverage. Если timeout был коротким, скажи это. Если instrumentation incomplete, не делай сильный поведенческий вывод.",
            "Защитная формулировка: 'Статически обнаружено необычное размещение unwind metadata в такой-то секции с такими-то правами. Динамический запуск не подтвердил достижение обработчика, поэтому я не усиливаю вывод поведением. Ручная проверка заключается в просмотре section permissions, unwind RVA и соответствующих строк Runtime functions'."
        ),
        (
            "Комбо-кейс: статика видит структуру, динамика видит действие",
            "Лучший демонстрационный пример для защиты - когда static и dynamic говорят об одном механизме с разных сторон. Например, static report показывает подозрительное размещение или handler metadata, а dynamic report показывает RtlAddFunctionTable, RtlInstallFunctionTableCallback, SetUnhandledExceptionFilter или hit обработчика.",
            "Статическую часть начинай с объекта: имя sample, команда запуска, путь к HTML/JSON. Затем покажи Final assessment, но не останавливайся на карточке. Перейди в Static findings, найди code, severity, affected count, representative RVA. После этого открой Runtime functions и покажи конкретную строку: begin, end, unwind RVA, section, handler, anomalies/error.",
            "Динамическую часть начинай со счетчиков. Runtime table calls > 0 означает, что процесс реально обратился к механизму динамических function tables. Handler hits > 0 означает, что выполнение дошло до обработчика, на который analyzer поставил breakpoint. Runtime log дает текстовое доказательство: строки BP set, API call, handler hit, exception event, exit process.",
            "Защитная формулировка: 'Статика показывает, где в PE лежит подозрительная metadata, а динамика показывает, что во время выполнения процесс действительно взаимодействует с механизмом исключений/function tables. Поэтому это не только необычная форма файла, но и наблюдаемое runtime-поведение в выбранном сценарии запуска'."
        ),
        (
            "Ghidra-проверка representative RVA",
            "Когда в отчете есть representative RVA, это приглашение к ручной проверке. Нельзя защищать адрес только словами. Нужно показать, как перейти к нему в Ghidra. Если ImageBase равен 0x140000000, то RVA 0x1010 соответствует адресу 0x140001010. Если base другой, расчет меняется. Эта арифметика должна быть автоматической привычкой.",
            "В Ghidra сначала проверь Memory Map и ImageBase. Затем используй Go To и введи calculated VA. Если адрес попал в функцию, сравни границы функции с Begin/End из Runtime functions. Если Ghidra не разметила функцию так же, не паникуй: Ghidra строит свою базу анализа, а analyzer читает PE metadata. Различие само по себе может быть предметом объяснения.",
            "После перехода смотри surrounding disassembly. Есть ли prolog? Есть ли изменение RSP? Есть ли переход к handler? Есть ли ссылки на область metadata? Если речь о handler RVA, проверь, попадает ли handler в executable section. Если речь о writable metadata, вернись к section permissions.",
            "Защитная формулировка: 'Я не прошу верить отчету как черному ящику. Вот representative RVA, вот перевод в адрес Ghidra, вот окружающие инструкции или данные, вот связь с таблицей отчета. Поэтому вывод можно проверить руками'."
        ),
        (
            "Как объяснить ограничения, не ослабляя работу",
            "Ограничения не делают проект хуже. Наоборот, честно названные ограничения делают вывод профессиональным. Статический анализ ограничен тем, что он читает структуру, а не все возможные пути выполнения. Динамический анализ ограничен timeout, входными аргументами, окружением и покрытием. Ghidra ограничена эвристиками разметки и качеством анализа конкретного файла.",
            "В отчете ограничения уже имеют технические следы. Instrumentation complete показывает, насколько наблюдение завершено. Breakpoint failures говорят, удалось ли поставить точки наблюдения. Dropped events говорят, не потерял ли collector часть событий. Manual validation plan говорит, какие ручные шаги нужны для усиления вывода.",
            "На защите не нужно прятать эти поля. Лучше сказать: 'этот запуск подтверждает такие-то события, но не доказывает отсутствие других путей'. Такая фраза звучит взросло. Она показывает, что ты понимаешь не только инструмент, но и научную дисциплину проверки.",
            "Финальная формулировка всей книги: 'EH/Unwind Analyzer не заменяет реверс-инженера. Он быстро и воспроизводимо поднимает структурные и runtime-факты, связывает их с адресами и отчетами, а человек затем проверяет самые важные места в Ghidra, JSON, HTML и исходном коде проекта'."
        ),
        (
            "Benign-контраст как доказательство аккуратности инструмента",
            "Показывать только подозрительные samples опасно: слушатель может решить, что analyzer везде находит тревогу. Поэтому рядом с combo sample полезно показать benign sample. Там важно не отсутствие красивой драмы, а спокойная инженерная проверка: parser прочитал PE, unwind table декодирована, сильных статических аномалий нет, dynamic validation не нашла необычных handler events.",
            "Benign-контраст объясняет границы чувствительности. Если benign report показывает score 0 или no strong anomalies, это не значит, что программа 'хорошая во всех смыслах'. Это значит, что именно проверяемые EH/Unwind признаки не дали сильного сигнала. Такой ответ честный и точный.",
            "На защите benign-кейс можно показать в одну минуту. Открой Final assessment, затем Runtime functions с OK-строками, затем Analysis details. Скажи: 'вот нормальная картина, с которой я сравниваю подозрительный sample'. После этого переход к combo sample становится понятнее.",
            "Защитная формулировка: 'Инструмент не обязан кричать на каждый PE. Его ценность в том, что он различает спокойные структуры, структурные нарушения и runtime-события. Benign-контраст нужен как контрольная точка эксперимента'."
        ),
        (
            "Когда отчет и Ghidra расходятся",
            "Иногда analyzer и Ghidra показывают разные границы функции или разную уверенность в коде. Это не обязательно ошибка. Analyzer читает PE metadata и runtime function table. Ghidra строит программу с помощью disassembly, анализа потоков управления, эвристик функций и decompiler pipeline. Они смотрят на один бинарник разными методами.",
            "Если Ghidra не размечает функцию там, где RUNTIME_FUNCTION указывает диапазон, нужно задать вопрос: область действительно содержит исполняемый код? попадает ли BeginAddress в .text? есть ли prolog? может ли это быть thunk, padding, намеренно странная разметка или поврежденная metadata? Ответ появляется только после ручного просмотра.",
            "Если Ghidra размечает функцию шире или уже, чем Runtime functions, это тоже материал для объяснения. Windows unwind metadata описывает диапазон, важный для exception unwinding. Ghidra пытается восстановить функцию как объект анализа. Эти цели близки, но не тождественны.",
            "Защитная формулировка: 'Расхождение между отчетом и Ghidra я не прячу. Я объясняю источник каждого взгляда: PE metadata против статической разметки инструмента. Затем вручную проверяю байты, секцию, prolog и references'."
        ),
    ]
    for i, (title, p1, p2, p3, p4) in enumerate(cases, 1):
        out.append(f"## Разбор {i}. {title}")
        out.append(p1)
        out.append(p2)
        out.append(p3)
        out.append(p4)
        out.append("Мини-зачет: сформулируй этот разбор в одном абзаце без потери слоев: файл, PE, адрес, finding, dynamic evidence, Ghidra, ограничение вывода. Если хотя бы один слой пропал, вернись к отчету и восстанови цепочку.")
    out.append("""
## Итоговый маршрут перед демонстрацией

Перед демонстрацией выбери один сильный combo sample и один спокойный benign sample. Benign нужен не для красоты, а для контраста: он показывает, что инструмент умеет молчать, когда сильных признаков нет. Combo sample нужен для основного рассказа: он показывает, как статическая аномалия и динамическое событие соединяются в доказательную цепочку.

Для каждого sample сохрани команду запуска, HTML, JSON и при необходимости Ghidra CSV. В HTML отметь карточку Final assessment, таблицу Static findings, Runtime functions и Runtime log. В JSON проверь точные поля. В Ghidra перейди к representative RVA. После этого проговори вывод вслух. Если рассказ занимает больше пяти минут, убери второстепенные детали, но не убирай адреса и ограничения.

Главная цель финального экзамена - не запомнить этот текст, а научиться двигаться. Сначала факт. Потом структура. Потом runtime. Потом ручная проверка. Потом осторожный вывод. Этот порядок превращает даже сложный EH/Unwind материал в понятный инженерный рассказ.
""")
    return "\n\n".join(out)


def closing_chapter(extra_notes: int) -> str:
    out = ["# Заключение. Как из этого курса вырастает реверс-инженер"]
    out.append("""
Если после этой книги ты смотришь на EXE уже не как на неизвестный значок, а как на систему договоров, цель достигнута. Компилятор договаривается с ABI. Linker договаривается с PE. Loader договаривается с секциями и relocations. Windows exception dispatcher договаривается с RUNTIME_FUNCTION и UNWIND_INFO. Analyzer читает эти договоры и ищет места, где они нарушены или выглядят необычно.

Реверс-инженер отличается не тем, что знает больше страшных слов. Он отличается тем, что умеет спокойно двигаться от наблюдения к выводу. Он не перескакивает через слои. Он не путает RVA и VA. Он не принимает finding за приговор. Он не считает один dynamic run полной истиной. Он умеет сказать: "вот факт, вот адрес, вот проверка, вот ограничение".

Этот учебник должен быть не последней точкой, а стартом. Дальше бери реальные отчеты проекта, открывай Ghidra, сравнивай benign и combo samples, читай исходный код analyzer и постепенно сокращай дистанцию между байтом и смыслом.
""")
    for i in range(extra_notes):
        concept = CONCEPTS[(i * 7) % len(CONCEPTS)]
        out.append(f"## Итоговая заметка {i + 1}. {concept.name}")
        out.append(f"Вернись к термину `{concept.name}` и проверь, изменилось ли твое ощущение. В начале книги он мог быть просто словом. Теперь за ним должна стоять цепочка: {concept.neighbor}. Если ты можешь показать эту цепочку в отчете, в Ghidra и в исходном коде, значит термин стал рабочим инструментом.")
    return "\n\n".join(out)


def base_markdown(lab_rounds: int, closing_notes: int) -> str:
    parts = [
        "# Предисловие. Почему этот учебник переписан заново",
        """
Предыдущая попытка сделать расширенное издание была неправильной: страницы выглядели слишком одинаково. Настоящий учебник не должен быть набором карточек с одинаковыми заголовками. Он должен вести мысль. Поэтому эта версия построена как связный университетский курс: сначала простое объяснение, затем строгая модель, затем проект, затем отчеты, Ghidra, динамика и защита вывода.

Здесь сохраняется требование глубины, но меняется подача. Мы будем говорить живо: иногда через бытовую аналогию, иногда через точную структуру, иногда через ошибку новичка, иногда через вопрос преподавателя. Цель не в том, чтобы дочитать 500 страниц. Цель в том, чтобы после чтения в голове сложилась карта.
""",
        source_method_chapter(),
        beginner_theory_bridge_chapter(),
        deep_foundation_chapter(),
        deep_unwind_mechanics_chapter(),
        deep_common_mistakes_chapter(),
        language_bridge_chapter(),
        whole_system_story_chapter(),
        concept_chapter(),
    ]

    for idx, (title, focus, terms) in enumerate(LECTURE_BLUEPRINTS, 1):
        parts.append(project_lecture_chapter(idx, title, focus, terms))

    parts.append(findings_chapter())
    parts.append(study_path_chapter())
    parts.append(lab_chapter(lab_rounds))
    parts.append(capstone_chapter())
    parts.append(closing_chapter(closing_notes))
    return polish_common_language("\n\n".join(parts))


def fit_to_500_pages() -> tuple[str, int]:
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    temp_pdf = TMP_DIR / "candidate.pdf"

    lab_rounds = 12
    closing_notes = 0
    while True:
        md = base_markdown(lab_rounds, closing_notes)
        pages = build_pdf(md, temp_pdf)
        print(f"candidate lab_rounds={lab_rounds} closing_notes={closing_notes} pages={pages}")
        if pages >= 500:
            break
        if lab_rounds >= 40:
            raise RuntimeError(
                "the manuscript is still too short after the planned practicum; "
                "add real lecture material instead of repeating labs"
            )
        lab_rounds += 4

    while True:
        md = base_markdown(lab_rounds, closing_notes)
        pages = build_pdf(md, temp_pdf)
        if pages == 500:
            return md, pages
        if pages < 500:
            closing_notes += 1
            continue
        if closing_notes > 0:
            closing_notes -= 1
        elif lab_rounds > 0:
            lab_rounds -= 1
        else:
            raise RuntimeError("cannot fit PDF to 500 pages")


def main() -> None:
    THEORY_DIR.mkdir(parents=True, exist_ok=True)
    md, pages = fit_to_500_pages()
    assert_supported_glyphs(md)
    MD_PATH.write_text(md, encoding="utf-8")
    final_pages = build_pdf(md, PDF_PATH)
    if final_pages != 500:
        raise RuntimeError(f"expected 500 pages, got {final_pages}")
    print(f"wrote {PDF_PATH}")
    print(f"wrote {MD_PATH}")
    print(f"pages={pages}")
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)


if __name__ == "__main__":
    main()
