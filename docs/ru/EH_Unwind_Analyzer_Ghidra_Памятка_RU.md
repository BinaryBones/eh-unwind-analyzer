> Документ показывает два обязательных сценария: обычная разметка функций по CSV на combo-бинарнике и warning/bookmark на специально поврежденном static-бинарнике.

Путь проекта: C:\Users\Templar\Desktop\вкр готовая\ip_full

Где лежит импортёр: ghidra\import_unwind_csv.py

Куда сохранён этот документ: docs\ru\EH_Unwind_Analyzer_Ghidra_Памятка_RU.pdf

# EH/Unwind Analyzer - памятка по Ghidra

# 1. Что именно проверяется

EH/Unwind Analyzer умеет экспортировать таблицу функций в формат CSV для Ghidra. CSV строится по данным PE Exception Directory: `.pdata` / `RUNTIME_FUNCTION` и `UNWIND_INFO`.

Ghidra-скрипт `import_unwind_csv.py` импортирует эти диапазоны в текущую программу Ghidra: создаёт или обновляет функции, добавляет комментарии с расшифровкой unwind-метаданных и ставит warning bookmarks на проблемные записи.

| Компонент | Что делает | Как понять, что работает |
|---|---|---|
| --ghidra-csv | Создаёт CSV с begin_rva, end_rva, name, comment | CSV содержит строки функций и комментарии UNWIND |
| import_unwind_csv.py | Создаёт/обновляет функции в Ghidra | В консоли есть created/updated/commented, skipped=0 |
| Listing | Показывает комментарии перед функциями | Есть строка [EH/Unwind Analyzer] ... |
| Bookmarks | Показывает предупреждения по parse failed/anomalies | Есть WARNING категории EH/Unwind Analyzer |

> Важно: Ghidra CSV не является динамической проверкой. Он нужен, чтобы визуально увидеть в Ghidra функции, диапазоны и комментарии по unwind-метаданным. Динамика проверяется отдельно через `--dynamic`.

# 2. Подготовка файлов

Открой PowerShell или терминал Visual Studio и перейди в корень проекта:

```text
Set-Location "C:\Users\Templar\Desktop\вкр готовая\ip_full"
```

Проверь, что анализатор собран и запускается:

```text
.\build\debug\eh_unwind_analyzer.exe --version
```

Для проверки Ghidra нужны два CSV-файла: один для нормального combo-сценария, второй для warning/bookmark-сценария.

## 2.1. CSV для combo_28

Этот сценарий показывает нормальный импорт 46 функций и комментариев. Сам бинарник имеет статические аномалии `unwind_unusual_section` и `unwind_writable_section`, а динамически вызывает runtime function table API.

```text
.\build\debug\eh_unwind_analyzer.exe "бинарники на тестирование\бинарники\combo\28_combo_rtl_xdata_renamed_writable.exe" --ghidra-csv reports\combo_28_ghidra.csv --heuristics
```

Ожидаемый смысл вывода:

```text
RUNTIME_FUNCTION entries: 46
Findings:
- [high/unwind_unusual_section] ...: 46
- [high/unwind_writable_section] ...: 46
Wrote Ghidra CSV: reports\combo_28_ghidra.csv
```

## 2.2. CSV для static_03

Этот сценарий нужен, чтобы проверить предупреждение в Ghidra: одна функция имеет ошибку разбора `UNWIND_INFO`.

```text
.\build\debug\eh_unwind_analyzer.exe "бинарники на тестирование\бинарники\static\03_static_unwind_oob_parse_fail.exe" --ghidra-csv reports\static_03_ghidra.csv --heuristics
```

Ожидаемый смысл вывода:

```text
RUNTIME_FUNCTION entries: 3
Findings:
- [high/unwind_rva_oob] ...
- [high/unwind_parse_fail] ...
Wrote Ghidra CSV: reports\static_03_ghidra.csv
```

# 3. Сценарий A: проверить обычную разметку функций

Используй этот сценарий для демонстрации, что проект нормально создаёт Ghidra CSV и Ghidra импортёр действительно размечает функции.

Файлы для сценария:

```text
EXE:
C:\Users\Templar\Desktop\вкр готовая\ip_full\бинарники на тестирование\бинарники\combo\28_combo_rtl_xdata_renamed_writable.exe

CSV:
C:\Users\Templar\Desktop\вкр готовая\ip_full\reports\combo_28_ghidra.csv

SCRIPT:
C:\Users\Templar\Desktop\вкр готовая\ip_full\ghidra\import_unwind_csv.py
```

## 3.1. Создать проект Ghidra

1. Запусти Ghidra.
2. Выбери `File -> New Project`.
3. Тип проекта: `Non-Shared Project`.
4. Назови проект, например `EH_Unwind_Demo`.
5. Папку проекта можно выбрать на рабочем столе или рядом с ВКР, но не внутри `build`.

## 3.2. Импортировать combo_28

1. В окне Project нажми `File -> Import File`.
2. Выбери `28_combo_rtl_xdata_renamed_writable.exe`.
3. В окне импорта проверь, что формат определился как `Portable Executable (PE)`.
4. Нажми `OK`.
5. После импорта дважды кликни по файлу, чтобы открыть CodeBrowser.
6. Когда Ghidra спросит `Analyze?`, нажми `Yes` или `Analyze Now`.
7. Оставь стандартные анализаторы включёнными и нажми `Analyze`.

> Не страшно, если Ghidra сама уже создаст часть функций. Импортёр в таком случае не создаёт их заново, а обновляет диапазоны и добавляет комментарии.

## 3.3. Подключить папку со скриптом

1. В CodeBrowser открой `Window -> Script Manager`.
2. В Script Manager нажми кнопку `Manage Script Directories` или значок списка/папки с путями.
3. Добавь папку `C:\Users\Templar\Desktop\вкр готовая\ip_full\ghidra`.
4. Закрой окно управления папками.
5. В списке скриптов найди `import_unwind_csv.py`. Он обычно появляется в категории `Analysis`.

## 3.4. Запустить импорт

1. Выдели `import_unwind_csv.py`.
2. Нажми `Run Script`.
3. Когда появится выбор файла, выбери `reports\combo_28_ghidra.csv`.
4. Дождись окончания. Внизу, в Console, появится строка результата.

Ожидаемый пример результата в консоли Ghidra:

```text
EH/Unwind import complete: created=... updated=... renamed=... commented=46 bookmarks=0 skipped=0
```

Как читать результат:

| Поле | Нормально | Что значит |
|---|---|---|
| created | 0 или больше | Сколько новых функций создал импортёр |
| updated | 0 или больше | Сколько существующих функций обновил |
| renamed | 0 или больше | Сколько функций переименовал в sub_XXXXXXXX |
| commented | около 46 | Сколько функций получили EH/Unwind комментарии |
| bookmarks | 0 для combo_28 | Предупреждений parse failed здесь нет |
| skipped | 0 | Строки CSV не были пропущены |

# 4. Что смотреть в Ghidra после импорта

Главная проверка - убедиться, что функции, адреса и комментарии появились в интерфейсе Ghidra.

## 4.1. Окно Functions

1. Открой `Window -> Functions`, если окно функций не видно.
2. В списке должны быть функции вида `sub_00001000`, `sub_000013F0`, `sub_00001410` и другие.
3. Клик по функции переносит Listing на её адрес.
4. Для combo_28 в CSV 46 строк, значит после импорта должно быть примерно 46 прокомментированных диапазонов.

## 4.2. Адреса: как сверять RVA и адрес Ghidra

CSV хранит RVA, а Ghidra показывает виртуальный адрес. Для PE64 образа base обычно `0x140000000`. Формула:

```text
адрес в Ghidra = ImageBase + begin_rva
пример: 0x140000000 + 0x000013F0 = 0x1400013F0
```

Поэтому строка CSV:

```text
0x000013F0,0x0000140D,sub_000013F0,... handler_rva=0x000027a0
```

в Ghidra должна соответствовать функции около адреса:

```text
0x1400013F0
```

## 4.3. Listing и комментарии

1. Открой функцию `sub_000013F0` или любую функцию из CSV.
2. Над началом функции должен появиться pre-comment от импортёра.
3. Комментарий всегда начинается с `[EH/Unwind Analyzer]`.
4. В комментарии смотри `UNWIND v1`, `flags`, `prolog`, `stack`, `frame`, `handler_rva`.

Пример корректного комментария:

```text
[EH/Unwind Analyzer] UNWIND v1 flags=EHANDLER prolog=4 stack=40B frame=-+0 saved_gp=[-] saved_xmm=[-] handler_rva=0x000027a0
```

## 4.4. Что именно не так в combo_28

В Ghidra ты видишь функции и комментарии. А сами статические аномалии смотри в HTML/JSON отчёте EH/Unwind Analyzer:

```text
start .\reports\combo_28_dynamic.html
```

Для combo_28 важные статические findings:

| Finding | Смысл |
|---|---|
| unwind_unusual_section | UNWIND_INFO лежит в нетипичной секции, не стандартная .xdata/.rdata/.pdata |
| unwind_writable_section | Секция с UNWIND_INFO доступна на запись, что подозрительно для metadata |

Динамически тот же файл вызывает `RtlAddFunctionTable` и `RtlInstallFunctionTableCallback`. Это проверяется в HTML-блоке `Dynamic validation`, а не в Ghidra.

# 5. Сценарий B: проверить warning/bookmark

Этот сценарий нужен, чтобы показать, что Ghidra-импортёр не только создаёт функции, но и помечает проблемные unwind-записи предупреждениями.

Файлы для сценария:

```text
EXE:
C:\Users\Templar\Desktop\вкр готовая\ip_full\бинарники на тестирование\бинарники\static\03_static_unwind_oob_parse_fail.exe

CSV:
C:\Users\Templar\Desktop\вкр готовая\ip_full\reports\static_03_ghidra.csv
```

## 5.1. Импортировать static_03 в Ghidra

1. В том же Ghidra Project нажми `File -> Import File`.
2. Выбери `03_static_unwind_oob_parse_fail.exe`.
3. Открой его в CodeBrowser.
4. Запусти стандартный анализ Ghidra через `Analyze Now`.
5. Запусти `import_unwind_csv.py` и выбери `reports\static_03_ghidra.csv`.

## 5.2. Ожидаемый результат

В консоли Ghidra ожидай примерно:

```text
EH/Unwind import complete: created=... updated=... renamed=... commented=3 bookmarks=1 skipped=0
```

Почему `bookmarks=1`: в CSV первая строка содержит `UNWIND parse failed`, а скрипт ставит Warning bookmark на такие комментарии.

## 5.3. Где открыть Bookmarks

1. Открой `Window -> Bookmarks`.
2. В списке найди тип `Warning`.
3. Категория должна быть `EH/Unwind Analyzer`.
4. Кликни по bookmark - Ghidra перенесёт Listing к проблемной функции.

Текст предупреждения должен быть близок к:

```text
UNWIND parse failed: UnwindInfo RVA 0x00007100 not mappable to file offset.
```

## 5.4. Как объяснять static_03 на защите

Короткая формулировка:

> В `03_static_unwind_oob_parse_fail.exe` одна запись `RUNTIME_FUNCTION` указывает на `UNWIND_INFO` по RVA `0x00007100`, который не отображается в файловое смещение. Анализатор фиксирует `unwind_rva_oob` и `unwind_parse_fail`, а импортёр Ghidra ставит warning bookmark на проблемную функцию.

# 6. Частые проблемы и как их исправить

| Проблема | Причина | Что сделать |
|---|---|---|
| Скрипт не виден | Папка ghidra не добавлена в Script Manager | Добавить `ip_full\ghidra` через Manage Script Directories |
| CSV не выбирается | Выбран не тот файл или CSV не создан | Сначала выполнить команду `--ghidra-csv ...` |
| skipped > 0 | Адреса CSV не совпали с текущим открытым EXE | Проверить, что EXE и CSV от одного и того же бинарника |
| created=0 | Ghidra сама уже нашла функции | Это нормально, смотри `updated` и `commented` |
| Нет комментариев | Скрипт не завершился или выбран не тот CSV | Проверить Console и повторить импорт |
| Нет bookmarks для combo_28 | В combo_28 нет parse failed | Для bookmarks использовать `static_03_ghidra.csv` |
| Адрес не похож на RVA | Ghidra показывает VA, а CSV хранит RVA | Прибавить ImageBase: `0x140000000 + RVA` |

# 7. Мини-чеклист перед демонстрацией

- Собран `build\debug\eh_unwind_analyzer.exe`.
- Созданы `reports\combo_28_ghidra.csv` и `reports\static_03_ghidra.csv`.
- В Ghidra добавлена script directory `ip_full\ghidra`.
- На `combo_28` после скрипта видно `commented=46`, `skipped=0`.
- В Listing у функций есть комментарии `[EH/Unwind Analyzer] ...`.
- На `static_03` видно `bookmarks=1`, в Bookmarks есть Warning от EH/Unwind Analyzer.
- Для объяснения аномалий открыты HTML-отчёты `combo_28_dynamic.html` и/или `static_03.html`.

# 8. Готовые команды для копирования

```text
Set-Location "C:\Users\Templar\Desktop\вкр готовая\ip_full"

.\build\debug\eh_unwind_analyzer.exe "бинарники на тестирование\бинарники\combo\28_combo_rtl_xdata_renamed_writable.exe" --ghidra-csv reports\combo_28_ghidra.csv --heuristics

.\build\debug\eh_unwind_analyzer.exe "бинарники на тестирование\бинарники\static\03_static_unwind_oob_parse_fail.exe" --ghidra-csv reports\static_03_ghidra.csv --heuristics

start .\reports\combo_28_dynamic.html
start .\reports\static_03.html
```
