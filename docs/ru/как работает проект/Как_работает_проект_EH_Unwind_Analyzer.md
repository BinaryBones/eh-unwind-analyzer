# Как работает проект EH/Unwind Analyzer

Это Markdown-источник PDF. Основной материал находится в PDF, но текстовая версия оставлена для поиска и правок.

## 1. От полного нуля к бинарному файлу
Компьютерная программа на диске не похожа на исходный код. Исходный код читает человек, а EXE читает операционная система. Между ними есть compiler и linker. Они превращают понятные функции в машинный код, данные, таблицы и служебные структуры.
EH/Unwind Analyzer работает не с исходным кодом. Он работает с готовым PE-файлом. Поэтому его мир - это байты, адреса, секции и таблицы. Чтобы понять проект, надо сначала принять этот переход: программа как текст исчезла, остался формат файла.
Когда мы говорим 'анализатор нашел функцию', это не значит, что в EXE лежит слово function. Это значит, что в служебной таблице есть диапазон адресов, который Windows использует как описание функции для обработки исключений.

## 2. PE-файл и загрузка в память
PE-файл содержит заголовки, которые говорят Windows loader, как разместить файл в памяти. Секции имеют raw representation на диске и virtual representation в памяти. Между ними существует перевод RVA в file offset.
Analyzer обязан проверять этот перевод. Если RVA указывает в никуда, нельзя честно читать UNWIND_INFO. Поэтому PE parser в проекте - не вспомогательная мелочь, а фундамент всей системы.
Когда отчет показывает section_raw_oob или section_virtual_oob, он сообщает не про исключения, а про карту местности. Пока карта сломана, любые маршруты по ней сомнительны.

## 3. Windows x64 exceptions and unwind
На x64 Windows обработка исключений и раскрутка стека опираются не только на инструкции процессора, но и на metadata. Система должна понимать, как функция изменила RSP, какие nonvolatile registers сохранила и где искать handler.
Эта metadata находится в RUNTIME_FUNCTION и UNWIND_INFO. RUNTIME_FUNCTION задает диапазон функции и ссылку на unwind data. UNWIND_INFO объясняет, что происходило в prolog и есть ли exception handler.
Если metadata неправильная, reverse engineering становится опасным: decompiler может неверно понять stack frame, debugger может показать странный unwind, а analyst может пропустить handler.

## 4. Статический pipeline проекта
Static mode не запускает target. Он открывает файл как bytes, считает SHA-256, парсит PE, читает Exception Directory, строит RuntimeFunction array, декодирует UNWIND_INFO и затем запускает heuristics.
Такой pipeline безопаснее и воспроизводимее dynamic mode. Его можно запускать в CI, на большом corpus или на подозрительных файлах без риска выполнения кода.
Главное достоинство static mode - объяснимость. Каждый finding связан с конкретным полем, счетчиком, адресом и section context.

## 5. Heuristic engine
Heuristic engine превращает наблюдения в findings. Он не является machine learning model и не использует скрытые веса. Все правила документированы в evidence_matrix.md.
Каждый finding имеет code, family, severity, message, affected_count и representative_rva. Потом findings превращаются в score, confidence, verdict и manual validation steps.
Разделение score и confidence делает отчет честнее. Score говорит о подозрительности по весам, confidence - о надежности интерпретации.

## 6. Dynamic collector
Dynamic mode запускает target под Windows Debug API. Это уже execution boundary: файл действительно выполняется. Поэтому такой режим нужен для controlled lab, а не для бездумного запуска любых samples.
Collector ставит breakpoints на AddVectoredExceptionHandler, AddVectoredContinueHandler, SetUnhandledExceptionFilter, RtlAddFunctionTable и RtlInstallFunctionTableCallback. Еще он может ставить breakpoints на discovered handlers.
События dynamic report отвечают на вопрос: что target сделал при запуске? Это другой вопрос, чем static: что записано в PE-файле?

## 7. Отчеты и контракты
Проект пишет console output, CSV, Ghidra CSV, JSON и HTML. Каждый формат нужен разной аудитории. Console - быстро посмотреть. HTML - показать человеку. JSON - валидировать и автоматизировать. CSV - анализировать таблицами. Ghidra CSV - переносить функции и comments.
JSON Schema делает отчет контрактом. Это важно для диплома и продукта: downstream tools могут проверять, что формат не сломан.
HTML self-contained: он не грузит внешние скрипты и стили. Это важно для offline evidence archive.

## 8. Ghidra workflow
Ghidra не заменяется analyzer. Analyzer готовит адресную и unwind информацию, а Ghidra помогает глазами проверить код, функции, comments и bookmarks.
Ghidra CSV содержит begin_rva, end_rva, name и comment. Importer создает или обновляет функции, добавляет pre-comments и ставит bookmarks на parse failures/anomalies.
Главная формула для ручной проверки: Ghidra address = ImageBase + RVA. Без нее легко открыть не тот адрес.

## 9. Команды запуска
В Visual Studio проект открывается как CMake folder. Собранный analyzer лежит в build\debug\eh_unwind_analyzer.exe. Запуск без аргументов показывает help, потому что инструменту нужен target PE file.
Для static отчета используй --heuristics --json --html. Для dynamic добавляй --dynamic --timeout-ms и --trace-steps. Для Ghidra используй --ghidra-csv.
Пути с пробелами и кириллицей бери в кавычки. В PowerShell для перехода в папку надежнее использовать Set-Location -LiteralPath.

## 10. Как защищать проект
Защищать проект надо не словами 'он ищет вирусы', а словами 'он проверяет конкретный низкоуровневый механизм Windows x64 EH/Unwind'. Это уже и точнее, и сильнее.
Показывай chain of evidence: PE sections -> RUNTIME_FUNCTION -> UNWIND_INFO -> finding -> report -> Ghidra/manual validation -> optional dynamic event.
Если задают вопрос про ложные срабатывания, отвечай спокойно: поэтому есть confidence, weakening rules, benign explanations и ручной validation plan.
