ФАЙЛЫ ДЛЯ GHIDRA

Назначение папки:
1. CSV_РАЗМЕТКА - CSV-файлы с диапазонами функций и комментариями EH/Unwind Analyzer.
2. ГОТОВЫЙ_GHIDRA_ПРОЕКТ - готовый проект Ghidra, где бинарники уже импортированы и размечены.
3. manifest_ghidra_files.csv - список соответствия: бинарник -> CSV для Ghidra.
4. УСТАНОВИТЬ_СКРИПТ_В_GHIDRA.ps1 - копирует Java-скрипт ImportUnwindCsv.java в папку скриптов Ghidra.

Важно:
- Для вашей установленной Ghidra используйте Java-скрипт ImportUnwindCsv.java, а не import_unwind_csv.py.
- Python-скрипт требует PyGhidra/Jython, а в вашей Ghidra Python был недоступен.
- Java-скрипт работает из обычного Script Manager.

Быстрый способ:
1. Откройте ГОТОВЫЙ_GHIDRA_ПРОЕКТ/EH_Unwind_Marked.gpr.
2. Выберите нужный бинарник в проекте.
3. Откройте CodeBrowser.
4. Смотрите комментарии в Listing и Decompiler: строки начинаются с [EH/Unwind Analyzer].

Ручной способ:
1. Скопируйте ip_full/ghidra/ImportUnwindCsv.java в папку ghidra_scripts установленной Ghidra.
2. В Ghidra откройте бинарник.
3. Scripts -> Script Manager.
4. В фильтре введите ImportUnwindCsv.
5. Запустите скрипт зеленой кнопкой Run.
6. Выберите CSV из CSV_РАЗМЕТКА для того же бинарника.

Подробная инструкция лежит в:
ip_full/docs/ru/РАБОТА С ГИДРОЙ/КАК РАБОТАТЬ С ГИДРОЙ.pdf
