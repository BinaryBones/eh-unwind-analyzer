# Подготовка проекта к GitHub

Дата проверки: 20 октября 2026 года.

Корень репозитория — каталог `ip_full`, в котором находятся `README.md`,
`CMakeLists.txt`, `src/` и `include/`.

## Проверка работоспособности

Проверка выполнена на Windows x64 в отдельной копии проекта, сборки созданы
из исходников. Алгоритмы анализатора в `src/` и `include/` не изменялись.

| Проверка | Результат |
|---|---|
| Сборка MinGW-w64 GCC 13.2.0, Release, `-Werror` | Успешно |
| Сборка MSVC 19.51, Release, `/WX` | Успешно |
| Полный CTest, MinGW, включая чистоту релиза | 19/19 |
| Полный CTest, MSVC, включая чистоту релиза | 19/19 |
| Мутационное тестирование парсера | 120 случаев на каждой сборке |
| Статический анализ реального корпуса | 106/106 валидных отчётов, 0 сбоев |
| Функции в реальном корпусе | 174 795 |
| Статический учебный корпус, JSON/HTML/CSV/Ghidra CSV | 84/84 |
| Динамические smoke-сценарии VEH, UEF, VCH, Rtl* | 4/4 |
| Дополнительные динамические учебные сценарии | 9/9, включая штатный тайм-аут |
| Смешанные static + dynamic сценарии | 9/9 |

Проверены формат JSON, соответствие схеме и смысловая согласованность отчётов,
обработка повреждённых PE-заголовков, неподдерживаемой архитектуры и параметры CLI.
Эти проверки подтверждают перечисленные сценарии; они не доказывают отсутствие
всех возможных дефектов. Linux/macOS, sanitizers, coverage и libFuzzer локально
не запускались: для них сохранён workflow `.github/workflows/ci.yml`.

MSVC выдаёт предупреждение командной строки о намеренном снятии `NDEBUG`
в unit-тестах. Вспомогательный MinGW smoke-образец `rtl_ftable_test.c`
выдаёт предупреждения о приведении указателей из `GetProcAddress`.
Сами сборки анализатора и проверки проходят.

## Что сохраняется в репозитории

- исходники анализатора, CMake, сценарии сборки и CI;
- тесты, генераторы и **все 84 бинарных образца** расширенного учебного корпуса;
- шесть основных PE-образцов в `tests/samples/bin/`;
- документация ВКР, исходники учебных материалов и интеграция с Ghidra;
- лицензия MIT, правила участия и описание безопасности.

`.gitignore` исключает сборки, кэши, служебные файлы ОС, временные файлы,
локальные архивы релизов и переменные окружения.
Настройки окончания строк заданы в `.gitattributes`.

Следующие материалы сохранены локально, но не включаются в Git:

- `real_samples/inbox/`: скачанные сторонние программы;
- `reports/` и `бинарники на тестирование/reports_*/`: архивные результаты;
- `artifacts/` и `release-output/`: локальные бинарники и архивы;
- PDF с `.backup_` в имени: резервные версии документов;
- `docs/ru/пэт/` и `docs/ru/beauty_crm_reference_source/`: отдельные учебные проекты.

Архивные ссылки на эти результаты относятся к локальному полному комплекту.
Для новой проверки отчёты можно получить повторно из включённых образцов.

## Сборка и тесты на Windows с MinGW

Нужны MinGW-w64, Ninja, CMake **3.25+** и Python 3.
Ручная конфигурация без presets поддерживает CMake 3.23+.
Запускайте команды в корне проекта:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$python = (Resolve-Path .\.venv\Scripts\python.exe).Path
cmake --preset release "-DPython3_EXECUTABLE=$python"
cmake --build --preset release
ctest --preset release
.\build\release\eh_unwind_analyzer.exe --version
```

Для динамической проверки соберите собственные тестовые программы и задайте
тот же Python для проверки JSON. На машине могут одновременно быть установлены
разные версии `python` и `py -3`, поэтому явно используется Python из `.venv`.

```powershell
Push-Location tests
.\build_tests_mingw.bat
Pop-Location
# При активном окружении py -3 может выбрать другой Python.
# Запускаем сценарии напрямую и проверяем их тем же интерпретатором.
$tool = ".\build\release\eh_unwind_analyzer.exe"
& $tool tests/veh_test_mingw.exe --heuristics --dynamic --timeout-ms 8000 --trace-steps 32 --json tests/veh_dynamic_report.json
& $tool tests/uef_test_mingw.exe --heuristics --dynamic --timeout-ms 8000 --trace-steps 32 --json tests/uef_dynamic_report.json
& $tool tests/vch_test_mingw.exe --heuristics --dynamic --timeout-ms 8000 --trace-steps 32 --json tests/vch_dynamic_report.json
& $tool tests/rtl_ftable_test_mingw.exe --heuristics --dynamic --timeout-ms 8000 --trace-steps 0 --json tests/rtl_dynamic_report.json
& $python tests/validate_dynamic_reports.py --schema docs/report.schema.json --veh tests/veh_dynamic_report.json --uef tests/uef_dynamic_report.json --vch tests/vch_dynamic_report.json --rtl tests/rtl_dynamic_report.json
```

## Сохранённый Windows-релиз

Текущий код имеет версию продукта `1.0.0` и схему отчёта `1.3.0`.
Сохранённые `release/VERIFIED_WINDOWS_BUILD.json`, EXE в `artifacts/`
и отчёты июня 2026 года относятся к предыдущему состоянию схемы `1.1.0`.
Они сохранены как исторические материалы и не являются результатами
проверки текущего кода.

Скрипт упаковки теперь проверяет одновременно версию продукта, схему отчёта,
наличие EXE и его контрольную сумму. При отсутствии актуального подтверждённого
EXE обычный запуск создаёт только архив исходников. Строгий режим
`--require-windows` сообщает об ошибке, пока актуальная Windows-сборка
не получит новый манифест проверки.

```powershell
python scripts/create_release_bundles.py
```

Для запуска актуальной версии используйте результат новой сборки
`build/release/eh_unwind_analyzer.exe`.

## Первая загрузка на GitHub

В подготовленной папке уже создан локальный репозиторий с веткой `main`.
Коммитов, удалённого адреса и публикации ещё нет.
Если используется распакованный ZIP, выполните сначала `git init -b main`.

```powershell
git status --short
git add .
git diff --cached --stat
git commit -m "Initial import of EH/Unwind Analyzer"
```

После создания пустого репозитория в своём аккаунте GitHub добавьте его адрес
и отправьте ветку:

```powershell
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

Замените `OWNER` и `REPOSITORY` своими значениями.
Загружайте содержимое корня проекта через Git, чтобы применялись `.gitignore`
и `.gitattributes`. Не загружайте целиком полную локальную папку через браузер:
в ней намеренно сохранены исключённые архивные материалы.
