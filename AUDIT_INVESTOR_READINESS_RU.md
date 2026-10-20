# Аудит готовности EH/Unwind Analyzer 1.0.0

Дата финальной проверки: 19 июня 2026 года.

## Итог

Проект доведен до презентационного релиза `1.0.0`. Парсер PE32+ AMD64,
декодер `RUNTIME_FUNCTION`/`UNWIND_INFO`, эвристики, статические отчеты,
Windows dynamic collector, schema/semantic validation и release packaging
проверены на этой ревизии.

## Что проверено

| Область | Результат |
|---|---:|
| MinGW-w64 Release CTest | 16/16 PASS |
| MSVC Release CTest | 16/16 PASS |
| Static labeled corpus | 14/14 valid |
| Benign samples in labeled corpus | 2/2 score 0 |
| Anomalous samples in labeled corpus | 12/12 flagged |
| Real benign corpus | 106/106 valid |
| Non-zero scores in real benign corpus | 0 |
| Runtime functions parsed in real corpus | 174,795 |
| Dynamic smoke VEH/VCH/UEF/RtlFunctionTable | 4/4 PASS |
| Full dynamic corpus | 124/124 valid reports |
| Dynamic debug sessions started | 86 |
| Completed dynamic targets | 54 |
| Controlled timeouts | 32 |
| Elevation-required targets | 8 |
| DLL/PYD CreateProcess rejections | 30 |
| Unexpected dynamic failures | 0 |
| Dropped dynamic events | 0 |

## Что исправлено по аудиту

1. Поставляемый Windows EXE заменен свежей release-сборкой `1.0.0`.
2. `release/VERIFIED_WINDOWS_BUILD.json` обновлен под фактический SHA-256
   финального бинарника.
3. Windows JSON/HTML metadata теперь сохраняет кириллические пути как UTF-8.
4. MSVC strict build починен: два unit-теста больше не вызывают warning C4310
   при `/WX`.
5. Устаревшие `rc1/rc2` маркеры в основных release-документах заменены на
   `1.0.0`.
6. Временные файлы, macOS AppleDouble-файлы и Python cache не включаются в
   релизные архивы.

## Текущий Windows-артефакт

```text
artifacts/windows-x64/eh_unwind_analyzer.exe
Version: 1.0.0
Report schema: 1.1.0
Build: GCC 13.2.0, windows-x64, release
SHA-256: b1cee8678cdf21d96e2921625ffabc3d5c1be4d41cb022d4d0954ef3692df63a
```

## Документы

Папка `docs/ru` сохранена. Пять исходных файлов из нее не удалялись:
четыре PDF и один Markdown-курс. PDF-файлы читаются и рендерятся; они являются
теоретическими/презентационными материалами проекта. Актуальный статус релиза
`1.0.0` фиксируется в `release/RELEASE_STATUS_1.0.0_RU.md`,
`docs/PRODUCT_READINESS.md` и этом аудите.

## Вывод

Проект самодостаточен для демонстрации инвесторам как инженерный инструмент
версии `1.0.0`: есть проверенный Windows binary, воспроизводимые отчеты,
schema-контракт, статическая и динамическая evidence-база, Ghidra CSV export и
чистые release ZIP. Оставшиеся ограничения являются эксплуатационными, а не
блокирующими: динамический режим требует изоляции, DLL/PYD не запускаются
напрямую через `CreateProcess`, а elevation-required EXE требуют отдельного
запуска с повышенными правами.
