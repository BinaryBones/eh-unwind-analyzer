# Сборка архивов и выпуск релиза

## Архив исходников

Из корня репозитория:

```sh
python scripts/create_release_bundles.py
```

Скрипт создаёт `release-output/eh-unwind-analyzer-1.0.0-source.zip`,
`SHA256SUMS.txt` и версионную копию контрольных сумм.
Архив включает исходники, конфигурацию сборки, документацию и тестовые данные.
Локальные сборки, кэши, отчёты и сторонние PE-файлы исключены.

## Пакет готовой программы

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release
cpack --preset release
```

CPack создаёт ZIP для текущей платформы в `build/release/`. На Windows
готовая программа имеет расширение `.exe`. Динамический режим доступен
только в Windows x64; статический анализ поддерживает также Linux и macOS.

Готовые программы и архивы исходников публикуются как вложения GitHub Release.
В Git хранятся исходники и фиксированные тестовые входные данные.
Результат проверки конкретной ревизии доступен в
[GitHub Actions](https://github.com/BinaryBones/eh-unwind-analyzer/actions).

## Дополнительный пакет с подтверждённой Windows-проверкой

Для отдельной поставки EXE вместе с отчётами скрипт поддерживает
`--windows-exe PATH --require-windows`. Этот режим требует актуальный
`release/VERIFIED_WINDOWS_BUILD.json`; устаревший манифест прежней сборки
в репозиторий не включён.

Манифест должен содержать:

- `product_version` — версия продукта из `include/app_info.h`;
- `report_schema_version` — версия схемы полного отчёта из того же файла;
- `sha256` — SHA-256 именно проверенного Windows EXE;
- `source_evidence` — путь к каталогу отчётов относительно корня проекта;
- `release_status` — путь к описанию выполненных проверок относительно корня.

После проверки EXE создаются `*-windows-x64.zip` и `*-evidence.zip`.
Без подходящего манифеста обычный запуск создаёт архив исходников,
а `--require-windows` завершается ошибкой. Он не подтверждает качество
программы автоматически: перед подготовкой манифеста выполните CTest и
[Windows dynamic smoke tests](windows_dynamic_validation.md) на этой сборке.

Готовый нативный CPack ZIP можно добавить к контрольным суммам:

```sh
python scripts/create_release_bundles.py --native-package PATH_TO_CPACK_ZIP
```

Не включайте в релиз сторонние корпуса без проверки условий их распространения.
