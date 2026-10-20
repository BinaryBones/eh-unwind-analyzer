# Паспорт качества релиза 1.0.0

> Историческая проверка от 19 июня 2026 года для схемы отчёта `1.1.0`.
> Текущие исходники используют схему `1.3.0`; этот паспорт и связанный
> манифест не подтверждают готовность текущего Windows-бинарника.
> Текущие проверки описаны в `docs/PRODUCT_READINESS.md` и GitHub Actions.

Дата финальной проверки: 19 июня 2026 года.

Версия инструмента: `1.0.0`.
Версия формата отчета: `1.1.0`.

## Windows x64 artifact

```text
artifacts/windows-x64/eh_unwind_analyzer.exe
SHA-256 b1cee8678cdf21d96e2921625ffabc3d5c1be4d41cb022d4d0954ef3692df63a
Compiler MinGW-w64 GCC 13.2.0
```

## Подтвержденные gates

| Проверка | Результат |
|---|---:|
| MinGW-w64 Release build + CTest | 16/16 PASS |
| MSVC Release build + CTest | 16/16 PASS |
| Release metadata contract | PASS |
| Release hygiene | PASS |
| Static labeled corpus | 14/14 valid |
| Real benign corpus | 106/106 valid |
| Real benign corpus non-zero scores | 0 |
| Runtime functions parsed in real corpus | 174,795 |
| Dynamic smoke VEH/VCH/UEF/RtlFunctionTable | 4/4 PASS |
| Full Windows dynamic corpus | 124/124 valid reports |
| Full dynamic corpus unexpected failures | 0 |
| Dynamic reports with dropped events | 0 |

## Full dynamic corpus

| Outcome | Count |
|---|---:|
| completed | 54 |
| controlled_timeout | 32 |
| elevation_required | 8 |
| unsupported_library_launch | 30 |

Full dynamic corpus evidence:
`reports/final_validation_2026-06-19/dynamic_full`.

Dynamic evidence validator result:

```text
dynamic corpus evidence: OK reports=124 ran=86 completed=54 timeouts=32
```

## Static validation

The real benign corpus passed without false-positive scores:

```text
Files: 106
Valid reports: 106
Failed reports: 0
Files with non-zero heuristic score: 0
Runtime functions parsed: 174,795
```

The labeled static corpus confirms that the two benign samples stay at score 0
and all 12 anomalous samples are detected.

## Boundaries

- Dynamic mode executes the target and must be isolated for untrusted files.
- DLL/PYD inputs are not directly executable through `CreateProcess`; they are
  reported as `unsupported_library_launch`.
- Elevation-required EXE targets require a separate elevated validation run.
- The heuristic score is a triage signal, not a mathematical probability of
  maliciousness.
