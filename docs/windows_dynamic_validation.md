# Windows Dynamic Validation

This checklist verifies the Windows-only `--dynamic` collector on the final
build. Run untrusted targets only in an isolated VM.

## Build

MSVC, from an x64 Native Tools prompt:

```bat
cmake -S . -B build\msvc -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON
cmake --build build\msvc --config Release --parallel
ctest --test-dir build\msvc -C Release --output-on-failure
cd tests
build_tests_msvc.bat
cd ..
```

MinGW-w64:

```bat
cmake -S . -B build\mingw -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build\mingw --parallel
ctest --test-dir build\mingw --output-on-failure
cd tests
build_tests_mingw.bat
cd ..
```

## Automated Smoke Pack

MSVC:

```bat
tests\run_dynamic_smoke_windows.bat build\msvc\Release\eh_unwind_analyzer.exe
```

MinGW:

```bat
tests\run_dynamic_smoke_windows.bat build\mingw\eh_unwind_analyzer.exe
```

The script runs four scenarios:

| Scenario | Required evidence |
|---|---|
| VEH | `veh_registrations > 0`, `veh_hits > 0`, exception events |
| UEF | `uef_set_calls > 0`, `uef_hits > 0`, exception events |
| VCH | `vch_registrations > 0`, `vch_hits > 0` |
| Runtime tables | both runtime function-table APIs observed |

Every report must also satisfy:

- `enabled == true`;
- `ran == true`;
- `ok == true`;
- `timed_out == false`;
- `target_exited == true`;
- a non-empty structured event list;
- `docs/report.schema.json`.

The script writes `tests/*_dynamic_report.json` and
`tests/*_dynamic_console.txt`.

## Manual Checks

Inspect each JSON report for:

- API argument events with expected table/handler addresses;
- first- and second-chance exception counts;
- module names and thread IDs;
- no dropped events;
- target exit code;
- trace samples when a handler breakpoint was hit;
- reasonable static/dynamic correlation in `assessment`.

Timeout, context access, breakpoint re-arm or process continuation failures
must produce a non-zero tool exit code and `dynamic_validation.ok == false`.

## Current Evidence

The current MinGW-w64 release-candidate evidence was collected on
**June 8, 2026** from the final dynamic collector revision:

- analyzer SHA-256:
  `489e7571827693cd555c1958f9aec7694d1de717f896d33ecfebe8f13e843624`;
- 124/124 reports passed JSON Schema and semantic validation;
- 86 dynamic sessions started;
- all four VEH, VCH, UEF and runtime function-table smoke scenarios passed;
- no dynamic events were dropped;
- the configured 32-address trace budget was respected;
- controlled timeout cases returned within the documented cleanup window.

The complete evidence set is stored in
`reports/dynamic_validation_2026-06-08/`. The machine-readable summary is
`full/results.json`; the human-readable reports are `full/REPORT.md` and
`FINAL_REPORT_RU.docx`.

The archived evidence can be revalidated without executing any target:

```sh
python3 tests/validate_dynamic_corpus_evidence.py \
  --synthetic-root "бинарники на тестирование/бинарники" \
  --real-root real_samples/inbox
```

The June evidence covers MinGW-w64 on Windows x64. The MSVC job remains an
independent compiler gate in CI and must pass for a final multi-toolchain
release.
