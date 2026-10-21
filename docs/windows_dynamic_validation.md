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
cmake -S . -B build\mingw -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
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
| UEF | Registration plus a handler hit, or the fixture's second-chance exception and matching exit code |
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

Under a debugger, Windows can deliver the unhandled exception directly to the
debugger without calling the registered UEF. The validator accepts this only
when registration is observed, a second-chance `0xE0000003` event is recorded,
and the process exits with that exact fixture exception code. This accounts
for MSVC/MinGW runtime differences; a missing hit alone is not a passing result.
See [Microsoft's UnhandledExceptionFilter contract](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter).

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

## Evidence And CI

The Windows MSVC job in GitHub Actions builds the synthetic smoke targets,
runs all four scenarios and uploads their JSON reports and console logs.
Check the workflow run for the commit being delivered. Local smoke results
are written under `tests/` and are excluded from Git.

To validate reports from a separate corpus run, provide their directory and
the matching report schema explicitly:

```sh
python3 tests/validate_dynamic_corpus_evidence.py \
  --evidence path/to/evidence/full \
  --schema path/to/matching/report.schema.json \
  --synthetic-root "бинарники на тестирование/бинарники" \
  --real-root real_samples/inbox
```
