# Regression Samples

The repository contains six small reproducible PE32+ AMD64 samples:

| Sample | Purpose |
|---|---|
| `benign_minimal.exe` | Clean minimal unwind table |
| `benign_richer.exe` | Clean table with multiple functions |
| `suspicious_unwind_oob.exe` | Out-of-bounds `UnwindInfoRVA` |
| `suspicious_unwind_writable.exe` | Unwind metadata in writable section |
| `suspicious_section_raw_oob.exe` | Section raw range exceeds the file |
| `suspicious_eh_unwind_tamper.exe` | Writable metadata plus suspicious handler placement |

Rebuild:

```sh
python3 tests/samples/build_samples.py
```

The builder uses Clang + `lld-link` when available, then MinGW-w64, and keeps
the checked-in samples when neither Windows cross-toolchain exists.

Run:

```sh
python3 tests/run_regression_samples.py build/release/eh_unwind_analyzer
```

The runner performs a static smoke run, generates a heuristic JSON report,
validates it against `docs/report.schema.json` and checks the expected labeled
outcomes in `manifest.json`.
