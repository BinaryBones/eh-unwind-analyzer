# EH/Unwind Analyzer

EH/Unwind Analyzer is a defensive analysis tool for Windows PE32+ AMD64
exception and stack-unwind metadata. It parses `.pdata` / `RUNTIME_FUNCTION`,
decodes x64 `UNWIND_INFO`, evaluates structural anomalies, produces
machine-readable and analyst-friendly reports, and can collect runtime
exception evidence through the Windows Debug API.

Current release: **1.0.0**. Static analysis is cross-platform. Dynamic
validation is Windows x64 only.

The analyzer is implemented in **C17**. Python is used for test fixtures,
report validation, regression tests, the Ghidra importer and release packaging.

## What It Does

### Static analysis

- validates PE headers, section ranges, alignments, overlaps and exception
  directory placement;
- reads all `RUNTIME_FUNCTION` records as half-open ranges
  `[BeginAddress, EndAddress)`;
- decodes x64 `UNWIND_INFO` versions 1 and 2, including V2 epilog descriptors,
  unwind operations, frame register, fixed stack allocation, handlers and
  chained records;
- detects malformed ranges, out-of-bounds RVAs, invalid tails, chain problems,
  suspicious metadata permissions and reuse patterns;
- preserves the exact parse failure reason per function.

### Heuristic assessment

`--heuristics` emits:

- uncapped sum of active finding weights (`score_weight_sum`);
- bounded triage score `score = min(score_weight_sum, 100)`;
- explicit verdict and evidence level;
- structured findings with code, severity, family, affected count and a
  representative RVA/section;
- confidence and weakening rules;
- manual validation steps;
- static/dynamic correlation when runtime evidence is available.

The score is a transparent triage aid, not a statistical probability or proof
of a particular protector. The rules are documented in
[`docs/evidence_matrix.md`](docs/evidence_matrix.md).

### Windows dynamic validation

`--dynamic` starts the target under the Windows Debug API and records:

- first- and second-chance exceptions;
- hits of handlers referenced by static `UNWIND_INFO`;
- VEH, VCH and UEF registration and handler hits;
- calls to `RtlAddFunctionTable` and
  `RtlInstallFunctionTableCallback`, including captured arguments;
- a bounded RIP trace after a handler hit;
- target exit status, timeout state and a structured event timeline.
- instrumentation-completeness counters for modules, breakpoints, re-arming
  and dropped events.

Dynamic mode **executes the analyzed file**. Use an isolated VM for untrusted
samples; see [`SECURITY.md`](SECURITY.md).

## Reports

Outputs can be combined in one run:

| Option | Output |
|---|---|
| `--json report.json` | Versioned full report with SHA-256, build provenance and assessment |
| `--html report.html` | Self-contained interactive dashboard, no network assets |
| `--csv functions.csv` | Flat function/unwind table |
| `--ghidra-csv ghidra.csv` | Function ranges and comments for the bundled Ghidra importer |

JSON reports follow
[`docs/report.schema.json`](docs/report.schema.json). Regression and Windows
smoke tests additionally verify cross-field semantic invariants such as
function sizes, counters and final-assessment consistency. Target arguments
after `--` are redacted from report metadata.

## Quick Start

Requirements:

- CMake 3.25 or newer for the included presets (3.23 for manual configuration);
- a C17 compiler;
- Ninja for the included presets;
- Python 3 plus `requirements-dev.txt` for the full test suite.

```sh
python3 -m pip install -r requirements-dev.txt
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The executable is:

```text
build/release/eh_unwind_analyzer
```

On Windows, Visual Studio 2022 and MinGW-w64 are supported. The convenience
scripts `build_msvc.bat` and `build_mingw.bat` produce
`build\msvc-local\eh_unwind_analyzer.exe` and
`build\mingw-local\eh_unwind_analyzer.exe`.

## Usage

```sh
eh_unwind_analyzer target.exe
eh_unwind_analyzer target.exe --dump --limit 100 --ops
eh_unwind_analyzer target.exe --heuristics \
  --json report.json --html report.html --csv functions.csv
eh_unwind_analyzer target.exe --heuristics --strict-abi --json strict.json
eh_unwind_analyzer target.exe --ghidra-csv ghidra_unwind.csv
```

`--strict-abi` adds formal Microsoft x64 unwind ABI diagnostics without
changing the default compatibility mode or treating strict-only warnings as a
suspicion score.

Windows dynamic run:

```bat
eh_unwind_analyzer.exe target.exe --heuristics --dynamic ^
  --timeout-ms 15000 --trace-steps 64 ^
  --json report.json --html report.html
```

Pass arguments to the target after `--`:

```bat
eh_unwind_analyzer.exe target.exe --dynamic -- --input sample.dat
```

Important options:

| Option | Meaning |
|---|---|
| `--dump` | Print runtime-function records |
| `--limit N` | Limit dumped records |
| `--ops` | Include decoded unwind operations |
| `--heuristics` | Run anomaly assessment |
| `--no-follow-chain` | Do not recursively follow chained unwind records |
| `--max-chain-depth N` | Chain depth limit, `1..16` |
| `--dynamic` | Run Windows-only runtime validation |
| `--timeout-ms N` | Hard dynamic timeout |
| `--trace-steps N` | RIP samples after handler hit, `0..256` |
| `--version` | Print tool, schema and build versions |

Exit codes:

- `0`: requested analysis and outputs completed;
- `1`: input, analysis, dynamic session or output failure;
- `2`: invalid command line.

## Ghidra

1. Generate the import file:

   ```sh
   eh_unwind_analyzer target.exe --ghidra-csv ghidra_unwind.csv
   ```

2. Add the repository `ghidra/` directory in Ghidra Script Manager.
3. Run `import_unwind_csv.py`.

The importer uses a transaction, validates columns and address ranges, skips
overlapping functions, preserves user/imported names, merges tagged comments
and creates warning bookmarks for parse failures or anomalies.

## Verification Profiles

```sh
# Debug
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

# AddressSanitizer + UndefinedBehaviorSanitizer
cmake --preset sanitize
cmake --build --preset sanitize
ctest --preset sanitize

# Coverage instrumentation
cmake --preset coverage
cmake --build --preset coverage
ctest --preset coverage

# Package
cmake --preset release
cmake --build --preset release
cpack --preset release
```

To create the current source bundle, use:

```sh
python3 scripts/create_release_bundles.py
```

Windows and validation-evidence bundles are emitted only when the verified
manifest matches the current product and report schema versions and the
verified executable is available. A final Windows delivery should
use `--require-windows`; this fails closed instead of packaging a stale EXE.
The script excludes local build/cache metadata and writes reproducible ZIP
files plus versioned checksums to `release-output/`. See
[`docs/DELIVERY_RU.md`](docs/DELIVERY_RU.md).

The normal CTest run includes 19 tests: unit tests, six PE regression samples,
JSON Schema and semantic report validation, dynamic-report validator tests and
120 deterministic parser mutations. It also checks release metadata and
repository hygiene. CI additionally builds with MSVC and MinGW, runs four
Windows dynamic smoke scenarios, generates coverage artifacts and executes a
bounded Clang libFuzzer campaign.

## Project Layout

- `src/`, `include/`: parser, heuristics, reporting and dynamic collector;
- `tests/unit/`: cross-platform unit tests;
- `tests/samples/`: reproducible PE32+ regression corpus;
- `tests/fuzz/`: libFuzzer entry point;
- `ghidra/`: conservative CSV importer;
- `docs/`: architecture, evidence model, schema and Windows validation;
- `.github/workflows/ci.yml`: release, sanitizer, coverage, Windows and fuzz
gates.

An optional real-world compatibility runner is also included. It validates
reports against the JSON Schema and semantic invariants without executing any
sample:

```sh
python3 tests/run_real_corpus.py \
  build/release/eh_unwind_analyzer real_samples/inbox real_samples/reports
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for data flow and ownership
boundaries, and [`docs/PRODUCT_READINESS.md`](docs/PRODUCT_READINESS.md) for
the release checklist.

## Scope And Limits

- Input is PE32+ for AMD64; PE32/x86, ARM64 and ELF/Mach-O are rejected.
- The Intel APX `UNWIND_INFO` V3 preview format is reported as unsupported;
  it is structurally different from V1/V2.
- Static mode does not execute or disassemble `.text`.
- Fixed stack size is derived from unwind operations and does not include
  runtime-sized allocations such as `alloca`.
- Runtime evidence is bounded and observational; it is not a complete trace or
  a malware sandbox.
- Dynamic validation is unavailable on Linux and macOS.

## License

MIT, see [`LICENSE`](LICENSE).

