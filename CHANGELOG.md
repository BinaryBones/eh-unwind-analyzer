# Changelog

## 1.0.0 - 2026-06-19

### Changed

- Promoted the validated Windows release line from `1.0.0-rc2` to stable
  `1.0.0`.
- Added final Windows x64 investor-readiness evidence for MSVC, MinGW-w64,
  static corpus, dynamic smoke, full dynamic corpus, report validation and
  release packaging.

### Fixed

- Windows report metadata now preserves Cyrillic display paths as UTF-8 in
  JSON and HTML outputs.

## 1.0.0-rc2 - 2026-06-15

### Added

- Optional `--strict-abi` diagnostics separated from suspicion scoring.
- Dynamic instrumentation-completeness metrics for module discovery,
  breakpoints, re-arming and dropped events.
- Structured report metadata for unwind analysis options.
- Partial structural JSON/HTML reporting for malformed, unreadable or
  out-of-bounds exception directories.

### Changed

- Report schema advanced to `1.1.0`.
- Dynamic evidence from failed, timed-out or incomplete instrumentation is
  capped at weak and cannot increase final confidence or establish
  correlation.
- PE alignment validation now covers header-level alignment invariants,
  `SizeOfHeaders`, `SizeOfImage`, image base and raw section sizes.

### Fixed

- Invalid exception-directory placement is no longer lost before heuristic
  reporting.
- Strict ABI compatibility observations no longer create false suspicious
  scores on benign production binaries.
- Reuse-count allocation failures are propagated instead of silently
  undercounting.
- Release hygiene now passes without macOS metadata or Python cache files.
- Release bundling fails closed for a stale Windows manifest and can still
  create current source/native packages without mislabeling old evidence.

## 1.0.0-rc1 - 2026-06-08

### Added

- CMake presets for Debug, Release, ASan/UBSan and coverage builds.
- Cross-platform unit tests, six PE32+ regression samples and deterministic
  mutation testing.
- Clang libFuzzer harness and a bounded fuzz campaign in CI.
- Versioned JSON report metadata with UTC time, SHA-256, input size, command
  provenance and build information.
- Strict JSON Schema for all static, dynamic, assessment and function fields.
- Cross-field semantic report validator with negative mutation tests.
- Release metadata consistency test across CMake, CPack, headers, schema and
  documentation.
- Self-contained interactive HTML report.
- Structured dynamic event timeline with target exit and timeout state.
- VEH, VCH, UEF and runtime function-table Windows smoke targets.
- Conservative transactional Ghidra importer.
- MSVC, MinGW, Linux, macOS, sanitizer, coverage and fuzz CI jobs.
- ZIP packaging through CPack.
- Reproducible real-world corpus runner with JSON Schema and semantic report
  validation.

### Changed

- Heuristic output now exposes structured findings, evidence families,
  weakening rules, confidence, case strength and manual validation steps.
- PE validation now reports raw/virtual out-of-bounds sections, overlaps,
  alignment defects and exception-directory bounds.
- Dynamic breakpoints can carry multiple roles and capture API arguments.
- Target arguments are redacted from report metadata.
- JSON and HTML export now requires complete versioned report metadata.
- Moderate unwind reuse and normal runtime-handler dominance now require
  corroborating static evidence before affecting the score.

### Fixed

- Strict CLI validation and reliable exit codes.
- Header RVA mapping and overflow-safe PE range arithmetic.
- Nested `RUNTIME_FUNCTION` overlap detection.
- Truncated/invalid handler and chain tails, frame-register checks and unwind
  allocation encoding validation.
- Windows command-line quoting, breakpoint re-arming and debug-event
  continuation.
- CSV/JSON write failures and per-function parse diagnostics.
- String-buffer allocation failures now remain sticky and prevent partial
  JSON/HTML reports from being reported as successful.
- CSV, JSON and HTML reports are committed through atomic file replacement.
- Invalid UTF-8 bytes from malformed PE metadata are escaped in JSON and HTML.
- HTML reports include a restrictive offline Content Security Policy.
- Release tests keep assertions enabled.
- V2 epilog descriptors, chained frame/handler inheritance and real-world
  volatile-register/zero-offset unwind encodings are parsed without false
  structural anomalies.
- Resource-only and forwarding images without executable sections no longer
  receive a missing-`.pdata` finding.
- MinGW format checking now uses the GNU printf dialect.
- Windows trace collection respects the configured address budget and starts
  only once per dynamic session.
- Timeout cleanup drains pending debug events instead of adding a fixed
  five-second wait.
- Real-corpus discovery ignores macOS AppleDouble metadata files.
- CPack installation excludes AppleDouble, `.DS_Store` and Python cache files.

### Release note

The final MinGW-w64 Windows run and all four dynamic smoke scenarios passed on
June 8, 2026. This remains a release candidate until the independent MSVC CI
gate also passes on the release revision.
