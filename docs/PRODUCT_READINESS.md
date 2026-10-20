# Product Readiness

## Current State

The codebase is at `1.0.0`. Static analysis, dynamic collection, reports,
tests and packaging are productized for a presentation-ready Windows x64
release. Final local validation was completed on Windows x64 on June 19, 2026
with both MinGW-w64 GCC 13.2.0 and MSVC 19.44.35215.

| Area | Implemented | Verification |
|---|---|---|
| PE/UNWIND parser | Bounds, overflow, alignment, V1/V2 epilogs, chains, diagnostics | Unit tests, regression samples, mutation fuzzing, 106-file benign corpus |
| Heuristics | Findings, evidence matrix, mitigations, confidence, assessment | Unit tests, labeled static corpus, benign-corpus calibration |
| Dynamic collector | VEH/VCH/UEF, handlers, runtime function tables, completeness counters, timeout/exit events | 4/4 focused smoke, 124-input full Windows dynamic corpus |
| Reports | Console, CSV, Ghidra CSV, strict JSON, self-contained HTML | Schema validation, cross-field semantic validation, report unit tests |
| Build | MinGW-w64 and MSVC on Windows x64 | Release CTest 16/16 on both toolchains |
| Release | Version contract, manifest hash gate, clean ZIP bundles | Release metadata test, hygiene test, `--require-windows` packaging |

## Verified On This Revision

- MinGW-w64 Release CTest: 16/16 PASS.
- MSVC Release CTest: 16/16 PASS.
- Static labeled corpus: 14/14 valid reports; 2 benign samples scored 0,
  12 anomalous samples were flagged with low/moderate/high suspicion.
- Real benign corpus: 106/106 valid reports, 174,795 runtime functions parsed,
  zero failed reports and zero non-zero heuristic scores.
- Dynamic smoke: VEH, VCH, UEF and RtlFunctionTable scenarios passed 4/4 with
  schema/semantic-valid reports and zero dropped events.
- Full dynamic corpus: 124/124 schema/semantic-valid reports, 86 debug sessions
  started, 54 completed targets, 32 controlled timeouts, 8 elevation-required
  targets, 30 DLL/PYD CreateProcess rejections and 0 unexpected failures.
- Full dynamic corpus observed 344 exceptions, 136 unwind-handler hits,
  VEH/VCH/UEF activity and runtime function-table API calls.
- Windows report metadata preserves Cyrillic display paths as UTF-8 in JSON and
  HTML outputs.
- Release artifact:
  `artifacts/windows-x64/eh_unwind_analyzer.exe`.
- Release artifact SHA-256:
  `b1cee8678cdf21d96e2921625ffabc3d5c1be4d41cb022d4d0954ef3692df63a`.

## Release Gates

The final `1.0.0` Windows presentation gate is closed for the local evidence
set:

1. MinGW-w64 Release build and CTest: PASS.
2. MSVC Release build and CTest: PASS.
3. Static synthetic/labeled corpus validation: PASS.
4. Static real benign corpus validation: PASS.
5. VEH/VCH/UEF/RtlFunctionTable dynamic smoke: PASS.
6. Full Windows dynamic corpus rerun: PASS.
7. JSON Schema and semantic validation for generated reports: PASS.
8. Release hygiene and metadata consistency: PASS.
9. Windows artifact hash recorded in `release/VERIFIED_WINDOWS_BUILD.json`.

## Known Boundaries

- Dynamic mode executes the target and must be used in an isolated VM for
  untrusted files.
- DLL/PYD inputs cannot be directly launched through `CreateProcess`; the full
  corpus records them as `unsupported_library_launch` and keeps static reports
  valid.
- Some EXE targets require elevation before debugging; the corpus records them
  as `elevation_required` rather than unexpected failures.
- Heuristic confidence is engineering confidence, not calibrated probability.
- Static analysis does not compare unwind operations with disassembled machine
  instructions.
