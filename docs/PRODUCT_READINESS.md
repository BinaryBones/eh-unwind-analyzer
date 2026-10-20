# Product Readiness

## Current State

The codebase is at `1.0.0`. The current full-report schema is `1.3.0`.
The repository contains source code, build configuration, technical documentation
and synthetic test fixtures. Build products and local validation reports are
excluded from Git.

## Verification

A fresh checkout must pass all **19 CTest tests** with warnings treated as errors.
These cover the parser, heuristics, JSON/HTML output, CLI contract, unsupported
architectures, invalid inputs, six labeled PE samples and 120 deterministic
parser mutations.

```sh
python3 -m pip install -r requirements-dev.txt
cmake --preset release
cmake --build --preset release
ctest --preset release
```

GitHub Actions runs seven jobs: Ubuntu Release, ASan/UBSan, coverage, macOS
Release, Windows MSVC with four dynamic smoke scenarios, Windows MinGW UCRT64,
and Linux Clang libFuzzer. Check the result for the exact commit being delivered:
[repository CI](https://github.com/BinaryBones/eh-unwind-analyzer/actions/workflows/ci.yml).
A local test run does not replace these platform-specific checks.

The additional 84-file synthetic corpus is described in
`бинарники на тестирование/manifest_extended.json`. It includes malformed inputs
that must be rejected cleanly as well as Windows dynamic scenarios. Third-party
real-world samples are optional local inputs and are not redistributed.

## Packaging

`python3 scripts/create_release_bundles.py` creates a source ZIP.
`cpack --preset release` packages the executable built on the current platform.

The manifest in `release/VERIFIED_WINDOWS_BUILD.json` and its linked release
status document describe the historical June 19, 2026 build using schema `1.1.0`.
They are not evidence for the current `1.3.0` schema. The packaging script
therefore skips the historical Windows/evidence bundles; `--require-windows`
fails until a newly verified executable and matching manifest are supplied.
See `docs/DELIVERY_RU.md` for the delivery procedure.

## Known Boundaries

- Static analysis supports PE32+ AMD64 and does not execute the input.
- Dynamic analysis requires Windows x64 and executes the input. Use an isolated
  VM for untrusted files; the debugger is not a malware sandbox.
- DLL/PYD inputs require a host process and cannot be launched directly.
- Heuristic scores are triage signals, not calibrated probabilities.
- Static analysis does not compare unwind operations with disassembled machine
  instructions.
