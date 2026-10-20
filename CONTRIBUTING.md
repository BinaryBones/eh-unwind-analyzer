# Contributing

## Build And Test

Install the test tools:

```sh
python3 -m pip install -r requirements-dev.txt
```

Before submitting a change:

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release

cmake --preset sanitize
cmake --build --preset sanitize
ctest --preset sanitize
```

Parser/report changes should also pass:

```sh
python3 tests/run_mutation_fuzz.py build/release/eh_unwind_analyzer --cases 500
```

## Engineering Rules

- Keep the parser independent from Windows headers.
- Use checked arithmetic and `Buf` helpers for untrusted offsets.
- Preserve precise parse errors instead of returning a generic failure.
- Add a focused unit test for each bug fix.
- Update `docs/report.schema.json` only together with serializer tests and an
  explicit schema-version decision.
- Document new heuristic weights and benign explanations.
- Do not weaken dynamic timeouts or execute samples in ordinary CI runners
  outside the dedicated Windows smoke jobs.

## Formatting

The project uses C17, four-space indentation and warning-clean builds. Keep
comments concise and explain invariants rather than restating code.
