# Architecture

## Data Flow

```text
input bytes
  -> PE parser and structural validation
  -> exception directory / RUNTIME_FUNCTION reader
  -> UNWIND_INFO decoder
  -> heuristic assessment
  -> optional Windows dynamic collector
  -> console / CSV / JSON / HTML / Ghidra CSV
```

## Modules

| Module | Responsibility |
|---|---|
| `util.c` | Bounds-safe byte reads, string builder, SHA-256, file I/O |
| `pe.c` | PE32+ AMD64 headers, sections, RVA mapping and structure counters |
| `unwind.c` | Runtime-function table and x64 `UNWIND_INFO` decoding |
| `heuristics.c` | Findings, score, confidence, mitigations and verdict |
| `dynamic_win.c` | Windows Debug API session, breakpoints and event capture |
| `report.c` | Console, CSV, JSON and HTML serialization |
| `app_info.c` | Product, schema, compiler, platform and timestamp metadata |
| `main.c` | CLI validation, orchestration, ownership and exit status |

## Ownership

- `buf_init_from_file` allocates input bytes; `buf_free_owned` releases them.
- `pe_parse` owns `PeImage.sections`; `pe_free` releases them.
- `unwind_read_runtime_functions` returns a heap array owned by the caller.
- `heuristics_analyze` owns an internal `StrBuf`; `heuristics_free` releases it.
- `dynamic_report_init` owns `details`; `dynamic_report_free` releases it.
- Report writers borrow all model objects and do not retain pointers.

Every early failure path in `main.c` releases objects already constructed.
Sanitizer and mutation tests exercise malformed inputs through these paths.

## Trust Boundaries

- Static mode treats the input as untrusted bytes and performs no code
  execution.
- Dynamic mode crosses the execution boundary and starts the input as a child
  process under a debugger.
- JSON and HTML serializers require complete report metadata, reject invalid
  model bounds and escape arbitrary metadata bytes.
- CSV, JSON and HTML writers use temporary sibling files and atomic replacement
  so an interrupted write does not destroy an earlier report.
- HTML has no remote scripts, styles, fonts or network requests and carries a
  restrictive offline Content Security Policy.
- Test validators apply both JSON Schema and computed cross-field invariants.
- Ghidra CSV is treated as untrusted input by the importer.

## Extension Points

- Add architecture-specific parsers behind a separate model rather than
  weakening AMD64 assumptions in `pe.c`/`unwind.c`.
- Add new heuristic signals as structured findings and document their weights
  in `docs/evidence_matrix.md`.
- Add report fields only with a schema version decision and corresponding
  unit/schema tests.
- Add dynamic API hooks as breakpoint role bits plus structured events.
