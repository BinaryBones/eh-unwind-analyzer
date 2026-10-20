# Unit Tests

Preferred execution:

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The local Makefile remains available for GCC/Clang:

```sh
cd tests/unit
make clean
make run
```

Coverage:

- `unit_unwind`: decoding, ordering, flags, operands and chain errors;
- `unit_heuristics`: score, placement, verdict and confidence;
- `unit_heuristics_mitigations`: all weakening rules;
- `unit_heuristics_context`: benign context and writable placement;
- `unit_heuristics_combos`: corroborating signal combinations;
- `unit_core_edges`: empty tables, overflow, mapping and nested overlaps;
- `unit_report_json`: complete static/dynamic serialization and UTF-8 safety;
- `unit_report_html`: HTML escaping, dashboard sections and filter script;
- `unit_matrix_report`: final verdict, case strength and correlation.

CTest also runs the PE regression corpus, dynamic validator tests and
deterministic mutation fuzzing.
