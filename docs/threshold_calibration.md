# Heuristic threshold evaluation

The defaults in `src/heuristics.c` are engineering rules, not calibrated
probabilities. Their weights, contextual weakening and verdict rules are
documented in [the evidence matrix](evidence_matrix.md).

`tests/score_sweep.py` collects scores, verdicts, evidence levels and findings
for the labeled samples in `tests/samples/manifest.json`:

```sh
python tests/run_regression_samples.py build/release/eh_unwind_analyzer
python tests/score_sweep.py build/release/eh_unwind_analyzer
```

On Windows, append `.exe` to the analyzer path. To compare threshold changes,
run the same labeled corpus before and after changing the rules, and compare
the collected output. The script evaluates the current build; it does not
automatically search for optimal thresholds.

The six baseline samples check expected behavior but are too small for
statistical calibration. A broader, independently labeled benchmark is needed
before making claims about detection rates or false-positive rates.
