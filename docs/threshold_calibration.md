# Threshold calibration notes

This project now ships with a small reproducible **threshold-sweep scaffold** instead of claiming fake statistical calibration.

## What is calibrated today

Current defaults in `src/heuristics.c` are still **engineering defaults**.
They are not presented as universal probabilities.

## What was added

- context-sensitive weakening for `handler_dominance`
- suppression of moderate unwind reuse unless another static signal corroborates it
- suppression of empty `.pdata` findings for images with no executable sections
- broader benign placement recognition for xdata/pdata/rdata-like non-exec sections
- explicit writable-section placement checks for unwind metadata and handler targets
- combined-signal bonuses for correlated static evidence
- a reproducible script `tests/score_sweep.py` to inspect how score/verdict move across a sample corpus

## Minimal workflow for the thesis

1. Build the tool.
2. Run `tests/run_regression_samples.py` to confirm the baseline samples still behave correctly.
3. Extend `tests/samples/manifest.json` with additional benign/protected samples.
4. Run `tests/score_sweep.py <tool>` and record:
   - per-sample score
   - verdict
   - evidence level
   - which findings triggered
5. Compare 2-3 threshold variants and justify the chosen defaults in the thesis.

## What this document does **not** claim

- that the current defaults are statistically optimal;
- that the bundled sample set is large enough for final ROC-quality evaluation.

That larger benchmark remains future work, but the project now contains a reproducible path to perform it.
