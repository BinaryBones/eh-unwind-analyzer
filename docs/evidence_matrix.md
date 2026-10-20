# Evidence matrix for heuristic anomaly assessment

This document freezes the **engineering evidence matrix** used by the current heuristic anomaly assessment implementation.  
The goal is not to claim mathematical optimality, but to make the heuristic logic **explicit, reviewable and stable** for reverse-engineering work and for the thesis.

## 1. Core concepts

- **score_weight_sum** — arithmetic sum of the base weights of all active findings before the upper limit is applied.
- **score** — bounded triage score calculated as `min(score_weight_sum, 100)`.
- **suspicion** — normalized `score / 100`.
- **confidence** — confidence in the interpretation of the static verdict; this is **not** a statistical probability.
- **finding** — structured signal with `code`, `family`, `severity`, `message`.
- **mitigation / weakening rule** — rule that lowers confidence when the evidence is isolated, sample size is tiny, or a benign explanation is plausible.
- **case strength** — final static/dynamic class used by the JSON `assessment` block.

## 2. Evidence families

| Family | Meaning |
|---|---|
| `table_integrity` | Damage or inconsistencies in `RUNTIME_FUNCTION` layout itself |
| `unwind_integrity` | Damage or anomalies in `UNWIND_INFO` parsing / structure |
| `metadata_placement` | Unwind / handler metadata placed in suspicious sections |
| `unwind_reuse` | Too many functions share the same `UnwindInfoRVA` |
| `handler_dominance` | A single handler target dominates too many functions |

## 3. Static findings matrix

| Finding code | Family | Severity rule | Base weight | Confidence effect | Mitigations that can weaken it |
|---|---|---:|---:|---|---|
| `pe_section_raw_oob` | `table_integrity` | `high` | `+25` | strong malformed-file signal | none |
| `pe_section_virtual_oob` | `table_integrity` | `high` | `+20` | strong image-layout signal | none |
| `pe_section_raw_overlap` | `table_integrity` | `medium` | `+15` | contributes through family and medium count | `small_sample_size` only when otherwise isolated |
| `pe_section_virtual_overlap` | `table_integrity` | `high` | `+20` | strong ambiguous-mapping signal | none |
| `pe_section_misaligned` | `table_integrity` | `medium` | `+8` | weak-to-medium structural signal | single-family mitigations may apply |
| `pe_exception_directory_oob` | `table_integrity` | `high` | `+25` | strong exception-directory integrity signal | none |
| `no_runtime_functions` | `table_integrity` | `medium` | `+10` | weak standalone signal because a leaf-only image may legitimately have no entries | `single_signal_only`, `small_sample_size`, `single_family_only` |
| `invalid_ranges` | `table_integrity` | `medium` if `<=1%`, else `high` | `+10 / +20` | `+0.08` via hard table-integrity bonus | `small_sample_size` (only if isolated and non-strong) |
| `rf_oob` | `table_integrity` | `medium` if `<=1%`, else `high` | `+10 / +25` | `+0.08` via hard table-integrity bonus | `small_sample_size` (only if isolated and non-strong) |
| `unwind_rva_oob` | `table_integrity` | `medium` if `<=1%`, else `high` | `+10 / +25` | `+0.08` via hard table-integrity bonus | `small_sample_size` (only if isolated and non-strong) |
| `rf_unsorted` | `table_integrity` | `medium` | `+15` | contributes through family count and medium count | `small_sample_size`, `single_family_only` when isolated |
| `rf_overlaps` | `table_integrity` | `high` | `+25` | `+0.08` via hard table-integrity bonus | none |
| `duplicate_begin` | `table_integrity` | `medium` | `+10` | contributes through family count and medium count | `small_sample_size`, `single_family_only` when isolated |
| `unwind_parse_fail` | `unwind_integrity` | `medium` if `<=1%`, else `high` | `+10 / +25` | `+0.08` via hard unwind-integrity bonus | `small_sample_size` (only if isolated and non-strong) |
| `unwind_anomalies` | `unwind_integrity` | `medium` if `<=5%`, else `high` | `+10 / +20` | `+0.08` via hard unwind-integrity bonus | `small_sample_size` (only if isolated and non-strong) |
| `unwind_reuse_moderate` | `unwind_reuse` | `medium` | `+10` | emitted only when another static signal corroborates moderate reuse | `single_family_only` if remaining evidence is weak |
| `unwind_reuse_strong` | `unwind_reuse` | `high` | `+20` | contributes through family count and strong count | usually not weakened |
| `handler_dominance` | `handler_dominance` | `medium` | `+15` | normal executable runtime handlers require corroborating static context | `single_family_only` if remaining evidence is weak |
| `unwind_in_exec_section` | `metadata_placement` | `high` | `+20` | contributes through family count and strong count | no placement-only mitigation |
| `unwind_unusual_section` | `metadata_placement` | `medium` if `<=5%`, else `high` | `+8 / +15` | contributes through family count and medium/strong count | `placement_only_signal`, `single_signal_only`, `small_sample_size`, `single_family_only` |
| `unwind_writable_section` | `metadata_placement` | `medium` if `<=5%`, else `high` | `+10 / +18` | writable unwind metadata is stronger than merely unusual placement | `single_signal_only`, `small_sample_size`, `single_family_only` when isolated |
| `handler_nonexec_section` | `metadata_placement` | `high` | `+15` | contributes through family count and strong count | usually not weakened |
| `handler_writable_section` | `metadata_placement` | `medium` | `+10` | writable handler target is suspicious, especially when paired with other placement signals | `single_family_only` when isolated |
| `placement_exec_nonexec_handler_combo` | `metadata_placement` | `high` | `+10` | raises confidence through extra strong evidence when both placement sides are suspicious | none |
| `placement_integrity_combo` | `unwind_integrity` | `medium` | `+8` | corroborates placement with structural unwind damage | `single_family_only` only if the rest of the sample stays weak |
| `reuse_dominance_combo` | `unwind_reuse` | `medium` | `+8` | corroborates centralized metadata reuse with a dominant handler target | `single_family_only` if isolated |
| `writable_metadata_handler_combo` | `metadata_placement` | `high` | `+10` | writable unwind metadata and writable handler targets reinforce each other | none |

`no_strong_static_anomalies` is now emitted as an informational note in `details`, not as a structured finding.

## 4. Confidence model

The static confidence model is intentionally simple and reviewable.

### Base bonuses

- base = `0.15`
- if `score == 0`, use `0.20` before penalties
- per evidence family = `+0.11`
- per strong finding (`high`/`critical`) = `+0.08`
- per medium finding = `+0.04`
- any hard table-integrity issue = `+0.08`
- any hard unwind-integrity issue = `+0.08`

### Weakening rules

| Code | Trigger | Confidence penalty |
|---|---|---:|
| `single_signal_only` | exactly one non-strong finding | `-0.12` |
| `small_sample_size` | `<32` functions, findings exist, but no strong finding | `-0.06` |
| `placement_only_signal` | only unusual placement signal without exec/non-exec/parse/range damage | `-0.10` |
| `single_family_only` | no strong finding and evidence comes from one family only | `-0.08` |

### Clamp

Final static confidence is clamped to `0.05 .. 0.90`.

## 5. Evidence level rules

### Static evidence level

- `strong` — `strong_count >= 2` **or** `score >= 70`
- `medium` — `strong_count >= 1` **or** `medium_count >= 2` **or** `score >= 30`
- `weak` — any finding exists or `score > 0`, but the above rules are not met
- `none` — no findings and `score == 0`

### Runtime evidence level

- `strong` — runtime handler hit and at least one extra medium runtime signal
- `medium` — handler hit **or** at least two medium runtime signals
- `weak` — only weak runtime activity (e.g. first-chance only, registrations only)
- `none` — no runtime activity recorded

An incomplete session (`ok == false`, timeout, or no natural target exit) keeps
its raw events, but its runtime evidence level is capped at `weak`. Incomplete
sessions cannot establish static/dynamic correlation and do not increase final
confidence.

### Strict ABI diagnostics

`--strict-abi` records formal Microsoft x64 unwind ABI deviations separately as
`unwind_abi_warnings`. These diagnostics remain visible per function, but do
not by themselves increase suspicion score, evidence level, verdict or
confidence because compatible production toolchains frequently emit such
records.

## 6. Final case rules

| Case strength | Rule |
|---|---|
| `strong_correlated_case` | static/dynamic correlation present and either static or runtime evidence is `strong` |
| `medium_correlated_case` | static/dynamic correlation present and either side is `medium` |
| `strong_unconfirmed_case` | strong static or runtime evidence without cross-layer correlation |
| `medium_case` | medium static or runtime evidence |
| `weak_case` | weak static or runtime evidence only |
| `no_case` | no meaningful evidence |

## 7. Correlation rules

Current cross-layer correlation is intentionally conservative and only returns `true` when:

1. suspicious static handler-related evidence exists (`handler_dominance`, writable/non-exec handler placement, similar handler-focused findings) **and** runtime handler/VEH/VCH/UEF hits are seen, or
2. static placement anomalies exist **and** runtime dynamic function-table activity is seen.

This is a **coarse correlation layer**, not a per-function proof graph.

## 8. Manual review policy

`requires_manual_review = true` when any of the following is true:

- `score >= 20`
- unwind metadata is in executable sections
- unwind metadata is in writable sections
- handler target is in non-executable / unknown section
- handler target is in writable sections
- `UNWIND_INFO` parse failures exist
- any mitigation rule was applied

The JSON report always emits `manual_validation_steps` so an analyst can continue in Ghidra / PE viewers / a Windows debugger.

## 9. What this matrix claims — and what it does not

This matrix claims:
- stable, reviewable engineering rules;
- non-flat reporting (`findings`, `families`, `mitigations`, `assessment`);
- explicit separation of suspiciousness and confidence.

This matrix does **not** claim:
- calibrated statistical probability;
- universal thresholds for every compiler/runtime/interceptor family;
- complete runtime reconstruction of dynamic function tables.


For a reproducible threshold-sweep workflow, see `docs/threshold_calibration.md`.
