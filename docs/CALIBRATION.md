# Score calibration (spec Appendix P): what was done, what it shows, what it does not

**Status: NOT CALIBRATED.** `score-v1` is unchanged and still provisional. Everything below produces *evidence* and a
*candidate* (`config/candidates/score-v1-candidate.json`, `status: candidate-not-approved`) for the scoring owner to
review. Do not enable policy blocking on either version.

## Why there is no "training"
The score is a fixed formula (`D = I × E × C × A`, `Score = 100(1 − e^(−D/K))`), not a learned model. "Calibrating" means
choosing its parameters from labeled evidence: **C** (confidence per rule, from measured precision) and **K** (the scale).
Impact, exposure and aging are not fitted from this corpus: they have no outcome data behind them.

## What was built
* `tests/corpus/`: 82 labeled cases in three cohorts. **4 independent** (copied byte-for-byte from `sample_projects/`,
  written separately from these detectors) and **78 synthetic**: positives in varied syntax, safe look-alikes (such as
  `model.eval()`, strings/comments, placeholders, `defusedxml`, ORM calls), and deliberately hard cases. Vulnerability lines
  are located by text, so labels cannot drift from the code.
  * `tuning`: cases that existed while the rules were written (improvements here may be in-sample).
  * `holdout` / `holdout-2`: written after the rules were frozen (`scripts/build_corpus_holdout.py`). Cases that were then
    used to extend rules were reclassified as `tuning` (the `RECLASSIFIED` set), so the holdout is not quietly re-fit.
* `python -m avishkar calibrate tests/corpus` -> precision per rule and per rule@confidence with Wilson 95% bounds, recall
  per vulnerability kind and per cohort, factor monotonicity, replay/gaming checks, approval blockers.
* `python -m avishkar calibrate tests/corpus --fit OUT.json --anchor-case ind_python_app --anchor-index 80` -> candidate
  config:
  * **Confidence caps** keyed `RULE@reported-confidence`. A cap can only *lower* a finding's confidence (never raise it
    above the detector's own). A rule with fewer than 8 labeled findings is capped at `low`, as spec P.3 requires.
  * **K** solved so a reference case reads as a chosen index. The reference case and the index are **human decisions**.
    With the current detectors the reference case carries 49.5 raw units under the caps (55.75 under the current version),
    so the candidate K is 30.756 (the shipped K = 20). This moves whenever detectors change, which is another reason the
    candidate must not be used for blocking.
* Coverage fix found while labeling: a repo containing only unsupported-language source (e.g. the Go sample) is
  `incomplete` / `not_evaluated`, never *complete, 0 findings, pass*. Mixed repos stay complete but list
  `securityDebt.coverage.notEvaluated` and a `NOT EVALUATED` note (also in SARIF and the PR comment).

## What the evidence says (details: `docs/calibration-report.generated.md`)
* **Out-of-sample numbers (frozen before the rules were extended, `docs/calibration-holdout-frozen.json`):** holdout
  precision **0.821**, recall **0.793** (27 cases, 23 TP, 5 FP, 6 missed) versus tuning precision 0.969, recall 0.900.
  That gap is the honest measure of how much the tuning numbers flatter the detectors. After the rules were extended
  using the holdout, the in-sample table in the generated report shows holdout recall 1.0; do not quote it as accuracy.
  A second, smaller set (`holdout-2`, 11 cases, written after that) gives precision 0.909 and recall 0.769.
* **No rule has enough data.** The best rules have n = 5-6 labeled findings; reaching `high` needs a Wilson 95% lower bound
  of at least 0.80 with at least 8 findings per rule@confidence, which is on the order of 15-20 correct findings per rule
  with no misses. Every rule's tier is therefore `low` in the candidate.
* **Recall is the larger problem than precision.** Known misses on the current corpus: secrets in unusual shapes, one
  CORS-by-subscript case, info disclosure, ReDoS and insecure-temp-file variants. A low score can be partly *absence of
  rules*, which is exactly why zero findings must never be read as safe.
* **Known false-positive risks:** heuristic secret-assignment findings at `low` confidence (precision 2/6 at that
  confidence on this corpus), and shell/weak-hash rules on look-alike code.
* Mechanics hold: factors are monotonic, identical inputs give identical scores, accepting risk cannot lower the index,
  fixing lowers it.

## Why this cannot be approved yet (the report's own blockers)
1. Labels are not adjudicated by ≥ 2 reviewers (P.2). I authored them; the 3 independent cases were labeled by me from
   their own `VULNERABILITY` comments. That is better than self-written code, but still one reviewer.
2. Only 3 independent cases; the other 78 are synthetic and measure self-consistency with the author's idea of a
   vulnerability, not real-world precision. Real precision needs real repositories reviewed by humans.
3. Fewer than 8 labeled findings for most rules (22 of them in the latest report).

## To finish calibration (owner actions)
1. Collect 30+ real repositories (supported-language slices, with secure/near-miss examples), have two reviewers
   adjudicate findings, and add them as `source: independent` cases with `adjudicated: true, reviewers: 2`.
2. Rerun `calibrate --fit`; review `ruleEvidence`; decide the anchor case and index; record the decision using the
   P.9 template; approve as a *new* version id (do not edit `score-v1`); only then consider `status` changes.
3. Improve detectors where recall is poor (new rules need labeled cases first); never delete or relabel a case to raise a
   number.

Regenerate this evidence any time: `python -m avishkar calibrate tests/corpus --fit config/candidates/score-v1-candidate.json`.
