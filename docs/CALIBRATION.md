# Score calibration (spec Appendix P): what was done, what it shows, what it does not

**Status: NOT CALIBRATED.** `score-v1` is unchanged and still provisional. Everything below produces *evidence* and a
*candidate* (`config/candidates/score-v1-candidate.json`, `status: candidate-not-approved`) for the scoring owner to
review. Do not enable policy blocking on either version.

## Why there is no "training"
The score is a fixed formula (`D = I × E × C × A`, `Score = 100(1 − e^(−D/K))`), not a learned model. "Calibrating" means
choosing its parameters from labeled evidence: **C** (confidence per rule, from measured precision) and **K** (the scale).
Impact, exposure and aging are not fitted from this corpus: they have no outcome data behind them.

## What was built
* `tests/corpus/`: 43 labeled cases. **3 independent** (copied byte-for-byte from `sample_projects/`, written separately
  from these detectors: a vulnerable Python app, a vulnerable Node app, and a Java app) and **40 synthetic** (positives in
  varied syntax, safe look-alikes such as `model.eval()`, strings/comments, placeholders, and deliberately hard cases).
  Vulnerability lines are located by text, so labels cannot drift from the code.
* `python -m avishkar calibrate tests/corpus` -> precision per rule and per rule@confidence with Wilson 95% bounds, recall
  per vulnerability kind, factor monotonicity, replay/gaming checks, approval blockers.
* `python -m avishkar calibrate tests/corpus --fit OUT.json [--anchor-case C --anchor-index I]` -> candidate config:
  * **Confidence caps** keyed `RULE@reported-confidence`. A cap can only *lower* a finding's confidence (never raise it
    above the detector's own). A rule with fewer than 8 labeled findings is capped at `low`, as spec P.3 requires.
  * **K** solved so a reference case reads as a chosen index. Default: the heaviest independent case reads **80**
    (`ind_python_app`, 21.0 raw units under the caps → **K = 13.05**; the shipped K = 20). The reference case and the
    index are **human decisions**; the median of the corpus is deliberately *not* used because most cases are one-line
    snippets and say nothing about how a real repository should read.
* Coverage fix found while labeling: a repo containing only unsupported-language source (e.g. the Java sample) used to
  scan as *complete, 0 findings, pass*. It is now `incomplete` / `not_evaluated`; mixed repos stay complete but list
  `securityDebt.coverage.notEvaluated` and a `NOT EVALUATED` note (also in SARIF and the PR comment).

## What the evidence says (details: `docs/calibration-report.generated.md`)
* **No rule has enough data.** The best rule has n = 5 labeled findings; the 95% lower bound on precision is below
  0.57 everywhere, so every rule's tier is `low` in the candidate. The minimum sample is 8 *per rule@confidence* and a
  Wilson lower bound ≥ 0.80 for `high`; reaching `high` needs on the order of 15–20 correct findings per rule with no misses.
* **Recall is the larger problem than precision.** Found vs. missed on this corpus: secrets 10/18, SQL injection 4/8
  (taint through a variable is invisible to the detector), debug 2/3, path traversal 0/4, XXE, ReDoS, weak random,
  insecure temp file, info disclosure, CORS by subscript: all 0 (no rule). A low score here is partly *absence of rules*,
  which is exactly why zero findings must never be read as safe.
* **Real false positives exist:** `model.eval()` is flagged by the JS eval rule (JS regex); placeholder secrets still
  produce `SEC-GENERIC@low` findings (the detector already downgrades them: 1 of 3 correct).
* **Secret detection misses the most common real-world shapes**: prefixed names (`AWS_SECRET_KEY`, `JWT_SECRET`,
  `DB_PASSWORD`), dict-style `'password': '…'`, and short values. Fix candidates are listed above in the corpus labels.
* Mechanics hold: factors are monotonic, identical inputs give identical scores, accepting risk cannot lower the index,
  fixing lowers it.

## Why this cannot be approved yet (the report's own blockers)
1. Labels are not adjudicated by ≥ 2 reviewers (P.2). I authored them; the 3 independent cases were labeled by me from
   their own `VULNERABILITY` comments. That is better than self-written code, but still one reviewer.
2. Only 3 independent cases. Synthetic cases measure self-consistency with my own idea of a vulnerability, not real-world
   precision. Real precision needs real repositories reviewed by humans.
3. Fewer than 8 labeled findings for every rule.

## To finish calibration (owner actions)
1. Collect 30+ real repositories (supported-language slices, with secure/near-miss examples), have two reviewers
   adjudicate findings, and add them as `source: independent` cases with `adjudicated: true, reviewers: 2`.
2. Rerun `calibrate --fit`; review `ruleEvidence`; decide the anchor case and index; record the decision using the
   P.9 template; approve as a *new* version id (do not edit `score-v1`); only then consider `status` changes.
3. Improve detectors where recall is poor (new rules need labeled cases first); never delete or relabel a case to raise a
   number.

Regenerate this evidence any time: `python -m avishkar calibrate tests/corpus --fit config/candidates/score-v1-candidate.json`.
