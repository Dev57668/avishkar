# Calibration report - score-v1
**NOT CALIBRATED - evidence only; the scoring owner must approve (App. P.7)**

Corpus: 81 cases (3 independent), 0 adjudicated by >=2 reviewers.

## Precision by rule
| Rule | TP | FP | Unlabeled | n | Precision | Wilson 95% lower |
|---|---|---|---|---|---|---|
| DEP-DJANGO-OLD | 2 | 1 | 0 | 3 | 0.667 | 0.208 |
| DEP-LODASH | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| DEP-MINIMIST | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| DEP-NOLOCK | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| DEP-PYYAML | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| DEP-UNPINNED | 2 | 1 | 0 | 3 | 0.667 | 0.208 |
| JS-CMDI | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| JS-EVAL | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| JS-INNERHTML | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| JS-PATH | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| JS-RANDOM | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| JS-SECRET-ASSIGN | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| JS-SQLI | 5 | 0 | 0 | 5 | 1.0 | 0.566 |
| JS-TLS | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| JS-WEAKHASH | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| JS-XSS-REFLECT | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| PY-DEBUG | 5 | 0 | 0 | 5 | 1.0 | 0.566 |
| PY-EVAL | 3 | 0 | 0 | 3 | 1.0 | 0.438 |
| PY-NOVERIFY | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| PY-PATH | 5 | 0 | 0 | 5 | 1.0 | 0.566 |
| PY-PICKLE | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| PY-RANDOM | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| PY-SECRET-ASSIGN | 11 | 4 | 0 | 15 | 0.733 | 0.48 |
| PY-SHELL | 8 | 1 | 0 | 9 | 0.889 | 0.565 |
| PY-SQLI | 6 | 0 | 0 | 6 | 1.0 | 0.61 |
| PY-SQLI-FLOW | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| PY-WEAKHASH | 5 | 1 | 0 | 6 | 0.833 | 0.436 |
| PY-XML-PARSE | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| PY-YAML | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| SEC-AWS-KEY | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| SEC-GH-TOKEN | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| SEC-PRIVKEY | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| SEC-SLACK | 1 | 0 | 0 | 1 | 1.0 | 0.207 |

## Precision by rule @ detector-reported confidence (drives the confidence caps)
| Rule@confidence | TP | FP | n | Wilson 95% lower |
|---|---|---|---|---|
| DEP-DJANGO-OLD@high | 2 | 1 | 3 | 0.208 |
| DEP-LODASH@high | 1 | 0 | 1 | 0.207 |
| DEP-MINIMIST@high | 1 | 0 | 1 | 0.207 |
| DEP-NOLOCK@medium | 2 | 0 | 2 | 0.342 |
| DEP-PYYAML@high | 2 | 0 | 2 | 0.342 |
| DEP-UNPINNED@high | 2 | 1 | 3 | 0.208 |
| JS-CMDI@medium | 4 | 0 | 4 | 0.51 |
| JS-EVAL@medium | 4 | 0 | 4 | 0.51 |
| JS-INNERHTML@medium | 2 | 0 | 2 | 0.342 |
| JS-PATH@low | 1 | 0 | 1 | 0.207 |
| JS-RANDOM@low | 1 | 0 | 1 | 0.207 |
| JS-SECRET-ASSIGN@low | 1 | 0 | 1 | 0.207 |
| JS-SECRET-ASSIGN@medium | 3 | 0 | 3 | 0.438 |
| JS-SQLI@low | 1 | 0 | 1 | 0.207 |
| JS-SQLI@medium | 4 | 0 | 4 | 0.51 |
| JS-TLS@high | 2 | 0 | 2 | 0.342 |
| JS-WEAKHASH@medium | 2 | 0 | 2 | 0.342 |
| JS-XSS-REFLECT@low | 2 | 0 | 2 | 0.342 |
| PY-DEBUG@low | 5 | 0 | 5 | 0.566 |
| PY-EVAL@medium | 3 | 0 | 3 | 0.438 |
| PY-NOVERIFY@high | 4 | 0 | 4 | 0.51 |
| PY-PATH@low | 5 | 0 | 5 | 0.566 |
| PY-PICKLE@medium | 4 | 0 | 4 | 0.51 |
| PY-RANDOM@low | 2 | 0 | 2 | 0.342 |
| PY-SECRET-ASSIGN@low | 2 | 4 | 6 | 0.097 |
| PY-SECRET-ASSIGN@medium | 9 | 0 | 9 | 0.701 |
| PY-SHELL@medium | 8 | 1 | 9 | 0.565 |
| PY-SQLI-FLOW@low | 4 | 0 | 4 | 0.51 |
| PY-SQLI@medium | 6 | 0 | 6 | 0.61 |
| PY-WEAKHASH@medium | 5 | 1 | 6 | 0.436 |
| PY-XML-PARSE@low | 1 | 0 | 1 | 0.207 |
| PY-YAML@medium | 2 | 0 | 2 | 0.342 |
| SEC-AWS-KEY@high | 1 | 0 | 1 | 0.207 |
| SEC-GH-TOKEN@high | 2 | 0 | 2 | 0.342 |
| SEC-PRIVKEY@high | 1 | 0 | 1 | 0.207 |
| SEC-SLACK@high | 1 | 0 | 1 | 0.207 |

## Tuning vs holdout cohorts
`tuning` = cases that existed while the rules were written (improvements here may be in-sample); `holdout` = written after the rules were frozen (a fairer, still self-authored, estimate).
| Cohort | Cases | TP | FP | Precision | Found | Missed | Recall |
|---|---|---|---|---|---|---|---|
| holdout | 21 | 21 | 5 | 0.808 | 21 | 0 | 1.0 |
| holdout-2 | 11 | 10 | 1 | 0.909 | 10 | 3 | 0.769 |
| tuning | 48 | 71 | 2 | 0.973 | 71 | 7 | 0.91 |

## Recall by vulnerability kind
| Kind | Found | Missed | Recall |
|---|---|---|---|
| cmdi | 12 | 0 | 1.0 |
| cors | 0 | 1 | 0.0 |
| debug | 5 | 0 | 1.0 |
| dependency | 10 | 0 | 1.0 |
| deserialization | 2 | 0 | 1.0 |
| eval | 7 | 0 | 1.0 |
| info-disclosure | 0 | 2 | 0.0 |
| noverify | 6 | 0 | 1.0 |
| path-traversal | 6 | 0 | 1.0 |
| pickle | 4 | 0 | 1.0 |
| redos | 0 | 1 | 0.0 |
| secret | 20 | 4 | 0.833 |
| sqli | 15 | 0 | 1.0 |
| tempfile | 0 | 1 | 0.0 |
| weak-random | 3 | 0 | 1.0 |
| weakhash | 7 | 0 | 1.0 |
| xss | 4 | 1 | 0.8 |
| xxe | 1 | 0 | 1.0 |

## Factor sensitivity (one factor at a time)
- impact: monotonic=True debt=[0.75, 1.5, 2.25, 3.0, 3.75]
- confidence: monotonic=True debt=[1.5, 2.25, 3.0]
- exposure: monotonic=True debt=[1.6875, 2.25, 2.8125, 3.375]
- age_days: monotonic=True debt=[2.25, 2.625, 3.0, 3.375, 3.375]

## Stability / gaming
- identicalInputsIdenticalScore: True
- corpusReplayIdentical: True
- acceptingRiskDoesNotLowerIndex: True
- fixingLowersIndex: True

## Normalization constant
```json
{
 "currentK": 20.0,
 "cases": 80,
 "rawUnits": {
  "min": 0.0,
  "p25": 1.5,
  "median": 3.0,
  "p75": 3.75,
  "max": 55.75
 },
 "indexAtLandmarks": {
  "10": {
   "p25": 13.9,
   "median": 25.9,
   "p75": 31.3,
   "max": 99.6
  },
  "20": {
   "p25": 7.2,
   "median": 13.9,
   "p75": 17.1,
   "max": 93.8
  },
  "40": {
   "p25": 3.7,
   "median": 7.2,
   "p75": 8.9,
   "max": 75.2
  },
  "80": {
   "p25": 1.9,
   "median": 3.7,
   "p75": 4.6,
   "max": 50.2
  }
 }
}
```

## Approval blockers
- labels are not adjudicated by >=2 reviewers (App. P.2)
- only 3 independent (not written by the detector author) cases; synthetic cases measure self-consistency, not real-world precision
- 31 rule(s) have fewer than 8 labeled findings: confidence stays low
