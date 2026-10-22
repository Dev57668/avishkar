# Calibration report - score-v1
**NOT CALIBRATED - evidence only; the scoring owner must approve (App. P.7)**

Corpus: 43 cases (3 independent), 0 adjudicated by >=2 reviewers.

## Precision by rule
| Rule | TP | FP | Unlabeled | n | Precision | Wilson 95% lower |
|---|---|---|---|---|---|---|
| DEP-DJANGO-OLD | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| DEP-LODASH | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| DEP-NOLOCK | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| DEP-PYYAML | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| DEP-UNPINNED | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| JS-CMDI | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| JS-EVAL | 2 | 1 | 0 | 3 | 0.667 | 0.208 |
| JS-INNERHTML | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| JS-TLS | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| PY-DEBUG | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| PY-EVAL | 3 | 0 | 0 | 3 | 1.0 | 0.438 |
| PY-NOVERIFY | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| PY-PICKLE | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| PY-SHELL | 5 | 0 | 0 | 5 | 1.0 | 0.566 |
| PY-SQLI | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| PY-WEAKHASH | 4 | 0 | 0 | 4 | 1.0 | 0.51 |
| PY-YAML | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| SEC-AWS-KEY | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| SEC-GENERIC | 4 | 2 | 0 | 6 | 0.667 | 0.3 |
| SEC-GH-TOKEN | 2 | 0 | 0 | 2 | 1.0 | 0.342 |
| SEC-PRIVKEY | 1 | 0 | 0 | 1 | 1.0 | 0.207 |
| SEC-SLACK | 1 | 0 | 0 | 1 | 1.0 | 0.207 |

## Precision by rule @ detector-reported confidence (drives the confidence caps)
| Rule@confidence | TP | FP | n | Wilson 95% lower |
|---|---|---|---|---|
| DEP-DJANGO-OLD@high | 1 | 0 | 1 | 0.207 |
| DEP-LODASH@high | 1 | 0 | 1 | 0.207 |
| DEP-NOLOCK@medium | 1 | 0 | 1 | 0.207 |
| DEP-PYYAML@high | 1 | 0 | 1 | 0.207 |
| DEP-UNPINNED@high | 1 | 0 | 1 | 0.207 |
| JS-CMDI@medium | 2 | 0 | 2 | 0.342 |
| JS-EVAL@medium | 2 | 1 | 3 | 0.208 |
| JS-INNERHTML@medium | 1 | 0 | 1 | 0.207 |
| JS-TLS@high | 1 | 0 | 1 | 0.207 |
| PY-DEBUG@low | 2 | 0 | 2 | 0.342 |
| PY-EVAL@medium | 3 | 0 | 3 | 0.438 |
| PY-NOVERIFY@high | 2 | 0 | 2 | 0.342 |
| PY-PICKLE@medium | 2 | 0 | 2 | 0.342 |
| PY-SHELL@medium | 5 | 0 | 5 | 0.566 |
| PY-SQLI@medium | 4 | 0 | 4 | 0.51 |
| PY-WEAKHASH@medium | 4 | 0 | 4 | 0.51 |
| PY-YAML@medium | 1 | 0 | 1 | 0.207 |
| SEC-AWS-KEY@high | 1 | 0 | 1 | 0.207 |
| SEC-AWS-KEY@low | 1 | 0 | 1 | 0.207 |
| SEC-GENERIC@low | 1 | 2 | 3 | 0.061 |
| SEC-GENERIC@medium | 3 | 0 | 3 | 0.438 |
| SEC-GH-TOKEN@high | 2 | 0 | 2 | 0.342 |
| SEC-PRIVKEY@high | 1 | 0 | 1 | 0.207 |
| SEC-SLACK@high | 1 | 0 | 1 | 0.207 |

## Recall by vulnerability kind
| Kind | Found | Missed | Recall |
|---|---|---|---|
| cmdi | 7 | 0 | 1.0 |
| cors | 0 | 1 | 0.0 |
| debug | 2 | 1 | 0.667 |
| dependency | 4 | 1 | 0.8 |
| deserialization | 1 | 0 | 1.0 |
| eval | 5 | 0 | 1.0 |
| info-disclosure | 0 | 2 | 0.0 |
| noverify | 3 | 0 | 1.0 |
| path-traversal | 0 | 4 | 0.0 |
| pickle | 2 | 0 | 1.0 |
| redos | 0 | 1 | 0.0 |
| secret | 10 | 8 | 0.556 |
| sqli | 4 | 4 | 0.5 |
| tempfile | 0 | 1 | 0.0 |
| weak-random | 0 | 1 | 0.0 |
| weakhash | 4 | 1 | 0.8 |
| xss | 1 | 1 | 0.5 |
| xxe | 0 | 1 | 0.0 |

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
 "cases": 42,
 "rawUnits": {
  "min": 0.0,
  "p25": 1.125,
  "median": 3.0,
  "p75": 3.25,
  "max": 31.75
 },
 "indexAtLandmarks": {
  "10": {
   "p25": 10.6,
   "median": 25.9,
   "p75": 27.7,
   "max": 95.8
  },
  "20": {
   "p25": 5.5,
   "median": 13.9,
   "p75": 15.0,
   "max": 79.6
  },
  "40": {
   "p25": 2.8,
   "median": 7.2,
   "p75": 7.8,
   "max": 54.8
  },
  "80": {
   "p25": 1.4,
   "median": 3.7,
   "p75": 4.0,
   "max": 32.8
  }
 }
}
```

## Approval blockers
- labels are not adjudicated by >=2 reviewers (App. P.2)
- only 3 independent (not written by the detector author) cases; synthetic cases measure self-consistency, not real-world precision
- 22 rule(s) have fewer than 8 labeled findings: confidence stays low
