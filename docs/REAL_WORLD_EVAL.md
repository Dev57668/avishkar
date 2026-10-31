# Real-world review of the scanners (what it shows and what it does not)

The calibration corpus (`docs/CALIBRATION.md`) is made of small cases we wrote ourselves. This review runs the scanners on
**real open-source projects** that nobody wrote for our detectors, reads the findings, and records what was right and wrong.
It found real false alarms, which were fixed and are pinned by `tests/unit/test_real_world_regressions.py`.

## What was scanned

Intentionally vulnerable training applications, cloned read-only with `git clone --depth 1` and scanned, never executed. Their code
is **not** stored in this repository (some are GPL or unlicensed); only the commit ids and our own counts are recorded here.

| Project | Language | Commit | License | Files analyzed |
|---|---|---|---|---|
| DVWA (digininja/DVWA) | PHP (+ some JS) | `a1978a2` | GPL-3.0 | 179 |
| govwa (0c34/govwa) | Go | `4058f79` | none stated | 24 |
| go-test-bench (Contrast-Security-OSS) | Go | `9244570` | MIT | 129 |
| WebGoat.NET (jerryhoff/WebGoat.NET) | C# (+ some JS) | `1c6cab1` | none stated | 169 |
| NodeGoat (OWASP/NodeGoat) | JavaScript | `c5cb68a` | Apache-2.0 | 50 |
| pygoat (adeyosemanputra/pygoat) | Python | `32a0a59` | MIT | 117 |

No Kotlin or Java project was reviewed here (no suitable Kotlin project was found; Java was checked earlier on Logisim Evolution).
Re-run any of them with `python -m avishkar scan <folder>` after cloning.

## How findings were judged

One reviewer (the author of the scanners, so **not independent**) read the code around each finding and put it in one bucket:

* **True positive**: the dangerous construct is really there and plausibly attacker-reachable, or the app deliberately demonstrates it.
* **Pattern only**: the construct is there but the value is provably not attacker-controlled (a config value, a validated value).
* **False positive**: the finding does not describe what the code does.

This is a judgement call, made by one person, on training apps that are vulnerable by design. It is evidence, not a benchmark.

## Findings after the fixes (reviewed by hand)

| Project / rules | Findings | True positive | Pattern only | False positive | Notes |
|---|---|---|---|---|---|
| go-test-bench, Go rules | 5 | 3 | 0 | 0 | 2 reflected-output findings (`fmt.Fprint(w, data)`) are plausible but unclear |
| govwa, all Go-related rules | 6 | 5 | 1 | 0 | the pattern-only one concatenates a config value into `CREATE DATABASE` |
| WebGoat.NET, C# rules | 11 | 9 | 2 | 0 | 5 SQL injections and 3 `BinaryFormatter` uses are real; 2 SQL texts also splice in a helper's clause string |
| DVWA, PHP non-SQL rules | 30 | ~24 | 2 | 4 | false: one include-by-map path, two `$token = "userid:2"` secrets, one `md5()` on a constant |
| DVWA, PHP SQL injection (13 of 39 read, before the fixes) | 13 | 4 | 9 | 0 | most pattern-only cases splice config values, session names or integer ids into SQL |
| NodeGoat, all rules | 9 | 8 | 0 | 1 | false: a `writeFile` path in a test script |
| pygoat, secrets (about 40 of 52 read) | 40 | 40 | 0 | 0 | all hard-coded values in deliberately vulnerable labs (placeholders are reported at low confidence) |
| pygoat, `debug=True` (4 of 23 read) | 4 | 4 | 0 | 0 | |

## False alarms found, and what changed

| Where | What went wrong | Fix |
|---|---|---|
| C#, WebGoat.NET | 42 findings: SQL text concatenated with constant table names (`"DELETE FROM " + USER_TB_NAME + " WHERE x = $x"`) while every value was bound | constant-style names (ALL_CAPS, or `Tables.USER_TB`) count as constants (Java, Go, PHP too) |
| Go, both projects | the same variable name used in different functions, or in different `switch` cases of one function, carried "built from input" state between them | names are tracked per function and the latest assignment before the use decides |
| PHP, DVWA | `require_once ROOT . "x/{$file}"` flagged though `$file` was one of a few fixed names | include is flagged only when the path really comes from the request |
| JavaScript, NodeGoat and WebGoat.NET | `innerHTML` and `eval` hits inside minified vendor libraries (jquery.min.js, raphael-min.js) | minified bundles are not scanned (the dependency check covers libraries) |
| JavaScript, DVWA | `eval("require('crypto')")` flagged though the argument is a constant | `eval` of a constant string is not injection |
| JavaScript, NodeGoat | `session_cookie_secret_key_here` reported at normal confidence | a trailing `_here` / `-here` marks a placeholder |

Before the fixes the new-language rules gave 15 Go findings, 49 C# SQL findings and 80 PHP findings on these projects; after them 11, 7 and 75.

## What it does not show

* **Recall is not measured.** Training apps contain dozens of weaknesses, and the scanners find only a few kinds. Clearly missed, in all the projects:
  broken access control (IDOR), CSRF, weak sessions, logic flaws, NoSQL injection, SSRF, open redirects, template-level XSS, missing security
  headers and insecure cookie flags. A low finding count on a project is never evidence it is secure.
* **The counts are small and single-reviewer.** PHP SQL injection and the pygoat secrets were only partly read; the numbers above are for what was read.
* **Training apps are not typical code.** They are dense with vulnerabilities by design, so precision here is likely higher than on ordinary code, while
  recall on ordinary code is unknown.
* **Kotlin, Java (beyond one project) and Python/JavaScript at scale remain unmeasured**, and nothing here changes the calibration status:
  the score is still uncalibrated and must not be used to block releases.

## Next steps that would make this credible

1. A second, independent reviewer repeating the judgements on the same findings.
2. Labelled real projects with known CVEs (not training apps), so recall can be counted.
3. A Kotlin and a larger Java project.
