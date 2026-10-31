# Demo sample projects

Each folder here is a sample the **Demo lab** can scan. To add your own, create a folder with your code and a `sample.json`:

```json
{
  "name": "My sample",
  "language": "Python",
  "kind": "vulnerable",
  "description": "One or two sentences shown on the card.",
  "expected": "What a scan should show.",
  "fixes": [
    {
      "id": "my-fix",
      "title": "Short title",
      "file": "app.py",
      "removes": ["PY-SHELL"],
      "explanation": "Why this change is safer.",
      "edits": [["exact old text (must occur once)", "new text"]],
      "imports": ["import subprocess"]
    }
  ]
}
```

* `kind` is `vulnerable`, `secure` or `unsupported`. The folder name is the sample id (lowercase letters, digits, `-`).
* `fixes` is optional. Each edit is an exact, single-match string replacement applied to a **copy** of the sample.
* After adding or changing a sample, run `python scripts/gen_demo_results.py` (refreshes the recorded results used by the
  landing page) and `python -m pytest tests/integration/test_demo_flow.py`, which checks every fix really removes the
  findings it claims and adds none. The seeded demo repositories are created on server start.
* Only trusted files belong here: the server scans them without a sandbox boundary on public hosts.
