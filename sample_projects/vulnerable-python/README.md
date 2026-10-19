# Vulnerable Python Sample

Intentionally vulnerable Python application for testing the Security Debt Scorer.

## Known Vulnerabilities

1. **SQL Injection** - String concatenation in queries
2. **Command Injection** - os.system() with user input
3. **Hardcoded Secrets** - API keys, passwords in source
4. **Weak Cryptography** - MD5/SHA1 for passwords
5. **Path Traversal** - Unvalidated file paths
6. **Code Injection** - eval() and pickle.loads()
7. **Insecure Configuration** - debug=True, verify=False

## Expected Findings

When scanned, this project should produce:
- 6-8 critical/high severity findings
- Security Debt Score: 70-85 (HIGH)
- All findings should have AI explanations

## Testing

```bash
# Scan this project
POST /api/upload
# Upload vulnerable-python.zip

# Expected output
{
  "score": 78,
  "risk_band": "HIGH",
  "findings": [
    {
      "severity": "critical",
      "category": "Injection",
      "file": "app.py",
      "line": 25
    }
  ]
}
```

⚠️ **DO NOT USE IN PRODUCTION** - For testing only!
