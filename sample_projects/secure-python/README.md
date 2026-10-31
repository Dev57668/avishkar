# Secure Python sample

The same features as `vulnerable-python`, written with safe patterns (parameterized SQL, argument-list subprocess,
environment secrets, key derivation, path checks, defusedxml, `secrets`, TLS verification on).

Expected scan: **no findings**, a complete analysis, index 0. That means Second Read's detectors found none of the patterns
they know about. It does not prove the code is secure.
