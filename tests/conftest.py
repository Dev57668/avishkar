# Corpus cases are *data* (some are named like tests on purpose); pytest must never collect or import them.
collect_ignore_glob = ["corpus/*"]
