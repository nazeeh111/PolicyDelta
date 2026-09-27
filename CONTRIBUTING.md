# Contributing

Describe the observed behavior, expected result, and a minimal synthetic fixture. Keep policy decisions in the real engine instead of adding an approximate evaluator.

Install the package and run the unit and real-server checks in the README. A change to suite semantics needs a regression case; a documentation-only edit does not require rerunning unrelated engine tests. Preserve the report data-exclusion boundary, fixture independence, and exit-code contract.

Keep changes focused. If adding an engine version or backend, document its behavior and verify a real request before declaring support.
