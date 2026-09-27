# Execution and tradeoffs

`load_suite` validates all input before any process starts. It reads bounded UTF-8 JSON, rejects duplicate keys and unknown fields, and loads policy text only from files contained inside the suite directory. The report hashes the original suite bytes and loaded policy text, so changes can be traced to their inputs.

`run_suite` launches one OpenBao process per revision. Each case resets the declared mounts, seeds their data, creates a token for its principal, queries capabilities, and sends the declared HTTP request with that token. Capability metadata explains the result but never substitutes for it. The response status determines the outcome; secret bodies are discarded.

`assess` compares observed decisions with expectations and marks permission expansions. A new allow needs a matching expectation and a case-specific approval. An execution failure outranks an otherwise passing comparison. `write_reports` creates a fresh directory and replaces each completed temporary file atomically; if writing fails, it removes its own incomplete output. The pair is intended for inspection after the command exits, not concurrent streaming consumption.

## Why reset before every case?

Writes and deletes can otherwise alter later outcomes. Resetting is slower than sharing state, but it makes cases independent and makes an absent fixture meaningful. Each revision also has a separate process, preventing policy or storage state from carrying across the comparison. Tests that intentionally model request sequences would require a distinct scenario format; this release does not pretend independent cases are such sequences.

## Why a pinned engine?

Policy semantics and dev-server behavior belong to OpenBao. Pinning 2.7.0 makes the supported behavior reproducible without maintaining an approximate authorization evaluator. The helper verifies archive bytes against recorded upstream SHA-256 values. This verifies artifact identity, not a separate audit of the engine. A compatible Vault version has not been validated and is rejected.

## A consequential failure case

Removing `required_parameters` and `allowed_parameters` can grant access without changing the list of capabilities. The expansion example deliberately includes both changes. Conversely, a read with valid policy but absent fixture returns 404: treating every non-2xx response as a denial would conceal broken setup. PolicyDelta reports that request as an error.

## Extension points

The suite loader, runner and report assessment are separate. Another backend would need its own fixture reset semantics, status interpretation and integration cases before it belongs in the schema. Arbitrary remote URLs and production credentials are intentionally absent from the execution interface.
