# PolicyDelta design

PolicyDelta compares OpenBao policy revisions by executing declared requests against disposable local servers. Actual requests reveal parameter restrictions that capability lists alone cannot establish. The suite records before/after outcomes, isolated fixture state and explicit approval for intended access expansions.

## Initial product

A Python 3.11+ standard-library CLI accepts one JSON suite and an explicit path to an OpenBao 2.7.0 executable. No hosted services, model, personal credential stores, existing server addresses, deployment, or live secret access. Runtime binaries are external dependencies with their original license; our separate runner is MIT. The initial tested platforms are macOS arm64 and Linux amd64.

The suite has `version: 1`, `name`, `mounts`, `policies`, `principals`, and `cases`. All unknown keys are errors. Limit the JSON file to 1 MiB, 1–100 cases, 100 total fixture secrets, 8 mounts, 16 policies per variant, and 16 principals. Strict JSON rejects duplicate keys and nonfinite numbers. Policy files resolve within the suite directory, each no larger than 256 KiB; absolute paths, traversal, and escaping symlinks are rejected.

`mounts` is an object keyed by a single ASCII mount segment; built-in sys, auth, cubbyhole and identity mounts are reserved. Each value contains `version` (integer 1 or 2) and `secrets`, an object mapping clean relative key paths to JSON objects. `policies` has exactly `before` and `after`, each mapping policy names to relative HCL file paths. `principals` maps names to nonempty policy-name lists; every name must exist in both variants. Names use `[a-z][a-z0-9_-]{0,39}`. `root` and `default` are reserved policy names.

Each case has unique `id`, `principal`, `method` (GET, POST, DELETE, LIST), `path`, optional `body` object, `expect` with `before` and `after` (allow or deny), and optional boolean `allow_expansion` (default false). Path segments use ASCII letters, digits, underscore, hyphen, tilde, and dot (not standalone dot/dot-dot). Paths must remain within a declared mount; forbid absolute URLs, `%`, `?`, `#`, backslash, empty/interior-dot segments, and control characters. KV-v2 requests use explicit `data/` or `metadata/` API paths. GET/LIST/DELETE have no body; POST requires an object. The suite is synthetic fixture input, not a production policy deployment format.

## Execution contract

Use the real OpenBao server as the authority; do not reimplement ACL matching. Spawn an owned loopback dev server for each policy variant with a random in-memory root token and `-dev-no-store-token`; ignore inherited BAO/VAULT configuration. No server output or tokens enter files/reports. Drain and discard child output in memory, requiring its exact successful startup marker before any HTTP calls; an unrelated listener cannot satisfy readiness. Use bounded startup, request, and shutdown timeouts and terminate only owned processes in finally blocks. Check the executable version. Generate short-lived tokens without default policy, bound to the requested principal policy set.

Before every case, reset all fixture mounts and seed their original data. Cases cannot contaminate one another or the other variant. The HTTP client is fixed to the owned loopback server and never follows redirects. Paths are already validated. Collect status and capability names, never response bodies or fixture values. `allow` means 2xx; `deny` means exactly 403; all other responses, timeouts, process failure, or protocol failures are `error`. A capabilities result is explanatory metadata and cannot turn a denied request into an allow.

## Results and delivery

`run_suite(suite, bao_path) -> dict` returns `schema_version`, `suite_name`, `engine_version`, `suite_sha256`, policy hashes per variant, and `cases`. Each case result includes `id`, `principal`, `method`, `path`, `allow_expansion`, `expect`, and `before`/`after` objects with `status` (integer or null), `decision`, `capabilities` (list), and optional sanitized `error` code. No raw request/response body.

The CLI writes JSON and self-contained HTML reports atomically into a fresh output directory whose parent already exists. Existing paths, including symlinks, are rejected. Escape every user-provided value in HTML. Do not overwrite the suite or policy inputs. Tables show expected versus observed outcomes, newly allowed/denied cases, and capability lists. Mark expansions with unchanged capabilities. Include engine/policy identities and the explicit tested-case limit. No badge claiming universal security.

Exit 0 when expectations match and no unapproved expansion occurs; exit 1 for expectation mismatch or an unapproved deny-to-allow change; exit 2 for invalid input or any runtime error. An explicit `allow_expansion: true` permits only that named case's expansion and remains visible. Errors take precedence over regressions. `python -m policy_delta SUITE --bao PATH --output DIR` is the entry point.

Acceptance: unchanged policies pass; wildcard broadening and parameter restriction removal fail with exact changed cases; explicit denies and allowed LIST remain; approved changes remain visible with exit0; 404 is an error; malformed suites fail before starting a process; fixture mutation does not change later cases; interrupted runs close the owned server; report HTML escapes hostile labels. Review and run real OpenBao integration before publication. Finite test cases do not prove all policy behavior; identities, namespace templates, auth backends, replication and real production data are outside this first release.
