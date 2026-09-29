# PolicyDelta

Test an OpenBao policy change by sending the same requests before and after it. PolicyDelta starts disposable local servers, loads synthetic fixtures, and produces request-by-request HTML, JSON, and JUnit XML comparisons.

A capability list can say `update` while a parameter restriction still denies the request. The included example removes a required parameter and broadens a path. It detects four newly allowed requests, including two whose capability lists never change.

## Try the example

Use Python 3.11 or newer on macOS arm64 or Linux amd64. From this checkout:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python scripts/fetch_runtime.py
policy-delta examples/expansion.json --bao .runtime/bao --output review-expansion
```

The example exits **1**, intentionally: four requests gain access. Open `review-expansion/index.html` to compare results, inspect `report.json`, or upload `junit.xml` to a CI service that accepts JUnit reports. The runtime helper downloads the pinned OpenBao 2.7.0 archive, verifies its SHA-256, and retains its license. You can instead pass your own OpenBao 2.7.0 executable with `--bao`.

```sh
# Same policy on both sides: exit 0.
policy-delta examples/unchanged.json --bao .runtime/bao --output review-unchanged

# The same four expansions explicitly approved in their named cases: exit 0.
policy-delta examples/approved.json --bao .runtime/bao --output review-approved
```

Each output directory must be new, with an existing parent. Existing reports and inputs are never overwritten. Runtime setup failures print a short error and exit 2; they do not produce a passing report. Per-request failures appear in reports and also exit 2. The three report files are written as one output set; an incomplete set is removed after a write failure.

An [example JSON report](docs/example/report.json), its [portable HTML view](docs/example/index.html), and [JUnit XML](docs/example/junit.xml) are included from a local OpenBao 2.7.0 run.

## Write a suite

Start with [examples/expansion.json](examples/expansion.json). A suite contains:

- **Mounts:** synthetic key-value fixtures, using KV version 1 or 2.
- **Policies:** local HCL files for `before` and `after`, contained within the suite directory.
- **Principals:** named collections of policies, used to create short-lived tokens without a default policy.
- **Cases:** a principal, HTTP method, API path, optional POST body, and expected `allow` or `deny` for each revision.

For example, a named case can verify that production writes stay denied:

```json
{
  "id": "production-write",
  "principal": "builder",
  "method": "POST",
  "path": "legacy/release",
  "body": {"stage": "prod", "value": "synthetic"},
  "expect": {"before": "deny", "after": "deny"}
}
```

If an expansion is intended, set that case's `expect.after` to `allow` **and** add `"allow_expansion": true`. The report still shows the expansion. Matching expectations alone cannot silently approve new access.

| Exit | Meaning |
| --- | --- |
| 0 | Every expectation matches, with no unapproved deny-to-allow change. |
| 1 | An expectation differs or a request gains access without explicit approval. |
| 2 | Input, setup, request, or cleanup failed. Errors take precedence. |

Only HTTP 403 counts as a denial. A missing fixture returning 404 is an error, even if access was expected to be denied. GET, POST, DELETE and LIST are supported; KV-v2 paths include `data/` or `metadata/` explicitly. See the [suite contract](docs/design.md) for validation rules and limits.

## CI test reports

`junit.xml` contains one testcase per declared case. An execution error becomes `<error>`; an expectation mismatch or unapproved expansion becomes `<failure>`. A case with both an execution error and a mismatch has one `<error>` only. Approved expansions remain passing and their before/after status and finding stay in testcase output. JUnit counts refer to testcase outcomes, while `report.json` retains its separate policy finding counters. The XML omits request bodies, response values, and tokens.

For GitLab CI, run PolicyDelta directly so its exit code still determines job status, and upload the JUnit file even when a policy regression makes the job fail:

```yaml
policy-review:
  script:
    - python -m pip install .
    - python scripts/fetch_runtime.py
    - policy-delta path/to/synthetic-suite.json --bao .runtime/bao --output policy-review
  artifacts:
    when: always
    paths:
      - policy-review/
    reports:
      junit: policy-review/junit.xml
```

The report format and `artifacts:reports:junit` setting follow [GitLab's unit test report documentation](https://docs.gitlab.com/ci/testing/unit_test_reports/). This repository's checks validate the XML locally; a live GitLab import has not been exercised. A setup failure may leave no report file, while the command still exits 2.

## How execution stays isolated

Each revision gets its own loopback-only OpenBao dev server and an in-memory root token. PolicyDelta ignores inherited OpenBao/Vault settings, never connects to an existing server, never invokes a credential helper, and stops its owned server when execution finishes or is interrupted.

Every case starts with freshly mounted, reseeded fixtures. The examples delete a value in one case and read it in the next to check this isolation. Results include HTTP status, capability names, expectations and input hashes. Tokens, request bodies and returned values are omitted. Paths and case names remain visible, so use synthetic input rather than private production fixtures.

This is a finite regression suite, not proof that a policy is universally safe. The first release covers single-node synthetic KV fixtures. Identity templates, external authentication, replication and production data are outside its scope. Dev mode is a disposable local execution environment, not a production hardening boundary.

## Development

```sh
python -m unittest discover -s tests -v
python scripts/check_integration.py --bao .runtime/bao
```

The integration check runs the installed package from a temporary directory against the actual engine. It verifies unchanged and approved changes, four unapproved expansions, unchanged capabilities for parameter restrictions, fixture resets, HTTP 404 classification, JUnit case outcomes, and output protection. Unit tests cover input rejection, request failures, cleanup, report escaping, XML controls, and three-file rollback.

Python is used for orchestration and reporting; authorization decisions come from [OpenBao](https://github.com/openbao/openbao), an external MPL-2.0 dependency. PolicyDelta's separate code is MIT licensed. [Verification scope](docs/verification.md) records the tested cases. [Architecture and tradeoffs](docs/architecture.md) explain the execution path and boundaries.
