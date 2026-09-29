# Verification scope

## Local v0.2.0 checks, September 29, 2026

On macOS arm64 with Python 3.14 and the previously verified official OpenBao 2.7.0 executable:

- 48 unit tests passed. New report tests parsed JUnit XML, checked one outcome per case with error precedence, verified XML-invalid suite-name controls are replaced, and confirmed an injected third-file write failure removes the full output directory. A startup test distinguishes marker timeout from health-probe timeout without weakening the marker gate.
- The installed 0.2.0 package ran from a temporary directory against disposable loopback servers. JUnit contained 11 testcases and four failures for the expansion example; 11 passing cases for unchanged and approved examples; one error for a missing fixture; and one failure plus one error in a mixed two-case suite. The approved expansion remained a passing testcase with before/after evidence.
- The integration check included JUnit in its synthetic fixture-value exclusion check. Existing collision, invalid-input, default-mount, and foreign-listener checks passed.

The JUnit shape follows [GitLab's documented unit test report subset](https://docs.gitlab.com/ci/testing/unit_test_reports/), including testcase class/name and failure/error elements. Consult the [repository workflow](https://github.com/nazeeh111/PolicyDelta/actions/workflows/verify.yml) for current remote results. A live GitLab artifact import has not been exercised. XML reports omit request bodies, returned values, tokens, and unmeasured timing fields.

## Local checks, September 27, 2026

On macOS arm64 with Python 3.14 and official OpenBao 2.7.0:

- 44 unit tests passed, covering strict suite input, owned-process startup and cleanup, request failures, report decisions and escaping, and verified runtime extraction.
- The installed CLI ran from a temporary directory, away from the checkout. The expansion, unchanged and approved examples each exercised 11 cases against both revisions. The expansion example returned exit 1 with exactly four newly allowed cases; two had unchanged capabilities. Unchanged and explicitly approved examples returned exit 0.
- A missing fixture produced HTTP 404 and exit 2. A default `secret/` mount was reset correctly. Deleting one fixture did not affect the next read. Existing report bytes survived an output collision. Invalid input was rejected before trying a missing executable.
- A separate owned HTTP listener occupied the chosen port. OpenBao failed to bind, PolicyDelta rejected startup, and the unrelated listener received zero HTTP requests. The successful process emitted the exact startup marker; the failed process did not.
- The HTML report was inspected in Chrome at desktop and 390-pixel widths. The input hashes expand, the comparison scrolls horizontally without widening the mobile document, and the visible scroll guidance explains the narrow layout.

The workflow checks Python 3.11 and 3.14 on Linux amd64, including the real runtime download and request cases. See the [current workflow result](https://github.com/nazeeh111/PolicyDelta/actions/workflows/verify.yml) for its status.

These checks validate the declared synthetic workflows. They do not validate production secrets, identity templates, authentication plugins, clusters, arbitrary engine versions, or all possible policy paths.
