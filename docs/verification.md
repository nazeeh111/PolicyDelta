# Verification scope

## Local checks, September 27, 2026

On macOS arm64 with Python 3.14 and official OpenBao 2.7.0:

- 44 unit tests passed, covering strict suite input, owned-process startup and cleanup, request failures, report decisions and escaping, and verified runtime extraction.
- The installed CLI ran from a temporary directory, away from the checkout. The expansion, unchanged and approved examples each exercised 11 cases against both revisions. The expansion example returned exit 1 with exactly four newly allowed cases; two had unchanged capabilities. Unchanged and explicitly approved examples returned exit 0.
- A missing fixture produced HTTP 404 and exit 2. A default `secret/` mount was reset correctly. Deleting one fixture did not affect the next read. Existing report bytes survived an output collision. Invalid input was rejected before trying a missing executable.
- A separate owned HTTP listener occupied the chosen port. OpenBao failed to bind, PolicyDelta rejected startup, and the unrelated listener received zero HTTP requests. The successful process emitted the exact startup marker; the failed process did not.
- The HTML report was inspected in Chrome at desktop and 390-pixel widths. The input hashes expand, the comparison scrolls horizontally without widening the mobile document, and the visible scroll guidance explains the narrow layout.

The workflow checks Python 3.11 and 3.14 on Linux amd64, including the real runtime download and request cases. See the [current workflow result](https://github.com/nazeeh111/PolicyDelta/actions/workflows/verify.yml) for its status.

These checks validate the declared synthetic workflows. They do not validate production secrets, identity templates, authentication plugins, clusters, arbitrary engine versions, or all possible policy paths.
