"""Fixed synthetic protocol fixtures for the observed KV-v2 upgrade window.

No captured engine responses, tokens, headers or server output are retained.
"""
import io
import json
import unittest
from unittest.mock import patch

from policy_delta import runner

UPGRADE = "Upgrading from non-versioned to versioned data."


class Response:
    def __init__(self, status, value):
        self.status = status
        self.stream = io.BytesIO(value if isinstance(value, bytes) else json.dumps(value).encode())

    def read(self, limit):
        return self.stream.read(limit)


class MountReadinessTests(unittest.TestCase):
    def test_registration_ack_does_not_allow_seed_before_upgrade_finishes(self):
        calls = []
        pending = 0

        class Connection:
            def __init__(self, host, port, timeout):
                pass

            def request(self, method, path, body, headers):
                self.method, self.path = method, path
                calls.append((method, path))

            def getresponse(self):
                nonlocal pending
                if self.path == "/v1/sys/mounts/kv":
                    if self.method == "POST":
                        pending = 2
                    return Response(204, b"")
                if self.path == "/v1/kv/config":
                    if pending:
                        pending -= 1
                        return Response(400, {"errors": [UPGRADE]})
                    return Response(200, {"data": {}})
                if self.path == "/v1/kv/data/item":
                    return (Response(400, {"errors": [UPGRADE]}) if pending
                            else Response(200, {"data": {}}))
                raise AssertionError("Unexpected synthetic operation")

            def close(self):
                pass

        with patch.object(runner.http.client, "HTTPConnection", Connection):
            runner._reset_fixtures(12345, "synthetic", {
                "kv": {"version": 2, "secrets": {"item": {"value": "synthetic"}}},
            })
        self.assertEqual(calls, [
            ("DELETE", "/v1/sys/mounts/kv"), ("POST", "/v1/sys/mounts/kv"),
            ("GET", "/v1/kv/config"), ("GET", "/v1/kv/config"),
            ("GET", "/v1/kv/config"), ("POST", "/v1/kv/data/item"),
        ])

    def test_only_known_upgrade_classification_can_wait(self):
        for status, payload in [(400, {"initializing": False}), (403, {}), (404, {}), (500, {})]:
            with self.subTest(status=status), patch.object(runner, "_request", return_value=(status, payload)) as request:
                with self.assertRaisesRegex(runner.RunError, "admin_http_status"):
                    runner._wait_mount_ready(12345, "kv", "synthetic")
                request.assert_called_once()

    def test_error_text_never_leaves_readiness_transport(self):
        for value, expected in [
            ({"errors": [UPGRADE]}, True),
            ({"errors": ["other synthetic error"]}, False),
            ({"errors": [UPGRADE, "other"]}, False),
            ({"errors": None}, False),
            (b"not-json", False),
        ]:
            class Connection:
                def __init__(self, *args, **kwargs):
                    pass
                def request(self, *args, **kwargs):
                    pass
                def getresponse(self):
                    return Response(400, value)
                def close(self):
                    pass
            with self.subTest(expected=expected), patch.object(runner.http.client, "HTTPConnection", Connection):
                self.assertEqual(runner._request(12345, "GET", "kv/config", "synthetic", json_response=True, mount_readiness=True),
                                 (400, {"initializing": expected}))
                self.assertEqual(runner._request(12345, "GET", "kv/config", "synthetic", json_response=True), (400, {}))

    def test_wait_and_http_timeout_share_existing_five_second_bound(self):
        now = [0.0]
        timeouts = []
        def request(*args, **kwargs):
            timeouts.append(kwargs["timeout"])
            now[0] = runner._HTTP_SECONDS
            return 400, {"initializing": True}
        with patch.object(runner.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(runner.time, "sleep") as sleep, \
             patch.object(runner, "_request", side_effect=request):
            with self.assertRaisesRegex(runner.RunError, "admin_http_status"):
                runner._wait_mount_ready(12345, "kv", "synthetic")
        self.assertEqual(timeouts, [runner._HTTP_SECONDS])
        sleep.assert_not_called()

    def test_success_after_budget_is_not_accepted(self):
        now = [0.0]
        def request(*args, **kwargs):
            now[0] = runner._HTTP_SECONDS + .1
            return 200, {"data": {}}
        with patch.object(runner.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(runner, "_request", side_effect=request):
            with self.assertRaisesRegex(runner.RunError, "admin_http_status"):
                runner._wait_mount_ready(12345, "kv", "synthetic")

    def test_v1_does_not_add_a_readiness_operation(self):
        with patch.object(runner, "_admin"), patch.object(runner, "_wait_mount_ready") as ready:
            runner._reset_fixtures(12345, "synthetic", {
                "kv": {"version": 1, "secrets": {"item": {"value": "synthetic"}}},
            })
        ready.assert_not_called()

    def test_transport_failure_keeps_existing_admin_error(self):
        with patch.object(runner, "_request", side_effect=TimeoutError):
            with self.assertRaisesRegex(runner.RunError, "admin_request_failed"):
                runner._wait_mount_ready(12345, "kv", "synthetic")


if __name__ == "__main__":
    unittest.main()
