"""Focused tests for the owned OpenBao runtime boundaries."""

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch

from policy_delta import runner


def suite():
    return {
        "version": 1,
        "name": "synthetic",
        "mounts": {"kv": {"version": 2, "secrets": {"item": {"value": "secret-marker"}}}},
        "policies": {"before": {"reader": "before.hcl"}, "after": {"reader": "after.hcl"}},
        "principals": {"alice": ["reader"]},
        "cases": [
            {"id": "first", "principal": "alice", "method": "GET", "path": "kv/data/item",
             "expect": {"before": "allow", "after": "deny"}},
            {"id": "second", "principal": "alice", "method": "GET", "path": "kv/data/item",
             "expect": {"before": "allow", "after": "deny"}},
        ],
        "_root": Path("/tmp/synthetic-suite"),
        "_sha256": "suite-hash",
        "_policy_texts": {"before": {"reader": "before-marker"}, "after": {"reader": "after-marker"}},
    }


class FakeProcess:
    def __init__(self, timeout_once=False, marker_ready=True):
        self.terminated = False
        self.killed = False
        self.waited = False
        self.timeout_once = timeout_once
        self._policy_delta_started = threading.Event()
        if marker_ready:
            self._policy_delta_started.set()

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout):
        self.waited = True
        if self.timeout_once:
            self.timeout_once = False
            raise subprocess.TimeoutExpired("bao", timeout)
        return 0


class RunnerTests(unittest.TestCase):
    def test_foreign_healthy_listener_cannot_unlock_admin_without_owned_marker(self):
        process = FakeProcess(marker_ready=False)
        with patch.object(runner, "_STARTUP_SECONDS", 0.01), \
             patch.object(runner, "_request", return_value=(200, {})) as request:
            with self.assertRaisesRegex(runner.RunError, "startup_timeout"):
                runner._wait_ready(process, 12345, "private-root-token")
        request.assert_not_called()

    def test_owned_child_exit_before_marker_does_not_probe_foreign_listener(self):
        process = FakeProcess(marker_ready=False)
        polls = iter((None, 1))
        process.poll = lambda: next(polls)
        with patch.object(runner, "_STARTUP_SECONDS", 0.1), \
             patch.object(runner, "_request", return_value=(200, {})) as request:
            with self.assertRaisesRegex(runner.RunError, "server_exited_during_startup"):
                runner._wait_ready(process, 12345, "private-root-token")
        request.assert_not_called()

    def test_output_drainer_detects_only_complete_marker_line_across_chunks(self):
        read_fd, write_fd = os.pipe()
        ready = threading.Event()
        stop = threading.Event()
        with os.fdopen(read_fd, "rb", buffering=0) as output:
            worker = threading.Thread(target=runner._drain_server_output,
                                      args=(output, ready, stop), daemon=True)
            worker.start()
            os.write(write_fd, b"random root token\n==> OpenBao server sta")
            self.assertFalse(ready.is_set())
            os.write(write_fd, b"rted!\n")
            os.close(write_fd)
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
            self.assertTrue(ready.is_set())

    def test_shutdown_joins_output_reader_even_if_pipe_stays_open(self):
        read_fd, write_fd = os.pipe()
        process = FakeProcess()
        process.stdout = os.fdopen(read_fd, "rb", buffering=0)
        process._policy_delta_output_stop = threading.Event()
        process._policy_delta_output_thread = threading.Thread(
            target=runner._drain_server_output,
            args=(process.stdout, process._policy_delta_started, process._policy_delta_output_stop),
            daemon=True,
        )
        process._policy_delta_output_thread.start()
        try:
            runner._stop_server(process)
            self.assertFalse(process._policy_delta_output_thread.is_alive())
            self.assertTrue(process.stdout.closed)
        finally:
            os.close(write_fd)

    def test_relative_executable_uses_same_absolute_path_for_check_and_spawn(self):
        relative = Path("../PolicyDelta-probe/bin/bao")
        with patch.object(runner, "_check_version", return_value="OpenBao 2.7.0") as check, \
             patch.object(runner, "_free_port", return_value=12345), \
             patch.object(runner, "_start_server", side_effect=runner.RunError("server_start_failed")) as spawn:
            with self.assertRaisesRegex(runner.RunError, "server_start_failed"):
                runner.run_suite(suite(), relative)
        expected = relative.resolve()
        self.assertEqual(check.call_args.args[0], expected)
        self.assertEqual(spawn.call_args.args[0], expected)

    def test_wrong_engine_version_is_rejected_before_spawn(self):
        completed = subprocess.CompletedProcess(["bao", "version"], 0, b"OpenBao v2.8.0\n", b"")
        with patch.object(runner.subprocess, "run", return_value=completed), \
             patch.object(runner, "_start_server") as spawn:
            with self.assertRaisesRegex(runner.RunError, "unsupported_engine_version"):
                runner.run_suite(suite(), Path("/tmp/bao"))
        spawn.assert_not_called()

    def test_bind_failure_is_sanitized(self):
        with patch.object(runner.socket, "socket", side_effect=PermissionError("private context")):
            with self.assertRaisesRegex(runner.RunError, "port_allocation_failed") as caught:
                runner._free_port()
        self.assertNotIn("private context", str(caught.exception))

    def test_server_environment_discards_inherited_configuration(self):
        with patch.dict(os.environ, {"BAO_ADDR": "https://elsewhere", "VAULT_TOKEN": "private", "HTTPS_PROXY": "http://proxy"}):
            env = runner._clean_env("generated-token")
        self.assertEqual(set(env), {"PATH", "BAO_DEV_ROOT_TOKEN_ID"})
        self.assertEqual(env["BAO_DEV_ROOT_TOKEN_ID"], "generated-token")

    def test_health_probe_does_not_send_root_token(self):
        process = FakeProcess()
        with patch.object(runner, "_request", return_value=(200, {})) as request:
            runner._wait_ready(process, 12345, "private-root-token")
        self.assertEqual(request.call_args.args, (12345, "GET", "sys/health", ""))

    def test_observations_use_status_not_capabilities(self):
        self.assertEqual(runner._observed(204, ["deny"])["decision"], "allow")
        self.assertEqual(runner._observed(403, ["read"])["decision"], "deny")
        observation = runner._observed(404, ["read"])
        self.assertEqual(observation["decision"], "error")
        self.assertEqual(observation["status"], 404)
        self.assertEqual(observation["error"], "unexpected_status")

    def test_each_case_rebuilds_fixtures_and_returns_only_metadata(self):
        data = suite()
        processes = [FakeProcess(), FakeProcess()]
        calls = []
        variant = ["before"]

        def fake_request(port, method, path, token, body=None, *, json_response=False):
            calls.append((variant[0], method, path, body))
            if path == "sys/policies/acl/reader":
                variant[0] = "before" if body["policy"] == "before-marker" else "after"
            if path == "auth/token/create":
                return 200, {"auth": {"client_token": "token-marker"}}
            if path == "sys/capabilities":
                return 200, {"capabilities": ["read"]}
            if path == "kv/data/item" and method == "GET":
                return (200 if variant[0] == "before" else 403), {}
            return 204, {}

        with patch.object(runner, "_check_version", return_value="OpenBao 2.7.0"), \
             patch.object(runner, "_start_server", side_effect=processes), \
             patch.object(runner, "_wait_ready"), \
             patch.object(runner, "_request", side_effect=fake_request), \
             patch.object(runner, "_free_port", return_value=12345):
            result = runner.run_suite(data, Path("/tmp/bao"))

        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["suite_sha256"], "suite-hash")
        self.assertEqual(result["policy_sha256"]["before"]["reader"], hashlib.sha256(b"before-marker").hexdigest())
        self.assertEqual([case["before"]["decision"] for case in result["cases"]], ["allow", "allow"])
        self.assertEqual([case["after"]["decision"] for case in result["cases"]], ["deny", "deny"])
        for policy_variant in ("before", "after"):
            mount_actions = [c[1] for c in calls if c[0] == policy_variant and c[2] == "sys/mounts/kv"]
            self.assertEqual(mount_actions, ["DELETE", "POST", "DELETE", "POST"])
        self.assertEqual(len([c for c in calls if c[1:3] == ("POST", "kv/data/item")]), 4)
        self.assertTrue(all(p.terminated and p.waited for p in processes))
        self.assertNotIn("secret-marker", json.dumps(result))
        self.assertNotIn("token-marker", json.dumps(result))

    def test_request_failure_becomes_error_and_next_case_runs(self):
        data = suite()
        processes = [FakeProcess(), FakeProcess()]
        failures = 0

        def fake_request(port, method, path, token, body=None, *, json_response=False):
            nonlocal failures
            if path == "auth/token/create":
                return 200, {"auth": {"client_token": "private-token"}}
            if path == "sys/capabilities":
                return 200, {"capabilities": ["read"]}
            if path == "kv/data/item" and method == "GET":
                failures += 1
                if failures == 1:
                    raise TimeoutError("private-token")
                return 403, {}
            return 204, {}

        with patch.object(runner, "_check_version", return_value="OpenBao 2.7.0"), \
             patch.object(runner, "_start_server", side_effect=processes), \
             patch.object(runner, "_wait_ready"), \
             patch.object(runner, "_request", side_effect=fake_request), \
             patch.object(runner, "_free_port", return_value=12345):
            result = runner.run_suite(data, Path("/tmp/bao"))

        self.assertEqual(result["cases"][0]["before"]["decision"], "error")
        self.assertEqual(result["cases"][0]["before"]["error"], "request_failed")
        self.assertEqual(result["cases"][1]["before"]["decision"], "deny")
        self.assertNotIn("private-token", json.dumps(result))

    def test_startup_failure_terminates_owned_process(self):
        process = FakeProcess(timeout_once=True)
        with patch.object(runner, "_check_version", return_value="OpenBao 2.7.0"), \
             patch.object(runner, "_start_server", return_value=process), \
             patch.object(runner, "_wait_ready", side_effect=runner.RunError("startup_timeout")), \
             patch.object(runner, "_free_port", return_value=12345):
            with self.assertRaisesRegex(runner.RunError, "startup_timeout"):
                runner.run_suite(suite(), Path("/tmp/bao"))
        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)

    def test_interrupt_terminates_owned_process(self):
        process = FakeProcess()
        with patch.object(runner, "_check_version", return_value="OpenBao 2.7.0"), \
             patch.object(runner, "_start_server", return_value=process), \
             patch.object(runner, "_wait_ready", side_effect=KeyboardInterrupt), \
             patch.object(runner, "_free_port", return_value=12345):
            with self.assertRaises(KeyboardInterrupt):
                runner.run_suite(suite(), Path("/tmp/bao"))
        self.assertTrue(process.terminated and process.waited)

    def test_unresponsive_child_is_killed_with_bounded_wait(self):
        process = FakeProcess(timeout_once=True)
        runner._stop_server(process)
        self.assertTrue(process.terminated and process.killed and process.waited)

    def test_capability_failure_remains_an_error(self):
        with patch.object(runner, "_reset_fixtures"), \
             patch.object(runner, "_create_token", return_value="private-token"), \
             patch.object(runner, "_capabilities", side_effect=runner.RunError("capabilities_failed")), \
             patch.object(runner, "_request") as request:
            result = runner._run_case(12345, "root-token", suite(), suite()["cases"][0], "before")
        self.assertEqual(result, {"status": None, "decision": "error", "capabilities": [], "error": "capabilities_failed"})
        request.assert_not_called()

    def test_http_client_is_loopback_and_does_not_follow_redirect(self):
        observed = []

        class Response:
            status = 302

            def read(self, limit):
                return b""

        class Connection:
            def __init__(self, host, port, timeout):
                observed.append((host, port, timeout))

            def request(self, method, path, body, headers):
                observed.append((method, path, headers.get("X-Vault-Token")))

            def getresponse(self):
                return Response()

            def close(self):
                observed.append("closed")

        with patch.object(runner.http.client, "HTTPConnection", Connection):
            status, payload = runner._request(12345, "GET", "kv/data/item", "token", json_response=True)
        self.assertEqual((status, payload), (302, {}))
        self.assertEqual(observed[0][:2], ("127.0.0.1", 12345))
        self.assertEqual(observed[1][:2], ("GET", "/v1/kv/data/item"))
        self.assertEqual(observed[-1], "closed")
        self.assertEqual(len([x for x in observed if isinstance(x, tuple) and x[0] == "GET"]), 1)

        observed.clear()
        with patch.object(runner.http.client, "HTTPConnection", Connection):
            runner._request(12345, "GET", "sys/health", "")
        self.assertIsNone(observed[1][2])


if __name__ == "__main__":
    unittest.main()
