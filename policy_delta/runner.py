"""Execute validated synthetic suites against disposable loopback OpenBao servers."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import subprocess
import threading
import time
from .execution import RunState


class RunError(RuntimeError):
    """A sanitized runtime failure that makes a run incomplete."""

    def __init__(self, code: str, *, startup_diagnostics: dict | None = None):
        super().__init__(code)
        self.startup_diagnostics = startup_diagnostics


class _StartFailure(RunError):
    """Carry controlled startup and cleanup facts to the lifecycle owner."""

    def __init__(self, code, process, cleanup_error):
        super().__init__(code)
        self.process = process
        self.cleanup_error = cleanup_error


_VERSION = "OpenBao 2.7.0"
_STARTUP_SECONDS = 15
_HTTP_SECONDS = 5
_SHUTDOWN_SECONDS = 5
_MAX_ADMIN_RESPONSE = 1024 * 1024
_MAX_OUTPUT_LINE = 8192
_STARTED_LINE = b"==> OpenBao server started!"


class _StartupDiagnostics:
    """Fixed numeric counters and reader state, never child output."""

    def __init__(self):
        self._lock = threading.Lock()
        self._values = dict(bytes_seen=0, complete_lines=0, marker_lines=0,
                            marker_extra_lines=0, oversized_lines=0,
                            drain_state="running")

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._values[name] += amount

    def state(self, value: str) -> None:
        with self._lock:
            self._values["drain_state"] = value

    def snapshot(self) -> dict:
        with self._lock:
            return self._values.copy()


def _startup_failure(process, code: str, began: float, health_checks: int,
                     process_exit: int | None = None) -> RunError:
    counters = getattr(process, "_policy_delta_startup_diagnostics", None)
    details = counters.snapshot() if counters is not None else {"drain_state": "unavailable"}
    reader = getattr(process, "_policy_delta_output_thread", None)
    marker = getattr(process, "_policy_delta_started", None)
    details.update(elapsed_ms=max(0, int((time.monotonic() - began) * 1000)),
                   health_checks=health_checks, marker_seen=bool(marker and marker.is_set()),
                   reader_alive=bool(reader and reader.is_alive()), process_exit=process_exit)
    return RunError(code, startup_diagnostics=details)


def _clean_env(root_token: str) -> dict[str, str]:
    # The executable and its child must not inherit BAO/VAULT, proxy or token helpers.
    return {"PATH": os.defpath, "BAO_DEV_ROOT_TOKEN_ID": root_token}


def _check_version(bao_path: Path) -> str:
    try:
        finished = subprocess.run(
            [str(bao_path), "version"], env={"PATH": os.defpath},
            stdin=subprocess.DEVNULL, capture_output=True, timeout=_HTTP_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RunError("version_check_failed") from None
    if finished.returncode != 0 or not re.match(rb"^OpenBao v2\.7\.0(?:\s|\()", finished.stdout):
        raise RunError("unsupported_engine_version")
    return _VERSION


def _free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]
    except OSError:
        raise RunError("port_allocation_failed") from None


def _drain_server_output(output, started: threading.Event, stop: threading.Event,
                         diagnostics: _StartupDiagnostics | None = None) -> None:
    """Discard child output, retaining only a bounded partial line for readiness."""
    pending = bytearray()
    discard_line = False
    diagnostics = diagnostics if diagnostics is not None else _StartupDiagnostics()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(output, selectors.EVENT_READ)
            while not stop.is_set():
                if not selector.select(timeout=0.1):
                    continue
                chunk = os.read(output.fileno(), 4096)
                if not chunk:
                    diagnostics.state("eof")
                    return
                diagnostics.increment("bytes_seen", len(chunk))
                position = 0
                while position < len(chunk):
                    newline = chunk.find(b"\n", position)
                    end = len(chunk) if newline < 0 else newline
                    if not discard_line:
                        part = chunk[position:end]
                        if len(pending) + len(part) > _MAX_OUTPUT_LINE:
                            pending.clear()
                            discard_line = True
                            diagnostics.increment("oversized_lines")
                        else:
                            pending.extend(part)
                    if newline < 0:
                        break
                    diagnostics.increment("complete_lines")
                    if not discard_line:
                        line = bytes(pending).rstrip(b"\r")
                        if line == _STARTED_LINE:
                            diagnostics.increment("marker_lines")
                            started.set()
                        elif _STARTED_LINE in line:
                            diagnostics.increment("marker_extra_lines")
                        del line
                    pending.clear()
                    discard_line = False
                    position = newline + 1
            diagnostics.state("stopped")
    except (OSError, ValueError):
        diagnostics.state("io_error")
        return


def _start_server(bao_path: Path, port: int, root_token: str) -> subprocess.Popen:
    process = None
    try:
        process = subprocess.Popen(
            [str(bao_path), "server", "-dev", "-dev-no-store-token",
             f"-dev-listen-address=127.0.0.1:{port}"],
            env=_clean_env(root_token), cwd=Path(__file__).resolve().parent,
            # The owned readiness marker is stdout; concurrent stderr logs must not join its line.
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        started = threading.Event()
        stop = threading.Event()
        diagnostics = _StartupDiagnostics()
        reader = threading.Thread(
            target=_drain_server_output, args=(process.stdout, started, stop, diagnostics),
            name="policy-delta-output-drain", daemon=True,
        )
        process._policy_delta_started = started
        process._policy_delta_output_stop = stop
        process._policy_delta_startup_diagnostics = diagnostics
        reader.start()
        process._policy_delta_output_thread = reader
        return process
    except (OSError, RuntimeError, KeyboardInterrupt) as error:
        cleanup_error = None
        if process is not None:
            try:
                _stop_server(process)
            except (RunError, OSError, KeyboardInterrupt) as failure:
                cleanup_error = failure
        code = "interrupted" if isinstance(error, KeyboardInterrupt) else "server_start_failed"
        raise _StartFailure(code, process, cleanup_error) from None
    except BaseException:
        if process is not None:
            _stop_server(process)
        raise


def _stop_server(process: subprocess.Popen) -> None:
    """Reap the owned child before propagating a bounded cleanup interruption."""
    interrupted = False
    failed = False
    permission_denied = False

    def attempt(operation, *args, **kwargs):
        nonlocal interrupted
        for _ in range(3):
            try:
                return operation(*args, **kwargs)
            except KeyboardInterrupt:
                interrupted = True
        raise _CleanupInterrupted()

    try:
        try:
            if attempt(process.poll) is None:
                attempt(process.terminate)
            attempt(process.wait, timeout=_SHUTDOWN_SECONDS)
        except (subprocess.TimeoutExpired, _CleanupInterrupted):
            # A timeout or repeated interruption leaves ownership unresolved.
            attempt(process.kill)
            attempt(process.wait, timeout=_SHUTDOWN_SECONDS)
    except PermissionError:
        permission_denied = True
        failed = True
    except (OSError, subprocess.TimeoutExpired, _CleanupInterrupted):
        failed = True
    finally:
        def finish(operation, *args, **kwargs):
            nonlocal failed, permission_denied
            try:
                return attempt(operation, *args, **kwargs)
            except PermissionError:
                permission_denied = True
                failed = True
                return None
            except (OSError, _CleanupInterrupted):
                failed = True
                return None

        stop = getattr(process, "_policy_delta_output_stop", None)
        if stop is not None:
            finish(stop.set)
        reader = getattr(process, "_policy_delta_output_thread", None)
        if reader is not None:
            finish(reader.join, timeout=1)
        output = getattr(process, "stdout", None)
        if output is not None:
            finish(output.close)
        if reader is not None and finish(reader.is_alive):
            finish(reader.join, timeout=1)
            failed = failed or bool(finish(reader.is_alive))
    if failed:
        error = RunError("shutdown_failed")
        error.cleanup_interrupted = interrupted
        error.cleanup_permission_denied = permission_denied
        raise error from None
    if interrupted:
        raise KeyboardInterrupt


class _CleanupInterrupted(Exception):
    """A bounded series of interrupts prevented a cleanup operation."""


def _request(
    port: int, method: str, path: str, token: str, body: dict | None = None,
    *, json_response: bool = False, mount_readiness: bool = False,
    timeout: float | None = None,
) -> tuple[int, dict]:
    """One fixed-host HTTP request. No proxy, URL parser, or redirect handler."""
    connection = http.client.HTTPConnection(
        "127.0.0.1", port,
        timeout=_HTTP_SECONDS if timeout is None else min(_HTTP_SECONDS, timeout),
    )
    try:
        encoded = None if body is None else json.dumps(body, separators=(",", ":"))
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        connection.request(
            method, "/v1/" + path, body=encoded,
            headers=headers,
        )
        response = connection.getresponse()
        status = response.status
        if mount_readiness and status == 400:
            # The fixed KV-v2 upgrade response is transient initialization, not
            # fixture acceptance. Never return or retain the engine's error text.
            raw = response.read(_MAX_ADMIN_RESPONSE + 1)
            initializing = False
            if len(raw) <= _MAX_ADMIN_RESPONSE:
                try:
                    payload = json.loads(raw)
                    errors = payload.get("errors") if isinstance(payload, dict) else None
                    initializing = (isinstance(errors, list) and len(errors) == 1
                                    and isinstance(errors[0], str)
                                    and errors[0].startswith(
                                        "Upgrading from non-versioned to versioned data."))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            return status, {"initializing": initializing}
        if not json_response or not 200 <= status < 300:
            return status, {}
        raw = response.read(_MAX_ADMIN_RESPONSE + 1)
        if len(raw) > _MAX_ADMIN_RESPONSE:
            raise RunError("admin_response_too_large")
        if not raw:
            return status, {}
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RunError("invalid_admin_response") from None
        if not isinstance(payload, dict):
            raise RunError("invalid_admin_response")
        return status, payload
    finally:
        connection.close()


def _wait_ready(process: subprocess.Popen, port: int, root_token: str) -> None:
    began = time.monotonic()
    health_checks = 0
    started = getattr(process, "_policy_delta_started", None)
    if started is None:
        raise _startup_failure(process, "startup_marker_unavailable", began, health_checks)
    deadline = began + _STARTUP_SECONDS
    while not started.is_set():
        process_exit = process.poll()
        if process_exit is not None:
            raise _startup_failure(process, "server_exited_during_startup", began, health_checks,
                                   process_exit)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _startup_failure(process, "startup_marker_timeout", began, health_checks)
        started.wait(timeout=min(0.1, remaining))
    while time.monotonic() < deadline:
        process_exit = process.poll()
        if process_exit is not None:
            raise _startup_failure(process, "server_exited_during_startup", began, health_checks,
                                   process_exit)
        try:
            health_checks += 1
            if _request(port, "GET", "sys/health", "")[0] == 200 and process.poll() is None:
                return
        except (OSError, http.client.HTTPException, TimeoutError):
            pass
        time.sleep(0.1)
    raise _startup_failure(process, "startup_health_timeout", began, health_checks)


def _admin(port: int, method: str, path: str, root_token: str, body: dict | None = None,
           *, accepted: tuple[int, ...] | None = None) -> dict:
    try:
        status, payload = _request(port, method, path, root_token, body, json_response=True)
    except (OSError, http.client.HTTPException, TimeoutError):
        raise RunError("admin_request_failed") from None
    success = status in accepted if accepted is not None else 200 <= status < 300
    if not success:
        raise RunError("admin_http_status")
    return payload



def _wait_mount_ready(port: int, mount: str, root_token: str) -> None:
    """Poll this owned KV-v2 backend before writes under the existing HTTP budget."""
    deadline = time.monotonic() + _HTTP_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RunError("admin_http_status")
        try:
            status, payload = _request(
                port, "GET", f"{mount}/config", root_token, json_response=True,
                mount_readiness=True, timeout=remaining,
            )
        except (OSError, http.client.HTTPException, TimeoutError):
            raise RunError("admin_request_failed") from None
        if time.monotonic() >= deadline:
            raise RunError("admin_http_status")
        if status == 200:
            return
        if status != 400 or payload != {"initializing": True}:
            raise RunError("admin_http_status")
        time.sleep(min(0.01, max(0, deadline - time.monotonic())))

def _reset_fixtures(port: int, root_token: str, mounts: dict) -> None:
    for mount, fixture in mounts.items():
        _admin(port, "DELETE", f"sys/mounts/{mount}", root_token, accepted=(204, 404))
        _admin(port, "POST", f"sys/mounts/{mount}", root_token,
               {"type": "kv", "options": {"version": str(fixture["version"])}})
        if fixture["version"] == 2:
            _wait_mount_ready(port, mount, root_token)
        for key, value in fixture["secrets"].items():
            path = f"{mount}/data/{key}" if fixture["version"] == 2 else f"{mount}/{key}"
            body = {"data": value} if fixture["version"] == 2 else value
            _admin(port, "POST", path, root_token, body)


def _create_token(port: int, root_token: str, policies: list[str]) -> str:
    payload = _admin(port, "POST", "auth/token/create", root_token,
                     {"policies": policies, "no_default_policy": True, "ttl": "10m"})
    token = payload.get("auth", {}).get("client_token") if isinstance(payload.get("auth"), dict) else None
    if not isinstance(token, str) or not token:
        raise RunError("invalid_token_response")
    return token


def _capabilities(port: int, root_token: str, token: str, path: str) -> list[str]:
    payload = _admin(port, "POST", "sys/capabilities", root_token,
                     {"token": token, "paths": [path]})
    values = payload.get("capabilities")
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise RunError("invalid_capabilities_response")
    return sorted(set(values))


def _observed(status: int, capabilities: list[str]) -> dict:
    result = {"status": status, "decision": "error", "capabilities": capabilities}
    if 200 <= status < 300:
        result["decision"] = "allow"
    elif status == 403:
        result["decision"] = "deny"
    else:
        result["error"] = "unexpected_status"
    return result


def _case_error(code: str, capabilities: list[str] | None = None) -> dict:
    return {"status": None, "decision": "error", "capabilities": capabilities or [], "error": code}


def _run_case(port: int, root_token: str, data: dict, case: dict) -> dict:
    _reset_fixtures(port, root_token, data["mounts"])
    token = _create_token(port, root_token, data["principals"][case["principal"]])
    try:
        capabilities = _capabilities(port, root_token, token, case["path"])
    except RunError:
        return _case_error("capabilities_failed")
    try:
        status, _ = _request(port, case["method"], case["path"], token, case.get("body"))
    except (OSError, http.client.HTTPException, TimeoutError, RunError):
        return _case_error("request_failed", capabilities)
    return _observed(status, capabilities)


def _record_failure(state: RunState, error: BaseException) -> None:
    if isinstance(error, RunError):
        if getattr(error, "cleanup_interrupted", False):
            state.fail("interrupted")
        state.fail(str(error), error.startup_diagnostics)
    else:
        state.fail("interrupted" if isinstance(error, KeyboardInterrupt) else "operation_failed")


def _record_cleanup_failure(state: RunState, error: BaseException, process) -> None:
    _record_failure(state, error)
    try:
        status = "running" if process.poll() is None else "exited"
    except (OSError, KeyboardInterrupt):
        status = "unknown"
    pid = getattr(process, "pid", None)
    if getattr(error, "cleanup_permission_denied", False):
        state.report["execution"]["failures"][-1]["reason"] = "permission_denied"
    state.report["execution"]["failures"][-1]["owned_process"] = {
        "pid": pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 else None,
        "status_at_cleanup": status,
    }


def _run_variant(state: RunState, suite: dict, executable: Path, variant: str) -> None:
    process = None
    try:
        state.at("port", variant)
        port = _free_port()
        root_token = secrets.token_hex(32)
        state.at("server_start", variant)
        process = _start_server(executable, port, root_token)
        state.at("startup", variant)
        _wait_ready(process, port, root_token)
        state.at("policy_setup", variant)
        for name, policy_text in suite["_policy_texts"][variant].items():
            _admin(port, "POST", f"sys/policies/acl/{name}", root_token,
                   {"policy": policy_text})
        for case, result in zip(suite["cases"], state.report["cases"]):
            state.at("case", variant, case["id"])
            # An interruption can happen after a request was sent but before its
            # response arrives. Only cases not started at all remain not_run.
            result[variant] = _case_error("observation_incomplete")
            result[variant] = _run_case(port, root_token, suite, case)
    except _StartFailure as error:
        _record_failure(state, error)
        if error.cleanup_error is not None:
            state.at("shutdown", variant)
            _record_cleanup_failure(state, error.cleanup_error, error.process)
    except (RunError, OSError, http.client.HTTPException, KeyboardInterrupt) as error:
        _record_failure(state, error)
    finally:
        if process is not None:
            state.at("shutdown", variant)
            try:
                _stop_server(process)
            except (RunError, OSError, KeyboardInterrupt) as error:
                _record_cleanup_failure(state, error, process)


def run_suite(suite: dict, bao_path: Path) -> dict:
    """Return complete or incomplete evidence for a prevalidated synthetic suite."""
    state = RunState(suite)
    try:
        executable = Path(bao_path).resolve()
        state.report["engine_version"] = _check_version(executable)
        for variant in ("before", "after"):
            _run_variant(state, suite, executable, variant)
            if state.failed:
                break
    except (RunError, OSError, KeyboardInterrupt) as error:
        _record_failure(state, error)
    return state.finish()
