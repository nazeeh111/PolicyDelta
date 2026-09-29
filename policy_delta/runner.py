"""Execute validated synthetic suites against disposable loopback OpenBao servers."""

from __future__ import annotations

import hashlib
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


class RunError(RuntimeError):
    """A sanitized runtime failure that invalidates the whole run."""


_VERSION = "OpenBao 2.7.0"
_STARTUP_SECONDS = 15
_HTTP_SECONDS = 5
_SHUTDOWN_SECONDS = 5
_MAX_ADMIN_RESPONSE = 1024 * 1024
_MAX_OUTPUT_LINE = 8192
_STARTED_LINE = b"==> OpenBao server started!"


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


def _drain_server_output(output, started: threading.Event, stop: threading.Event) -> None:
    """Discard child output, retaining only a bounded partial line for readiness."""
    pending = bytearray()
    discard_line = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(output, selectors.EVENT_READ)
            while not stop.is_set():
                if not selector.select(timeout=0.1):
                    continue
                chunk = os.read(output.fileno(), 4096)
                if not chunk:
                    return
                position = 0
                while position < len(chunk):
                    newline = chunk.find(b"\n", position)
                    end = len(chunk) if newline < 0 else newline
                    if not discard_line:
                        part = chunk[position:end]
                        if len(pending) + len(part) > _MAX_OUTPUT_LINE:
                            pending.clear()
                            discard_line = True
                        else:
                            pending.extend(part)
                    if newline < 0:
                        break
                    if not discard_line and bytes(pending).rstrip(b"\r") == _STARTED_LINE:
                        started.set()
                    pending.clear()
                    discard_line = False
                    position = newline + 1
    except (OSError, ValueError):
        return


def _start_server(bao_path: Path, port: int, root_token: str) -> subprocess.Popen:
    process = None
    try:
        process = subprocess.Popen(
            [str(bao_path), "server", "-dev", "-dev-no-store-token",
             f"-dev-listen-address=127.0.0.1:{port}"],
            env=_clean_env(root_token), cwd=Path(__file__).resolve().parent,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        started = threading.Event()
        stop = threading.Event()
        reader = threading.Thread(
            target=_drain_server_output, args=(process.stdout, started, stop),
            name="policy-delta-output-drain", daemon=True,
        )
        process._policy_delta_started = started
        process._policy_delta_output_stop = stop
        reader.start()
        process._policy_delta_output_thread = reader
        return process
    except (OSError, RuntimeError):
        if process is not None:
            _stop_server(process)
        raise RunError("server_start_failed") from None
    except BaseException:
        if process is not None:
            _stop_server(process)
        raise


def _stop_server(process: subprocess.Popen) -> None:
    failed = False
    try:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=_SHUTDOWN_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_SHUTDOWN_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        failed = True
    finally:
        stop = getattr(process, "_policy_delta_output_stop", None)
        if stop is not None:
            stop.set()
        reader = getattr(process, "_policy_delta_output_thread", None)
        if reader is not None:
            reader.join(timeout=1)
        output = getattr(process, "stdout", None)
        if output is not None:
            output.close()
        if reader is not None and reader.is_alive():
            reader.join(timeout=1)
            failed = failed or reader.is_alive()
    if failed:
        raise RunError("shutdown_failed") from None


def _request(
    port: int, method: str, path: str, token: str, body: dict | None = None,
    *, json_response: bool = False,
) -> tuple[int, dict]:
    """One fixed-host HTTP request. No proxy, URL parser, or redirect handler."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=_HTTP_SECONDS)
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
    started = getattr(process, "_policy_delta_started", None)
    if started is None:
        raise RunError("startup_marker_unavailable")
    deadline = time.monotonic() + _STARTUP_SECONDS
    while not started.is_set():
        if process.poll() is not None:
            raise RunError("server_exited_during_startup")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RunError("startup_marker_timeout")
        started.wait(timeout=min(0.1, remaining))
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RunError("server_exited_during_startup")
        try:
            if _request(port, "GET", "sys/health", "")[0] == 200 and process.poll() is None:
                return
        except (OSError, http.client.HTTPException, TimeoutError):
            pass
        time.sleep(0.1)
    raise RunError("startup_health_timeout")


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


def _reset_fixtures(port: int, root_token: str, mounts: dict) -> None:
    for mount, fixture in mounts.items():
        _admin(port, "DELETE", f"sys/mounts/{mount}", root_token, accepted=(204, 404))
        _admin(port, "POST", f"sys/mounts/{mount}", root_token,
               {"type": "kv", "options": {"version": str(fixture["version"])}})
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


def _run_case(port: int, root_token: str, data: dict, case: dict, variant: str) -> dict:
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


def run_suite(suite: dict, bao_path: Path) -> dict:
    """Run a prevalidated suite and return case evidence without body/token data."""
    executable = Path(bao_path).resolve()
    engine_version = _check_version(executable)
    policy_hashes = {
        variant: {name: hashlib.sha256(text.encode("utf-8")).hexdigest()
                  for name, text in suite["_policy_texts"][variant].items()}
        for variant in ("before", "after")
    }
    results = [
        {"id": case["id"], "principal": case["principal"], "method": case["method"],
         "path": case["path"], "allow_expansion": case.get("allow_expansion", False),
         "expect": case["expect"]}
        for case in suite["cases"]
    ]
    for variant in ("before", "after"):
        root_token = secrets.token_hex(32)
        port = _free_port()
        process = _start_server(executable, port, root_token)
        try:
            _wait_ready(process, port, root_token)
            for name, policy_text in suite["_policy_texts"][variant].items():
                _admin(port, "POST", f"sys/policies/acl/{name}", root_token,
                       {"policy": policy_text})
            for case, result in zip(suite["cases"], results):
                result[variant] = _run_case(port, root_token, suite, case, variant)
        finally:
            _stop_server(process)
    return {
        "schema_version": 1,
        "suite_name": suite["name"],
        "engine_version": engine_version,
        "suite_sha256": suite["_sha256"],
        "policy_sha256": policy_hashes,
        "cases": results,
    }
