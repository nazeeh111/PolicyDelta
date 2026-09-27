"""Load and validate a local PolicyDelta fixture suite without side effects."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from pathlib import Path
from typing import Any


class SuiteError(ValueError):
    """The suite or one of its local policy files is invalid."""


_NAME = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z", re.ASCII)
_SECRET_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+\Z", re.ASCII)
_METHODS = {"GET", "POST", "DELETE", "LIST"}
_DECISIONS = {"allow", "deny"}
_BUILTIN_MOUNTS = {"sys", "auth", "cubbyhole", "identity"}
_MAX_SUITE_BYTES = 1024 * 1024
_MAX_POLICY_BYTES = 256 * 1024


def _fail(message: str) -> None:
    raise SuiteError(message)


def _object(value: Any, label: str, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing or extra:
        _fail(f"{label} has missing or unknown keys")
    return value


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        _fail(f"{label} must match [a-z][a-z0-9_-]{{0,39}}")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    _fail(f"nonfinite JSON number: {value}")


def _check_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        _fail("suite contains a nonfinite JSON number")
    if isinstance(value, dict):
        for child in value.values():
            _check_finite(child)
    elif isinstance(value, list):
        for child in value:
            _check_finite(child)


def _relative_segments(value: Any, label: str, *, allow_current: bool = False) -> list[str]:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        _fail(f"{label} must be a relative slash-separated path")
    parts = value.split("/")
    forbidden = ("", "..") if allow_current else ("", ".", "..")
    if any(part in forbidden for part in parts) or (allow_current and all(part == "." for part in parts)):
        _fail(f"{label} contains an empty or dot segment")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise SuiteError(f"{label} must be valid Unicode") from error
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        _fail(f"{label} contains a control character")
    return parts


def _policy_text(root: Path, relative: Any) -> str:
    parts = _relative_segments(relative, "policy file", allow_current=True)
    try:
        resolved = (root / Path(*parts)).resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            _fail("policy file must resolve to a file inside the suite directory")
        with resolved.open("rb") as stream:
            raw = stream.read(_MAX_POLICY_BYTES + 1)
    except (OSError, RuntimeError) as error:
        raise SuiteError("cannot read policy file") from error
    if len(raw) > _MAX_POLICY_BYTES:
        _fail("policy file exceeds 256 KiB")
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise SuiteError("policy file must be UTF-8") from error


def _validate_mounts(mounts: Any) -> dict:
    if not isinstance(mounts, dict) or len(mounts) > 8:
        _fail("mounts must be an object with at most 8 entries")
    total_secrets = 0
    for mount_name, mount in mounts.items():
        _name(mount_name, "mount name")
        if mount_name in _BUILTIN_MOUNTS:
            _fail(f"mount name {mount_name} is reserved by OpenBao")
        _object(mount, f"mount {mount_name}", {"version", "secrets"})
        if type(mount["version"]) is not int or mount["version"] not in (1, 2):
            _fail(f"mount {mount_name} version must be integer 1 or 2")
        secrets = mount["secrets"]
        if not isinstance(secrets, dict):
            _fail(f"mount {mount_name} secrets must be an object")
        total_secrets += len(secrets)
        if total_secrets > 100:
            _fail("suite has more than 100 fixture secrets")
        for key, value in secrets.items():
            parts = _relative_segments(key, "secret key")
            if any(not _SECRET_SEGMENT.fullmatch(part) for part in parts):
                _fail("secret key must use ASCII URL-safe segments")
            if not isinstance(value, dict):
                _fail("fixture secret value must be a JSON object")
    return mounts


def _validate_policies(policies: Any, root: Path) -> dict[str, dict[str, str]]:
    _object(policies, "policies", {"before", "after"})
    texts: dict[str, dict[str, str]] = {}
    for variant in ("before", "after"):
        entries = policies[variant]
        if not isinstance(entries, dict) or len(entries) > 16:
            _fail(f"{variant} policies must be an object with at most 16 entries")
        texts[variant] = {}
        for name, relative in entries.items():
            _name(name, "policy name")
            if name in ("root", "default"):
                _fail(f"policy name {name} is reserved")
            texts[variant][name] = _policy_text(root, relative)
    return texts


def _validate_principals(principals: Any, policies: dict) -> dict:
    if not isinstance(principals, dict) or len(principals) > 16:
        _fail("principals must be an object with at most 16 entries")
    for principal, names in principals.items():
        _name(principal, "principal name")
        if not isinstance(names, list) or not names:
            _fail(f"principal {principal} needs a nonempty policy list")
        if len(names) != len(set(name for name in names if isinstance(name, str))):
            _fail(f"principal {principal} repeats a policy")
        for name in names:
            _name(name, "principal policy name")
            if name not in policies["before"] or name not in policies["after"]:
                _fail(f"principal {principal} references an absent policy")
    return principals


def _validate_request_path(value: Any, mounts: dict) -> None:
    parts = _relative_segments(value, "case path")
    if any(ch in value for ch in ("%", "?", "#")):
        _fail("case path contains a forbidden URL character")
    if any(not _SECRET_SEGMENT.fullmatch(part) for part in parts):
        _fail("case path must use ASCII URL-safe segments")
    if len(parts) < 2 or parts[0] not in mounts:
        _fail("case path must remain within a declared mount")
    if mounts[parts[0]]["version"] == 2 and (len(parts) < 3 or parts[1] not in ("data", "metadata")):
        _fail("KV-v2 case path needs an explicit data/ or metadata/ API path")


def _validate_cases(cases: Any, mounts: dict, principals: dict) -> list:
    if not isinstance(cases, list) or not 1 <= len(cases) <= 100:
        _fail("cases must be a list with 1 to 100 entries")
    seen = set()
    for case in cases:
        _object(case, "case", {"id", "principal", "method", "path", "expect"}, {"body", "allow_expansion"})
        case_id = _name(case["id"], "case ID")
        if case_id in seen:
            _fail(f"duplicate case ID: {case_id}")
        seen.add(case_id)
        if not isinstance(case["principal"], str) or case["principal"] not in principals:
            _fail(f"case {case_id} references an unknown principal")
        if not isinstance(case["method"], str) or case["method"] not in _METHODS:
            _fail(f"case {case_id} has an invalid method")
        _validate_request_path(case["path"], mounts)
        if case["method"] == "POST":
            if "body" not in case or not isinstance(case["body"], dict):
                _fail(f"POST case {case_id} needs an object body")
        elif "body" in case:
            _fail(f"{case['method']} case {case_id} cannot have a body")
        _object(case["expect"], f"case {case_id} expect", {"before", "after"})
        if any(not isinstance(case["expect"][variant], str) or case["expect"][variant] not in _DECISIONS for variant in ("before", "after")):
            _fail(f"case {case_id} has an invalid expectation")
        if "allow_expansion" in case and type(case["allow_expansion"]) is not bool:
            _fail(f"case {case_id} allow_expansion must be boolean")
        case.setdefault("allow_expansion", False)
    return cases


def load_suite(path: Path) -> dict:
    """Return validated input with resolved root, SHA-256 and policy texts."""
    try:
        suite_path = Path(path).resolve(strict=True)
        if not suite_path.is_file():
            _fail("suite path must be a file")
        with suite_path.open("rb") as stream:
            raw = stream.read(_MAX_SUITE_BYTES + 1)
    except (OSError, RuntimeError, TypeError) as error:
        raise SuiteError("cannot read suite file") from error
    if len(raw) > _MAX_SUITE_BYTES:
        _fail("suite JSON exceeds 1 MiB")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except SuiteError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise SuiteError("suite must be valid UTF-8 JSON") from error
    _check_finite(data)
    _object(data, "suite", {"version", "name", "mounts", "policies", "principals", "cases"})
    if type(data["version"]) is not int or data["version"] != 1:
        _fail("suite version must be integer 1")
    if not isinstance(data["name"], str) or not 1 <= len(data["name"]) <= 160:
        _fail("suite name must contain 1 to 160 characters")
    try:
        data["name"].encode("utf-8")
    except UnicodeError as error:
        raise SuiteError("suite name must be valid Unicode") from error
    root = suite_path.parent
    mounts = _validate_mounts(data["mounts"])
    texts = _validate_policies(data["policies"], root)
    principals = _validate_principals(data["principals"], data["policies"])
    _validate_cases(data["cases"], mounts, principals)
    data["_root"] = root
    data["_sha256"] = hashlib.sha256(raw).hexdigest()
    data["_policy_texts"] = texts
    return data
