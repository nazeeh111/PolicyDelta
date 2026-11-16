"""Own the evidence for one invocation, independently of HTTP and rendering."""
from copy import deepcopy
import hashlib


class RunState:
    def __init__(self, suite: dict):
        self.report = {
            "schema_version": 2,
            "suite_name": suite["name"],
            "engine_version": None,
            "suite_sha256": suite["_sha256"],
            "policy_sha256": {
                variant: {name: hashlib.sha256(text.encode("utf-8")).hexdigest()
                          for name, text in policies.items()}
                for variant, policies in suite["_policy_texts"].items()
            },
            "execution": {"status": "running", "failures": []},
            "cases": [
                {**{key: deepcopy(case[key]) for key in
                    ("id", "principal", "method", "path", "expect")},
                 "allow_expansion": case.get("allow_expansion", False),
                 **{variant: {"status": None, "decision": "not_run", "capabilities": []}
                    for variant in ("before", "after")}}
                for case in suite["cases"]
            ],
        }
        self.at("engine_version")

    def at(self, stage: str, variant: str | None = None,
           case_id: str | None = None) -> None:
        self.location = {"stage": stage}
        if variant is not None:
            self.location["variant"] = variant
        if case_id is not None:
            self.location["case_id"] = case_id

    def fail(self, code: str, diagnostics: dict | None = None) -> None:
        failure = {**self.location, "code": code}
        if diagnostics is not None:
            failure["startup_diagnostics"] = deepcopy(diagnostics)
        self.report["execution"]["failures"].append(failure)

    @property
    def failed(self) -> bool:
        return bool(self.report["execution"]["failures"])

    def finish(self) -> dict:
        self.report["execution"]["status"] = "incomplete" if self.failed else "completed"
        return self.report
