"""Embedded PBAC policy engine — deny-by-default, boot-fatal on any defect.

Implements the platform's rego-independent JSON policy format (the same
format blueeconomy-credential-verification evaluates in TypeScript), so a
single policy authoring style covers the fleet:

{
  "version": "1.0",
  "policies": [
    {"name": "...", "roles": ["firs-officer"], "resource": "assessment",
     "action": "approve", "tenant": "*", "clearance": ["*"],
     "classification": ["INTERNAL"]}
  ]
}

A request that matches no ALLOW rule is denied. A missing directory, no
policy files, malformed JSON, schema violations, duplicate rule names or
zero rules abort boot. There is no fail-open path.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from taxstamps.api.auth import Identity

_CLASSIFICATIONS = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "FIDUCIARY_SEGREGATED"}
_IDENT_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_ALLOWED_FIELDS = {"name", "roles", "resource", "action", "tenant", "clearance", "classification"}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    name: str
    roles: frozenset[str]
    resource: str
    action: str
    tenant: str
    clearance: frozenset[str]
    classification: frozenset[str]

    def matches(self, identity: Identity, resource: str, action: str, classification: str) -> bool:
        if "*" not in self.roles and not (self.roles & identity.roles):
            return False
        if self.resource != "*" and self.resource != resource:
            return False
        if self.action != "*" and self.action != action:
            return False
        if self.tenant != "*" and self.tenant != identity.tenant:
            return False
        if "*" not in self.clearance and identity.clearance not in self.clearance:
            return False
        if "*" not in self.classification and classification not in self.classification:
            return False
        return True


def _validate_rule(raw: Any, source: Path) -> Rule:
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: rule is not an object")
    unknown = set(raw) - _ALLOWED_FIELDS
    if unknown:
        raise PolicyError(f"{source}: unknown rule fields {sorted(unknown)}")
    for req in ("name", "roles", "resource", "action"):
        if req not in raw:
            raise PolicyError(f"{source}: rule missing required field {req!r}")
    name = raw["name"]
    if not isinstance(name, str) or not name:
        raise PolicyError(f"{source}: rule name must be a non-empty string")
    roles = raw["roles"]
    if not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles):
        raise PolicyError(f"{source} rule {name}: roles must be a non-empty string list")
    for ident in (raw["resource"], raw["action"]):
        if ident != "*" and (not isinstance(ident, str) or not _IDENT_RE.match(ident)):
            raise PolicyError(f"{source} rule {name}: malformed identifier {ident!r}")
    tenant = raw.get("tenant", "*")
    if not isinstance(tenant, str) or not tenant:
        raise PolicyError(f"{source} rule {name}: tenant must be a non-empty string or '*'")
    clearance = raw.get("clearance", ["*"])
    if not isinstance(clearance, list) or not all(isinstance(c, str) for c in clearance):
        raise PolicyError(f"{source} rule {name}: clearance must be a string list")
    classification = raw.get("classification", ["*"])
    if not isinstance(classification, list) or not all(isinstance(c, str) for c in classification):
        raise PolicyError(f"{source} rule {name}: classification must be a string list")
    bad = set(classification) - _CLASSIFICATIONS - {"*"}
    if bad:
        raise PolicyError(f"{source} rule {name}: unknown classification labels {sorted(bad)}")
    return Rule(
        name=name,
        roles=frozenset(roles),
        resource=raw["resource"],
        action=raw["action"],
        tenant=tenant,
        clearance=frozenset(clearance),
        classification=frozenset(classification),
    )


class PolicyEngine:
    def __init__(self, rules: list[Rule]) -> None:
        if not rules:
            raise PolicyError("no policy rules loaded")
        self._rules = rules
        self.denied_total = 0

    @classmethod
    def load(cls, policy_dir: str) -> PolicyEngine:
        d = Path(policy_dir)
        if not d.is_dir():
            raise PolicyError(f"policy directory {policy_dir} does not exist")
        files = sorted(d.glob("*.policy.json"))
        if not files:
            raise PolicyError(f"policy directory {policy_dir} contains no *.policy.json files")
        rules: list[Rule] = []
        names: set[str] = set()
        for f in files:
            try:
                doc = json.loads(f.read_text("utf-8"))
            except Exception as exc:
                raise PolicyError(f"{f}: malformed JSON: {exc}") from exc
            if not isinstance(doc, dict) or doc.get("version") != "1.0":
                raise PolicyError(f"{f}: version must be \"1.0\"")
            policies = doc.get("policies")
            if not isinstance(policies, list):
                raise PolicyError(f"{f}: policies must be an array")
            for raw in policies:
                rule = _validate_rule(raw, f)
                if rule.name in names:
                    raise PolicyError(f"{f}: duplicate rule name {rule.name!r}")
                names.add(rule.name)
                rules.append(rule)
        return cls(rules)

    def allow(self, identity: Identity, resource: str, action: str, classification: str) -> bool:
        for rule in self._rules:
            if rule.matches(identity, resource, action, classification):
                return True
        self.denied_total += 1
        return False
