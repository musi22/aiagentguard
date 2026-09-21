"""Deterministic, fail-closed AgentGuard policy evaluation.

Higher numeric priority wins. At equal priority deny wins, then approval,
then allow. Non-terminal actions are obligations and never grant authority.
"""

from __future__ import annotations

import copy
import json
from decimal import Decimal, InvalidOperation
from typing import Any

import yaml

ACTIONS = {"allow", "deny", "require_approval", "warn", "redact", "rate_limit"}
OPS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "exists"}
FIELDS = {
    "organization",
    "organization_id",
    "workspace",
    "workspace_id",
    "team",
    "team_id",
    "user",
    "user_id",
    "agent",
    "agent_id",
    "tool",
    "tool_id",
    "provider",
    "amount",
    "environment",
    "resource",
    "customer",
    "customer_id",
    "time",
    "ip",
    "tags",
    "risk_score",
    "data_classification",
    "request_count",
    "destination",
}
MISSING = object()


def _key(key: str) -> tuple[str, str]:
    if not isinstance(key, str) or not key or len(key) > 256:
        raise ValueError("Condition key must be a nonempty field path")
    # Long operators must precede their suffixes (not_in before in).
    for op in sorted(OPS, key=len, reverse=True):
        suffix = "_" + op
        if key.endswith(suffix):
            return key[: -len(suffix)], op
    if key in FIELDS or "." in key:
        return key, "eq"
    raise ValueError(f"Unknown condition field or operator: {key}")


def _validate_when(when: Any, depth: int = 0) -> None:
    if depth > 16 or not isinstance(when, dict) or len(when) > 64:
        raise ValueError("Conditions must be bounded objects")
    for key, value in when.items():
        if key in {"all", "any"}:
            if not isinstance(value, list) or not value or len(value) > 64:
                raise ValueError(f"{key} requires a nonempty bounded list")
            for clause in value:
                _validate_when(clause, depth + 1)
        elif key == "not":
            _validate_when(value, depth + 1)
        else:
            field, op = _key(key)
            if not field or field.startswith(".") or field.endswith(".") or ".." in field:
                raise ValueError("Invalid condition path")
            if op in {"in", "not_in"} and (not isinstance(value, list) or len(value) > 256):
                raise ValueError(f"{op} requires a bounded list")
            if op == "exists" and not isinstance(value, bool):
                raise ValueError("exists requires a boolean")
            if op in {"gt", "gte", "lt", "lte"}:
                _decimal(value)
            elif not isinstance(value, (str, int, float, bool, list, type(None))):
                raise ValueError("Unsupported condition value")


def validate_policy(document: Any) -> dict:
    errors: list[str] = []
    try:
        if not isinstance(document, dict):
            raise ValueError("Policy must be an object")
        unknown = set(document) - {
            "name",
            "description",
            "subject",
            "resource",
            "rules",
            "priority",
            "id",
            "version",
            "enabled",
        }
        if unknown:
            raise ValueError(f"Unknown policy keys: {', '.join(sorted(unknown))}")
        for scope in ("subject", "resource"):
            selector = document.get(scope, {})
            if not isinstance(selector, dict):
                raise ValueError(f"{scope} must be an object")
            _validate_when(selector)
        rules = document.get("rules")
        if not isinstance(rules, list) or not rules or len(rules) > 256:
            raise ValueError("Policy requires 1..256 rules")
        if isinstance(document.get("priority", 0), bool) or not isinstance(document.get("priority", 0), int):
            raise ValueError("Policy priority must be an integer")
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) - {"when", "action", "reason", "obligations"}:
                raise ValueError("Malformed rule")
            if rule.get("action") not in ACTIONS:
                raise ValueError("Unknown policy action")
            if not isinstance(rule.get("reason", ""), str):
                raise ValueError("Rule reason must be a string")
            if not isinstance(rule.get("obligations", {}), (dict, list)):
                raise ValueError("Rule obligations must be an object or list")
            _validate_when(rule.get("when", {}))
        normalized = copy.deepcopy(document)
        json.dumps(normalized, allow_nan=False)
    except (ValueError, TypeError, InvalidOperation) as exc:
        errors.append(str(exc))
        normalized = None
    return {"valid": not errors, "errors": errors, "document": normalized}


def parse_policy(value: str | dict) -> dict:
    if isinstance(value, str):
        if len(value) > 262144:
            raise ValueError("Policy is too large")
        try:
            value = yaml.safe_load(value)
        except yaml.YAMLError as exc:
            raise ValueError("Malformed YAML policy") from exc
    result = validate_policy(value)
    if not result["valid"]:
        raise ValueError("; ".join(result["errors"]))
    return result["document"]


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ValueError("Expected finite numeric value")
    if len(str(value)) > 128:
        raise ValueError("Numeric value is too large")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("Expected finite numeric value") from exc
    if not result.is_finite():
        raise ValueError("Expected finite numeric value")
    return result


def _get(facts: dict, path: str) -> Any:
    current: Any = facts
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    # Registry objects are selected by stable id or configured name, not repr.
    if isinstance(current, dict) and path in {"agent", "tool", "team", "workspace", "organization"}:
        return current.get("id", current.get("name", MISSING))
    return current


def _when(when: dict, facts: dict) -> bool:
    for key, expected in when.items():
        if key == "all":
            ok = all(_when(clause, facts) for clause in expected)
        elif key == "any":
            ok = any(_when(clause, facts) for clause in expected)
        elif key == "not":
            ok = not _when(expected, facts)
        else:
            path, op = _key(key)
            actual = _get(facts, path)
            if op == "exists":
                ok = (actual is not MISSING) == expected
            elif actual is MISSING:
                ok = False
            elif op in {"gt", "gte", "lt", "lte"}:
                left, right = _decimal(actual), _decimal(expected)
                ok = {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[op]
            elif op in {"eq", "ne"}:
                # Do not allow Python's True == 1 coercion to bypass conditions.
                eq = actual == expected and (isinstance(actual, bool) == isinstance(expected, bool))
                if path == "amount" and not isinstance(actual, bool):
                    eq = _decimal(actual) == _decimal(expected)
                ok = eq if op == "eq" else not eq
            elif op in {"in", "not_in"}:
                contained = any(
                    actual == item and (isinstance(actual, bool) == isinstance(item, bool)) for item in expected
                )
                ok = contained if op == "in" else not contained
            else:
                ok = isinstance(actual, (str, list)) and expected in actual
        if not ok:
            return False
    return True


def evaluate(policies: list[dict], facts: dict) -> dict:
    default: dict[str, Any] = {
        "decision": "deny",
        "reason": "No matching allow policy; deny by default",
        "policy_id": None,
        "policy_version": None,
        "obligations": [],
    }
    if not isinstance(policies, list) or not isinstance(facts, dict) or len(policies) > 1024:
        return {**default, "reason": "Malformed policy evaluation input"}
    matches: list[tuple[int, int, str, dict, dict]] = []
    obligations: list[dict] = []
    severity = {"allow": 1, "require_approval": 2, "deny": 3}
    try:
        for outer in policies:
            if not isinstance(outer, dict):
                raise ValueError("Malformed stored policy")
            doc = parse_policy(outer.get("document", outer))
            if outer.get("enabled", doc.get("enabled", True)) is False:
                continue
            priority = outer.get("priority", doc.get("priority", 0))
            if isinstance(priority, bool) or not isinstance(priority, int):
                raise ValueError("Invalid policy priority")
            if not _when(doc.get("subject", {}), facts) or not _when(doc.get("resource", {}), facts):
                continue
            for rule in doc["rules"]:
                if _when(rule.get("when", {}), facts):
                    action = rule["action"]
                    meta = {
                        "id": outer.get("id", doc.get("id", doc.get("name"))),
                        "version": outer.get("version", doc.get("version", 1)),
                    }
                    if action in severity:
                        matches.append((priority, severity[action], str(meta["id"]), rule, meta))
                    else:
                        obligations.append(
                            {
                                "action": action,
                                "policy_id": meta["id"],
                                "parameters": rule.get("obligations", {}),
                                "reason": rule.get("reason", ""),
                            }
                        )
        if not matches:
            return {**default, "obligations": obligations}
        priority, rank, _, rule, meta = sorted(matches, key=lambda item: (-item[0], -item[1], item[2]))[0]
        if rule.get("obligations"):
            obligations.append({"action": "constraints", "parameters": rule["obligations"], "policy_id": meta["id"]})
        return {
            "decision": rule["action"],
            "reason": rule.get("reason") or f"Matched {rule['action']} policy",
            "policy_id": meta["id"],
            "policy_version": meta["version"],
            "obligations": obligations,
        }
    except (ValueError, TypeError, KeyError, InvalidOperation, RecursionError) as exc:
        return {**default, "reason": f"Policy evaluation failed closed: {exc}"}
