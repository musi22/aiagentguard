from agentguard_policy import evaluate, parse_policy, validate_policy
from agentguard_risk import score
from agentguard_shared import scan_and_redact, validate_custom_patterns


REFUND = {
    "id": "refund",
    "version": 7,
    "priority": 10,
    "document": {
        "name": "refund",
        "subject": {"agent": "refund-agent"},
        "resource": {"tool": "stripe.refund"},
        "rules": [
            {"when": {"amount_lte": 500}, "action": "allow", "reason": "small refund"},
            {"when": {"amount_gt": 500, "amount_lte": 5000}, "action": "require_approval"},
            {"when": {"amount_gt": 5000}, "action": "deny"},
        ],
    },
}


def test_refund_policy_decimal_boundaries_and_default_deny():
    base = {"agent": "refund-agent", "tool": "stripe.refund"}
    assert evaluate([REFUND], {**base, "amount": "500.00"})["decision"] == "allow"
    result = evaluate([REFUND], {**base, "amount": "500.01"})
    assert result["decision"] == "require_approval" and result["policy_version"] == 7
    assert evaluate([REFUND], {**base, "amount": "10000"})["decision"] == "deny"
    assert evaluate([REFUND], {**base, "amount": "NaN"})["decision"] == "deny"
    assert evaluate([REFUND], {**base, "amount": 1, "tool": "other"})["decision"] == "deny"


def test_nested_logic_priority_and_deny_tie():
    allow = {
        "id": "a",
        "priority": 2,
        "document": {
            "name": "a",
            "rules": [
                {"when": {"all": [{"context.environment": "prod"}, {"tags_contains": "safe"}]}, "action": "allow"}
            ],
        },
    }
    deny = {
        "id": "d",
        "priority": 2,
        "document": {"name": "d", "rules": [{"when": {"context.environment": "prod"}, "action": "deny"}]},
    }
    result = evaluate([allow, deny], {"context": {"environment": "prod"}, "tags": ["safe"]})
    assert result["decision"] == "deny" and result["policy_id"] == "d"
    allow["priority"] = 3
    assert evaluate([allow, deny], {"context": {"environment": "prod"}, "tags": ["safe"]})["decision"] == "allow"


def test_policy_parse_yaml_and_reject_unknown_operator():
    assert parse_policy("name: x\nrules:\n  - when: {}\n    action: deny\n")["name"] == "x"
    result = validate_policy({"name": "bad", "rules": [{"when": {"amount_between": [1, 2]}, "action": "allow"}]})
    assert result["valid"] is False
    assert evaluate([{"document": result}], {})["decision"] == "deny"


def test_risk_score_is_bounded_explainable_and_ignores_supplied_risk_score():
    result = score(
        {"financial": True, "destructive": True, "sensitive_data": True, "environment": "production"},
        {},
        {"amount": 10000, "risk_score": -500},
        {"tool_uses": 0, "agent_uses": 0, "incidents": 2},
    )
    assert result["score"] == 100
    assert all(set(item) == {"reason", "points"} for item in result["factors"])
    assert score({}, {}, {"risk_score": 100}, {"tool_uses": 1, "agent_uses": 1})["score"] == 0
    assert score({"environment": []}, None, {"arguments": None}, {"known_destinations": {}})["score"] == 15


def test_recursive_dlp_luhn_credentials_and_paths():
    value = {
        "password": "should never survive",
        "nested": ["mail me a@example.com", "card 4242 4242 4242 4242", "ghp_abcdefghijklmnopqrstuvwxyz123456"],
    }
    result = scan_and_redact(value)
    assert result["sanitized"]["password"] == "[REDACTED]"  # noqa: S105
    assert "4242" not in result["sanitized"]["nested"][1]
    assert result["has_secrets"] is True
    assert {item["path"] for item in result["findings"]} >= {"$.password", "$.nested[0]", "$.nested[1]", "$.nested[2]"}
    assert scan_and_redact({"monkey": "banana"})["sanitized"] == {"monkey": "banana"}


def test_custom_regex_is_bounded():
    assert scan_and_redact("employee-123", [{"name": "employee", "pattern": r"employee-[0-9][0-9][0-9]"}])[
        "has_secrets"
    ]
    try:
        validate_custom_patterns([{"name": "evil", "pattern": "(a+)+$"}])
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe regex accepted")
