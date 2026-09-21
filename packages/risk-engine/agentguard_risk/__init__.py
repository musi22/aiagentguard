"""Explainable risk scores. Registry and history inputs must be server-owned."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation


def _number(value) -> Decimal:
    try:
        text = str(value)
        if len(text) > 128:
            return Decimal(0)
        number = Decimal(text)
        return number if number.is_finite() and number >= 0 else Decimal(0)
    except (InvalidOperation, ValueError):
        return Decimal(0)


def score(tool: dict, agent: dict, context: dict, history: dict) -> dict:
    tool = tool if isinstance(tool, dict) else {}
    agent = agent if isinstance(agent, dict) else {}
    context = context if isinstance(context, dict) else {}
    history = history if isinstance(history, dict) else {}
    factors: list[dict] = []

    def add(reason: str, points: int, condition: bool):
        if condition:
            factors.append({"reason": reason, "points": points})

    add("Financial operation", 25, tool.get("financial") is True)
    add("Destructive operation", 30, tool.get("destructive") is True)
    add("Write operation", 5, tool.get("read_write_classification") in ("write", "read_write"))
    add("Production environment", 20, tool.get("environment", agent.get("environment")) in ("production", "prod"))
    add("Sensitive data", 10, tool.get("sensitive_data") is True)
    add("First tool use", 10, history.get("tool_uses", 0) == 0)
    add("New agent", 5, history.get("agent_uses", 0) == 0)
    raw_arguments = context.get("arguments")
    arguments = raw_arguments if isinstance(raw_arguments, dict) else {}
    amount = _number(context.get("amount", arguments.get("amount", 0)))
    historical = _number(history.get("average_amount", 0))
    add("Amount above historical average", 15, amount > historical * 2 and historical > 0)
    add("High transaction amount", 15, amount > 5000)
    add(
        "Unusual request frequency",
        8,
        _number(history.get("recent_requests", 0)) > max(Decimal(20), _number(history.get("average_frequency", 0)) * 3),
    )
    known_destinations = history.get("known_destinations", [])
    known_destinations = known_destinations if isinstance(known_destinations, (list, tuple)) else []
    add(
        "New destination",
        8,
        bool(context.get("destination")) and context.get("destination") not in known_destinations,
    )
    add("Unusual parameters", 8, history.get("unusual_parameters") is True)
    add("Previous incidents", 12, _number(history.get("incidents", 0)) > 0)
    return {"score": min(100, sum(factor["points"] for factor in factors)), "factors": factors}
