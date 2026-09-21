"""Structured redaction for audit, notification, and tool payloads.

Custom patterns intentionally accept a safe regex subset (no repetition or
lookarounds); production may use a linear-time engine for broader expressions.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "[REDACTED]"
SECRET_KEYS = re.compile(
    r"^(?:.*[_.-])?(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?token|accesstoken|refresh[_-]?token|refreshtoken|authorization|private[_-]?key|privatekey|client[_-]?secret|clientsecret|database[_-]?(?:url|password)|connection[_-]?string|credential)s?$",
    re.I,
)
PATTERNS = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
    ),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "api_key",
        re.compile(
            r"\b(?:sk_(?:live|test)_[A-Za-z0-9]{8,255}|sk-[A-Za-z0-9_-]{16,255}|ag_[A-Za-z0-9_-]{16,255}|xox[baprs]-[A-Za-z0-9-]{8,255})\b"
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{2,4096}\.[A-Za-z0-9_-]{2,4096}\.[A-Za-z0-9_-]{2,4096}\b")),
    (
        "database_credential",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]{1,256}:[^\s/@]{1,256}@[^\s]{1,2048}", re.I
        ),
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")),
    ("phone", re.compile(r"(?<!\w)\+[1-9][0-9 ()-]{7,18}[0-9](?!\w)")),
]
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def validate_custom_patterns(patterns: list[dict] | None) -> list[tuple[str, re.Pattern]]:
    if patterns is None:
        return []
    if not isinstance(patterns, list) or len(patterns) > 32:
        raise ValueError("Custom patterns must be a list of at most 32 objects")
    compiled = []
    for entry in patterns:
        if not isinstance(entry, dict):
            raise ValueError("Custom pattern must be an object")
        expression = entry.get("pattern", "")
        name = entry.get("name", "custom")
        if (
            not isinstance(expression, str)
            or not expression
            or len(expression) > 256
            or not isinstance(name, str)
            or len(name) > 64
        ):
            raise ValueError("Invalid custom pattern")
        # Prevent backtracking explosions rather than attempting regex timeouts.
        if any(token in expression for token in ("*", "+", "{", "}", "(", ")", "|")) or re.search(
            r"\\[1-9]", expression
        ):
            raise ValueError("Custom regex only allows literals, classes, ?, and anchors")
        try:
            compiled.append((name, re.compile(expression)))
        except re.error as exc:
            raise ValueError("Invalid custom regex") from exc
    return compiled


def _luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19 or len(set(digits)) == 1:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            digit = digit - 9 if digit > 9 else digit
        total += digit
    return total % 10 == 0


def scan_and_redact(value: Any, custom_patterns: list[dict] | None = None) -> dict:
    patterns = PATTERNS + validate_custom_patterns(custom_patterns)
    findings: list[dict] = []
    secret_found = False
    nodes = 0

    def finding(kind: str, path: str):
        nonlocal secret_found
        findings.append({"kind": kind, "path": path})
        if kind not in {"email", "phone"}:
            secret_found = True

    def visit(item: Any, path: str, depth: int):
        nonlocal nodes
        nodes += 1
        if depth > 32 or nodes > 10000:
            finding("payload_limit", path)
            return MASK
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                key = str(key)
                child_path = f"{path}.{key}"
                if SECRET_KEYS.search(key):
                    finding("secret_field", child_path)
                    result[key] = MASK
                else:
                    result[key] = visit(child, child_path, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            return [visit(child, f"{path}[{index}]", depth + 1) for index, child in enumerate(item)]
        if not isinstance(item, str):
            return item
        if len(item) > 1048576:
            finding("payload_limit", path)
            return MASK
        for kind, pattern in patterns:

            def replace(match, kind=kind):
                finding(kind, path)
                return MASK

            item = pattern.sub(replace, item)

        def card_replace(match):
            if _luhn(match.group()):
                finding("credit_card", path)
                return MASK
            return match.group()

        return CARD.sub(card_replace, item)

    sanitized = visit(value, "$", 0)
    return {"sanitized": sanitized, "findings": findings, "has_secrets": secret_found}
