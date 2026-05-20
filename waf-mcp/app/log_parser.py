"""Parse AWS WAF log entries into structured data."""

from __future__ import annotations

import json
from typing import Any


class WAFLogParseError(ValueError):
    pass


def parse_waf_log(raw: str | dict[str, Any]) -> dict[str, Any]:
    """Accept a JSON string or dict and return a normalised WAF log record.

    Raises WAFLogParseError if the payload is not recognisable as a WAF log.
    """
    if isinstance(raw, str):
        try:
            data: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise WAFLogParseError(f"Invalid JSON: {exc}") from exc
    else:
        data = raw

    # Minimal required fields
    required = {"action", "httpRequest", "terminatingRuleId"}
    # AWS WAF logs use lowercase keys in some versions
    normalised = {k.lower(): v for k, v in data.items()}

    # Try both casings
    http_request = data.get("httpRequest") or data.get("httprequest") or {}
    terminating_rule_id = (
        data.get("terminatingRuleId")
        or data.get("terminatingruleid")
        or "UNKNOWN"
    )
    terminating_rule_type = (
        data.get("terminatingRuleType")
        or data.get("terminatingruletype")
        or "UNKNOWN"
    )
    action = data.get("action") or normalised.get("action") or "UNKNOWN"
    timestamp = data.get("timestamp") or normalised.get("timestamp")
    rule_group_list = data.get("ruleGroupList") or data.get("rulegrouplist") or []
    non_terminating = (
        data.get("nonTerminatingMatchingRules")
        or data.get("nonterminatingmatchingrules")
        or []
    )

    return {
        "action": action.upper(),
        "timestamp": timestamp,
        "terminating_rule_id": terminating_rule_id,
        "terminating_rule_type": terminating_rule_type,
        "http_method": http_request.get("httpMethod") or http_request.get("httpmethod", ""),
        "uri": http_request.get("uri", ""),
        "client_ip": http_request.get("clientIp") or http_request.get("clientip", ""),
        "headers": http_request.get("headers", []),
        "args": http_request.get("args", ""),
        "rule_group_list": rule_group_list,
        "non_terminating_rules": non_terminating,
        "raw": data,
    }


def summarise_for_prompt(parsed: dict[str, Any]) -> str:
    """Return a concise, human-readable summary of the log for embedding in a prompt."""
    lines = [
        f"Action: {parsed['action']}",
        f"Terminating Rule ID: {parsed['terminating_rule_id']}",
        f"Terminating Rule Type: {parsed['terminating_rule_type']}",
        f"HTTP Method: {parsed['http_method']}",
        f"URI: {parsed['uri']}",
        f"Client IP: {parsed['client_ip']}",
    ]
    if parsed["args"]:
        lines.append(f"Query String: {parsed['args']}")
    if parsed["headers"]:
        header_strs = [
            f"  {h.get('name', '')}: {h.get('value', '')}"
            for h in parsed["headers"][:10]  # cap at 10 headers
        ]
        lines.append("Headers:\n" + "\n".join(header_strs))
    if parsed["rule_group_list"]:
        lines.append(f"Rule Groups Evaluated: {len(parsed['rule_group_list'])}")
    if parsed["non_terminating_rules"]:
        ntrs = [r.get("ruleId", r.get("ruleid", "?")) for r in parsed["non_terminating_rules"]]
        lines.append(f"Additional Matching Rules: {', '.join(ntrs)}")
    return "\n".join(lines)
