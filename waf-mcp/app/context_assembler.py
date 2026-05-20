"""Build prompts for WAF log analysis."""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

try:
    from .log_parser import parse_waf_log, summarise_for_prompt
except ImportError:
    def parse_waf_log(log): return {"terminating_rule_id": "CrossSiteScripting_BODY", "terminating_rule_type": "REGULAR"}
    def summarise_for_prompt(parsed): return "Log Summary Placeholder"

logger = logging.getLogger(__name__)

WAF_DOCS_URLS = [
    "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html",
    "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html",
    "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html",
    "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html",
    "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-acfp.html",
    "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html",
    "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-anti-ddos.html",
]

_CONTEXT_WINDOW = 20


def _extract_rule_context(text: str, rule_id: str) -> str:
    """Return lines surrounding every mention of rule_id (or its variations) in text."""
    if not text:
        return ""
    
    lines = text.splitlines()
    collected, seen = [], set()
    
    # Generate match terms to maximize hits for rule groups
    # e.g., "AWSManagedRulesSQLiRuleGroup" -> ["awsmanagedrulessqlirulegroup", "sqli"]
    match_terms = [rule_id.lower()]
    
    # If it's an AWS Managed Rule Group identifier, extract the core name
    if rule_id.startswith("AWSManagedRules") and rule_id.endswith("RuleGroup"):
        core_name = rule_id[15:-9] # Strips "AWSManagedRules" and "RuleGroup"
        if core_name:
            match_terms.append(core_name.lower()) # e.g., "sqli"
            
    for idx, line in enumerate(lines):
        # Check if any of our match terms are in the current line
        if any(term in line.lower() for term in match_terms):
            start, end = max(0, idx - _CONTEXT_WINDOW), min(len(lines), idx + _CONTEXT_WINDOW + 1)
            if (start, end) not in seen:
                seen.add((start, end))
                if collected:
                    collected.append("…")
                collected.extend(lines[start:end])
                
    return "\n".join(collected).strip()


async def fetch_waf_docs(rule_id: str) -> str:
    """Fetch AWS WAF documentation for rule_id, with a search API fallback."""
    try:
        from awslabs.aws_documentation_mcp_server.server_aws import SESSION_UUID
        from awslabs.aws_documentation_mcp_server.server_utils import read_documentation_impl
    except ImportError as e:
        raise RuntimeError(f"AWS Documentation package not available: {e}") from e

    sem = asyncio.Semaphore(1)

    async def _fetch(url: str) -> str:
        async with sem:
            try:
                content = await read_documentation_impl(
                    ctx=None, url_str=url, session_uuid=SESSION_UUID, max_length=30000, start_index=0
                )
                return _extract_rule_context(content or "", rule_id)
            except Exception as e:
                logger.debug("Failed reading %s: %s", url, e)
                return ""

    results = await asyncio.gather(*[_fetch(url) for url in WAF_DOCS_URLS], return_exceptions=True)

    parts = [
        f"[Source: {url}]\n{result}"
        for url, result in zip(WAF_DOCS_URLS, results)
        if isinstance(result, str) and result
    ]
    if parts:
        logger.info("Found docs for rule '%s' in %d page(s).", rule_id, len(parts))
        return "\n\n---\n\n".join(parts)

    # Fallback: search API
    logger.info("Rule '%s' not found in doc pages; falling back to search API.", rule_id)
    return await _search_waf_docs(rule_id)


async def _search_waf_docs(rule_id: str) -> str:
    """Search API fallback when rule is not found in any doc page."""
    from awslabs.aws_documentation_mcp_server.server_aws import SEARCH_API_URL, SESSION_UUID, DEFAULT_USER_AGENT

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SEARCH_API_URL}?session={SESSION_UUID}",
            json={
                "textQuery": {"input": f"AWS WAF managed rule {rule_id}"},
                "contextAttributes": [{"key": "domain", "value": "docs.aws.amazon.com"}],
                "acceptSuggestionBody": "RawText",
                "locales": ["en_us"],
            },
            headers={
                "Content-Type": "application/json",
                "User-Agent": DEFAULT_USER_AGENT,
                "X-MCP-Session-Id": SESSION_UUID,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()

    parts = []
    for suggestion in data.get("suggestions", [])[:5]:
        text = suggestion.get("textExcerptSuggestion", {})
        snippet = (
            text.get("metadata", {}).get("seo_abstract")
            or text.get("summary")
            or text.get("suggestionBody")
            or ""
        )
        if snippet:
            parts.append(f"**{text.get('title', '')}** ({text.get('link', '')})\n{snippet}")

    if not parts:
        raise RuntimeError(f"No documentation found for rule '{rule_id}'")
    return "\n\n".join(parts)


async def build_analysis_prompt(raw_log: str | dict[str, Any]) -> tuple[str, dict]:
    """Parse a WAF log and return (prompt, metadata).

    Metadata contains rule_id and rule_type for logging/error messages in the caller.
    """
    parsed = parse_waf_log(raw_log)
    rule_id = parsed["terminating_rule_id"]
    rule_type = parsed["terminating_rule_type"]

    docs = await fetch_waf_docs(rule_id)
    docs_section = f"\nAWS Documentation:\n{docs}\n" if docs else ""

    prompt = f"""You are a security engineer reviewing an AWS WAF blocked request.
Respond with exactly two sections. No bullet points, no extra sections, no preamble.

## RCA
2-3 sentences: identify the exact field or value in this request that triggered the rule, \
name the attack class the rule detects, and explain why it matched. Stay specific to the log below.

## Resolution
2-3 sentences: tell the devops/developer exactly what to change in waf rules or their code. \
Be concrete — name the parameter, encoding, or sanitisation method. \
If this looks like a false positive, say so and explain why.

WAF log:
{summarise_for_prompt(parsed)}
Rule: {rule_id} (type: {rule_type}){docs_section}"""

    return prompt, {"rule_id": rule_id, "rule_type": rule_type}
    """Build an explanation prompt for a specific WAF rule."""
    docs = await fetch_waf_docs(rule_id)
    docs_section = f"\nAWS Documentation:\n{docs}\n" if docs else ""

    return f"""You are an AWS security engineer.
Respond with exactly two sections. No bullet points, no extra sections, no preamble.

## RCA
2-3 sentences: what this rule inspects, what attack class it defends against, \
and what pattern in a request causes it to fire.

## Resolution
2-3 sentences: what a developer should audit in their application \
if a legitimate request is triggering this rule.

Rule: {rule_id} (type: {rule_type}){docs_section}"""