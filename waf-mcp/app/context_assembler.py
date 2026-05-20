# context_assembler.py
"""Build the analysis context that is fed to the LLM."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx
from loguru import logger as _loguru

# Note: assuming these exist in your log_parser module
try:
    from .log_parser import parse_waf_log, summarise_for_prompt, WAFLogParseError
except ImportError:
    # Fallback placeholders for standalone testing
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
_SECTION_RE = re.compile(r'"([^"]+)"')
_MCP_MODULE = "awslabs.aws_documentation_mcp_server"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_rule_context(text: str, rule_id: str) -> str:
    """Return lines surrounding every mention of rule_id in text."""
    if not text:
        return ""
    lines = text.splitlines()
    collected: list[str] = []
    seen: set[tuple[int, int]] = set()

    for idx, line in enumerate(lines):
        if rule_id.lower() in line.lower():
            start = max(0, idx - _CONTEXT_WINDOW)
            end = min(len(lines), idx + _CONTEXT_WINDOW + 1)
            if (start, end) not in seen:
                seen.add((start, end))
                if collected:
                    collected.append("…")
                collected.extend(lines[start:end])

    return "\n".join(collected).strip()


def _parse_available_sections(captured_errors: list[str]) -> list[str]:
    """Extract quoted section names from 'Available sections: ...' error lines."""
    for msg in captured_errors:
        if "Available sections:" in msg:
            after = msg.split("Available sections:", 1)[1]
            sections = _SECTION_RE.findall(after)
            if sections:
                return sections
    return []


# ── Per-URL dynamic read ──────────────────────────────────────────────────────

async def _read_url_dynamically(
    url: str,
    rule_id: str,
    read_documentation_impl,
    session_uuid: str,
    max_length: int = 30000,
    start_index: int = 0,
) -> str:
    """Reads the entire document layout via MCP and extracts the rule context."""
    try:
        full_content = await read_documentation_impl(
            ctx=None,
            url_str=url,
            session_uuid=session_uuid,
            max_length=max_length,
            start_index=start_index
        )
    except Exception as e:
        logger.warning("Failed reading complete document layout on %s: %s", url, e)
        return ""

    if not full_content or not isinstance(full_content, str) or len(full_content.strip()) < 50:
        logger.debug("Empty page context returned for %s", url)
        return ""

    # Pull out lines surrounding the specific rule ID (e.g., CrossSiteScripting_BODY)
    excerpt = _extract_rule_context(full_content, rule_id)
    if excerpt:
        logger.info(
            "Rule context successfully isolated: rule=%s  url=%s  chars=%d",
            rule_id, url, len(excerpt),
        )
    else:
        logger.debug("Rule '%s' not explicitly mentioned in %s", rule_id, url)

    return excerpt

# ── Public API ────────────────────────────────────────────────────────────────

async def fetch_all_waf_docs(rule_id: str) -> str:
    """Read all WAF doc URLs via the AWS Documentation MCP server."""
    try:
        from awslabs.aws_documentation_mcp_server.server_aws import SESSION_UUID
        from awslabs.aws_documentation_mcp_server.server_utils import read_documentation_impl
    except ImportError as e:
        raise RuntimeError(
            f"AWS Documentation package not available: {e}. "
            "Install with: pip install awslabs.aws-documentation-mcp-server"
        ) from e

    logger.info(
        "Discovering WAF doc sections dynamically via MCP for rule '%s'.",
        rule_id,
    )

    sem = asyncio.Semaphore(1)

    async def _bounded(url: str) -> str:
        async with sem:
            try:
                return await _read_url_dynamically(
                    url, rule_id, read_documentation_impl, SESSION_UUID , max_length=5000, start_index=0
                )
            except Exception as exc:
                logger.debug("In-flight failure processing URL %s: %s", url, exc)
                return ""

    results = await asyncio.gather(
        *[_bounded(url) for url in WAF_DOCS_URLS],
        return_exceptions=True,
    )

    parts: list[str] = []
    for url, result in zip(WAF_DOCS_URLS, results):
        if isinstance(result, Exception):
            logger.warning("Error reading %s: %s", url, result)
            continue
        if result:
            parts.append(f"[Source: {url}]\n{result}")

    if not parts:
        logger.warning("Rule '%s' not found in any WAF doc page.", rule_id)
        return ""

    aggregated = "\n\n---\n\n".join(parts)
    logger.info(
        "Aggregated %d doc section(s), %d total chars, for rule '%s'.",
        len(parts), len(aggregated), rule_id,
    )
    return aggregated

async def lookup_rule_from_aws_docs(rule_id: str) -> str:
    """Return AWS docs context for rule_id.

    Step 1 — Dynamic MCP read across all WAF doc URLs.
    Step 2 — Search API fallback if nothing was found in Step 1.
    """
    docs_context = await fetch_all_waf_docs(rule_id)
    if docs_context:
        return docs_context

    # ── Search API fallback ───────────────────────────────────────────────────
    logger.info(
        "Rule '%s' not found in doc pages; falling back to search API.", rule_id
    )
    try:
        from awslabs.aws_documentation_mcp_server.server_aws import (
            SEARCH_API_URL,
            SESSION_UUID,
            DEFAULT_USER_AGENT,
        )
    except ImportError as e:
        raise RuntimeError(
            f"AWS Documentation package not available: {e}. "
            "Install with: pip install awslabs.aws-documentation-mcp-server"
        ) from e

    request_body = {
        "textQuery": {"input": f"AWS WAF managed rule {rule_id}"},
        "contextAttributes": [{"key": "domain", "value": "docs.aws.amazon.com"}],
        "acceptSuggestionBody": "RawText",
        "locales": ["en_us"],
    }
    search_url = f"{SEARCH_API_URL}?session={SESSION_UUID}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                search_url,
                json=request_body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": DEFAULT_USER_AGENT,
                    "X-MCP-Session-Id": SESSION_UUID,
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.error("Search API failed for rule '%s': %s", rule_id, exc)
        raise RuntimeError(f"AWS docs search failed for rule {rule_id}: {exc}") from exc

    parts: list[str] = []
    for suggestion in data.get("suggestions", [])[:5]:
        text = suggestion.get("textExcerptSuggestion", {})
        meta = text.get("metadata", {})
        snippet = (
            meta.get("seo_abstract")
            or text.get("summary")
            or text.get("suggestionBody")
            or ""
        )
        title = text.get("title", "")
        link = text.get("link", "")
        if snippet:
            parts.append(f"**{title}** ({link})\n{snippet}")

    if parts:
        return "\n\n".join(parts)

    raise RuntimeError(f"No documentation found for rule {rule_id}")


async def build_analysis_context(raw_log: str | dict[str, Any]) -> dict[str, Any]:
    """Parse the WAF log and return all context needed by the LLM."""
    parsed = parse_waf_log(raw_log)
    rule_id = parsed["terminating_rule_id"]

    logger.debug("Building analysis context for rule '%s'.", rule_id)
    aws_docs_context = await lookup_rule_from_aws_docs(rule_id)

    return {
        "parsed": parsed,
        "log_summary": summarise_for_prompt(parsed),
        "rule_id": rule_id,
        "rule_type": parsed["terminating_rule_type"],
        "aws_docs_context": aws_docs_context,
    }


def build_analysis_prompt(context: dict[str, Any]) -> str:
    docs_hint = (
        f"\nAWS Documentation context:\n{context['aws_docs_context']}\n"
        if context.get("aws_docs_context")
        else ""
    )
    return f"""You are a security expert helping a developer understand why AWS WAF blocked an HTTP request.
Explain the block in plain English — no jargon, no bullet-point lists. Write 2-4 clear paragraphs:
1. What happened (what the request was trying to do).
2. Why WAF blocked it (what attack pattern was detected).
3. How a legitimate developer could fix their code or request to avoid triggering this rule.

WAF log details:
{context['log_summary']}
Terminating Rule: {context['rule_id']} (type: {context['rule_type']}){docs_hint}

Explanation:"""


def build_rule_explanation_prompt(rule_id: str, rule_type: str, aws_docs_context: str = "") -> str:
    docs_hint = (
        f"\nAWS Documentation context:\n{aws_docs_context}\n"
        if aws_docs_context
        else ""
    )
    return f"""You are an AWS security expert.
Explain in plain English what the AWS WAF rule '{rule_id}' (type: {rule_type}) does,
what attack it protects against, and what a developer should check if their legitimate
request triggered it. Write 2-3 clear, jargon-free paragraphs.{docs_hint}

Explanation:"""