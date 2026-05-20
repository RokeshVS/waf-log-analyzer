"""FastMCP server exposing WAF analysis tools."""
from __future__ import annotations

import logging

from fastmcp import FastMCP

from .context_assembler import build_analysis_prompt, fetch_waf_docs
from .llm_client import generate, check_health
from .log_parser import WAFLogParseError

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="aws-waf-analyzer",
    instructions=(
        "Analyses AWS WAF blocked-request logs and explains them in plain English. "
        "Use analyze_waf_log to understand a block, explain_waf_rule to learn about a rule, "
        "and check_ollama_health to verify the LLM backend."
    ),
)


@mcp.tool()
async def analyze_waf_log(waf_log: str) -> str:
    """Analyse an AWS WAF blocked-request log and explain why it was blocked.

    Args:
        waf_log: Raw AWS WAF log entry as a JSON string.
                 Must contain at least 'action', 'httpRequest', and 'terminatingRuleId'.
    """
    try:
        prompt, meta = await build_analysis_prompt(waf_log)
        logger.info("Analysing rule=%s type=%s", meta["rule_id"], meta["rule_type"])
    except WAFLogParseError as e:
        return f"Could not parse WAF log: {e}\n\nPlease supply a valid AWS WAF JSON log entry."
    except Exception as e:
        logger.error("Error building prompt: %s", e, exc_info=True)
        return f"Error building prompt: {e}"

    try:
        return await generate(prompt)
    except Exception as e:
        logger.error("LLM generation failed: %s", e, exc_info=True)
        return (
            f"Log parsed (rule: {meta['rule_id']}) but LLM unreachable.\n"
            f"Error: {e}\n"
            f"Ensure Ollama is running at the configured OLLAMA_BASE_URL and the model is pulled."
        )


@mcp.tool()
async def check_ollama_health() -> str:
    """Check whether Ollama is reachable and the configured model is available."""
    status = await check_health()
    return "\n".join(f"{k}: {v}" for k, v in status.items())


@mcp.tool()
async def lookup_waf_rule_docs(rule_id: str) -> str:
    """Fetch live AWS documentation for a WAF rule.

    Args:
        rule_id: The AWS WAF rule ID (e.g. 'CrossSiteScripting_BODY').
    """
    try:
        return await fetch_waf_docs(rule_id)
    except Exception as e:
        logger.error("Docs lookup failed for %s: %s", rule_id, e, exc_info=True)
        raise