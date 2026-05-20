"""FastMCP server exposing WAF analysis tools."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastmcp import FastMCP

from .context_assembler import (
    build_analysis_context,
    build_analysis_prompt,
    build_rule_explanation_prompt,
    lookup_rule_from_aws_docs
)
from .llm_client import generate, check_health
from .log_parser import WAFLogParseError

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="aws-waf-analyzer",
    instructions=(
        "This server analyses AWS WAF blocked-request logs and explains them in plain English. "
        "Use analyze_waf_log to understand why a request was blocked, "
        "explain_block_reason to learn about a specific WAF rule, "
        "and check_aws_docs_health to verify AWS documentation is available."
    ),
)


@mcp.tool()
async def analyze_waf_log(waf_log: str) -> str:
    """Analyse an AWS WAF blocked-request log entry and explain it in plain English.

    Args:
        waf_log: The raw AWS WAF log entry as a JSON string.
                 Must contain at least 'action', 'httpRequest', and 'terminatingRuleId'.

    Returns:
        A plain-English explanation of why the request was blocked and how to fix it.
    """
    logger.info(f"Analyzing WAF log ({len(waf_log)} chars)")
    
    try:
        context = await build_analysis_context(waf_log)
        logger.info(f"Log parsed successfully: rule={context['rule_id']}, action={context['rule_type']}")
    except WAFLogParseError as exc:
        logger.warning(f"WAF log parse error: {exc}")
        return f"Could not parse the WAF log: {exc}\n\nPlease supply a valid AWS WAF JSON log entry."
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Unexpected error parsing log: {exc}", exc_info=True)
        return f"Unexpected error parsing log: {exc}"

    prompt = build_analysis_prompt(context)

    try:
        logger.debug(f"Generating explanation for rule {context['rule_id']}")
        explanation = await generate(prompt)
        logger.info(f"Analysis complete for rule {context['rule_id']}")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"LLM generation failed: {exc}", exc_info=True)
        return (
            f"The WAF log was parsed successfully but the LLM could not be reached.\n\n"
            f"Rule triggered: {context['rule_id']} ({context['rule_type']})\n\n"
            f"LLM error: {exc}\n\n"
            f"Make sure Ollama is running at the configured OLLAMA_BASE_URL and the model is pulled."
        )

    return explanation


@mcp.tool()
async def explain_block_reason(rule_id: str, rule_type: str = "MANAGED_RULE_GROUP") -> str:
    """Explain what a specific AWS WAF rule does and what attack it protects against.

    Args:
        rule_id:   The AWS WAF rule ID (e.g. 'CrossSiteScripting_BODY').
        rule_type: The rule type (e.g. 'MANAGED_RULE_GROUP', 'RATE_BASED', 'REGULAR').

    Returns:
        A plain-English explanation of the rule and guidance for developers.
    """
    logger.info(f"Explaining rule {rule_id} (type: {rule_type})")
    prompt = build_rule_explanation_prompt(rule_id, rule_type)

    try:
        explanation = await generate(prompt)
        logger.info(f"Rule explanation generated for {rule_id}")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"LLM generation failed for rule {rule_id}: {exc}", exc_info=True)
        return (
            f"The LLM could not be reached: {exc}\n\n"
            f"Make sure Ollama is running at the configured OLLAMA_BASE_URL and the model is pulled."
        )

    return explanation


@mcp.tool()
async def check_ollama_health() -> str:
    """Check whether the Ollama service is reachable and the configured model is available.

    Returns:
        A status report for the Ollama backend.
    """
    logger.info("Checking Ollama health")
    status = await check_health()
    lines = [f"{k}: {v}" for k, v in status.items()]
    result = "\n".join(lines)
    logger.info(f"Ollama health check: {status.get('ollama_status', 'unknown')}")
    return result

@mcp.tool()
async def lookup_aws_waf_rule_docs(rule_id: str) -> str:
    """Fetch live AWS documentation for a WAF rule from the AWS Documentation MCP server.

    Args:
        rule_id: The AWS WAF rule ID (e.g. 'CrossSiteScripting_BODY').

    Returns:
        The rule documentation from AWS docs, or an empty string if unavailable.
    """
    logger.info(f"Looking up AWS docs for rule {rule_id}")
    try:
        docs = await lookup_rule_from_aws_docs(rule_id)
        logger.info(f"AWS docs lookup successful for {rule_id} ({len(docs)} chars)")
        return docs
    except Exception as e:
        logger.error(f"AWS docs lookup failed for {rule_id}: {e}", exc_info=True)
        raise
