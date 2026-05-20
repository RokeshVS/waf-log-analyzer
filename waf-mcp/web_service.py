"""FastAPI web service for WAF log analysis with HTTP endpoints."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("waf_analyzer.log")
    ]
)

logger = logging.getLogger("waf-analyzer.web")


# ──────────────────────────────────────────────────────────────────────────────
# Request/Response Models
# ──────────────────────────────────────────────────────────────────────────────

class RCARequest(BaseModel):
    """RCA request - list of AWS WAF logs."""
    logs: list[dict[str, Any] | str]
    context: str | None = None


class RCAAnalysis(BaseModel):
    """Single log analysis result."""
    log_index: int
    rule_id: str
    action: str
    analysis: str


class RCAResponse(BaseModel):
    """Root Cause Analysis response."""
    status: str
    total_logs: int
    successful: int
    failed: int
    analyses: list[RCAAnalysis]
    errors: list[str] = []


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI App
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="WAF Log Analysis API",
    description="Analyzes AWS WAF logs and provides RCA (Root Cause Analysis)",
    version="1.0.0",
)


# Import analysis tools
async def _import_tools():
    """Lazy import to avoid hanging on module init."""
    try:
        from app.mcp_server import (
            analyze_waf_log,
            check_ollama_health,
            lookup_waf_rule_docs,
        )
        return {
            "analyze_waf_log": analyze_waf_log,
            "check_ollama_health": check_ollama_health,
            "lookup_waf_rule_docs": lookup_waf_rule_docs,
        }
    except ImportError as e:
        logger.error(f"Failed to import analysis tools: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to import analysis tools: {e}")


@app.on_event("startup")
async def startup():
    """Startup event."""
    logger.info("WAF Log Analysis API starting...")
    health = await _get_health()
    logger.info(f"System health: {health}")


@app.get("/health")
async def health():
    """Health check endpoint."""
    logger.debug("Health check requested")
    return await _get_health()


async def _get_health():
    """Check system health."""
    try:
        tools = await _import_tools()
        ollama_health = await tools["check_ollama_health"]()
        return {
            "status": "ok",
            "service": "waf-analyzer",
            "ollama_health": ollama_health,
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "degraded",
            "service": "waf-analyzer",
            "error": str(e),
        }


@app.post("/get-rca", response_model=RCAResponse)
async def get_rca(request: RCARequest) -> RCAResponse:
    """
    Root Cause Analysis endpoint.
    
    Accepts list of AWS WAF logs and returns batch analysis.
    
    Args:
        logs: List of WAF log dicts or JSON strings
        context: Optional additional context
    
    Returns:
        RCAResponse with analyses and any errors
    """
    logger.info(f"RCA request received: {len(request.logs)} logs, context: {request.context}")
    
    try:
        tools = await _import_tools()
    except HTTPException:
        raise
    
    # Validate and normalize logs
    logs_to_analyze: list[tuple[int, str]] = []  # (index, json_string)
    errors: list[str] = []
    
    logger.debug(f"Validating {len(request.logs)} log entries")
    for i, log in enumerate(request.logs):
        try:
            # Normalize to JSON string
            if isinstance(log, dict):
                log_json = json.dumps(log)
            elif isinstance(log, str):
                # Validate it's valid JSON
                json.loads(log)
                log_json = log
            else:
                error_msg = f"Log {i}: Invalid type {type(log).__name__} (expected dict or str)"
                logger.warning(error_msg)
                errors.append(error_msg)
                continue
            
            # Basic WAF log validation
            parsed = json.loads(log_json)
            required_fields = ["action", "terminatingRuleId", "terminatingRuleType", "httpRequest"]
            missing = [f for f in required_fields if f not in parsed]
            if missing:
                error_msg = f"Log {i}: Missing required fields: {missing}"
                logger.warning(error_msg)
                errors.append(error_msg)
                continue
            
            logs_to_analyze.append((i, log_json))
            logger.debug(f"Log {i} validated: rule={parsed.get('terminatingRuleId')}, action={parsed.get('action')}")
        except json.JSONDecodeError as e:
            error_msg = f"Log {i}: Invalid JSON - {str(e)}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except Exception as e:
            error_msg = f"Log {i}: Validation error - {str(e)}"
            logger.warning(error_msg)
            errors.append(error_msg)
    
    if not logs_to_analyze:
        logger.error("No valid logs to analyze")
        raise HTTPException(status_code=400, detail=f"No valid logs found. Errors: {errors}")
    
    # Analyze logs
    logger.info(f"Analyzing {len(logs_to_analyze)} validated logs")
    analyses: list[RCAAnalysis] = []
    
    for orig_index, log_json in logs_to_analyze:
        try:
            logger.debug(f"Analyzing log {orig_index}")
            analysis = await tools["analyze_waf_log"](log_json)
            
            # Extract metadata
            parsed_log = json.loads(log_json)
            rule_id = parsed_log.get("terminatingRuleId", "UNKNOWN")
            action = parsed_log.get("action", "UNKNOWN")
            
            analyses.append(RCAAnalysis(
                log_index=orig_index,
                rule_id=rule_id,
                action=action,
                analysis=analysis,
            ))
            
            logger.info(f"Log {orig_index} analyzed: rule={rule_id}, action={action}")
        except Exception as e:
            error_msg = f"Analysis failed for log {orig_index}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)
    
    if not analyses:
        logger.error("All log analyses failed")
        raise HTTPException(status_code=500, detail=f"Failed to analyze any logs. Errors: {errors}")
    
    response = RCAResponse(
        status="success" if len(errors) == 0 else "partial",
        total_logs=len(request.logs),
        successful=len(analyses),
        failed=len(errors),
        analyses=analyses,
        errors=errors,
    )
    
    logger.info(f"RCA complete: {len(analyses)} successful, {len(errors)} errors")
    return response


@app.get("/rule-docs/{rule_id}")
async def get_rule_docs(rule_id: str):
    """
    Fetch AWS documentation for a specific WAF rule ID.

    Args:
        rule_id: The WAF rule ID (e.g. 'CrossSiteScripting_BODY').

    Returns:
        Documentation excerpt for the rule.
    """
    logger.info(f"Rule docs request for rule_id={rule_id}")
    try:
        tools = await _import_tools()
        docs = await tools["lookup_waf_rule_docs"](rule_id)
        return {"rule_id": rule_id, "docs": docs}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rule docs lookup failed for {rule_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    """Root endpoint with API info."""
    logger.debug("Root endpoint accessed")
    return {
        "service": "WAF Log Analysis API",
        "version": "1.0.0",
        "endpoints": {
            "health": "GET /health",
            "rca": "POST /get-rca",
            "rule_docs": "GET /rule-docs/{rule_id}",
        },
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    
    host = os.environ.get("WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("WEB_PORT", "8000"))
    
    logger.info(f"Starting web service on {host}:{port}")
    uvicorn.run(app, host=host, port=port)