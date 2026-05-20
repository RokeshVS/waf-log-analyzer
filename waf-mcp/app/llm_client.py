"""Ollama LLM client for generating WAF explanations."""

from __future__ import annotations

import os
import httpx

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:1.5b")
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT_SECONDS", "120"))


async def generate(prompt: str) -> str:
    """Send a prompt to Ollama and return the generated text."""
    url = f"{OLLAMA_BASE_URL}/api/generate"
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "").strip()


async def check_health() -> dict[str, str]:
    """Return the status of the Ollama service and whether the model is available."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            tags_resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            tags_resp.raise_for_status()
            models = [m["name"] for m in tags_resp.json().get("models", [])]
            model_ready = any(OLLAMA_MODEL in m for m in models)
            return {
                "ollama_status": "ok",
                "model": OLLAMA_MODEL,
                "model_available": str(model_ready),
                "available_models": ", ".join(models) if models else "none",
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "ollama_status": "error",
            "model": OLLAMA_MODEL,
            "error": str(exc),
        }
