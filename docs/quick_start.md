# Quick Start

## Prerequisites

- Docker & Docker Compose
- ~5GB disk space (for Ollama model)

## Start Everything

```bash
cd waf-mcp
docker-compose up
```

This starts:
- **Ollama** (LLM backend) on port 11434
- **waf-analyzer** (Web API) on port 8000

## Pull Model

In another terminal:
```bash
docker exec waf-log-analysis-waf-mcp-ollama-1 ollama pull qwen2.5:1.5b
```

## Test API

```bash
# Health check
curl http://localhost:8000/health

# Analyze single log
curl -X POST http://localhost:8000/analyze-log \
  -H "Content-Type: application/json" \
  -d '{"log": {"timestamp": 1715000000000, "action": "BLOCK", "terminatingRuleId": "CrossSiteScripting_BODY", "terminatingRuleType": "MANAGED_RULE_GROUP", "httpRequest": {"clientIp": "203.0.113.1", "httpMethod": "POST", "uri": "/api", "headers": []}}, "rule_details": true}'
```

## View Logs

```bash
docker-compose logs -f waf-analyzer
```

## Swagger UI

Open: http://localhost:8000/docs

---

See [web_api.md](web_api.md) for endpoint details.
