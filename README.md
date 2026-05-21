# WAF Log Analysis

AWS WAF log analysis using LLM (Ollama) to provide Root Cause Analysis (RCA) in plain English.

## Quick Start

```bash
cd waf-mcp
docker-compose up
```

Open http://localhost:8000/docs for API documentation.

## Documentation

- **[docs/quick_start.md](docs/quick_start.md)** - Getting started
- **[docs/web_api.md](docs/web_api.md)** - API endpoints
- **[docs/architecture.md](docs/architecture.md)** - System design

## What's Inside

```
waf-mcp/
├── app/                    # Core analysis modules
│   ├── context_assembler.py
│   ├── llm_client.py
│   ├── log_parser.py
│   └── mcp_server.py
├── scripts/
│   └── waf-mcp/smoke-test-scripts/test_rca_sanity.py
├── web_service.py          # FastAPI REST endpoints
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── docs/                   # Simplified documentation
    ├── architecture.md
    ├── quick_start.md
    └── web_api.md
```

## Features

✅ **REST API** - POST `/get-rca` for batch RCA, POST `/analyze-log` for single logs  
✅ **CloudWatch Integration** - Forward WAF logs from CloudWatch  
✅ **Comprehensive Logging** - All operations logged to file  
✅ **Docker Ready** - Single container (FastAPI + MCP tools)  
✅ **Ollama Backend** - Local LLM for explanations  

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Service health |
| POST | `/analyze-log` | Single log analysis |
| POST | `/get-rca` | Batch RCA (CloudWatch logs) |
| GET | `/docs` | API documentation |

## Architecture

- **Single Container**: waf-analyzer (FastAPI web service)
- **External Service**: ollama (port 11434)
- **Logging**: Console + file (`waf_analyzer.log`)
- **Stateless**: Can be scaled horizontally

See [docs/architecture.md](docs/architecture.md) for details.

## Environment Variables

| Var | Default | Description |
|-----|---------|-------------|
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama endpoint |
| `OLLAMA_MODEL` | `qwen2.5:1.5b` | Model name |
| `WEB_HOST` | `0.0.0.0` | Bind address |
| `WEB_PORT` | `8000` | API port |

## Testing

```bash
# Inside container
docker-compose exec waf-analyzer python waf-mcp/smoke-test-scripts/test_rca_sanity.py

# Local (if dev environment set up)
python waf-mcp/smoke-test-scripts/test_rca_sanity.py
```

## Troubleshooting

**Port already in use?**
```bash
# Change in docker-compose.yml or stop conflicting service
lsof -i :8000
```

**Ollama model missing?**
```bash
docker exec waf-log-analysis-waf-mcp-ollama-1 ollama pull qwen2.5:1.5b
```

**API not responding?**
```bash
docker-compose logs -f waf-analyzer
```

---

See [docs/quick_start.md](docs/quick_start.md) to get started.
