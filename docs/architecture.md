# WAF Log Analysis Architecture

## System Design

```
┌─────────────────────────────────────────────────────────────┐
│  Docker Container: waf-analyzer (FastAPI + MCP)             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  FastAPI Web Service (Port 8000)                            │
│  ├─ POST /get-rca           → Batch RCA (CloudWatch logs)   │
│  ├─ GET  /rule-docs/{id}    → Fetch AWS docs for a rule     │
│  ├─ GET  /health            → Health check                  │
│  └─ GET  /docs              → OpenAPI docs                  │
│                              ↓                               │
│  MCP Tools (app/mcp_server.py)                              │
│  ├─ analyze_waf_log()                                       │
│  ├─ lookup_waf_rule_docs()                                  │
│  └─ check_ollama_health()                                   │
│         ↓                          ↓                         │
│  WAF Log Parser          Context Assembler                  │
│  (Validate/normalize)    (AWS docs + prompt)                │
│                              ↓                               │
│                          LLM Client (Ollama)                │
│                                                               │
└─────────────────────────────────────────────────────────────┘
              ↓                                  ↓
        ┌──────────────┐              ┌─────────────────┐
        │ CloudWatch   │              │ Ollama Service  │
        │ WAF Logs     │              │ (External)      │
        └──────────────┘              └─────────────────┘
```

## Components

| Component | Purpose | Tech |
|-----------|---------|------|
| **web_service.py** | REST API endpoints | FastAPI |
| **app/mcp_server.py** | Analysis tools | FastMCP |
| **app/log_parser.py** | Parse WAF logs | Python |
| **app/context_assembler.py** | Build analysis context | Python + AsyncIO |
| **app/llm_client.py** | Connect to Ollama | httpx |

## Data Flow

**Single Log:**
```
Request → Parse → Gather Context → Generate via LLM → Response
```

**Batch RCA:**
```
CloudWatch Logs (Array)
  ↓
Process Each Log (similar single flow)
  ↓
Aggregate Results + Errors
  ↓
Response with status/analyses/errors
```

## Environment Variables

| Var | Default | Description |
|-----|---------|-------------|
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama service |
| `OLLAMA_MODEL` | `qwen2.5:1.5b` | Model name |
| `WEB_HOST` | `0.0.0.0` | Bind address |
| `WEB_PORT` | `8000` | API port |

## Logging

- **Console**: Real-time output
- **File**: `/app/waf_analyzer.log`
- **Format**: `[timestamp] [level] module: message`

---

See [QUICKSTART](quick_start.md) for setup.