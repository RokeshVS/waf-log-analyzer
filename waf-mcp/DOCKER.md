# WAF-Log-Analysis Docker Deployment

## Quick Start with Docker Compose

Run everything (Ollama, WAF Analyzer, and tests) in containers:

```bash
# Start Ollama and WAF Analyzer services
docker-compose up ollama waf-analyzer

# In another terminal, run the smoke tests
docker-compose run --rm test-runner
```

## Build Docker Image

```bash
docker build -t waf-analyzer:latest .
```

## Run Container Manually

### Run the MCP Server (stdio mode - default)
```bash
docker run --rm \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  -e OLLAMA_MODEL=qwen2.5:1.5b \
  waf-analyzer:latest
```

### Run the MCP Server (HTTP mode)
```bash
docker run --rm -p 5000:5000 \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  -e OLLAMA_MODEL=qwen2.5:1.5b \
  -e MCP_TRANSPORT=http \
  -e MCP_HOST=0.0.0.0 \
  -e MCP_PORT=5000 \
  waf-analyzer:latest
```

### Run Tests
```bash
docker run --rm \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  -e OLLAMA_MODEL=qwen2.5:1.5b \
  waf-analyzer:latest \
  python scripts/test_mcp.py
```

## Environment Variables

- `OLLAMA_BASE_URL`: URL to Ollama service (default: `http://localhost:11434`)
- `OLLAMA_MODEL`: Model to use (default: `qwen2.5:1.5b`)
- `LLM_TIMEOUT_SECONDS`: Timeout for LLM requests (default: `120`)

## Prerequisites

- Docker and Docker Compose installed
- Ollama running (or use docker-compose to start it automatically)
- ~2GB disk space for Ollama model

## Ollama Setup

If running Ollama separately:
```bash
# Install Ollama: https://ollama.ai
# Start Ollama service
ollama serve

# In another terminal, pull the model
ollama pull qwen2.5:1.5b
```
