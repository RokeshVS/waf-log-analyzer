# AWS WAF Log Analysis MCP Server

An AI-powered MCP server that analyses AWS WAF blocked requests and explains them in plain English.

## Run & Operate

### MCP Server (stdio — for Claude Desktop / Cursor)
```bash
cd waf-mcp && python main.py
```

### MCP Server (HTTP/SSE — for remote MCP clients)
```bash
cd waf-mcp && python main.py --transport http --host 0.0.0.0 --port 5000
```

### Quick smoke-test
```bash
cd waf-mcp && python scripts/test_mcp.py
```

## Stack

- **Language**: Python 3.11
- **MCP framework**: FastMCP 3.x
- **LLM backend**: Ollama (configurable URL + model)
- **HTTP client**: httpx (async)
- **AWS Documentation**: awslabs.aws-documentation-mcp-server package

## Where things live

```
waf-mcp/
├── main.py                    # Entry point — stdio or HTTP transport
├── requirements.txt
├── app/
│   ├── mcp_server.py          # FastMCP tools: analyze_waf_log, explain_block_reason, etc.
│   ├── log_parser.py          # Parse & normalise AWS WAF JSON logs
│   ├── llm_client.py          # Ollama async client
│   └── context_assembler.py   # Builds LLM prompt + local rule descriptions
└── scripts/
    ├── start.sh               # Shell start script
    └── test_mcp.py            # Smoke-test (no MCP client needed)
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `analyze_waf_log` | Takes a raw WAF JSON log, returns plain-English explanation |
| `explain_block_reason` | Explains a specific rule ID without a full log |
| `check_ollama_health` | Verifies Ollama is reachable and the model is available |
| `lookup_aws_waf_rule_docs` | Fetches live AWS documentation for a WAF rule |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `qwen2.5:1.5b` | Model to use |
| `LLM_TIMEOUT_SECONDS` | `120` | LLM request timeout |
| `WAF_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `WAF_MCP_PORT` | `5000` | Port for HTTP transport |

## Claude Desktop Integration

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "waf-analyzer": {
      "command": "python",
      "args": ["/path/to/waf-mcp/main.py"],
      "env": {
        "OLLAMA_BASE_URL": "http://localhost:11434",
        "OLLAMA_MODEL": "qwen2.5:1.5b"
      }
    }
  }
}
```

## Architecture decisions

- **FastMCP over raw MCP SDK**: Higher-level API, less boilerplate, supports both stdio and SSE transports with a single flag.
- **Direct AWS Documentation package integration**: Uses the `awslabs.aws-documentation-mcp-server` Python package directly instead of spawning it as a subprocess. This provides better reliability and integration.
- **LLM-driven explanations**: Tools rely on Ollama to generate human-friendly explanations. Rule documentation is always fetched from the AWS documentation package.
- **Transport-agnostic entry point**: `main.py --transport stdio|http` keeps one codebase for both local (Claude Desktop) and remote (SSE) use cases.

## Gotchas

- Ollama must be running locally before starting the server (`ollama serve`).
- Pull the model first: `ollama pull qwen2.5:1.5b`
- AWS WAF logs use inconsistent key casing across versions; the parser normalises both.
- The `awslabs.aws-documentation-mcp-server` package is required. Install it with: `pip install awslabs.aws-documentation-mcp-server`

## User preferences

- No frontend — pure MCP server only.
- Ollama as the local LLM backend.
