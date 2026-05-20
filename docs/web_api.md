# WAF Log Analysis API

Base URL: `http://localhost:8000`

## Endpoints

### 1. Health Check
**GET** `/health`

Check system status and Ollama connectivity.

**Response:**
```json
{
  "status": "ok",
  "service": "waf-analyzer",
  "ollama_health": {
    "status": "ok",
    "model": "qwen2.5:1.5b"
  }
}
```

---

### 2. Root Endpoint
**GET** `/`

Get API metadata and available endpoints.

**Response:**
```json
{
  "service": "WAF Log Analysis API",
  "version": "1.0.0",
  "endpoints": {
    "health": "GET /health",
    "rca": "POST /get-rca"
  },
  "docs": "/docs"
}
```

---

### 3. Root Cause Analysis (RCA)
**POST** `/get-rca`

Batch analyze AWS WAF logs and generate root cause analysis.

**Request:**
```json
{
  "logs": [
    {
      "version": "1",
      "id": "1:123456:789",
      "timestamp": 1691234567890,
      "webaclId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/abc123",
      "terminatingRuleId": "AWSManagedRulesCommonRuleGroup",
      "terminatingRuleType": "MANAGED_RULE_GROUP",
      "action": "BLOCK",
      "httpRequest": {
        "clientIp": "192.0.2.1",
        "country": "US",
        "headers": [
          {"name": "Host", "value": "example.com"},
          {"name": "User-Agent", "value": "curl"}
        ],
        "uri": "/admin",
        "httpMethod": "POST"
      }
    },
    {
      "version": "1",
      "id": "1:123456:790",
      "timestamp": 1691234568890,
      "webaclId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/abc123",
      "terminatingRuleId": "AWSManagedRulesSQLiRuleGroup",
      "terminatingRuleType": "MANAGED_RULE_GROUP",
      "action": "BLOCK",
      "httpRequest": {
        "clientIp": "192.0.2.2",
        "country": "BR",
        "headers": [
          {"name": "Host", "value": "api.example.com"}
        ],
        "uri": "/api/users",
        "args": "id=1' OR '1'='1",
        "httpMethod": "GET"
      }
    }
  ],
  "context": "Security audit - analyzing attack patterns"
}
```

**Request Schema:**
- `logs` (required): List of AWS WAF log objects
  - Each log must be a valid AWS WAF JSON log from CloudWatch Logs or WAF console
  - Minimum required fields: `action`, `terminatingRuleId`, `terminatingRuleType`, `httpRequest`
  - Can be dict or JSON string format
- `context` (optional): Additional context for analysis (string)

**Response:**
```json
{
  "status": "success",
  "total_logs": 2,
  "successful": 2,
  "failed": 0,
  "analyses": [
    {
      "log_index": 0,
      "rule_id": "AWSManagedRulesCommonRuleGroup",
      "action": "BLOCK",
      "analysis": "The request was blocked due to a rule in the Common Rule Group. The request to /admin endpoint from IP 192.0.2.1 (US) matched a pattern indicating potential administrative access attempt. This is likely a precaution rule."
    },
    {
      "log_index": 1,
      "rule_id": "AWSManagedRulesSQLiRuleGroup",
      "action": "BLOCK",
      "analysis": "The request was blocked due to SQL injection attempt detection in the SQLi Rule Group. The query parameter contains SQL syntax (1' OR '1'='1), which is a classic SQL injection payload."
    }
  ],
  "errors": []
}
```

**Response Schema:**
- `status`: "success" (all logs analyzed) or "partial" (some failed)
- `total_logs`: Total logs submitted
- `successful`: Number successfully analyzed
- `failed`: Number that failed validation/analysis
- `analyses`: List of successful analyses
  - `log_index`: Position in original request (0-based)
  - `rule_id`: WAF rule that triggered the block
  - `action`: Block action (BLOCK, ALLOW, COUNT)
  - `analysis`: LLM-generated explanation of the block reason
- `errors`: List of error messages for failed logs

**Status Codes:**
- `200 OK`: Analysis complete (check `status` field for success/partial)
- `400 Bad Request`: No valid logs in request or invalid JSON
- `500 Internal Server Error`: Analysis service error

**Example with cURL:**
```bash
curl -X POST http://localhost:8000/get-rca \
  -H "Content-Type: application/json" \
  -d @logs_batch.json
```

---

## Data Validation

### Log Format
- Logs can be provided as:
  - **Objects**: `{"version": "1", "action": "BLOCK", ...}`
  - **JSON Strings**: `"{\"version\": \"1\", \"action\": \"BLOCK\", ...}"`
- Invalid logs are skipped with error tracking
- At least one valid log required per request

### Required Fields
Every log must include:
- `action`: ALLOW, BLOCK, COUNT
- `terminatingRuleId`: Rule that triggered
- `terminatingRuleType`: MANAGED_RULE_GROUP, RATE_BASED, etc.
- `httpRequest`: Object with client request details

### Examples

**Valid Log:**
```json
{
  "version": "1",
  "id": "123:456:789",
  "timestamp": 1691234567890,
  "webaclId": "arn:aws:wafv2:...",
  "terminatingRuleId": "AWSManagedRulesCommonRuleGroup",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "action": "BLOCK",
  "httpRequest": {
    "clientIp": "192.0.2.1",
    "uri": "/admin",
    "httpMethod": "POST"
  }
}
```

**Invalid Log (missing httpRequest):**
```json
{
  "version": "1",
  "action": "BLOCK",
  "terminatingRuleId": "Rule123"
}
```
Error: `Log 0: Missing required fields: ['terminatingRuleType', 'httpRequest']`

---

## Example Workflows

### Analyze Single Log
```bash
curl -X POST http://localhost:8000/get-rca \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [{
      "version": "1",
      "webaclId": "arn:aws:wafv2:...",
      "action": "BLOCK",
      "terminatingRuleId": "AWSManagedRulesCommonRuleGroup",
      "terminatingRuleType": "MANAGED_RULE_GROUP",
      "httpRequest": {"clientIp": "1.2.3.4", "uri": "/"}
    }]
  }'
```

### Batch Analyze from CloudWatch Logs
```bash
# Export logs from CloudWatch Logs and format as JSON array
aws logs get-log-events \
  --log-group-name "/aws/waf/web-acl" \
  --log-stream-name "..." \
  --query 'events[].{message:message,timestamp:timestamp}' \
  > logs.json

# Send to API
curl -X POST http://localhost:8000/get-rca \
  -H "Content-Type: application/json" \
  -d "{\"logs\": $(cat logs.json | jq '[.[] | fromjson]')}"
```

### Analyze with Context
```bash
curl -X POST http://localhost:8000/get-rca \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [...],
    "context": "Investigating DDoS attack on 2024-01-15, source IPs 1.2.3.0/24"
  }'
```

---

## Interactive API Docs

Visit `/docs` for Swagger UI with live examples:
```
http://localhost:8000/docs
```
