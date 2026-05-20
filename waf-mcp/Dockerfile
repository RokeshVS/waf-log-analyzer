FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Default to running the MCP server via stdio transport
# Can be overridden with other commands (e.g., `python scripts/test_mcp.py`)
ENTRYPOINT ["python"]
CMD ["run_mcp_server.py"]
