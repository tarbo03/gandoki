FROM python:3.11-slim

WORKDIR /app

# Copy project files
COPY . .

# Install Gandoki and its MCP dependencies
RUN pip install --no-cache-dir -e ".[mcp]"
RUN pip install --no-cache-dir uvicorn starlette

# Expose the HTTP port
EXPOSE 8080

# Start the SSE server
CMD ["python", "-m", "gandoki.mcp.http_server"]
