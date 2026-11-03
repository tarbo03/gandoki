import os
from gandoki.mcp.server import mcp

if __name__ == "__main__":
    # Azure Container Apps requires stateless HTTP for scaling
    mcp.run(
        transport="streamable-http",
        stateless_http=True,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
    )
