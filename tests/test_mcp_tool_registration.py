"""MCP server registers all tools without error."""
import asyncio

import pytest


EXPECTED_TOOLS = {
    "scan_domains", "scan_file", "get_job", "list_jobs",
    "get_finding", "explain_finding", "diff_jobs",
}


def test_mcp_module_imports():
    from gandoki.mcp import server  # noqa: F401
    assert server.mcp is not None


def test_tool_functions_exist_as_callables():
    from gandoki.mcp import server

    for name in EXPECTED_TOOLS:
        assert hasattr(server, name), f"missing tool: {name}"
        assert callable(getattr(server, name)), f"{name} is not callable"


def test_tools_registered_with_mcp():
    from gandoki.mcp import server

    try:
        tools = asyncio.run(server.mcp.list_tools())
        registered = {t.name for t in tools}
        missing = EXPECTED_TOOLS - registered
        assert not missing, f"tools not registered: {missing}"
    except (AttributeError, TypeError) as e:
        # The callable check above verified the functions exist, but
        # the wire-level registration is what actually matters. If
        # list_tools() isn't available, we cannot verify the 7 tools
        # are reachable via the MCP protocol. Fail loudly.
        pytest.fail(
            f"mcp.list_tools() not available: {e}. "
            f"Cannot verify tools are registered over the wire. "
            f"Run /tmp/mcp_e2e_test.py for true end-to-end verification."
        )
