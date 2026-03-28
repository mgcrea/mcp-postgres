"""Tests for Postgres MCP tool registration."""

import pytest
from mcp.server.fastmcp import FastMCP

from mcp_postgres.tools.postgres import register_postgres_tools


@pytest.fixture()
def readonly_mcp(monkeypatch):
    """Register tools in read-only mode."""
    monkeypatch.setenv("POSTGRES_READONLY", "true")
    mcp = FastMCP(name="test")
    register_postgres_tools(mcp)
    return mcp


@pytest.fixture()
def readwrite_mcp(monkeypatch):
    """Register tools in read-write mode."""
    monkeypatch.setenv("POSTGRES_READONLY", "false")
    mcp = FastMCP(name="test")
    register_postgres_tools(mcp)
    return mcp


class TestToolDescription:
    def test_readonly_description(self, readonly_mcp):
        tool = readonly_mcp._tool_manager._tools["postgres_query"]
        assert "read-only" in tool.description
        assert "Only SELECT statements" in tool.description

    def test_readwrite_description(self, readwrite_mcp):
        tool = readwrite_mcp._tool_manager._tools["postgres_query"]
        assert "read and write" in tool.description
        assert "INSERT, UPDATE, DELETE" in tool.description
