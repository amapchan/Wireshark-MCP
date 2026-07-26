"""Smoke tests for public tool registration and compatibility behavior."""

import asyncio
import json

from conftest import MockTSharkClient
from mcp.server.fastmcp import FastMCP

from wireshark_mcp.tools.envelope import success_response
from wireshark_mcp.tools.extract import register_extract_tools
from wireshark_mcp.tools.registry import ToolRegistry


def _run_async(coro):
    return asyncio.run(coro)


def test_read_packets_remains_available_for_1_x_compatibility(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    register_extract_tools(mcp, mock_client)

    result = json.loads(_run_async(mcp._tool_manager.call_tool("wireshark_read_packets", {"pcap_file": "demo.pcap"})))

    assert result["success"] is True
    assert "-T json" in result["data"]


def test_list_ips_preserves_public_behavior(mock_client: MockTSharkClient) -> None:
    async def fake_extract_fields(*_args, **_kwargs) -> str:
        return success_response('ip.src\tip.dst\n"1.1.1.1"\t"2.2.2.2"\n"1.1.1.1"\t""\n')

    mcp = FastMCP("test")
    register_extract_tools(mcp, mock_client)
    mock_client.extract_fields = fake_extract_fields  # type: ignore[method-assign]

    result = json.loads(_run_async(mcp._tool_manager.call_tool("wireshark_list_ips", {"pcap_file": "demo.pcap"})))

    assert result["success"] is True
    assert result["data"] == "1.1.1.1\n2.2.2.2"


def test_protocol_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.register()

    result = json.loads(
        _run_async(mcp._tool_manager.call_tool("wireshark_extract_tls_handshakes", {"pcap_file": "demo.pcap"}))
    )

    assert result["success"] is True
    assert "Client Hello" in result["data"]


def test_threat_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.register()

    result = json.loads(
        _run_async(mcp._tool_manager.call_tool("wireshark_detect_port_scan", {"pcap_file": "demo.pcap"}))
    )

    assert result["success"] is True
    assert "port scanning" in result["data"].lower()


def test_extract_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.register()

    result = json.loads(
        _run_async(mcp._tool_manager.call_tool("wireshark_extract_dns_queries", {"pcap_file": "demo.pcap"}))
    )

    assert result["success"] is True
    assert "-e dns.qry.name" in result["data"]


def test_full_server_exposes_a_stable_tool_surface(monkeypatch) -> None:
    """Guard the advertised tool count so docs and code cannot silently drift."""
    from wireshark_mcp.server import _build_server

    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    tools = _run_async(mcp.list_tools())
    names = {t.name for t in tools}

    # Entry point + agentic workflows are always present.
    assert "wireshark_open_file" in names
    assert "wireshark_security_audit" in names
    assert "wireshark_quick_analysis" in names

    # No tools from the removed investigation/report/playbook/nl_query surface.
    removed = {
        "wireshark_investigate",
        "wireshark_execute_playbook_step",
        "wireshark_add_hypothesis",
        "wireshark_generate_report",
        "wireshark_suggest_rules",
        "wireshark_list_playbooks",
        "wireshark_nl_query",
    }
    assert names.isdisjoint(removed)

    # The advertised floor in the README ("80+ tools"). Bump deliberately, never by accident.
    assert len(names) >= 80


def test_every_protocol_recommendation_is_registered() -> None:
    """No PROTOCOL_TOOL_MAP entry may point at a tool the server never registers."""
    from wireshark_mcp.server import _build_server
    from wireshark_mcp.tools.registry import PROTOCOL_TOOL_MAP

    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    names = {t.name for t in _run_async(mcp.list_tools())}

    referenced = {tool for tools in PROTOCOL_TOOL_MAP.values() for tool in tools}
    missing = referenced - names
    assert not missing, f"Recommended but unregistered tools: {sorted(missing)}"
