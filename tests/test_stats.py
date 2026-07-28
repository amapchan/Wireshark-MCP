"""Tests for stats tools."""

import pytest
from conftest import MockTSharkClient


class TestProtocolHierarchy:
    """Tests for get_protocol_stats."""

    @pytest.mark.asyncio
    async def test_phs_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_protocol_stats("test.pcap")
        assert "-z io,phs" in result
        assert "-q" in result


class TestEndpoints:
    """Tests for get_endpoints."""

    @pytest.mark.asyncio
    async def test_default_ip_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_endpoints("test.pcap")
        assert "-z endpoints,ip" in result

    @pytest.mark.asyncio
    async def test_tcp_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_endpoints("test.pcap", type="tcp")
        assert "-z endpoints,tcp" in result


class TestConversations:
    """Tests for get_conversations."""

    @pytest.mark.asyncio
    async def test_default_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_conversations("test.pcap")
        assert "-z conv,ip" in result


class TestIOGraph:
    """Tests for get_io_graph."""

    @pytest.mark.asyncio
    async def test_default_interval(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_graph("test.pcap")
        assert "-z io,stat,1" in result

    @pytest.mark.asyncio
    async def test_custom_interval(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_graph("test.pcap", interval=5)
        assert "-z io,stat,5" in result


class TestExpertInfo:
    """Tests for get_expert_info."""

    @pytest.mark.asyncio
    async def test_expert_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_expert_info("test.pcap")
        assert "-z expert" in result


class TestServiceResponseTime:
    """Tests for get_service_response_time."""

    @pytest.mark.asyncio
    async def test_http_srt(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_service_response_time("test.pcap", protocol="http")
        assert "-z http,tree" in result


class TestIoGraphFilterConsolidation:
    """The former wireshark_io_stat_filters folded into wireshark_stats_io_graph as `filters`."""

    @pytest.mark.asyncio
    async def test_filters_route_to_the_multi_filter_command(self, mock_client: MockTSharkClient) -> None:
        import json

        from mcp.server.fastmcp import FastMCP

        from wireshark_mcp.tools.stats import register_stats_tools

        mcp = FastMCP("test")
        register_stats_tools(mcp, mock_client)

        result = json.loads(
            await mcp._tool_manager.call_tool(
                "wireshark_stats_io_graph", {"pcap_file": "demo.pcap", "interval": 2, "filters": "tcp;dns"}
            )
        )
        assert result["success"]
        assert '"tcp"' in result["data"]
        assert '"dns"' in result["data"]
        assert "io,stat,2" in result["data"]

    @pytest.mark.asyncio
    async def test_no_filters_uses_the_plain_command(self, mock_client: MockTSharkClient) -> None:
        import json

        from mcp.server.fastmcp import FastMCP

        from wireshark_mcp.tools.stats import register_stats_tools

        mcp = FastMCP("test")
        register_stats_tools(mcp, mock_client)

        result = json.loads(await mcp._tool_manager.call_tool("wireshark_stats_io_graph", {"pcap_file": "demo.pcap"}))
        assert result["success"]
        assert "io,stat,1" in result["data"]
        assert '"' not in result["data"].split("io,stat,1")[1][:20]
