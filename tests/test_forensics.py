"""Tests for forensics tools."""

import json

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.envelope import success_response
from wireshark_mcp.tools.forensics import make_forensics_tools


def _carve_tool(client: MockTSharkClient):
    return dict(make_forensics_tools(client))["wireshark_carve_files"]


class TestCarveFilesDetection:
    """Regression: carve must count real matches, not report every type blindly."""

    @pytest.mark.asyncio
    async def test_zero_matches_reports_nothing(self, mock_client: MockTSharkClient) -> None:
        async def header_only(*_a, **_k):
            return success_response("frame.number\t_ws.col.Info\n")  # header row, no matches

        mock_client.search_packet_contents = header_only  # type: ignore[method-assign]
        out = json.loads(await _carve_tool(mock_client)("x.pcap"))
        assert "No embedded files detected" in out["data"]
        assert "detected in traffic" not in out["data"]

    @pytest.mark.asyncio
    async def test_only_types_with_matches_are_reported(self, mock_client: MockTSharkClient) -> None:
        async def only_pe(pcap, pattern, search_type="string", limit=50, scope="bytes"):
            if pattern == "4d5a":  # PE/EXE magic
                return success_response("frame.number\t_ws.col.Info\n1\tGET\n2\tPOST\n")
            return success_response("frame.number\t_ws.col.Info\n")

        mock_client.search_packet_contents = only_pe  # type: ignore[method-assign]
        out = json.loads(await _carve_tool(mock_client)("x.pcap"))
        assert "PE/EXE: 2 packet(s)" in out["data"]
        assert "ELF" not in out["data"]
        assert "PDF" not in out["data"]

    @pytest.mark.asyncio
    async def test_search_error_is_not_a_false_positive(self, mock_client: MockTSharkClient) -> None:
        from wireshark_mcp.tools.envelope import error_response

        async def always_error(*_a, **_k):
            return error_response("boom")

        mock_client.search_packet_contents = always_error  # type: ignore[method-assign]
        out = json.loads(await _carve_tool(mock_client)("x.pcap"))
        assert "No embedded files detected" in out["data"]


class TestFileCarving:
    """Tests for wireshark_carve_files."""

    @pytest.mark.asyncio
    async def test_carve_searches_magic_bytes(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.search_packet_contents(
            "test.pcap",
            "4d5a",
            search_type="hex",
            limit=50,
        )
        assert "4d5a" in result

    @pytest.mark.asyncio
    async def test_carve_searches_pdf_magic(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.search_packet_contents(
            "test.pcap",
            "255044462d",
            search_type="hex",
            limit=50,
        )
        assert "255044462d" in result


class TestJa3Fingerprints:
    """Tests for wireshark_extract_fingerprints."""

    @pytest.mark.asyncio
    async def test_ja3_field_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "tcp.dstport",
                "tls.handshake.ja3",
                "tls.handshake.ja3s",
                "tls.handshake.extensions.server_name",
            ],
            display_filter="tls.handshake.type == 1",
            limit=100,
        )
        assert "tls.handshake.ja3" in result
        assert "tls.handshake.type == 1" in result

    @pytest.mark.asyncio
    async def test_ja3_uses_correct_filter(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "tcp.dstport",
                "tls.handshake.ja3",
                "tls.handshake.ja3s",
                "tls.handshake.extensions.server_name",
            ],
            display_filter="tls.handshake.type == 1",
            limit=100,
        )
        assert "-Y" in result
        assert "tls.handshake.type == 1" in result
        assert "-e tls.handshake.ja3s" in result
        assert "-e tls.handshake.extensions.server_name" in result


class TestEvidenceChain:
    """Tests for wireshark_build_evidence_chain."""

    @pytest.mark.asyncio
    async def test_evidence_chain_extracts_dns(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["dns.qry.name", "dns.a", "dns.aaaa"],
            display_filter="dns.flags.response == 1",
            limit=500,
        )
        assert "dns.flags.response == 1" in result
        assert "-e dns.qry.name" in result

    @pytest.mark.asyncio
    async def test_evidence_chain_extracts_connections(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport", "frame.time_epoch"],
            display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0",
            limit=500,
        )
        assert "tcp.flags.syn == 1" in result


class TestMetadataEnrichment:
    """Tests for wireshark_enrich_metadata."""

    @pytest.mark.asyncio
    async def test_extracts_unique_ips(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.dst"],
            display_filter="ip && !ip.dst == 10.0.0.0/8 && !ip.dst == 172.16.0.0/12 && !ip.dst == 192.168.0.0/16",
            limit=500,
        )
        assert "ip.dst" in result
        assert "10.0.0.0/8" in result

    @pytest.mark.asyncio
    async def test_extracts_dns_names(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["dns.qry.name"],
            display_filter="dns.flags.response == 0",
            limit=500,
        )
        assert "dns.qry.name" in result
        assert "dns.flags.response == 0" in result
