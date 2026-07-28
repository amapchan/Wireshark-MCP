"""Tests for forensics tools."""

import json
from pathlib import Path

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.envelope import success_response
from wireshark_mcp.tools.forensics import make_forensics_tools


def _scan_tool(client: MockTSharkClient):
    return dict(make_forensics_tools(client))["wireshark_scan_file_signatures"]


class TestFileSignatureScan:
    """Regression: the scan must count real matches, not report every type blindly."""

    @pytest.mark.asyncio
    async def test_zero_matches_reports_nothing(self, mock_client: MockTSharkClient) -> None:
        async def header_only(*_a, **_k):
            return success_response("frame.number\t_ws.col.Info\n")  # header row, no matches

        mock_client.search_packet_contents = header_only  # type: ignore[method-assign]
        out = json.loads(await _scan_tool(mock_client)("x.pcap"))
        assert "No embedded files detected" in out["data"]
        assert "detected in traffic" not in out["data"]

    @pytest.mark.asyncio
    async def test_only_types_with_matches_are_reported(self, mock_client: MockTSharkClient) -> None:
        async def only_pe(pcap, pattern, search_type="string", limit=50, scope="bytes"):
            if pattern == "4d5a":  # PE/EXE magic
                return success_response("frame.number\t_ws.col.Info\n1\tGET\n2\tPOST\n")
            return success_response("frame.number\t_ws.col.Info\n")

        mock_client.search_packet_contents = only_pe  # type: ignore[method-assign]
        out = json.loads(await _scan_tool(mock_client)("x.pcap"))
        assert "PE/EXE: 2 packet(s)" in out["data"]
        assert "ELF" not in out["data"]
        assert "PDF" not in out["data"]

    @pytest.mark.asyncio
    async def test_search_error_is_not_a_false_positive(self, mock_client: MockTSharkClient) -> None:
        from wireshark_mcp.tools.envelope import error_response

        async def always_error(*_a, **_k):
            return error_response("boom")

        mock_client.search_packet_contents = always_error  # type: ignore[method-assign]
        out = json.loads(await _scan_tool(mock_client)("x.pcap"))
        assert "No embedded files detected" in out["data"]


def _fingerprint_tool(client: MockTSharkClient):
    return dict(make_forensics_tools(client))["wireshark_extract_fingerprints"]


class TestJa3Fingerprints:
    """Tests for wireshark_extract_fingerprints, through the tool."""

    @pytest.mark.asyncio
    async def test_ja3_and_ja3s_are_queried_under_their_own_handshake_types(
        self, mock_client: MockTSharkClient
    ) -> None:
        # JA3 comes from the Client Hello and JA3S from the Server Hello. Asking for both
        # under `type == 1` — as this tool used to — leaves the ja3s column empty in every
        # row while still advertising JA3S, so the two passes must stay separate.
        await _fingerprint_tool(mock_client)("x.pcap")

        client_pass = [c for c in mock_client._commands if "tls.handshake.ja3" in c]
        server_pass = [c for c in mock_client._commands if "tls.handshake.ja3s" in c]
        assert client_pass, "no pass requested tls.handshake.ja3"
        assert server_pass, "no pass requested tls.handshake.ja3s"

        assert "tls.handshake.type == 1" in client_pass[0]
        assert "tls.handshake.type == 2" in server_pass[0]
        # ja3s must not ride along on the Client Hello pass, where it is always empty.
        assert "tls.handshake.ja3s" not in client_pass[0]

    @pytest.mark.asyncio
    async def test_no_fingerprint_list_ships_with_the_package(self, tmp_path, monkeypatch) -> None:
        # The bundled five-entry JA3 list was removed: a JA3 identifies a TLS
        # configuration rather than an application, so a shipped label attributes
        # traffic it cannot actually attribute. Assert the absence directly — checking
        # the tool's output instead would pass whenever a shipped list simply had no
        # match in the capture.
        import wireshark_mcp
        import wireshark_mcp.tools.forensics as forensics

        pkg_dir = Path(next(iter(wireshark_mcp.__path__)))
        assert not list(pkg_dir.glob("data/fingerprints/*.json")), (
            "a fingerprint list is shipping inside the package again"
        )

        # With no user list either, matching must be skipped entirely.
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        forensics._FINGERPRINT_DB = None
        try:
            assert forensics._load_fingerprint_db() == []
        finally:
            forensics._FINGERPRINT_DB = None

    @pytest.mark.asyncio
    async def test_user_supplied_list_is_still_matched(self, tmp_path, monkeypatch) -> None:
        # Removing the bundled list must not remove the capability for an operator who
        # maintains their own intel.
        import wireshark_mcp.tools.forensics as forensics

        fp_dir = tmp_path / ".wireshark-mcp" / "fingerprints"
        fp_dir.mkdir(parents=True)
        (fp_dir / "mine.json").write_text(
            json.dumps({"fingerprints": [{"ja3": "abc123", "label": "Mine", "category": "internal"}]})
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        forensics._FINGERPRINT_DB = None
        try:
            assert forensics._load_fingerprint_db() == [{"ja3": "abc123", "label": "Mine", "category": "internal"}]
        finally:
            forensics._FINGERPRINT_DB = None

    @pytest.mark.asyncio
    async def test_match_compares_the_ja3_column_not_the_whole_row(self, mock_client: MockTSharkClient) -> None:
        # A substring test against the line also fires when the hash appears in SNI or
        # an address, which would report a match for traffic that has none.
        import wireshark_mcp.tools.forensics as forensics

        ja3 = "0b85eb0d4981e69064e40753e4f0ac5f"

        async def rows(*_a, **_k):
            # The hash appears only inside the server_name column.
            return success_response(
                f'ip.src\tip.dst\ttcp.dstport\ttls.handshake.ja3\tsni\n"10.0.0.1"\t"10.0.0.2"\t"443"\t"deadbeef"\t"{ja3}.example.com"\n'
            )

        mock_client.extract_fields = rows  # type: ignore[method-assign]
        forensics._FINGERPRINT_DB = [{"ja3": ja3, "label": "Test", "category": "test"}]
        try:
            out = json.loads(await _fingerprint_tool(mock_client)("x.pcap"))
        finally:
            forensics._FINGERPRINT_DB = None

        assert "MATCH" not in out["data"], "matched a hash that was not in the JA3 column"
