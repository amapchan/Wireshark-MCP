"""Tests for TSharkClient core functionality."""

import json
import shutil

import pytest

from wireshark_mcp.tshark.client import TSharkClient


class TestValidation:
    """Tests for file and protocol validation."""

    def test_validate_file_not_found(self, real_client: TSharkClient) -> None:
        result = real_client._validate_file("/nonexistent/file.pcap")
        assert not result["success"]
        assert result["error"]["type"] == "FileNotFound"

    def test_validate_file_empty_path(self, real_client: TSharkClient) -> None:
        result = real_client._validate_file("")
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_file_exists(self, tmp_pcap: str, real_client: TSharkClient) -> None:
        result = real_client._validate_file(tmp_pcap)
        assert result["success"]

    def test_validate_file_is_directory(self, tmp_dir: str, real_client: TSharkClient) -> None:
        result = real_client._validate_file(tmp_dir)
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_protocol_valid(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("tcp", TSharkClient.VALID_ENDPOINT_TYPES)
        assert result["success"]

    def test_validate_protocol_invalid(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("invalid", TSharkClient.VALID_ENDPOINT_TYPES)
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_protocol_case_insensitive(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("TCP", TSharkClient.VALID_ENDPOINT_TYPES)
        assert result["success"]


class TestSandbox:
    """Tests for path sandbox enforcement."""

    def test_sandbox_allows_file_in_allowed_dir(self, tmp_dir: str, tmp_pcap: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_file(tmp_pcap)
        assert result["success"]

    def test_sandbox_blocks_file_outside_allowed_dir(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_file("/etc/passwd")
        assert not result["success"]
        assert result["error"]["type"] == "PermissionDenied"

    def test_sandbox_blocks_path_traversal(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        malicious_path = f"{tmp_dir}/../../../etc/passwd"
        result = client._validate_file(malicious_path)
        assert not result["success"]
        assert result["error"]["type"] == "PermissionDenied"

    def test_no_sandbox_allows_any_path(self, tmp_pcap: str) -> None:
        client = TSharkClient()
        result = client._validate_file(tmp_pcap)
        assert result["success"]

    def test_sandbox_output_path_validation(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_output_path(f"{tmp_dir}/output.pcap")
        assert result["success"]

        result = client._validate_output_path("/tmp/evil/output.pcap")
        assert not result["success"]


class TestCapabilities:
    """Tests for check_capabilities."""

    @pytest.mark.asyncio
    async def test_check_capabilities(self, real_client: TSharkClient) -> None:
        result = await real_client.check_capabilities()
        assert result["success"]
        assert "tshark" in result["data"]
        assert "capinfos" in result["data"]
        assert "_meta" in result["data"]

    def test_client_prefers_env_tool_paths(self, monkeypatch) -> None:
        monkeypatch.setenv("WIRESHARK_MCP_TSHARK_PATH", "/opt/wireshark/tshark")
        monkeypatch.setenv("WIRESHARK_MCP_CAPINFOS_PATH", "/opt/wireshark/capinfos")
        monkeypatch.setenv("WIRESHARK_MCP_MERGECAP_PATH", "/opt/wireshark/mergecap")
        monkeypatch.setenv("WIRESHARK_MCP_EDITCAP_PATH", "/opt/wireshark/editcap")
        monkeypatch.setenv("WIRESHARK_MCP_DUMPCAP_PATH", "/opt/wireshark/dumpcap")
        monkeypatch.setenv("WIRESHARK_MCP_TEXT2PCAP_PATH", "/opt/wireshark/text2pcap")

        client = TSharkClient()

        assert client.tshark_path == "/opt/wireshark/tshark"
        assert client.capinfos_path == "/opt/wireshark/capinfos"
        assert client.mergecap_path == "/opt/wireshark/mergecap"
        assert client.editcap_path == "/opt/wireshark/editcap"
        assert client.dumpcap_path == "/opt/wireshark/dumpcap"
        assert client.text2pcap_path == "/opt/wireshark/text2pcap"

    def test_describe_capabilities_reports_capture_backend_fallback(self, mock_client) -> None:
        capabilities = mock_client.describe_capabilities()
        assert capabilities["_meta"]["capture_backend"] == "dumpcap"
        assert capabilities["dumpcap"]["requirement"] == "optional"

        mock_client.dumpcap_path = None
        mock_client._tool_paths["dumpcap"] = None

        fallback_capabilities = mock_client.describe_capabilities()
        assert fallback_capabilities["_meta"]["capture_backend"] == "tshark"

    @pytest.mark.asyncio
    async def test_check_capabilities_detects_real_tshark_when_installed(self) -> None:
        if shutil.which("tshark") is None:
            pytest.skip("tshark not installed on this host")

        result = await TSharkClient().check_capabilities()

        assert result["success"]
        assert result["data"]["tshark"]["available"] is True


class TestRunCommand:
    """Tests for _run_command error handling."""

    @pytest.mark.asyncio
    async def test_file_not_found_returns_error(self, real_client: TSharkClient) -> None:
        result_str = await real_client.get_protocol_stats("/nonexistent.pcap")
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] == "FileNotFound"

    @pytest.mark.asyncio
    async def test_binary_whitelist_blocks_unknown(self, real_client: TSharkClient) -> None:
        result_str = await real_client._run_command(["curl", "http://evil.com"])
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] == "SecurityError"

    @pytest.mark.asyncio
    async def test_binary_whitelist_allows_windows_exe_names(self, real_client: TSharkClient) -> None:
        result_str = await real_client._run_command(["C:\\Wireshark\\tshark.exe", "-v"])
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] != "SecurityError"

    @pytest.mark.asyncio
    async def test_binary_whitelist_allows_windows_exe_names_case_insensitive(self, real_client: TSharkClient) -> None:
        result_str = await real_client._run_command(["C:\\Wireshark\\tshark.EXE", "-v"])
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] != "SecurityError"


class TestEnvelopeContract:
    """The client must always return an envelope, so `data` is never re-parsed."""

    def test_ok_wraps_data_as_string(self) -> None:
        wrapped = json.loads(TSharkClient._ok("hello"))
        assert wrapped == {"success": True, "data": "hello"}

    def test_stderr_kept_out_of_data(self) -> None:
        # Diagnostic stderr must not corrupt structured data (e.g. -T json).
        wrapped = json.loads(TSharkClient._ok('[{"frame":1}]', stderr="tshark: warning"))
        assert wrapped["data"] == '[{"frame":1}]'
        assert json.loads(wrapped["data"]) == [{"frame": 1}]  # data stays parseable
        assert wrapped["stderr"] == "tshark: warning"

    def test_unwrap_success_returns_data(self) -> None:
        ok, text = TSharkClient._unwrap(TSharkClient._ok("payload"))
        assert ok is True
        assert text == "payload"

    def test_unwrap_error_propagates_envelope(self) -> None:
        err = json.dumps({"success": False, "error": {"type": "X", "message": "boom"}})
        ok, text = TSharkClient._unwrap(err)
        assert ok is False
        assert text == err

    def test_unwrap_tolerates_bare_text(self) -> None:
        ok, text = TSharkClient._unwrap("just raw text")
        assert ok is True
        assert text == "just raw text"

    @pytest.mark.asyncio
    async def test_packet_data_mimicking_error_is_not_misclassified(self, monkeypatch, tmp_path) -> None:
        """Regression: field data that looks like {"success": false} must stay data."""
        from wireshark_mcp.tools.envelope import parse_tool_result

        pcap = tmp_path / "cap.pcap"
        pcap.write_bytes(b"\x00" * 64)
        evil = '{"success": false, "error": "this is packet DATA not an error"}'

        class FakeProc:
            returncode = 0

            async def communicate(self):
                return evil.encode(), b""

            def kill(self) -> None:  # pragma: no cover
                pass

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        client = TSharkClient()
        raw = await client._run_command([client.tshark_path, "-r", str(pcap), "-T", "fields"])
        wrapped = parse_tool_result(raw)

        assert wrapped["success"] is True
        assert wrapped["data"] == evil


class TestPagination:
    """Tests for offset/limit windowing and cache/pagination independence."""

    def test_paginate_windows_and_marks_truncation(self) -> None:
        output = "\n".join(str(i) for i in range(10))
        text, truncated = TSharkClient._paginate(output, limit_lines=3, offset_lines=0)
        assert text.startswith("0\n1\n2")
        assert truncated is True
        assert "Next: offset=3" in text

    def test_paginate_offset_slices_from_start(self) -> None:
        output = "\n".join(str(i) for i in range(10))
        text, truncated = TSharkClient._paginate(output, limit_lines=0, offset_lines=5)
        assert text == "5\n6\n7\n8\n9"
        assert truncated is False

    def test_paginate_no_limit_returns_all(self) -> None:
        output = "a\nb\nc"
        text, truncated = TSharkClient._paginate(output, limit_lines=0, offset_lines=0)
        assert text == "a\nb\nc"
        assert truncated is False

    def test_output_paths_detects_write_target(self) -> None:
        assert TSharkClient._output_paths(["mergecap", "-w", "out.pcap", "a.pcap"]) == ["out.pcap"]
        assert TSharkClient._output_paths(["tshark", "-r", "in.pcap"]) == []

    @pytest.mark.asyncio
    async def test_different_offsets_do_not_pollute_cache(self, monkeypatch, tmp_path) -> None:
        """Regression: paginated reads must not overwrite each other in the cache."""
        pcap = tmp_path / "cap.pcap"
        pcap.write_bytes(b"\x00" * 64)
        full = "\n".join(f"row{i}" for i in range(6))

        client = TSharkClient()
        calls = {"n": 0}

        class FakeProc:
            returncode = 0

            async def communicate(self):
                calls["n"] += 1
                return full.encode(), b""

            def kill(self) -> None:  # pragma: no cover - not reached
                pass

        async def fake_exec(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        cmd = [client.tshark_path, "-r", str(pcap), "-T", "fields"]

        _, first = client._unwrap(await client._run_command(cmd, limit_lines=2, offset_lines=0))
        assert first.startswith("row0\nrow1")
        assert "Next: offset=2" in first

        # Second call: same command, different window — served from cache, correct slice.
        _, second = client._unwrap(await client._run_command(cmd, limit_lines=0, offset_lines=4))
        assert second == "row4\nrow5"
        assert calls["n"] == 1  # subprocess ran only once; window applied post-cache


class TestSuiteBehavior:
    @pytest.mark.asyncio
    async def test_list_interfaces_prefers_dumpcap_when_available(self, mock_client) -> None:
        result = await mock_client.list_interfaces()
        assert "dumpcap" in result
        assert mock_client._last_cmd[0] == "dumpcap"

    @pytest.mark.asyncio
    async def test_list_interfaces_falls_back_to_tshark(self, mock_client) -> None:
        mock_client.dumpcap_path = None
        mock_client._tool_paths["dumpcap"] = None

        result = await mock_client.list_interfaces()
        assert "tshark" in result
        assert mock_client._last_cmd[0] == "tshark"

    @pytest.mark.asyncio
    async def test_capture_prefers_dumpcap_when_available(self, mock_client) -> None:
        result = await mock_client.capture_packets("en0", "/tmp/out.pcapng", duration=10)
        assert "dumpcap" in result
        assert mock_client._last_cmd[0] == "dumpcap"

    @pytest.mark.asyncio
    async def test_capture_falls_back_to_tshark(self, mock_client) -> None:
        mock_client.dumpcap_path = None
        mock_client._tool_paths["dumpcap"] = None

        result = await mock_client.capture_packets("en0", "/tmp/out.pcapng", duration=10)
        assert "tshark" in result
        assert mock_client._last_cmd[0] == "tshark"
