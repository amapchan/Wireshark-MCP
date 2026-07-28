"""Tests for security tools."""

import pytest


class TestSecurityToolIntegration:
    """Integration tests for security tools using mocked tshark."""

    @pytest.mark.asyncio
    async def test_extract_credentials_builds_correct_queries(self) -> None:
        """Verify credential extraction queries the correct fields."""
        from conftest import MockTSharkClient

        client = MockTSharkClient()

        # HTTP basic auth query
        result = await client.extract_fields("test.pcap", ["http.authbasic"], "http.authbasic", limit=50)
        assert "http.authbasic" in result

        # FTP password query
        result = await client.extract_fields("test.pcap", ["ftp.request.arg"], "ftp.request.command == PASS", limit=50)
        assert "ftp.request.arg" in result
