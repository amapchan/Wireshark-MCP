"""Security analysis tools for Wireshark MCP."""

from typing import Any

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response


def make_security_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build security tools."""

    async def wireshark_extract_credentials(pcap_file: str) -> str:
        """[Security] Scan for plaintext credentials (HTTP Basic Auth, FTP passwords, Telnet)."""
        findings: list[str] = []

        http_auth = await client.extract_fields(pcap_file, ["http.authbasic"], "http.authbasic", limit=50)
        http_auth_wrapped = parse_tool_result(http_auth)
        if not http_auth_wrapped["success"]:
            return normalize_tool_result(http_auth_wrapped)
        http_auth_data = http_auth_wrapped.get("data")
        if isinstance(http_auth_data, str) and len(http_auth_data.strip()) > 20:
            findings.append(f"HTTP Basic Auth:\n{http_auth_data[:500]}")

        ftp_pass = await client.extract_fields(pcap_file, ["ftp.request.arg"], "ftp.request.command == PASS", limit=50)
        ftp_pass_wrapped = parse_tool_result(ftp_pass)
        if not ftp_pass_wrapped["success"]:
            return normalize_tool_result(ftp_pass_wrapped)
        ftp_pass_data = ftp_pass_wrapped.get("data")
        if isinstance(ftp_pass_data, str) and len(ftp_pass_data.strip()) > 20:
            findings.append(f"FTP Passwords:\n{ftp_pass_data[:500]}")

        telnet_data = await client.search_packet_contents(pcap_file, "login", "string", limit=10)
        telnet_wrapped = parse_tool_result(telnet_data)
        if not telnet_wrapped["success"]:
            return normalize_tool_result(telnet_wrapped)
        telnet_payload = telnet_wrapped.get("data")
        if isinstance(telnet_payload, str) and ("Login" in telnet_payload or "Password" in telnet_payload):
            findings.append("Possible Telnet/cleartext authentication detected (use follow_stream to analyze)")

        if not findings:
            return success_response("No obvious plaintext credentials found.")

        return success_response("\n\n---\n".join(findings))

    return [
        ("wireshark_extract_credentials", wireshark_extract_credentials),
    ]
