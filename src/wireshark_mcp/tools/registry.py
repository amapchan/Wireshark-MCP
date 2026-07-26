"""Analysis tool registration with protocol-aware recommendations.

All analysis tools are registered once at startup — the tool surface is static.
`wireshark_open_file` inspects a capture's protocol hierarchy and points the
caller at the subset of already-registered tools most relevant to what the
capture actually contains. It does not add or remove tools.
"""

import logging
import re
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")

# A factory maps a client to a list of (tool_name, tool_function) pairs.
ToolFactory = Callable[[TSharkClient], list[tuple[str, Any]]]


# ── Protocol → recommended tools ────────────────────────────────────────────
# Maps a protocol seen in the capture to the analysis tools worth running for it.
# Used only to build recommendation text; every listed tool is always registered.
PROTOCOL_TOOL_MAP: dict[str, list[str]] = {
    "http": [
        "wireshark_extract_http_requests",
        "wireshark_export_objects",
        "wireshark_extract_credentials",
        "wireshark_yara_scan",
    ],
    "dns": [
        "wireshark_extract_dns_queries",
        "wireshark_detect_dns_tunnel",
    ],
    "tls": [
        "wireshark_extract_tls_handshakes",
        "wireshark_verify_ssl_decryption",
        "wireshark_extract_fingerprints",
    ],
    "ssl": [
        "wireshark_extract_tls_handshakes",
        "wireshark_verify_ssl_decryption",
    ],
    "arp": [
        "wireshark_detect_arp_spoofing",
    ],
    "smtp": [
        "wireshark_extract_smtp_emails",
    ],
    "dhcp": [
        "wireshark_extract_dhcp_info",
    ],
    "bootp": [
        "wireshark_extract_dhcp_info",
    ],
    "ftp": [
        "wireshark_extract_credentials",
    ],
    "telnet": [
        "wireshark_extract_credentials",
    ],
    "ip": [
        "wireshark_check_threats",
        "wireshark_detect_port_scan",
        "wireshark_detect_dos_attack",
        "wireshark_analyze_suspicious_traffic",
        "wireshark_geoip_enrich",
    ],
    "tcp": [
        "wireshark_analyze_tcp_health",
    ],
    "quic": [
        "wireshark_analyze_quic",
    ],
    "http3": [
        "wireshark_analyze_quic",
    ],
    "websocket": [
        "wireshark_analyze_websocket",
    ],
    "mqtt": [
        "wireshark_analyze_mqtt",
    ],
    "grpc": [
        "wireshark_analyze_grpc",
    ],
    "http2": [
        "wireshark_analyze_grpc",
    ],
    "modbus": [
        "wireshark_analyze_modbus",
    ],
    "mbtcp": [
        "wireshark_analyze_modbus",
    ],
    "s7comm": [
        "wireshark_analyze_s7comm",
    ],
    "dnp3": [
        "wireshark_analyze_dnp3",
    ],
    "coap": [
        "wireshark_analyze_coap",
    ],
    "zbee_nwk": [
        "wireshark_analyze_zigbee",
    ],
    "zbee_aps": [
        "wireshark_analyze_zigbee",
    ],
    "btle": [
        "wireshark_analyze_ble",
    ],
    "wlan": [
        "wireshark_analyze_wifi",
    ],
    "wg": [
        "wireshark_analyze_wireguard",
    ],
    "icmp": [
        "wireshark_detect_icmp_tunnel",
    ],
}


class ToolRegistry:
    """Registers the analysis tool catalog and maps protocols to recommendations."""

    def __init__(self, mcp: FastMCP, client: TSharkClient) -> None:
        self._mcp = mcp
        self._client = client
        # tool_name -> tool function, for docstring lookup and recommendation validation
        self._catalog: dict[str, Any] = {}

    def register(self) -> list[str]:
        """Register every analysis tool on the MCP server. Returns registered names."""
        from .anomaly import make_anomaly_tools
        from .extract import make_extract_tools
        from .forensics import make_forensics_tools
        from .geoip import make_geoip_tools
        from .ics import make_ics_tools
        from .iot import make_iot_tools
        from .protocol import make_protocol_tools
        from .security import make_security_tools
        from .threat import make_threat_tools
        from .yara_scan import make_yara_tools

        factories: list[ToolFactory] = [
            make_extract_tools,
            make_protocol_tools,
            make_security_tools,
            make_threat_tools,
            make_ics_tools,
            make_iot_tools,
            make_forensics_tools,
            make_anomaly_tools,
            make_geoip_tools,
            make_yara_tools,
        ]

        for factory in factories:
            for name, fn in factory(self._client):
                self._catalog[name] = fn

        registered: list[str] = []
        for name in sorted(self._catalog):
            try:
                self._mcp.add_tool(self._catalog[name], name=name)
                registered.append(name)
            except Exception as exc:
                logger.warning("Failed to register tool %s: %s", name, exc)

        self._warn_on_unknown_recommendations()
        logger.info("Registered %d analysis tools", len(registered))
        return registered

    def _warn_on_unknown_recommendations(self) -> None:
        """Flag any PROTOCOL_TOOL_MAP entry that names a tool we never registered."""
        referenced = {tool for tools in PROTOCOL_TOOL_MAP.values() for tool in tools}
        for tool_name in sorted(referenced - self._catalog.keys()):
            logger.warning("PROTOCOL_TOOL_MAP references unregistered tool: %s", tool_name)

    def recommended_tools_for_protocols(self, detected_protocols: set[str]) -> list[str]:
        """Return registered tools relevant to the detected protocols."""
        recommended: set[str] = set()
        for protocol in detected_protocols:
            for tool_name in PROTOCOL_TOOL_MAP.get(protocol.lower().strip(), []):
                if tool_name in self._catalog:
                    recommended.add(tool_name)
        return sorted(recommended)

    def tool_doc(self, tool_name: str) -> str:
        """Return the first docstring line for a registered tool, or empty string."""
        fn = self._catalog.get(tool_name)
        return (fn.__doc__ or "").strip().split("\n")[0] if fn else ""

    @property
    def catalog_size(self) -> int:
        """Number of analysis tools in the catalog."""
        return len(self._catalog)


def parse_protocol_hierarchy(phs_output: str) -> set[str]:
    """Parse tshark `-z io,phs` output into a set of protocol names.

    Handles the typical hierarchy format::

        eth  frames:100 bytes:12345
          ip  frames:90 bytes:11000
            tcp  frames:80 bytes:10000
              http  frames:30 bytes:5000
    """
    protocols: set[str] = set()
    for line in phs_output.splitlines():
        match = re.match(r"^\s*(\w[\w.-]*)\s+frames:", line)
        if match:
            protocols.add(match.group(1).lower())
    return protocols


def register_open_file_tool(mcp: FastMCP, client: TSharkClient, registry: ToolRegistry) -> None:
    """Register the wireshark_open_file entry-point tool."""

    @mcp.tool()
    async def wireshark_open_file(pcap_file: str) -> str:
        """[Entry Point] Open a pcap and get protocol-aware tool recommendations. Returns protocols and relevant tools."""
        phs_raw = await client.get_protocol_stats(pcap_file)
        phs_result = parse_tool_result(normalize_tool_result(phs_raw))
        if not phs_result["success"]:
            return normalize_tool_result(phs_result)

        file_info_raw = await client.get_file_info(pcap_file)
        file_info = parse_tool_result(normalize_tool_result(file_info_raw))

        detected_protocols: set[str] = set()
        phs_data = phs_result.get("data", "")
        if isinstance(phs_data, str):
            detected_protocols = parse_protocol_hierarchy(phs_data)

        recommended_tools = registry.recommended_tools_for_protocols(detected_protocols)

        output_parts = ["File Info:"]
        if file_info["success"]:
            data = file_info.get("data", "N/A")
            output_parts.append(data if isinstance(data, str) else str(data))
        else:
            output_parts.append("Detailed file metadata unavailable (capinfos not installed or file summary failed).")

        if detected_protocols:
            output_parts.append(f"\nProtocols ({len(detected_protocols)}):")
            output_parts.append(", ".join(sorted(detected_protocols)))

        if recommended_tools:
            output_parts.append(f"\nRecommended Tools ({len(recommended_tools)}):")
            for tool_name in recommended_tools:
                output_parts.append(f"  {tool_name}: {registry.tool_doc(tool_name)}")
        else:
            output_parts.append("\nNo protocol-specific recommendations. Core tools are available.")

        output_parts.append(
            "\nStart with wireshark_quick_analysis or wireshark_get_packet_list, then use recommended tools."
        )

        return success_response("\n".join(output_parts))
