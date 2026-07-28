<div align="center">
<!-- mcp-name: io.github.bx33661/wireshark-mcp -->

<img src="Logo.png" width="150" alt="Wireshark MCP" style="margin-top: 20px; margin-bottom: 20px;">

<h1>Wireshark MCP</h1>

**Give your AI assistant a packet analyzer.**

*Drop a `.pcap` file, ask questions in plain English — get answers backed by real `tshark` data.*

<p style="margin-top: 15px;">
  <a href="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/bx33661/Wireshark-MCP/ci.yml?style=flat-square&logo=github&label=CI" alt="CI">
  </a>
  <a href="https://github.com/bx33661/Wireshark-MCP/releases/latest">
    <img src="https://img.shields.io/github/v/release/bx33661/Wireshark-MCP?style=flat-square&logo=github&color=24292f" alt="GitHub Release">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/v/wireshark-mcp?style=flat-square&logo=pypi&color=0066cc" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/pyversions/wireshark-mcp?style=flat-square&logo=python" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="MIT License">
  </a>
</p>

<p>
  <a href="README.md"><b>English</b></a> •
  <a href="README_zh.md"><b>中文</b></a> •
  <a href="https://github.com/bx33661/Wireshark-MCP/releases"><b>Changelog</b></a> •
  <a href="CONTRIBUTING.md"><b>Contributing</b></a>
</p>
</div>

---

## What is this?

An [MCP server](https://modelcontextprotocol.io/introduction) that wraps `tshark` (and optional Wireshark suite tools) into a structured analysis interface. Works with Claude Desktop, Claude Code, Cursor, VS Code, and 18+ other MCP clients.

```
You:    "Find all DNS queries going to suspicious domains in this capture."
Claude: [calls wireshark_extract_dns_queries → wireshark_detect_dns_tunnel]
        "Found repeated high-entropy DNS queries consistent with tunneling: ..."
```

---

## Install

**Prerequisites:** Python 3.10+ and [Wireshark](https://www.wireshark.org/) with `tshark` on PATH.

```sh
pip install wireshark-mcp
wireshark-mcp install   # auto-configures all detected MCP clients
```

Restart your AI client — done.

Run `wireshark-mcp doctor` if anything looks off. See [docs/manual-configuration.md](docs/manual-configuration.md) for manual setup or platform-specific notes.

---

## Quick Start

Point your AI client at a `.pcap` file and try:

```
Analyze capture.pcap using the Wireshark MCP tools.
Start with wireshark_open_file, then run wireshark_security_audit.
Write findings to report.md.
```

---

## Tools

80+ tools, each backed by real `tshark` output — organized into categories:

| Category | Highlights | Count |
|----------|-----------|:-----:|
| **Entry & Workflow** | `wireshark_open_file`, `wireshark_quick_analysis`, `wireshark_security_audit` | 3 |
| **Packet Analysis** | Packet list, details, bytes, context, stream follow, search | 8 |
| **Data Extraction** | HTTP requests, DNS queries, TLS handshakes, credentials, fields | 11 |
| **Statistics** | Protocol hierarchy, endpoints, conversations, I/O graph, HTTP/SMB/RTP stats, plots | 13 |
| **Security & Threat** | Credential scan, port scan, DNS tunnel, DoS, beaconing, exfiltration | 12 |
| **Protocol Deep-Dive** | TCP health, QUIC, WebSocket, gRPC, MQTT, TLS/WPA decrypt, fingerprints | 11 |
| **ICS / IoT / Wireless** | Modbus, S7comm, DNP3, CoAP, Zigbee, BLE, Wi-Fi, WireGuard | 8 |
| **Forensics & Decode** | File carving, evidence chain, YARA scan, payload decode, GeoIP | 8 |
| **File Ops, Capture & Suite** | Live capture, merge, filter-save, editcap trim/split/dedup, text2pcap | 11 |

The server starts with only `tshark` required. Optional tools (`capinfos`, `mergecap`, `editcap`, `dumpcap`, `text2pcap`) are auto-detected and enable extra features when present.

### Context cost

The tool list travels in the prompt prefix of every request your client sends, so its size is a fixed per-request cost. The advertised surface is ~27 KB (~6.9k tokens) of schema plus ~5 KB of annotations, and it is byte-identical across restarts so clients can cache the prefix rather than re-reading it each session.

Tool results are bounded too, since a result stays in the conversation for the rest of the session. Output over 8000 characters is truncated head-and-tail with a marker, and the tool's `offset` / `limit` / `display_filter` parameters are the way to page through the rest. Raise or lower the ceiling with:

```bash
export WIRESHARK_MCP_MAX_RESULT_CHARS=16000
```

Every tool also declares whether it reads or writes, so clients can auto-approve the 74 read-only analysis tools and still prompt for the 11 that create files (live capture, merge, filter-save, editcap, text2pcap, object export).

---

## Documentation

| Topic | Link |
|-------|------|
| Platform setup (macOS/Linux/Windows) | [docs/platform-validation.md](docs/platform-validation.md) |
| Manual client configuration | [docs/manual-configuration.md](docs/manual-configuration.md) |
| Prompt templates | [docs/prompt-engineering.md](docs/prompt-engineering.md) |
| Release checklist | [docs/release-checklist.md](docs/release-checklist.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Changelog | [GitHub Releases](https://github.com/bx33661/Wireshark-MCP/releases) |
| Security policy | [SECURITY.md](SECURITY.md) |

---

## Development

```sh
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">Report a Bug</a></sub>
</div>
