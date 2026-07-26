<div align="center">
<!-- mcp-name: io.github.bx33661/wireshark-mcp -->

<img src="Logo.png" width="150" alt="Wireshark MCP" style="margin-top: 20px; margin-bottom: 20px;">

<h1>Wireshark MCP</h1>

**给你的 AI 助手一个数据包分析器。**

*丢入一个 `.pcap` 文件，用自然语言提问 — 获得基于真实 `tshark` 数据的回答。*

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

## 这是什么？

一个 [MCP 服务器](https://modelcontextprotocol.io/introduction)，将 `tshark`（及可选的 Wireshark 套件工具）封装为结构化分析接口。支持 Claude Desktop、Claude Code、Cursor、VS Code 等 [18+ MCP 客户端](docs-site/src/content/docs/getting-started/mcp-clients.md)。

```
你：    "找出这个抓包中所有访问可疑域名的 DNS 查询。"
Claude: [调用 wireshark_extract_dns_queries → wireshark_check_threats]
        "发现 3 条命中 URLhaus 威胁情报的域名查询：..."
```

---

## 安装

**前置条件：** Python 3.10+ 和 [Wireshark](https://www.wireshark.org/)（`tshark` 需在 PATH 中）。

```sh
pip install wireshark-mcp
wireshark-mcp install   # 自动配置所有检测到的 MCP 客户端
```

重启你的 AI 客户端即可。

如有问题运行 `wireshark-mcp doctor` 诊断。手动配置或平台特定说明见 [docs-site/src/content/docs/reference/manual-configuration.md](docs-site/src/content/docs/reference/manual-configuration.md)。

---

## 快速开始

将 AI 客户端指向一个 `.pcap` 文件，尝试：

```
使用 Wireshark MCP 工具分析 capture.pcap。
先用 wireshark_open_file 打开，然后运行 wireshark_security_audit。
将发现写入 report.md。
```

---

## 工具

80+ 工具，每个都由真实 `tshark` 输出支撑，按类别组织：

| 类别 | 亮点 | 数量 |
|------|------|:----:|
| **入口与工作流** | `wireshark_open_file`、`wireshark_quick_analysis`、`wireshark_security_audit` | 3 |
| **数据包分析** | 数据包列表、详情、字节、上下文、流追踪、搜索 | 8 |
| **数据提取** | HTTP 请求、DNS 查询、TLS 握手、凭据、字段提取 | 11 |
| **统计** | 协议层次、端点、会话、I/O 图、HTTP/SMB/RTP 统计、绘图 | 13 |
| **安全与威胁** | 威胁情报、凭据扫描、端口扫描、DNS 隧道、DoS、信标、外泄 | 13 |
| **协议深入** | TCP 健康、QUIC、WebSocket、gRPC、MQTT、TLS/WPA 解密、指纹 | 11 |
| **工控/物联网/无线** | Modbus、S7comm、DNP3、CoAP、Zigbee、BLE、Wi-Fi、WireGuard | 8 |
| **取证与解码** | 文件雕刻、证据链、YARA 扫描、载荷解码、GeoIP | 8 |
| **文件操作、抓包与套件** | 实时抓包、合并、过滤保存、editcap 裁剪/分割/去重、text2pcap | 11 |

服务器仅需 `tshark` 即可启动。可选工具（`capinfos`、`mergecap`、`editcap`、`dumpcap`、`text2pcap`）自动检测，存在时启用额外功能。

---

## 文档

| 主题 | 链接 |
|------|------|
| 平台配置（macOS/Linux/Windows） | [docs-site/src/content/docs/reference/toolchain.md](docs-site/src/content/docs/reference/toolchain.md) |
| 手动客户端配置 | [docs-site/src/content/docs/reference/manual-configuration.md](docs-site/src/content/docs/reference/manual-configuration.md) |
| Prompt 模板 | [docs-site/src/content/docs/reference/playbooks.mdx](docs-site/src/content/docs/reference/playbooks.mdx) |
| 发布清单 | [docs-site/src/content/docs/reference/changelog.md](docs-site/src/content/docs/reference/changelog.md) |
| 贡献指南 | [CONTRIBUTING.md](CONTRIBUTING.md) |
| 更新日志 | [GitHub Releases](https://github.com/bx33661/Wireshark-MCP/releases) |
| 安全策略 | [SECURITY.md](SECURITY.md) |

---

## 开发

```sh
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/
```

完整指南见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">报告 Bug</a></sub>
</div>
