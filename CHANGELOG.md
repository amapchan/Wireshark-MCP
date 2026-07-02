# Changelog

All notable changes to this project are documented below.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## Releases

| Version | Date | Highlights |
|---------|------|------------|
| 2.0.0 | 2026-05-22 | Architecture overhaul: modular installer, typed tshark client, investigation engine, and strict type safety. |
| 1.2.0 | 2026-05-10 | Performance, token optimization, and new protocol analysis tools. |
| 1.1.5 | 2026-04-18 | - **TUI arrow-key input on macOS / iTerm2 / Claude Code terminal** — `_read_key_unix` now handles both CSI (`\x1b[A/B`) and SS3 (`\x1bOA/B`) escape sequences. Previously, terminals that emit SS3 sequences (macOS Terminal, iTerm2, application cursor-key mode) caused every Up/Down keypress to be misread as ESC, immediately exiting the installer menu. |
| 1.1.0 | 2026-04-17 | - **OpenCode MCP client support** — Auto-install and manual config for [OpenCode](https://opencode.ai) on macOS, Linux, and Windows. OpenCode uses a flat `"mcp"` key with `command` as an array and env under `"environment"`; a dedicated config generator handles this correctly. |
| 1.0.0 | 2026-03-16 | - **`wireshark_get_capabilities`** — New MCP tool and `wireshark://capabilities` resource that reports which Wireshark suite tools are present and which MCP tools are currently active. |
| 0.6.4 | 2026-03-14 | - Follow-up packaging release to restore a green CI state after the cross-client skill discovery work in 0.6.3 — fixed a lint issue introduced in the new skill distribution test. |
| 0.6.3 | 2026-03-14 | - **Cross-app skill discovery entrypoints** — Added `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, GitHub Copilot repository instructions (`.github/copilot-instructions.md`), and a reusable GitHub Copilot prompt file (`.github/prompts/wireshark-traffic-analysis.prompt.md`) so every major AI runtime can find the bundled skill. |
| 0.6.2 | 2026-03-14 | - **Bundled `wireshark-traffic-analysis` skill** — Added at `skills/wireshark-traffic-analysis/` covering structured packet triage, security hunting, incident response, troubleshooting, and CTF workflows. |
| 0.6.1 | 2026-03-14 | - **Cross-platform auto-install** — Config paths now use platform-correct separators and locations on macOS, Linux, and Windows; Python module entrypoint is stable across all three. |
| 0.6.0 | 2025-06-27 | - **`wireshark_security_audit`** — One-call comprehensive security audit across 8 analysis phases; produces a structured report with risk score (0–100), findings, and remediation recommendations. |
| 0.4.0 | 2025-06-01 | - **`wireshark_get_packet_bytes`** — Returns the raw Hex/ASCII dump of a frame (equivalent to Wireshark's Packet Bytes pane). |
| 0.2.1 | 2025-05-01 | Initial public release. / 首次公开发布。 |

---

## 2.0.0 — 2026-05-22

Architecture overhaul: modular installer, typed tshark client, investigation engine, and strict type safety.

## Added

- **Investigation engine** — session-based investigation with playbook execution and evidence tracking
- **Playbook system** — 4 bundled playbooks (malware triage, lateral movement, data exfil, DNS tunnel)
- **Report generator** — Markdown/JSON reports with IOC extraction and detection rule generation
- **Natural language query** — intent-mapped NL interface for packet analysis
- **Anomaly detectors** — beacon detection (jitter analysis), exfiltration detection, protocol anomaly detection
- **Aggregate anomaly tool** — `wireshark_detect_anomalies` runs all detectors concurrently
- **Metadata enrichment** — external IP/domain extraction for forensic evidence chains
- **Hypothesis-driven prompts** — alert investigation and hypothesis prompts for guided analysis
- **`ToolRegistry.register_and_catalog()`** — convenience method for one-step tool registration
- **`_typing.py` Protocol class** — typed mixin interface for tshark client cross-references
- **`types-PyYAML`** — dev dependency for mypy yaml stub coverage

## Changed

- **tshark client split** — `client.py` god object decomposed into 6 focused mixins (`_validation`, `_packets`, `_extraction`, `_stats`, `_suite_ops`, `_capture`)
- **Installer split** — monolithic `installer.py` decomposed into 7-module package (`_detection`, `_config_gen`, `_clients`, `_writer`, `_orchestrator`, `_doctor`, `__init__`)
- **mypy strict mode** — enabled across all 51 source files with zero errors
- **`_analyze_urlhaus_matches`** — renamed to public `analyze_urlhaus_matches` API
- **CI actions** — pinned to official versions (`checkout@v4`, `setup-python@v5`)
- **Version bump** — 1.2.0 → 2.0.0 (breaking internal API changes)

## Breaking

- `installer.py` removed — import from `wireshark_mcp.installer` subpackage instead
- `TSharkClient` internal methods moved to mixin classes (public API unchanged)
- `_analyze_urlhaus_matches` renamed to `analyze_urlhaus_matches`

---

## 1.2.0 — 2026-05-10

Performance, token optimization, and new protocol analysis tools.

## Added

- **QUIC/HTTP3 analysis** — `wireshark_analyze_quic` extracts QUIC version, connection IDs, SNI, and HTTP/3 frames
- **WebSocket analysis** — `wireshark_analyze_websocket` reports frame types, payload lengths, and masking
- **MQTT analysis** — `wireshark_analyze_mqtt` extracts message types, topics, QoS, and client IDs with frequency stats
- **gRPC analysis** — `wireshark_analyze_grpc` with HTTP/2 content-type fallback detection
- **Result cache** — LRU cache for tshark read-only commands (file mtime + size invalidation, 5-min TTL)
- **Token budget test** — CI guard ensuring total tool docstring size stays under 8000 chars
- **Concurrency tests** — verify agents and TCP health run phases in parallel
- **Protocol tool tests** — coverage for all 4 new protocol tools

## Changed

- **Concurrent security audit** — 6 independent analysis phases now run via `asyncio.gather` (~3x faster)
- **Concurrent quick analysis** — 7 data fetches run in parallel
- **Concurrent TCP health** — 8 tshark checks run via `asyncio.gather` instead of sequential loop
- **Docstring optimization** — all 51 tool descriptions slimmed to 4447 chars total (~1100 tokens)
- **Output format** — emoji replaced with text tags (`[!]`/`[W]`/`[i]`/`[OK]`), ASCII box art removed
- **Stats truncation** — `expert_info` and `service_response_time` now auto-truncate large results
- **Publish workflow** — added `contents: read` permission and Homebrew tap notification step; tap dispatch HTTP failures now fail the release step instead of being silently ignored
- **Homebrew bottle workflow** — relies on `Homebrew/actions/setup-homebrew`'s local tap setup; bot bottle-block commits marked with `[skip bottles]` are now skipped
- **Homebrew formula** — generator and formula updated to satisfy current `brew style` checks
- **`.gitignore`** — generated Claude worktrees ignored so machine-local checkouts stay out of patches

## Fixed

- Version mismatch between `pyproject.toml` and `server.json`

---

## 1.1.5 — 2026-04-18

---

## English

### Fixed

- **TUI arrow-key input on macOS / iTerm2 / Claude Code terminal** — `_read_key_unix` now handles both CSI (`\x1b[A/B`) and SS3 (`\x1bOA/B`) escape sequences. Previously, terminals that emit SS3 sequences (macOS Terminal, iTerm2, application cursor-key mode) caused every Up/Down keypress to be misread as ESC, immediately exiting the installer menu.
- **Buffered stdin race condition** — Replaced `sys.stdin.buffer.read(1)` with `os.read(fd, 1)` throughout the key-reader. Python's `BufferedReader` was pre-buffering the entire 3-byte escape sequence (`\x1b[A`) in a single syscall, leaving the underlying fd empty so the subsequent `select.select()` always timed out and reported ESC. Direct fd reads bypass this layer entirely. `select.select` now also targets the raw fd integer rather than the stream object.
- **Select timeout increased** — Raised from 50 ms to 100 ms to accommodate slower terminals where escape-sequence bytes arrive with slight delays.

### Added

- **Void editor** — Auto-install support for [Void](https://voideditor.com) (open-source Cursor alternative) on macOS, Linux, and Windows. Config: `~/.config/void/mcp_servers.json`.
- **BoltAI** — Auto-install support for [BoltAI](https://boltai.com) (macOS-only native AI client). Config: `~/.boltai/mcp.json`.
- **Kiro** — Auto-install support for [Kiro](https://kiro.dev) (Amazon's AI IDE) on macOS, Linux, and Windows. Config: `~/.kiro/settings/mcp.json`.

---

## 中文

### 修复

- **macOS / iTerm2 / Claude Code 终端中箭头键无法使用** — `_read_key_unix` 现在同时处理 CSI（`\x1b[A/B`）和 SS3（`\x1bOA/B`）两种转义序列。之前，发送 SS3 序列的终端（macOS Terminal、iTerm2、应用光标键模式）会将每次上下键误判为 ESC，导致安装菜单立即退出。
- **BufferedReader 缓冲导致 select 失效** — 将 `sys.stdin.buffer.read(1)` 全部替换为 `os.read(fd, 1)`。Python 的 `BufferedReader` 在一次 syscall 中会把完整的 3 字节转义序列（`\x1b[A`）全部读入内部缓冲区，导致底层 fd 为空，后续 `select.select()` 始终超时并返回 ESC。直接读 fd 完全绕过缓冲层。`select.select` 也改为传入原始 fd 整数而非 stream 对象。
- **select 超时时间提升** — 从 50ms 增加到 100ms，兼容转义序列字节到达存在轻微延迟的终端。

### 新增

- **Void 编辑器** — 支持在 macOS、Linux、Windows 自动安装 [Void](https://voideditor.com)（开源 Cursor 替代品）。配置路径：`~/.config/void/mcp_servers.json`。
- **BoltAI** — 支持自动安装 [BoltAI](https://boltai.com)（macOS 专属原生 AI 客户端）。配置路径：`~/.boltai/mcp.json`。
- **Kiro** — 支持在 macOS、Linux、Windows 自动安装 [Kiro](https://kiro.dev)（Amazon 的 AI IDE）。配置路径：`~/.kiro/settings/mcp.json`。

---

## 1.1.0 — 2026-04-17

---

## English

### Added

- **OpenCode MCP client support** — Auto-install and manual config for [OpenCode](https://opencode.ai) on macOS, Linux, and Windows. OpenCode uses a flat `"mcp"` key with `command` as an array and env under `"environment"`; a dedicated config generator handles this correctly.
- **Interactive TUI installer** — `wireshark-mcp install` now shows an arrow-key + space checkbox menu (pure stdlib, no external dependencies) instead of installing to all detected clients at once. Already-detected clients are pre-selected. Falls back to install-all in non-TTY environments (CI, pipes).
- **`wireshark-mcp update` subcommand** — Explicitly re-writes the config only for clients that already have `wireshark-mcp` installed. Clients without an existing entry are skipped with `[SKIP] not installed`. Semantically distinct from `install` (which writes regardless).
- **`changelog/` directory** — Per-release Markdown files (bilingual EN/ZH) replacing the single `CHANGELOG.md`. The root `CHANGELOG.md` is now an index table pointing to each release file.

### Changed

- `CHANGELOG.md` restructured as a version index; full content moved to `changelog/<version>.md`.
- `AGENTS.md` now documents the `changelog/` convention so agents know where to record changes.
- Manual configuration docs (`docs/manual-configuration.md`, `docs/manual-configuration_zh.md`) updated with an OpenCode section.

---

## 中文

### 新增

- **OpenCode MCP 客户端支持** — 支持在 macOS、Linux、Windows 上自动安装和手动配置 [OpenCode](https://opencode.ai)。OpenCode 使用扁平 `"mcp"` 键、数组格式的 `command` 和 `"environment"` 环境变量，专用配置生成器正确处理这一差异。
- **交互式 TUI 安装器** — `wireshark-mcp install` 现在显示箭头键 + 空格勾选菜单（纯 stdlib，无外部依赖），不再一次性安装所有检测到的客户端。已检测到的客户端默认预选；非 TTY 环境（CI、管道）自动回退到全部安装。
- **`wireshark-mcp update` 子命令** — 只对已安装 `wireshark-mcp` 的客户端重新写入配置；未安装的客户端标注 `[SKIP] not installed` 跳过。语义上与 `install`（无论是否已安装都写入）明确区分。
- **`changelog/` 目录** — 将原单文件 `CHANGELOG.md` 拆分为每版本独立的双语（中英）Markdown 文件；根目录 `CHANGELOG.md` 改为指向各版本文件的索引表。

### 变更

- `CHANGELOG.md` 重构为版本索引，详细内容迁移至 `changelog/<version>.md`。
- `AGENTS.md` 新增 `changelog/` 目录规范说明。
- 手动配置文档（`docs/manual-configuration.md`、`docs/manual-configuration_zh.md`）新增 OpenCode 章节。

---

## 1.0.0 — 2026-03-16

---

## English

### Added

- **`wireshark_get_capabilities`** — New MCP tool and `wireshark://capabilities` resource that reports which Wireshark suite tools are present and which MCP tools are currently active.
- **Wireshark suite tool support** — Optional `editcap`-based operations: trim by timestamp, split by packet count or time interval, time-shift, and deduplication. `text2pcap` import also added when available.
- **Regression tests** — Added coverage for startup-wide contextual tool registration, `wireshark_open_file` recommendations, `capinfos`-free open-file fallback, and deterministic URLhaus URL/domain matching.
- **Machine-readable CLI output** — `wireshark-mcp doctor` and `wireshark-mcp clients` now accept `--format json` for programmatic consumption.
- **Focused `docs/` guides** — `docs/manual-configuration.md` and `docs/prompt-engineering.md` extracted from the README so the main README stays closer to a landing page.

### Changed

- **Stable 1.0 release** — Runtime `mcp` dependency pinned to the `1.x` line to reduce future compatibility drift.
- **Stable tool surface** — Contextual tools are now registered at server startup rather than mid-session; `wireshark_open_file` recommends tools instead of mutating the catalog.
- **`wireshark_open_file` graceful degradation** — Works on minimal `tshark`-only installations when `capinfos` is absent.
- **`wireshark_check_threats` semantics** — Now matches HTTP URLs and DNS/TLS hostnames against URLhaus data; replaces earlier IP-oriented matching for more reproducible results.
- **Documentation alignment** — `wireshark_security_audit`, MCP prompts, MCP resources, and both READMEs updated to reflect stable 1.0 workflow and new threat-intelligence semantics.
- **CLI documentation and CI** — Subcommand-oriented interface (`install`, `doctor`, `config`, `clients`) is now primary; legacy flag compatibility still documented.
- **Live capture backend** — Prefers `dumpcap` when available; `tshark` remains the only required dependency.
- **Installer diagnostics** — Wireshark tools now classified as `required`, `recommended`, or `optional`.
- **Release metadata** — Version agreed across `pyproject.toml`, registry metadata, and security documentation.

### Deprecated

- **`wireshark_read_packets`** — Remains available for 1.x compatibility; new workflows should use `wireshark_get_packet_list` + `wireshark_get_packet_details`.

### Removed

- Removed the unused root `requirements.txt` to avoid implying an undocumented second installation path.

---

## 中文

### 新增

- **`wireshark_get_capabilities`** — 新增 MCP 工具和 `wireshark://capabilities` 资源，报告当前已安装的 Wireshark 套件工具及激活的 MCP 工具列表。
- **Wireshark 套件工具支持** — 可选的 `editcap` 操作：按时间戳裁剪、按包数或时间间隔分割、时间偏移、去重。有 `text2pcap` 时同步支持导入。
- **回归测试** — 新增启动时全局上下文工具注册、`wireshark_open_file` 工具推荐、无 `capinfos` 降级、URLhaus URL/域名确定性匹配的覆盖测试。
- **CLI 机器可读输出** — `wireshark-mcp doctor` 和 `wireshark-mcp clients` 支持 `--format json`，便于程序化消费。
- **独立 `docs/` 指南** — 从 README 中拆出 `docs/manual-configuration.md` 和 `docs/prompt-engineering.md`，让主 README 更接近产品落地页。

### 变更

- **稳定 1.0 发布** — 运行时 `mcp` 依赖固定到 `1.x` 系列，降低未来兼容性漂移风险。
- **稳定工具面** — 上下文工具在服务器启动时注册，不再在会话中途变更；`wireshark_open_file` 改为推荐工具而非修改工具目录。
- **`wireshark_open_file` 优雅降级** — 无 `capinfos` 的最小化 `tshark` 安装下仍可正常工作。
- **`wireshark_check_threats` 语义变更** — 改为匹配 HTTP URL 和 DNS/TLS 主机名，替代原先基于 IP 的匹配，结果更可复现。
- **文档对齐** — `wireshark_security_audit`、MCP 提示、MCP 资源及两份 README 均更新以反映 1.0 稳定工作流和新威胁情报语义。
- **CLI 文档和 CI** — 子命令式接口（`install`、`doctor`、`config`、`clients`）成为主要方式；旧式 flag 兼容性仍有文档。
- **实时抓包后端** — 有 `dumpcap` 时优先使用；`tshark` 仍是唯一必需依赖。
- **安装诊断** — Wireshark 工具现分类为 `required`/`recommended`/`optional`。
- **发布元数据** — `pyproject.toml`、注册表元数据和安全文档版本号保持一致。

### 弃用

- **`wireshark_read_packets`** — 1.x 兼容性保留；新工作流应使用 `wireshark_get_packet_list` + `wireshark_get_packet_details`。

### 移除

- 删除未使用的根目录 `requirements.txt`，避免暗示存在未文档化的第二安装路径。

---

## 0.6.4 — 2026-03-14

---

## English

### Fixed

- Follow-up packaging release to restore a green CI state after the cross-client skill discovery work in 0.6.3 — fixed a lint issue introduced in the new skill distribution test.

---

## 中文

### 修复

- 0.6.3 跨客户端 skill 发现工作完成后的补丁发布，修复新增 skill 分发测试中引入的 lint 问题，恢复 CI 绿色状态。

---

## 0.6.3 — 2026-03-14

---

## English

### Added

- **Cross-app skill discovery entrypoints** — Added `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, GitHub Copilot repository instructions (`.github/copilot-instructions.md`), and a reusable GitHub Copilot prompt file (`.github/prompts/wireshark-traffic-analysis.prompt.md`) so every major AI runtime can find the bundled skill.
- **Machine-readable skill catalog** — `skills/manifest.json` enumerates all available skills with metadata; a sync script (`scripts/sync_skills.py`) mirrors the canonical `skills/` tree into `.github/skills/` and `.claude/skills/`.
- **Skill distribution tests** — New tests verify that mirrored skill directories and the skill catalog stay in sync with the canonical source.

### Changed

- **Refined `wireshark-traffic-analysis` skill** — More professional analyst language, clearer reporting structure, separate severity and confidence guidance.

---

## 中文

### 新增

- **跨应用 skill 发现入口** — 新增 `AGENTS.md`、`CLAUDE.md`、`GEMINI.md`、GitHub Copilot 仓库说明（`.github/copilot-instructions.md`）和可复用 Copilot 提示文件（`.github/prompts/wireshark-traffic-analysis.prompt.md`），使各主流 AI 运行时均可发现内置 skill。
- **机器可读 skill 目录** — `skills/manifest.json` 以元数据枚举所有可用 skill；同步脚本（`scripts/sync_skills.py`）将 canonical `skills/` 目录镜像到 `.github/skills/` 和 `.claude/skills/`。
- **Skill 分发测试** — 新增测试验证镜像目录和 skill 目录与 canonical 源保持同步。

### 变更

- **优化 `wireshark-traffic-analysis` skill** — 更专业的分析师语言、更清晰的报告结构，严重性与置信度指导分离。

---

## 0.6.2 — 2026-03-14

---

## English

### Added

- **Bundled `wireshark-traffic-analysis` skill** — Added at `skills/wireshark-traffic-analysis/` covering structured packet triage, security hunting, incident response, troubleshooting, and CTF workflows.
- **Focused skill references** — Separate Markdown files for playbooks, evidence grading rubric, report template, and official Wireshark behavior notes under `skills/wireshark-traffic-analysis/references/`.

### Changed

- **Strengthened traffic-analysis skill** — Guidance grounded in official Wireshark documentation covering protocol hierarchy, endpoints, conversations, expert info, display filters, and follow-stream behavior.
- **Wheel builds now ship `skills/`** — The repository `skills/` directory is included under the installed `wireshark_mcp` package so the bundled skill ships with release artifacts, not just the Git repository.

---

## 中文

### 新增

- **内置 `wireshark-traffic-analysis` skill** — 新增于 `skills/wireshark-traffic-analysis/`，覆盖结构化包分诊、安全狩猎、事件响应、故障排查和 CTF 工作流。
- **独立 skill 参考文档** — 在 `skills/wireshark-traffic-analysis/references/` 下分别提供 playbook、证据评级标准、报告模板和官方 Wireshark 行为说明。

### 变更

- **强化流量分析 skill** — 指导内容以官方 Wireshark 文档为基础，涵盖协议层次、端点、会话、专家信息、显示过滤器和流追踪行为。
- **Wheel 构建现包含 `skills/`** — `skills/` 目录已纳入安装包，随发布产物一起发布，不再仅存在于 Git 仓库中。

---

## 0.6.1 — 2026-03-14

---

## English

### Fixed

- **Cross-platform auto-install** — Config paths now use platform-correct separators and locations on macOS, Linux, and Windows; Python module entrypoint is stable across all three.
- **GUI MCP client environment** — Runtime environment variables and detected absolute Wireshark tool paths are now forwarded to GUI clients, reducing failures caused by missing `PATH` state when the client is launched outside a shell.
- **`wireshark-mcp --doctor`** — New diagnostic command to verify Python resolution, Wireshark CLI tool discovery, and detected MCP client config locations.
- **TShark path validation on Windows** — Command validation now consistently accepts Windows-style executable paths (backslash separators, `.exe` suffix).

### Changed

- **CI: updated action versions** — GitHub Actions workflows now use current `actions/checkout` and `actions/setup-python` major versions.
- **CI: mypy invocation** — Type-check step now uses a package-based mypy invocation compatible with the repository's `src/` layout.
- **CI: tshark install** — The CI test job installs `tshark` non-interactively and no longer assumes a pre-existing `wireshark` Unix group on GitHub-hosted runners.

---

## 中文

### 修复

- **跨平台自动安装** — 配置路径现在在 macOS、Linux、Windows 上均使用正确的分隔符和目录；Python 模块入口点在三平台上保持稳定。
- **GUI MCP 客户端环境** — 运行时环境变量及检测到的 Wireshark 工具绝对路径现在会转发给 GUI 客户端，减少客户端在非 shell 环境启动时因缺少 `PATH` 导致的失败。
- **`wireshark-mcp --doctor`** — 新诊断命令，验证 Python 解析路径、Wireshark CLI 工具发现情况和检测到的 MCP 客户端配置位置。
- **Windows 上 TShark 路径验证** — 命令验证现在一致接受 Windows 风格的可执行路径（反斜杠、`.exe` 后缀）。

### 变更

- **CI：更新 Action 版本** — GitHub Actions 工作流现使用最新主版本的 `actions/checkout` 和 `actions/setup-python`。
- **CI：mypy 调用方式** — 类型检查步骤改用与仓库 `src/` 布局兼容的包式 mypy 调用。
- **CI：tshark 安装** — CI 测试任务以非交互方式安装 `tshark`，不再假设 GitHub 托管运行器上预先存在 `wireshark` Unix 组。

---

## 0.6.0 — 2025-06-27

---

## English

### Added

#### Agentic Workflows — Server-side Orchestrated Analysis

- **`wireshark_security_audit`** — One-call comprehensive security audit across 8 analysis phases; produces a structured report with risk score (0–100), findings, and remediation recommendations.
- **`wireshark_quick_analysis`** — One-call traffic overview: file info, protocol distribution, top talkers, conversations, hostnames, and anomaly summary.

#### Progressive Discovery — Dynamic Tool Registration

- **`wireshark_open_file`** — New entry-point tool that inspects a capture's protocol mix and dynamically activates the most relevant protocol-specific tools for that session.
- **`ToolRegistry` system** — Server starts with ~17 core tools; protocol-specific tools activate on demand when matching protocols are detected in the opened capture.
- **`PROTOCOL_TOOL_MAP`** — Configurable mapping from detected protocols (HTTP, DNS, TLS, SMTP, DHCP, etc.) to the tool sets that should be activated.

### Changed

- **Security tools are now contextual** — `wireshark_check_threats` and `wireshark_extract_credentials` are activated via `wireshark_open_file` rather than always registered.
- **Protocol tools are now contextual** — `wireshark_extract_tls_handshakes`, `wireshark_analyze_tcp_health`, `wireshark_detect_arp_spoofing`, `wireshark_extract_smtp_emails`, `wireshark_extract_dhcp_info` activate on demand.
- **Threat detection tools are now contextual** — `wireshark_detect_port_scan`, `wireshark_detect_dns_tunnel`, `wireshark_detect_dos_attack`, `wireshark_analyze_suspicious_traffic` activate on demand.
- **Extract tools are now contextual** — `wireshark_extract_http_requests`, `wireshark_extract_dns_queries`, `wireshark_export_objects`, `wireshark_verify_ssl_decryption` activate on demand.

---

## 中文

### 新增

#### 智能体工作流 — 服务端编排分析

- **`wireshark_security_audit`** — 单次调用完成 8 阶段综合安全审计，输出结构化报告（风险评分 0–100、发现项和整改建议）。
- **`wireshark_quick_analysis`** — 单次调用完成流量概览：文件信息、协议分布、Top 通信方、会话、主机名和异常摘要。

#### 渐进式发现 — 动态工具注册

- **`wireshark_open_file`** — 新入口工具，分析捕获文件的协议组成，并为当前会话动态激活最相关的协议专用工具。
- **`ToolRegistry` 系统** — 服务器启动时约有 17 个核心工具；检测到匹配协议后按需激活协议专用工具。
- **`PROTOCOL_TOOL_MAP`** — 可配置的协议（HTTP、DNS、TLS、SMTP、DHCP 等）到工具集的映射表。

### 变更

- **安全工具改为上下文激活** — `wireshark_check_threats` 和 `wireshark_extract_credentials` 通过 `wireshark_open_file` 激活，不再全局注册。
- **协议工具改为上下文激活** — `wireshark_extract_tls_handshakes`、`wireshark_analyze_tcp_health`、`wireshark_detect_arp_spoofing`、`wireshark_extract_smtp_emails`、`wireshark_extract_dhcp_info` 按需激活。
- **威胁检测工具改为上下文激活** — `wireshark_detect_port_scan`、`wireshark_detect_dns_tunnel`、`wireshark_detect_dos_attack`、`wireshark_analyze_suspicious_traffic` 按需激活。
- **提取工具改为上下文激活** — `wireshark_extract_http_requests`、`wireshark_extract_dns_queries`、`wireshark_export_objects`、`wireshark_verify_ssl_decryption` 按需激活。

---

## 0.4.0 — 2025-06-01

---

## English

### Added

- **`wireshark_get_packet_bytes`** — Returns the raw Hex/ASCII dump of a frame (equivalent to Wireshark's Packet Bytes pane).
- **`wireshark_get_packet_context`** — Returns the packets immediately before and after a specific frame number, giving surrounding context without loading the full capture.
- **`wireshark_search_packets` `scope` parameter** — Two new search scopes:
  - `scope="bytes"` — search inside raw payload (hex or string match)
  - `scope="details"` — search in decoded protocol fields/text with regex support
- **`wireshark_follow_stream` enhancements** — Added `offset_lines` for pagination and `search_content` to locate specific content inside a reassembled stream.

### Changed

- **`wireshark_get_packet_list` custom columns** — Accepts a comma-separated list of field names (e.g., `"ip.src,http.host"`) to return only the columns relevant to a workflow.
- **`wireshark_get_packet_details` layer filtering** — Accepts a comma-separated list of protocol layers (e.g., `"ip,tcp,http"`) to strip irrelevant layers and reduce token usage.

### Deprecated

- **`wireshark_read_packets`** — Superseded by `wireshark_get_packet_list` + `wireshark_get_packet_details`. Will be removed in a future major release.

---

## 中文

### 新增

- **`wireshark_get_packet_bytes`** — 返回数据帧的原始十六进制/ASCII 转储（相当于 Wireshark 的 Packet Bytes 面板）。
- **`wireshark_get_packet_context`** — 返回指定帧前后的数据包，在不加载完整捕获的情况下提供上下文。
- **`wireshark_search_packets` `scope` 参数** — 新增两种搜索范围：
  - `scope="bytes"` — 在原始负载中搜索（十六进制或字符串匹配）
  - `scope="details"` — 在解码后的协议字段/文本中搜索，支持正则表达式
- **`wireshark_follow_stream` 增强** — 新增 `offset_lines` 支持分页，`search_content` 定位重组流中的特定内容。

### 变更

- **`wireshark_get_packet_list` 自定义列** — 接受逗号分隔的字段名列表（如 `"ip.src,http.host"`），只返回工作流所需列。
- **`wireshark_get_packet_details` 层过滤** — 接受逗号分隔的协议层列表（如 `"ip,tcp,http"`），过滤无关层以减少 token 用量。

### 弃用

- **`wireshark_read_packets`** — 已被 `wireshark_get_packet_list` + `wireshark_get_packet_details` 取代，将在未来主版本中移除。

---

## 0.2.1 — 2025-05-01

Initial public release. / 首次公开发布。

---

## English

### Added

#### Core Packet Inspection
- **`wireshark_get_packet_list`** — Summary table of packets (top-pane view).
- **`wireshark_get_packet_details`** — Full JSON detail for a single frame.
- **`wireshark_follow_stream`** — Reassembled TCP/UDP/TLS/HTTP stream content.

#### Data Extraction
- **`wireshark_extract_fields`** — Tabular extraction of arbitrary display-filter fields.
- **`wireshark_extract_http_requests`** — HTTP method, URI, and host from all HTTP traffic.
- **`wireshark_extract_dns_queries`** — DNS query names and record types.
- **`wireshark_list_ips`** — Unique source, destination, or combined IP addresses.
- **`wireshark_export_objects`** — Embedded file extraction for HTTP, SMB, TFTP, IMF, DICOM.

#### Statistics
- **`wireshark_stats_protocol_hierarchy`** — Protocol distribution tree.
- **`wireshark_stats_endpoints`** — Per-endpoint traffic totals.
- **`wireshark_stats_conversations`** — Conversation pairs with bytes and packet counts.
- **`wireshark_stats_io_graph`** — Traffic volume over time buckets.
- **`wireshark_stats_expert_info`** — Automatic anomaly and error detection.
- **`wireshark_stats_service_response_time`** — HTTP/DNS/SMB service response time statistics.

#### File Operations
- **`wireshark_get_file_info`** — Capture file metadata (duration, packet count, encapsulation).
- **`wireshark_merge_pcaps`** — Merge multiple capture files into one.
- **`wireshark_filter_save`** — Apply a display filter and save matching packets to a new file.

#### Live Capture
- **`wireshark_list_interfaces`** — Available network interfaces.
- **`wireshark_capture`** — Live packet capture with BPF filter and ring buffer support.

#### Security
- **`wireshark_check_threats`** — Match IPs/domains against URLhaus threat intelligence.
- **`wireshark_extract_credentials`** — Scan for cleartext credentials (HTTP Basic, FTP, Telnet).

#### Decoding & Visualization
- **`wireshark_decode_payload`** — Decode Base64, Hex, URL, ROT13, Gzip, Deflate with auto-detection.
- **`wireshark_plot_traffic`** — ASCII I/O bar chart.
- **`wireshark_plot_protocols`** — ASCII protocol hierarchy tree.

---

## 中文

### 新增

#### 核心包检测
- **`wireshark_get_packet_list`** — 数据包摘要表（顶部面板视图）。
- **`wireshark_get_packet_details`** — 单帧完整 JSON 详情。
- **`wireshark_follow_stream`** — 重组的 TCP/UDP/TLS/HTTP 流内容。

#### 数据提取
- **`wireshark_extract_fields`** — 按显示过滤器提取任意字段的表格数据。
- **`wireshark_extract_http_requests`** — 提取所有 HTTP 流量的方法、URI 和主机。
- **`wireshark_extract_dns_queries`** — DNS 查询名称和记录类型。
- **`wireshark_list_ips`** — 唯一源、目标或合并 IP 地址列表。
- **`wireshark_export_objects`** — 提取 HTTP、SMB、TFTP、IMF、DICOM 中嵌入的文件。

#### 统计
- **`wireshark_stats_protocol_hierarchy`** — 协议分布树。
- **`wireshark_stats_endpoints`** — 各端点流量统计。
- **`wireshark_stats_conversations`** — 会话对（含字节数和包数）。
- **`wireshark_stats_io_graph`** — 按时间段统计的流量体积。
- **`wireshark_stats_expert_info`** — 自动异常和错误检测。
- **`wireshark_stats_service_response_time`** — HTTP/DNS/SMB 服务响应时间统计。

#### 文件操作
- **`wireshark_get_file_info`** — 捕获文件元数据（时长、包数、封装类型）。
- **`wireshark_merge_pcaps`** — 合并多个捕获文件。
- **`wireshark_filter_save`** — 应用显示过滤器并将匹配包保存为新文件。

#### 实时抓包
- **`wireshark_list_interfaces`** — 可用网络接口列表。
- **`wireshark_capture`** — 支持 BPF 过滤器和环形缓冲区的实时抓包。

#### 安全
- **`wireshark_check_threats`** — 将 IP/域名与 URLhaus 威胁情报匹配。
- **`wireshark_extract_credentials`** — 扫描明文凭证（HTTP Basic、FTP、Telnet）。

#### 解码与可视化
- **`wireshark_decode_payload`** — 自动检测并解码 Base64、Hex、URL、ROT13、Gzip、Deflate。
- **`wireshark_plot_traffic`** — ASCII I/O 柱状图。
- **`wireshark_plot_protocols`** — ASCII 协议层次树。

---

## Version Links

[2.0.0]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v2.0.0
[1.2.0]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.2.0
[1.1.5]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.1.5
[1.1.0]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.1.0
[1.0.0]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.0.0
[0.6.4]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.6.4
[0.6.3]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.6.3
[0.6.2]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.6.2
[0.6.1]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.6.1
[0.6.0]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.6.0
[0.4.0]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.4.0
[0.2.1]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.2.1
[Unreleased]: https://github.com/bx33661/Wireshark-MCP/compare/v2.0.0...HEAD
