"""Wireshark suite client — composed from focused mixins."""

import asyncio
import contextlib
import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from ..toolchain import (
    WIRESHARK_TOOL_ENV_VARS,
    WIRESHARK_TOOL_ORDER,
)
from ._capability import CapabilityMixin
from ._capture import CaptureMixin
from ._extraction import ExtractionMixin
from ._packets import PacketsMixin
from ._stats import StatsMixin
from ._suite_ops import SuiteOpsMixin
from ._validation import ValidationMixin
from .cache import ResultCache

logger = logging.getLogger("wireshark_mcp")


class WiresharkSuiteClient(
    ValidationMixin,
    CapabilityMixin,
    StatsMixin,
    PacketsMixin,
    ExtractionMixin,
    SuiteOpsMixin,
    CaptureMixin,
):
    """Production-grade Wireshark CLI suite wrapper with validation and error handling."""

    VALID_ENDPOINT_TYPES = {"eth", "ip", "ipv6", "tcp", "udp", "sctp", "wlan"}
    VALID_EXPORT_PROTOCOLS = {"http", "smb", "tftp", "imf", "dicom"}
    VALID_STREAM_PROTOCOLS = {"tcp", "udp", "tls", "http", "http2"}

    _ALLOWED_BINARIES = {name for tool in WIRESHARK_TOOL_ORDER for name in (tool, f"{tool}.exe")}
    _TOOL_ENV_VARS = WIRESHARK_TOOL_ENV_VARS

    def __init__(
        self,
        tshark_path: str = "tshark",
        allowed_dirs: list[str] | None = None,
    ) -> None:
        self._tool_paths: dict[str, str | None] = {
            "tshark": self._resolve_tool_path("tshark", tshark_path),
            "capinfos": self._resolve_tool_path("capinfos"),
            "mergecap": self._resolve_tool_path("mergecap"),
            "editcap": self._resolve_tool_path("editcap"),
            "dumpcap": self._resolve_tool_path("dumpcap"),
            "text2pcap": self._resolve_tool_path("text2pcap"),
        }
        self.tshark_path = self._tool_paths["tshark"] or tshark_path
        self.capinfos_path = self._tool_paths["capinfos"]
        self.mergecap_path = self._tool_paths["mergecap"]
        self.editcap_path = self._tool_paths["editcap"]
        self.dumpcap_path = self._tool_paths["dumpcap"]
        self.text2pcap_path = self._tool_paths["text2pcap"]
        self._version: str | None = None
        self._cache = ResultCache()

        self._allowed_dirs: list[Path] | None = None
        if allowed_dirs:
            self._allowed_dirs = [Path(d).resolve() for d in allowed_dirs]
            logger.info("Path sandbox enabled: %s", self._allowed_dirs)

    @staticmethod
    def _ok(data: str, stderr: str = "") -> str:
        """Wrap successful command output in the canonical success envelope.

        Every client method returns this shape (or an error envelope), so the
        raw text lives in ``data`` and is never re-parsed by consumers — output
        that happens to look like JSON can no longer be mistaken for an error.
        Diagnostic stderr is kept in a separate field so it never corrupts
        structured (``-T json`` / ``-T fields``) output in ``data``.
        """
        envelope: dict[str, Any] = {"success": True, "data": data}
        if stderr:
            envelope["stderr"] = stderr
        return json.dumps(envelope)

    @staticmethod
    def _unwrap(result: str) -> tuple[bool, str]:
        """Extract (success, text) from a client envelope for internal reuse.

        On a success envelope, returns the ``data`` text. On an error envelope,
        returns ``(False, <original envelope>)`` so callers can propagate it
        unchanged. Non-envelope strings are treated as raw success text.
        """
        try:
            parsed = json.loads(result)
        except (json.JSONDecodeError, ValueError):
            return True, result
        if isinstance(parsed, dict) and "success" in parsed:
            if parsed.get("success") is True:
                data = parsed.get("data", "")
                return True, data if isinstance(data, str) else json.dumps(data)
            return False, result
        return True, result

    @staticmethod
    def _output_paths(cmd: list[str]) -> list[str]:
        """Return files a command writes to via `-w`, so their cache can be dropped."""
        paths: list[str] = []
        for i, arg in enumerate(cmd):
            if arg == "-w" and i + 1 < len(cmd):
                paths.append(cmd[i + 1])
        return paths

    @staticmethod
    def _paginate(output: str, limit_lines: int, offset_lines: int) -> tuple[str, bool]:
        """Slice full command output to an offset/limit window.

        Returns the windowed text and whether it was truncated. A truncation
        footer is appended so callers can page forward. Applied *after* caching
        so the cache always holds the complete output.
        """
        lines = output.splitlines()
        total_lines = len(lines)

        if offset_lines > 0:
            lines = lines[offset_lines:]

        truncated = False
        if limit_lines > 0 and len(lines) > limit_lines:
            lines = lines[:limit_lines]
            truncated = True

        final_output = "\n".join(lines)
        if truncated:
            final_output += (
                f"\n\n[Showing {limit_lines}/{total_lines} lines. Next: offset={offset_lines + limit_lines}]"
            )
        return final_output, truncated

    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
    ) -> str:
        """Run command with error handling, validation, timeout, and caching."""
        pcap_file = None
        if "-r" in cmd:
            r_idx = cmd.index("-r")
            if r_idx + 1 < len(cmd):
                pcap_file = cmd[r_idx + 1]

        # The cache stores the full, unpaginated stdout keyed by the command only.
        # Pagination is applied *after* retrieval so different offset/limit values
        # over the same command never pollute one another.
        if pcap_file:
            cached = self._cache.get(pcap_file, cmd)
            if cached is not None:
                logger.debug("Cache hit for: %s", " ".join(cmd[:4]))
                text, _ = self._paginate(cached, limit_lines, offset_lines)
                return self._ok(text)

        binary = self._get_binary_name(cmd[0]) if cmd else ""
        if binary not in self._ALLOWED_BINARIES:
            logger.error("Blocked execution of disallowed binary: %s", binary)
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "SecurityError",
                        "message": f"Execution of '{binary}' is not allowed",
                        "details": f"Allowed binaries: {', '.join(sorted(self._ALLOWED_BINARIES))}",
                    },
                }
            )

        logger.debug("Executing: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                logger.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "TimeoutError",
                            "message": f"Command timed out after {timeout} seconds",
                            "details": f"Command: {' '.join(cmd)}",
                        },
                    }
                )

            output = stdout.decode("utf-8", errors="replace")
            error = stderr.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                logger.warning("Command failed (exit %d): %s", proc.returncode, " ".join(cmd))
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "ExecutionError",
                            "message": f"Command failed with exit code {proc.returncode}",
                            "details": error or output,
                        },
                    }
                )

            # Invalidate any cached reads of a file this command just wrote to.
            for out_path in self._output_paths(cmd):
                self._cache.invalidate_file(out_path)

            # Cache the full, unpaginated stdout so any offset/limit can be served from it.
            if pcap_file:
                self._cache.put(pcap_file, cmd, output)

            final_output, truncated = self._paginate(output, limit_lines, offset_lines)

            # Keep stderr out of `data` (would corrupt -T json/-T fields); surface
            # it in a sibling field only when the caller sees the complete output.
            stderr_note = error if (error and not truncated) else ""
            return self._ok(final_output, stderr_note)

        except Exception as e:
            logger.exception("Command execution failed: %s", " ".join(cmd))
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "ExecutionError",
                        "message": "Command execution failed",
                        "details": str(e),
                    },
                }
            )


TSharkClient = WiresharkSuiteClient
