"""Tests verifying concurrent execution in agents and TCP health."""

import asyncio
import json
import time

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.agents import _run_quick_analysis


class SlowMockClient(MockTSharkClient):
    """Mock client that adds a small delay to simulate I/O."""

    def __init__(self, delay: float = 0.05) -> None:
        super().__init__()
        self._delay = delay
        self._call_count = 0

    async def _run_command(self, cmd: list[str], limit_lines: int = 0, offset_lines: int = 0, timeout: int = 30) -> str:
        self._call_count += 1
        await asyncio.sleep(self._delay)
        return "CMD: " + " ".join(cmd)


class TestConcurrentQuickAnalysis:
    @pytest.mark.asyncio
    async def test_quick_analysis_runs_concurrently(self) -> None:
        client = SlowMockClient(delay=0.02)
        start = time.monotonic()
        result = await _run_quick_analysis(client, "test.pcap")
        elapsed = time.monotonic() - start
        data = json.loads(result)
        assert data["success"]
        # 7 concurrent fetches at 0.02s each: sequential ~0.14s, concurrent ~0.04s
        assert elapsed < 0.12, f"Took {elapsed:.2f}s — likely not concurrent"


class TestConcurrentTcpHealth:
    @pytest.mark.asyncio
    async def test_tcp_health_concurrent_checks(self) -> None:
        from wireshark_mcp.tools.protocol import make_protocol_tools

        client = SlowMockClient(delay=0.02)
        tools = make_protocol_tools(client)
        tcp_health_fn = next(fn for name, fn in tools if name == "wireshark_analyze_tcp_health")

        start = time.monotonic()
        result = await tcp_health_fn("test.pcap")
        elapsed = time.monotonic() - start

        data = json.loads(result)
        assert data["success"]
        # 8 checks at 0.02s each: sequential ~0.16s, concurrent ~0.04s
        assert elapsed < 0.12, f"Took {elapsed:.2f}s — likely not concurrent"
