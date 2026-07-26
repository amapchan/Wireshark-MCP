"""In-memory LRU cache for tshark read-only command results.

Cache key: (file_path, file_mtime, file_size, command_args_tuple)
This ensures cache invalidation when the pcap file changes.
"""

import hashlib
import logging
import time
from collections import OrderedDict
from pathlib import Path

logger = logging.getLogger("wireshark_mcp")

DEFAULT_MAX_ENTRIES = 128
DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB total cache size
DEFAULT_TTL_SECONDS = 300  # 5 minutes


class ResultCache:
    """LRU cache for tshark command results, keyed by file identity + command."""

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_bytes: int = DEFAULT_MAX_BYTES,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._cache: OrderedDict[str, tuple[str, float]] = OrderedDict()
        # key -> resolved file path, so a single file can be invalidated on write.
        self._key_paths: dict[str, str] = {}
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._ttl = ttl_seconds
        self._current_bytes = 0
        self._hits = 0
        self._misses = 0

    def _make_key(self, pcap_file: str, cmd: list[str]) -> tuple[str, str] | None:
        """Build a cache key and resolved path from file identity and command args."""
        try:
            path = Path(pcap_file).resolve()
            if not path.exists():
                return None
            stat = path.stat()
            identity = f"{path}:{stat.st_mtime_ns}:{stat.st_size}"
        except OSError:
            return None

        cmd_str = "\x00".join(cmd)
        raw = f"{identity}\x01{cmd_str}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32], str(path)

    def get(self, pcap_file: str, cmd: list[str]) -> str | None:
        """Look up a cached result. Returns None on miss."""
        made = self._make_key(pcap_file, cmd)
        if made is None:
            self._misses += 1
            return None
        key, _ = made

        entry = self._cache.get(key)
        if entry is None:
            self._misses += 1
            return None

        result, timestamp = entry
        if time.time() - timestamp > self._ttl:
            self._evict(key, len(result))
            self._misses += 1
            return None

        self._cache.move_to_end(key)
        self._hits += 1
        return result

    def put(self, pcap_file: str, cmd: list[str], result: str) -> None:
        """Store a result in the cache."""
        made = self._make_key(pcap_file, cmd)
        if made is None:
            return
        key, path = made

        result_size = len(result.encode("utf-8", errors="replace"))

        if result_size > self._max_bytes // 4:
            return

        if key in self._cache:
            old_result, _ = self._cache[key]
            self._current_bytes -= len(old_result.encode("utf-8", errors="replace"))
            del self._cache[key]

        while self._current_bytes + result_size > self._max_bytes and self._cache:
            self._evict_oldest()

        while len(self._cache) >= self._max_entries:
            self._evict_oldest()

        self._cache[key] = (result, time.time())
        self._key_paths[key] = path
        self._current_bytes += result_size

    def invalidate_file(self, pcap_file: str) -> int:
        """Remove every cache entry for a single file. Returns the count removed."""
        try:
            target = str(Path(pcap_file).resolve())
        except OSError:
            return 0

        keys = [key for key, path in self._key_paths.items() if path == target]
        for key in keys:
            entry = self._cache.get(key)
            if entry is not None:
                self._evict(key, len(entry[0].encode("utf-8", errors="replace")))
            self._key_paths.pop(key, None)
        return len(keys)

    def clear(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()
        self._key_paths.clear()
        self._current_bytes = 0

    def _evict(self, key: str, size: int) -> None:
        if key in self._cache:
            del self._cache[key]
            self._key_paths.pop(key, None)
            self._current_bytes -= size

    def _evict_oldest(self) -> None:
        if self._cache:
            key, (result, _) = self._cache.popitem(last=False)
            self._key_paths.pop(key, None)
            self._current_bytes -= len(result.encode("utf-8", errors="replace"))

    @property
    def stats(self) -> dict[str, int]:
        return {
            "entries": len(self._cache),
            "bytes": self._current_bytes,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate_pct": round(self._hits * 100 / max(1, self._hits + self._misses)),
        }
