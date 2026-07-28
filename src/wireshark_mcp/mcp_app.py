"""A FastMCP subclass that keeps the advertised tool surface small and stable.

Every request a client sends carries the full ``tools/list`` payload in its
prompt prefix, and every tool result stays in the conversation prefix for the
rest of the session. Two things therefore matter more than they look:

* **Prefix size.** FastMCP derives an ``outputSchema`` from each tool's ``-> str``
  annotation. For this server that schema is always ``{"result": {"type":
  "string"}}`` — it tells a model nothing, and because declaring it obliges the
  server to also emit ``structuredContent``, every result is sent *twice*.
  Pydantic also stamps a ``title`` onto the schema and onto every property
  (``"title": "Pcap File"`` beside ``pcap_file``). Dropping both roughly halves
  the payload.
* **Prefix stability.** A tool list that changes between restarts invalidates
  the client's cached prefix. Registration order is therefore fixed (see
  ``ToolRegistry.register``) and nothing here may introduce ordering that
  depends on set iteration, dict insertion, or ``PYTHONHASHSEED``.

Both fixes are applied at single choke points so they cannot drift as tools are
added: ``add_tool`` for the schema, ``call_tool`` for the result ceiling.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any, cast

from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

from .tool_annotations import annotations_for
from .tools.formatting import smart_truncate

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from mcp.types import ContentBlock, Icon, ToolAnnotations

logger = logging.getLogger("wireshark_mcp")

MAX_RESULT_CHARS_ENV = "WIRESHARK_MCP_MAX_RESULT_CHARS"
# 2x the smart_truncate default, so output that already bounds itself is untouched.
DEFAULT_MAX_RESULT_CHARS = 8000
MIN_MAX_RESULT_CHARS = 512


def _resolve_max_result_chars() -> int:
    """Read the result ceiling from the environment, falling back to the default."""
    raw = os.environ.get(MAX_RESULT_CHARS_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_RESULT_CHARS
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Ignoring non-integer %s=%r", MAX_RESULT_CHARS_ENV, raw)
        return DEFAULT_MAX_RESULT_CHARS
    if value < MIN_MAX_RESULT_CHARS:
        logger.warning("Clamping %s=%r to minimum %d", MAX_RESULT_CHARS_ENV, raw, MIN_MAX_RESULT_CHARS)
        return MIN_MAX_RESULT_CHARS
    return value


def strip_schema_titles(node: Any) -> Any:
    """Recursively drop ``title`` keys from a JSON Schema.

    Pydantic generates a title for the argument model and for every property;
    neither carries information the field name does not already give.
    """
    if isinstance(node, dict):
        return {key: strip_schema_titles(value) for key, value in node.items() if key != "title"}
    if isinstance(node, list):
        return [strip_schema_titles(item) for item in node]
    return node


def cap_result_text(text: str, max_chars: int) -> str:
    """Bound a tool result, truncating inside the envelope rather than around it.

    Tools return a JSON envelope (``{"success": true, "data": ...}``). Truncating
    that string directly would produce invalid JSON, so the payload is unwrapped,
    its ``data`` trimmed, and the envelope rebuilt. Anything that is not an
    envelope with string ``data`` — a plain string, a list, structured data — is
    returned unchanged, since only free-form text is safe to cut mid-way.
    """
    if len(text) <= max_chars:
        return text

    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return smart_truncate(text, max_chars)

    if max_chars <= 0:
        return ""

    if isinstance(payload, dict) and "data" in payload:
        capped = dict(payload)
        data = payload["data"]
        source = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    else:
        capped = {"truncated": True}
        source = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def render(preview_chars: int, *, preserve_fields: bool = True) -> str:
        envelope = dict(capped) if preserve_fields else {"success": bool(capped.get("success", True))}
        envelope["data"] = smart_truncate(source, preview_chars)
        return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))

    # Find the largest preview that keeps the complete JSON result inside the
    # configured ceiling. This includes envelope and escaping overhead.
    preserve_fields = len(render(0)) <= max_chars
    low, high = 0, min(len(source), max_chars)
    best = render(0, preserve_fields=preserve_fields)
    while low <= high:
        mid = (low + high) // 2
        candidate = render(mid, preserve_fields=preserve_fields)
        if len(candidate) <= max_chars:
            best = candidate
            low = mid + 1
        else:
            high = mid - 1
    return best


class WiresharkMCP(FastMCP):
    """FastMCP with a minimal tool schema and a hard ceiling on result size."""

    def __init__(self, *args: Any, max_result_chars: int | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._max_result_chars = max_result_chars if max_result_chars is not None else _resolve_max_result_chars()

    @property
    def max_result_chars(self) -> int:
        """Character ceiling applied to every tool result."""
        return self._max_result_chars

    def add_tool(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: ToolAnnotations | None = None,
        icons: list[Icon] | None = None,
        meta: dict[str, Any] | None = None,
        structured_output: bool | None = None,
    ) -> None:
        """Register a tool without the auto-derived output schema or schema titles.

        Both registration paths land here — ``FastMCP.tool()`` delegates to
        ``add_tool`` — so a tool cannot opt out by accident. ``structured_output``
        is only forced when the caller left it unset; passing ``True`` explicitly
        still works, and an explicit ``annotations`` argument likewise wins over
        the default read/write policy.
        """
        if structured_output is None:
            structured_output = False

        # FastMCP.add_tool returns None; the manager hands back the Tool we need.
        tool = self._tool_manager.add_tool(
            fn,
            name=name,
            title=title,
            description=description,
            annotations=annotations,
            icons=icons,
            meta=meta,
            structured_output=structured_output,
        )
        tool.parameters = strip_schema_titles(tool.parameters)
        if annotations is None:
            # Resolved name, not fn.__name__ — the two differ for registry-renamed tools.
            tool.annotations = annotations_for(tool.name)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[ContentBlock] | dict[str, Any]:
        """Invoke a tool and bound the size of whatever it returns."""
        result = await super().call_tool(name, arguments)
        # _cap_content preserves the shape it was handed; the parent's own return
        # type is the authority on what that shape is.
        return cast("Sequence[ContentBlock] | dict[str, Any]", self._cap_content(result, name))

    def _cap_content(self, result: Any, tool_name: str) -> Any:
        """Apply the ceiling to text blocks, leaving other content shapes alone."""
        # Structured tools return (content, structured_data); cap only the text side.
        if isinstance(result, tuple) and len(result) == 2:
            return (self._cap_content(result[0], tool_name), result[1])

        if not isinstance(result, (list, tuple)):
            return result

        capped: list[Any] = []
        for block in result:
            if isinstance(block, TextContent):
                text = cap_result_text(block.text, self._max_result_chars)
                if text != block.text:
                    logger.debug("Capped %s result from %d to %d chars", tool_name, len(block.text), len(text))
                    block = block.model_copy(update={"text": text})
            capped.append(block)
        return capped
