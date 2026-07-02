import base64
import binascii
import codecs
import gzip
import html
import quopri
import string
import struct
import urllib.parse
import zlib

from mcp.server.fastmcp import FastMCP

from .envelope import error_response, success_response


def _calculate_score(data: bytes) -> float:
    """Calculate a 'readability' score for bytes (0.0 to 1.0)."""
    if not data:
        return 0.0
    try:
        text = data.decode("utf-8")
        printable = set(string.printable)
        count = sum(1 for c in text if c in printable)
        return count / len(text)
    except UnicodeDecodeError:
        # If not utf-8, check if it's mostly ASCII printable bytes
        printable_bytes = set(string.printable.encode("ascii"))
        count = sum(1 for b in data if b in printable_bytes)
        return (count / len(data)) * 0.5  # Penalty for non-utf8


def _try_decode(data: str, encoding: str) -> tuple[bool, bytes | None, str | None]:
    """Try to decode data with specific encoding, returning (success, result_bytes, error)."""
    try:
        if encoding == "base64":
            # Handle standard and url-safe base64, and padding
            missing_padding = len(data) % 4
            if missing_padding:
                data += "=" * (4 - missing_padding)
            return True, base64.b64decode(data, validate=True), None

        elif encoding == "hex":
            # Remove spaces/colons/0x
            clean_data = data.replace(" ", "").replace(":", "").replace("0x", "")
            return True, binascii.unhexlify(clean_data), None

        elif encoding == "url":
            return True, urllib.parse.unquote_to_bytes(data), None

        elif encoding == "rot13":
            return True, codecs.decode(data, "rot_13").encode("utf-8"), None

        elif encoding == "gzip":
            # Latin-1 allows 1:1 mapping of bytes to chars
            b = data.encode("latin-1")
            return True, gzip.decompress(b), None

        elif encoding == "deflate":
            b = data.encode("latin-1")
            # -15 for raw deflate (no header), standard zlib has header
            try:
                return True, zlib.decompress(b), None
            except Exception:
                return True, zlib.decompress(b, -15), None

        elif encoding == "quopri":
            return True, quopri.decodestring(data.encode("utf-8")), None

        elif encoding == "html":
            return True, html.unescape(data).encode("utf-8"), None

        elif encoding == "unicode":
            # "Hello\u0020World" -> bytes
            return True, data.encode("utf-8").decode("unicode_escape").encode("utf-8"), None

        elif encoding == "ascii85":
            # Adobe Ascii85 usually delimited by <~ ~>
            d = data.strip()
            if d.startswith("<~"):
                d = d[2:]
            if d.endswith("~>"):
                d = d[:-2]
            return True, base64.a85decode(d), None

    except Exception as e:
        return False, None, str(e)

    return False, None, "Unknown encoding"


def register_decode_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    def wireshark_decode_payload(data: str, encoding: str = "auto") -> str:
        """[Utils] Decode encodings. encoding: base64|hex|url|rot13|gzip|deflate|html|unicode|quopri|ascii85|auto."""
        encodings = ["base64", "hex", "url", "rot13", "html", "unicode", "quopri", "ascii85"]
        # Exclude gzip/deflate from simple auto list, handled in chaining

        if encoding == "auto":
            results = []

            # 1. Try single-step decodes
            for enc in encodings:
                success, res_bytes, _ = _try_decode(data, enc)
                if success and res_bytes is not None:
                    try:
                        text = res_bytes.decode("utf-8")
                        score = _calculate_score(res_bytes)
                        # Filter out trivial results
                        if text == data and enc in ["url", "html", "unicode", "rot13"]:
                            continue
                        if enc == "hex" and score < 0.1:
                            continue

                        results.append(
                            {
                                "encoding": enc,
                                "result": text[:200] + "..." if len(text) > 200 else text,
                                "score": round(score, 2),
                                "is_text": True,
                            }
                        )
                    except Exception:
                        # Binary result
                        results.append(
                            {
                                "encoding": enc,
                                "result": "<binary_data>",
                                "hex_preview": binascii.hexlify(res_bytes[:20]).decode("ascii"),
                                "score": 0.0,
                                "is_text": False,
                            }
                        )

            # 2. Try Chained (e.g., Base64 -> Gzip)
            success, b64_bytes, _ = _try_decode(data, "base64")
            if success and b64_bytes is not None:
                try:
                    gzip_bytes = gzip.decompress(b64_bytes)
                    results.append(
                        {
                            "encoding": "base64+gzip",
                            "result": gzip_bytes.decode("utf-8", errors="replace")[:200],
                            "score": _calculate_score(gzip_bytes),
                            "is_text": True,
                        }
                    )
                except Exception:
                    pass

                try:
                    zlib_bytes = zlib.decompress(b64_bytes)
                    results.append(
                        {
                            "encoding": "base64+zlib",
                            "result": zlib_bytes.decode("utf-8", errors="replace")[:200],
                            "score": _calculate_score(zlib_bytes),
                            "is_text": True,
                        }
                    )
                except Exception:
                    pass

            # Sort by score desc
            results.sort(key=lambda x: float(str(x["score"])), reverse=True)

            return success_response({"candidates": results[:5]})

        else:
            success, res_bytes, err = _try_decode(data, encoding)
            if not success or res_bytes is None:
                return error_response(err or "Failed to decode payload")

            try:
                return success_response(res_bytes.decode("utf-8"))
            except UnicodeDecodeError:
                return success_response(f"[Binary Data] Hex: {binascii.hexlify(res_bytes).decode('ascii')}")

    @mcp.tool()
    def wireshark_xor_bruteforce(
        data: str,
        key: str = "",
        key_range: int = 256,
        encoding: str = "hex",
    ) -> str:
        """[Utils] XOR brute-force. Single-byte or multi-byte key. encoding: hex|base64."""
        try:
            if encoding == "hex":
                clean = data.replace(" ", "").replace(":", "").replace("0x", "").replace("\n", "")
                raw = binascii.unhexlify(clean)
            elif encoding == "base64":
                missing = len(data) % 4
                if missing:
                    data += "=" * (4 - missing)
                raw = base64.b64decode(data, validate=True)
            else:
                return error_response(f"Unsupported encoding: {encoding}. Use 'hex' or 'base64'.")
        except Exception as e:
            return error_response(f"Failed to decode input: {e}")

        if not raw:
            return error_response("Empty input data")

        if key:
            key_bytes = key.encode("utf-8")
            result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
            score = _calculate_score(result)
            try:
                text = result.decode("utf-8", errors="replace")
            except Exception:
                text = binascii.hexlify(result[:100]).decode("ascii")
            return success_response(
                {
                    "key": key,
                    "key_hex": binascii.hexlify(key_bytes).decode("ascii"),
                    "result": text[:500],
                    "score": round(score, 3),
                }
            )

        candidates: list[dict[str, object]] = []
        limit = min(key_range, 256)
        for k in range(limit):
            result = bytes(b ^ k for b in raw)
            score = _calculate_score(result)
            if score > 0.6:
                try:
                    text = result.decode("utf-8", errors="replace")
                except Exception:
                    text = binascii.hexlify(result[:100]).decode("ascii")
                candidates.append(
                    {
                        "key_byte": f"0x{k:02x}",
                        "key_decimal": k,
                        "result": text[:200],
                        "score": round(score, 3),
                    }
                )

        candidates.sort(key=lambda x: float(str(x["score"])), reverse=True)
        if not candidates:
            return success_response("No readable results found (all scores below 0.6 threshold).")
        return success_response({"top_candidates": candidates[:5]})

    @mcp.tool()
    def wireshark_struct_unpack(
        data: str,
        format_str: str,
        encoding: str = "hex",
    ) -> str:
        """[Utils] Struct unpack binary data. encoding: hex|base64. format_str: '>IHH', '<Q4s'."""
        try:
            if encoding == "hex":
                clean = data.replace(" ", "").replace(":", "").replace("0x", "").replace("\n", "")
                raw = binascii.unhexlify(clean)
            elif encoding == "base64":
                missing = len(data) % 4
                if missing:
                    data += "=" * (4 - missing)
                raw = base64.b64decode(data, validate=True)
            else:
                return error_response(f"Unsupported encoding: {encoding}. Use 'hex' or 'base64'.")
        except Exception as e:
            return error_response(f"Failed to decode input: {e}")

        try:
            expected_size = struct.calcsize(format_str)
        except struct.error as e:
            return error_response(f"Invalid format string '{format_str}': {e}")

        if len(raw) < expected_size:
            return error_response(f"Data too short: got {len(raw)} bytes, format '{format_str}' needs {expected_size}")

        try:
            values = struct.unpack(format_str, raw[:expected_size])
        except struct.error as e:
            return error_response(f"Unpack failed: {e}")

        fields: list[dict[str, str]] = []
        for i, val in enumerate(values):
            if isinstance(val, bytes):
                fields.append(
                    {
                        "index": str(i),
                        "value": val.hex(),
                        "repr": repr(val),
                        "type": "bytes",
                    }
                )
            elif isinstance(val, int):
                fields.append(
                    {
                        "index": str(i),
                        "value": str(val),
                        "hex": f"0x{val:x}" if val >= 0 else str(val),
                        "type": "int",
                    }
                )
            elif isinstance(val, float):
                fields.append(
                    {
                        "index": str(i),
                        "value": str(val),
                        "type": "float",
                    }
                )
            else:
                fields.append({"index": str(i), "value": str(val), "type": type(val).__name__})

        remaining = len(raw) - expected_size
        return success_response(
            {
                "format": format_str,
                "bytes_consumed": expected_size,
                "bytes_remaining": remaining,
                "fields": fields,
            }
        )
