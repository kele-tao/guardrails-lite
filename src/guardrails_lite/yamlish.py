"""A very small YAML subset parser (no PyYAML dependency).

Supported: mappings, nested mappings via indentation, sequences of scalars and
of mappings, quoted and unquoted scalars, integers, floats, booleans, null and
single-line comments. Explicitly *not* supported: anchors, aliases, multi-line
block scalars, flow style, tags and multiple documents. Unsupported syntax
raises ValueError with the line number so the CLI can print an actionable error.
"""

from __future__ import annotations

import re
from typing import Any

_KEY_RE = re.compile(r"^(?P<indent> *)(?P<key>[^:#\-][^:]*?):(?:\s+(?P<value>.*))?$")
_ITEM_RE = re.compile(r"^(?P<indent> *)-\s+(?P<rest>.*)$")
_NULLS = {"", "~", "null", "Null", "NULL"}
_TRUES = {"true", "True", "TRUE", "yes", "Yes", "on", "On"}
_FALSES = {"false", "False", "FALSE", "no", "No", "off", "Off"}


def _scalar(raw: str) -> Any:
    text = raw.strip()
    if text in _NULLS:
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        body = text[1:-1]
        if text[0] == '"':
            return (
                body.replace('\\n', "\n").replace('\\t', "\t").replace('\\"', '"')
            )
        return body.replace("''", "'")
    if text in _TRUES:
        return True
    if text in _FALSES:
        return False
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+(?:[eE][-+]?\d+)?", text):
        return float(text)
    if text.startswith(("{", "[")):
        return text  # flow collections are rejected later by the policy validator
    if text.startswith(("|", ">", "&", "*", "!")):
        raise ValueError("block scalars, anchors, aliases and tags are not supported")
    return text


def _strip_comment(line: str) -> str:
    out = []
    quote: str | None = None
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def load_yaml(text: str) -> Any:
    """Parse the supported YAML subset into Python dicts, lists and scalars."""
    raw_lines: list[tuple[int, str, int]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        clean = _strip_comment(raw.expandtabs(2))
        if not clean.strip():
            continue
        if clean.strip() == "---":
            continue
        indent = len(clean) - len(clean.lstrip(" "))
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ValueError(f"line {lineno}: tabs are not allowed for indentation")
        raw_lines.append((indent, clean.strip(), lineno))
    if not raw_lines:
        return {}
    value, pos = _parse_block(raw_lines, 0, raw_lines[0][0])
    if pos != len(raw_lines):
        raise ValueError(f"line {raw_lines[pos][2]}: unexpected content")
    return value


def _parse_block(
    lines: list[tuple[int, str, int]], pos: int, indent: int
) -> tuple[Any, int]:
    if pos >= len(lines):
        return None, pos
    is_list = bool(_ITEM_RE.match(" " * lines[pos][0] + lines[pos][1]))
    if is_list:
        result: list[Any] = []
        while pos < len(lines):
            cur_indent, text, lineno = lines[pos]
            if cur_indent < indent:
                break
            if cur_indent > indent:
                raise ValueError(f"line {lineno}: unexpected indentation")
            m = _ITEM_RE.match(" " * cur_indent + text)
            if not m:
                break
            rest = m.group("rest").strip()
            pos += 1
            if not rest:
                if pos < len(lines) and lines[pos][0] > cur_indent:
                    item, pos = _parse_block(lines, pos, lines[pos][0])
                    result.append(item)
                else:
                    result.append(None)
                continue
            inner = _KEY_RE.match(" " * (cur_indent + 2) + rest)
            if inner:
                mapping: dict[str, Any] = {}
                key = inner.group("key").strip()
                if inner.group("value") is not None and inner.group("value").strip():
                    mapping[key] = _scalar(inner.group("value"))
                elif pos < len(lines) and lines[pos][0] > cur_indent:
                    mapping[key], pos = _parse_block(lines, pos, lines[pos][0])
                else:
                    mapping[key] = None
                while pos < len(lines) and lines[pos][0] > cur_indent:
                    sub_indent, sub_text, sub_line = lines[pos]
                    if sub_indent != cur_indent + 2:
                        raise ValueError(f"line {sub_line}: inconsistent indentation")
                    m2 = _KEY_RE.match(" " * sub_indent + sub_text)
                    if not m2:
                        raise ValueError(f"line {sub_line}: expected a key")
                    k2 = m2.group("key").strip()
                    v2 = m2.group("value")
                    pos += 1
                    if v2 is not None and v2.strip():
                        mapping[k2] = _scalar(v2)
                    elif pos < len(lines) and lines[pos][0] > sub_indent:
                        mapping[k2], pos = _parse_block(lines, pos, lines[pos][0])
                    else:
                        mapping[k2] = None
                result.append(mapping)
            else:
                result.append(_scalar(rest))
        return result, pos

    result_map: dict[str, Any] = {}
    while pos < len(lines):
        cur_indent, text, lineno = lines[pos]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise ValueError(f"line {lineno}: unexpected indentation")
        m = _KEY_RE.match(" " * cur_indent + text)
        if not m:
            raise ValueError(f"line {lineno}: expected 'key: value'")
        key = m.group("key").strip()
        raw_value = m.group("value")
        pos += 1
        if raw_value is not None and raw_value.strip():
            result_map[key] = _scalar(raw_value)
        elif pos < len(lines) and lines[pos][0] > cur_indent:
            result_map[key], pos = _parse_block(lines, pos, lines[pos][0])
        else:
            result_map[key] = None
    return result_map, pos
