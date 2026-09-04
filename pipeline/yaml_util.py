"""Minimal YAML subset loader (mappings, lists, scalars). Stdlib only."""

from __future__ import annotations

from typing import Any


def load_yaml(text: str) -> Any:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    tokens: list[tuple[int, str]] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = raw.split(" #", 1)[0].rstrip()
        indent = len(raw) - len(raw.lstrip(" "))
        tokens.append((indent, stripped.lstrip(" ")))
    if not tokens:
        return None
    value, _ = _parse_block(tokens, 0, tokens[0][0])
    return value


def load_yaml_file(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return load_yaml(handle.read())


def _parse_block(tokens: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(tokens):
        return None, index
    _, content = tokens[index]
    if content.startswith("- "):
        return _parse_list(tokens, index, indent)
    return _parse_map(tokens, index, indent)


def _parse_map(tokens: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(tokens):
        current_indent, content = tokens[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError(f"invalid YAML indent at: {content}")
        if content.startswith("- "):
            raise ValueError(f"list item where mapping expected: {content}")
        if ":" not in content:
            raise ValueError(f"mapping line missing colon: {content}")
        key, rest = content.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        index += 1
        if rest == "":
            if index < len(tokens) and tokens[index][0] > indent:
                child, index = _parse_block(tokens, index, tokens[index][0])
                result[key] = child
            else:
                result[key] = None
        else:
            result[key] = _parse_scalar(rest)
    return result, index


def _parse_list(tokens: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(tokens):
        current_indent, content = tokens[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError(f"invalid YAML indent at: {content}")
        if not content.startswith("- "):
            break
        rest = content[2:].strip()
        index += 1
        if rest == "":
            if index < len(tokens) and tokens[index][0] > indent:
                child, index = _parse_block(tokens, index, tokens[index][0])
                result.append(child)
            else:
                result.append(None)
        elif rest.endswith(":") or (":" in rest and not rest.startswith("'") and not rest.startswith('"')):
            key, after = rest.split(":", 1)
            nested: dict[str, Any] = {key.strip(): _parse_scalar(after.strip()) if after.strip() else None}
            if index < len(tokens) and tokens[index][0] > indent:
                extra, index = _parse_map(tokens, index, tokens[index][0])
                if nested[key.strip()] is None and extra:
                    nested[key.strip()] = extra
                    extra = {}
                nested.update(extra)
            result.append(nested)
        else:
            result.append(_parse_scalar(rest))
    return result, index


def _parse_scalar(raw: str) -> Any:
    if raw in ("{}",):
        return {}
    if raw in ("[]",):
        return []
    if raw in ("null", "~", "Null", "NULL"):
        return None
    if raw in ("true", "True", "TRUE"):
        return True
    if raw in ("false", "False", "FALSE"):
        return False
    if len(raw) >= 2 and ((raw[0] == raw[-1] == '"') or (raw[0] == raw[-1] == "'")):
        return raw[1:-1]
    try:
        if raw.startswith("0") and raw not in ("0", "0.0") and not raw.startswith("0."):
            return raw
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw
