from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from nft_gui.errors import UnsupportedError


def quote(value: str) -> str:
    if any(ord(c) < 32 for c in value):
        raise UnsupportedError("Control characters are not supported in nft strings")
    return json.dumps(value, ensure_ascii=False)


def keyword(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", value):
        raise UnsupportedError(f"Unsupported nft keyword: {value!r}")
    return value


def number(value: Any) -> str:
    if type(value) is not int or value < 0:
        raise UnsupportedError("Expected a nonnegative integer")
    return str(value)


def exact(data: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(data, dict) or not required <= data.keys():
        raise UnsupportedError("Unsupported expression structure")
    if set(data) - required - (optional or set()):
        raise UnsupportedError("Expression contains unmapped fields")
    return data


def value(data: Any) -> str:
    if isinstance(data, bool):
        return "1" if data else "0"
    if isinstance(data, int):
        return str(data)
    if isinstance(data, str):
        if data.startswith("@"):
            return "@" + quote(data[1:])
        try:
            ipaddress.ip_address(data)
            return data
        except ValueError:
            return quote(data)
    if isinstance(data, list):
        if any(isinstance(v, list) for v in data):
            raise UnsupportedError("Nested anonymous arrays need an explicit mapping")
        return "{ " + ", ".join(value(v) for v in data) + " }"
    if not isinstance(data, dict) or len(data) != 1:
        raise UnsupportedError(f"Unmapped value: {data!r}")
    key, body = next(iter(data.items()))
    if key == "payload":
        b = exact(body, {"protocol", "field"})
        return f"{keyword(b['protocol'])} {keyword(b['field'])}"
    if key == "meta":
        return "meta " + keyword(exact(body, {"key"})["key"])
    if key == "ct":
        b = exact(body, {"key"}, {"family", "dir"})
        # ct [direction] [family] key, except address keys: ct [direction] family saddr.
        return " ".join(["ct"] + [keyword(b[k]) for k in ("dir", "family", "key") if k in b])
    if key == "prefix":
        b = exact(body, {"addr", "len"})
        address = ipaddress.ip_address(b["addr"])
        length = int(number(b["len"]))
        if length > address.max_prefixlen:
            raise UnsupportedError("Invalid network prefix")
        return f"{address}/{length}"
    if key == "range" and isinstance(body, list) and len(body) == 2:
        return f"{value(body[0])}-{value(body[1])}"
    if key == "concat" and isinstance(body, list) and body:
        return " . ".join(value(v) for v in body)
    if key == "set" and isinstance(body, list):
        return value(body)
    if key in {"accept", "drop", "continue", "return", "jump", "goto"}:
        return expression(data)
    # Per-element timeouts/expiry and binary expressions remain opaque until mapped safely.
    raise UnsupportedError(f"Unmapped nft value: {key}")


def expression(data: dict[str, Any]) -> str:
    if len(data) != 1:
        raise UnsupportedError("An expression needs exactly one key")
    key, body = next(iter(data.items()))
    if key in {"accept", "drop", "continue", "return", "notrack"} and body is None:
        return key
    if key in {"jump", "goto"}:
        return key + " " + quote(exact(body, {"target"})["target"])
    if key == "reject":
        if body is None or body == {}:
            return "reject"
        b = exact(body, {"type"}, {"expr"})
        if b["type"] == "tcp reset" and "expr" not in b:
            return "reject with tcp reset"
        if b["type"] in {"icmp", "icmpv6", "icmpx"} and "expr" in b:
            return f"reject with {b['type']} type {value(b['expr'])}"
        raise UnsupportedError("Unmapped reject type")
    if key in {"dnat", "snat"}:
        b = exact(body, {"addr"}, {"family", "port", "flags"})
        family = ""
        if "family" in b:
            if b["family"] not in {"ip", "ip6"}:
                raise UnsupportedError("Invalid NAT family")
            family = b["family"] + " "
        address = str(ipaddress.ip_address(b["addr"]))
        if "port" in b:
            address = f"[{address}]" if ":" in address else address
            address += ":" + value(b["port"])
        flags = b.get("flags", [])
        if isinstance(flags, str):
            flags = [flags]
        suffix = " " + ",".join(keyword(f) for f in flags) if flags else ""
        return f"{key} {family}to {address}{suffix}"
    if key == "match":
        b = exact(body, {"op", "left", "right"})
        if b["op"] not in {"==", "!=", "<", ">", "<=", ">=", "in"}:
            raise UnsupportedError("Unmapped match operator")
        operator = "" if b["op"] in {"==", "in"} else str(b["op"]) + " "
        return f"{value(b['left'])} {operator}{value(b['right'])}"
    if key == "counter":
        if body is None:
            return "counter"
        if isinstance(body, str):
            return "counter name " + quote(body)
        b = exact(body, {"packets", "bytes"})
        return f"counter packets {number(b['packets'])} bytes {number(b['bytes'])}"
    if key == "quota":
        if isinstance(body, str):
            return "quota name " + quote(body)
        b = exact(body, {"val"}, {"val_unit", "used", "used_unit", "inv"})
        over = "over " if b.get("inv") is True else ""
        unit = keyword(b.get("val_unit", "bytes"))
        used = f" used {number(b['used'])} {keyword(b.get('used_unit', 'bytes'))}" if "used" in b else ""
        return f"quota {over}{number(b['val'])} {unit}{used}"
    if key == "log":
        b = exact(body, set(), {"prefix", "level", "group", "snaplen", "queue-threshold"})
        options: list[str] = []
        for name, option in b.items():
            encoded = quote(option) if name == "prefix" else (
                keyword(option) if name == "level" else number(option))
            options.append(f"{name} {encoded}")
        return " ".join(["log", *options])
    if key in {"masquerade", "redirect"}:
        if body is None:
            return key
        b = exact(body, set(), {"port", "flags"})
        result = key + (f" to :{value(b['port'])}" if "port" in b else "")
        if "flags" in b:
            flags = b["flags"] if isinstance(b["flags"], list) else [b["flags"]]
            result += " " + ",".join(keyword(f) for f in flags)
        return result
    if key == "mangle":
        b = exact(body, {"key", "value"})
        return f"{value(b['key'])} set {value(b['value'])}"
    if key == "vmap":
        b = exact(body, {"key", "data"})
        if not isinstance(b["data"], str) or not b["data"].startswith("@"):
            raise UnsupportedError("Only named verdict maps are currently mapped")
        return f"{value(b['key'])} vmap {value(b['data'])}"
    raise UnsupportedError(f"Unmapped nft statement: {key}")
