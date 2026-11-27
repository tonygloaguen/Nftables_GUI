"""Conservative parser for the native syntax emitted by the visual editor."""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from nft_gui.models import Expr

LEX = re.compile(r'"(?:\\.|[^"\\])*"|[{},;]|[^\s{},;"#]+')


class NativeReader:
    def __init__(self, source: str) -> None:
        self.words = LEX.findall(source)
        self.pos = 0

    def peek(self) -> str:
        return self.words[self.pos] if self.pos < len(self.words) else ""

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if not token or (expected is not None and token != expected):
            raise ValueError("Unmapped native syntax")
        self.pos += 1
        return token

    def literal(self) -> Any:
        token = self.take()
        if token == "{":
            values = []
            while self.peek() != "}":
                values.append(self.literal())
                if self.peek() != "}":
                    self.take(",")
            self.take("}")
            return {"set": values}
        if token == "@":
            return "@" + str(self.literal())
        if token.startswith('"'):
            return json.loads(token)
        if token.startswith("@"):
            return token
        if re.fullmatch(r"-?\d+", token):
            return int(token)
        if "/" in token:
            address, prefix = token.split("/")
            ipaddress.ip_network(token, strict=False)
            return {"prefix": {"addr": address, "len": int(prefix)}}
        if "-" in token:
            left, right = token.split("-", 1)
            if left.isdigit() and right.isdigit():
                return {"range": [int(left), int(right)]}
            try:
                ipaddress.ip_address(left)
                ipaddress.ip_address(right)
                return {"range": [left, right]}
            except ValueError:
                pass
        if token in {"accept", "drop", "return", "continue"}:
            return {token: None}
        if token in {"jump", "goto"}:
            return {token: {"target": self.literal()}}
        if not re.fullmatch(r"[a-zA-Z0-9_.:*+-]+", token):
            raise ValueError("Unmapped literal")
        return token

    def sequence(self) -> Any:
        value = self.literal()
        if self.peek() != ",":
            return value
        values = [value]
        while self.peek() == ",":
            self.take(",")
            values.append(self.literal())
        return {"set": values}


def rule_expressions(source: str) -> tuple[list[Expr], str | None]:
    reader = NativeReader(source)
    statements: list[Expr] = []
    comment = None
    while reader.peek():
        key = reader.take()
        body: Any = None
        if key == "comment":
            value = reader.literal()
            if not isinstance(value, str) or reader.peek():
                raise ValueError("Unmapped comment")
            comment = value
            break
        if key in {"meta", "ct", "ip", "ip6", "tcp", "udp", "icmp", "icmpv6"}:
            field = reader.take()
            left = {key: {"key": field}} if key in {"meta", "ct"} else {
                "payload": {"protocol": key, "field": field}}
            operator = reader.take() if reader.peek() in {"==", "!=", "<", ">", "<=", ">="} else "=="
            right = reader.sequence()
            body = {"left": left, "op": operator, "right": right}
            key = "match"
        elif key == "counter":
            if reader.peek() == "name":
                reader.take()
                body = reader.literal()
            elif reader.peek() == "packets":
                reader.take()
                packets = reader.literal()
                reader.take("bytes")
                body = {"packets": packets, "bytes": reader.literal()}
        elif key == "log":
            body = {}
            if reader.peek() == "prefix":
                reader.take()
                body["prefix"] = reader.literal()
        elif key in {"jump", "goto"}:
            body = {"target": reader.literal()}
        elif key in {"snat", "dnat"}:
            family = reader.take() if reader.peek() in {"ip", "ip6"} else None
            reader.take("to")
            address = reader.take()
            port = None
            if address.startswith("["):
                match = re.fullmatch(r"\[([^]]+)]:(\d+)", address)
                if match is None:
                    raise ValueError("Unsupported NAT address")
                address, port = match[1], int(match[2])
            elif address.count(":") == 1 and "." in address:
                address, number = address.split(":")
                port = int(number)
            ipaddress.ip_address(address)
            body = {"addr": address}
            if family:
                body["family"] = family
            if port is not None:
                body["port"] = port
        elif key not in {"accept", "drop", "reject", "return", "continue", "notrack", "masquerade"}:
            raise ValueError("Advanced expression")
        statements.append(Expr(statement={key: body}))
    if not statements:
        raise ValueError("Empty native rule")
    # A successful parse is only mapped if the generator understands every field.
    from nft_gui.generator.expressions import expression
    for statement in statements:
        assert statement.statement is not None
        expression(statement.statement)
    return statements, comment


def object_elements(source: str, *, mapping: bool) -> list[Any]:
    reader = NativeReader(source)
    reader.take("{")
    values = []
    while reader.peek() != "}":
        value = reader.literal()
        if mapping:
            reader.take(":")
            value = [value, reader.literal()]
        values.append(value)
        if reader.peek() != "}":
            reader.take(",")
    reader.take("}")
    if reader.peek():
        raise ValueError("Extra element syntax")
    return values
