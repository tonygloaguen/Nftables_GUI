from __future__ import annotations

import re

from nft_gui.errors import UnsupportedError
from nft_gui.generator.expressions import expression, keyword, quote, value
from nft_gui.models import Chain, Counter, Map, NftObject, OpaqueObject, Quota, Rule, Ruleset, Set, Table


def _properties(obj: NftObject) -> list[str]:
    if obj.extra_fields:
        raise UnsupportedError(f"Unmapped {type(obj).__name__} fields: {', '.join(obj.extra_fields)}")
    return [f"comment {quote(obj.comment)};"] if obj.comment is not None else []


def _datatype(data: str | list[str]) -> str:
    return " . ".join(keyword(t) for t in data) if isinstance(data, list) else keyword(data)


def _object(obj: NftObject) -> str:
    if obj.raw_nft is not None:
        return obj.raw_nft
    properties = _properties(obj)
    if isinstance(obj, Chain):
        if obj.hook is not None:
            priority = str(obj.prio)
            if not re.fullmatch(r"-?\d+|[a-z_]+(?:\s*[+-]\s*\d+)?", priority):
                raise UnsupportedError("Unsupported chain priority")
            device = f" device {quote(obj.dev)}" if obj.dev is not None else ""
            properties.insert(0, f"type {obj.type} hook {obj.hook}{device} priority {priority};")
        if obj.policy is not None:
            properties.append(f"policy {obj.policy};")
    elif isinstance(obj, (Set, Map)):
        dtype = _datatype(obj.type)
        if isinstance(obj, Map):
            dtype += " : " + _datatype(obj.map)
        properties.insert(0, f"type {dtype};")
        if obj.flags:
            properties.append("flags " + ", ".join(keyword(f) for f in obj.flags) + ";")
        for name, label in (("timeout", "timeout"), ("gc_interval", "gc-interval")):
            duration = getattr(obj, name)
            if duration is not None:
                properties.append(f"{label} {duration}s;")
        if obj.size is not None:
            properties.append(f"size {obj.size};")
        if obj.policy is not None:
            properties.append(f"policy {obj.policy};")
        if obj.elem:
            if isinstance(obj, Map):
                elements: list[str] = []
                for pair in obj.elem:
                    if not isinstance(pair, list) or len(pair) != 2:
                        raise UnsupportedError("Unmapped map element; expected [key, value]")
                    elements.append(f"{value(pair[0])} : {value(pair[1])}")
            else:
                elements = [value(element) for element in obj.elem]
            properties.append("elements = { " + ", ".join(elements) + " };")
    elif isinstance(obj, Counter):
        properties.append(f"packets {obj.packets} bytes {obj.bytes};")
    elif isinstance(obj, Quota):
        properties.append(f"{'over ' if obj.inv else ''}{obj.bytes} bytes used {obj.used} bytes;")
    else:
        raise UnsupportedError(f"Unmapped object: {type(obj).__name__}")
    name = quote(obj.name)
    return f"{obj.kind} {name} {{\n" + "".join(f"    {p}\n" for p in properties) + "}"


def _rule(rule: Rule) -> str:
    if rule.raw_nft is not None:
        return rule.raw_nft
    _properties(rule)
    parts: list[str] = []
    for expr in rule.expr:
        if expr.raw_nft is not None:
            parts.append(expr.raw_nft)
        elif expr.statement is not None:
            parts.append(expression(expr.statement))
        else:
            raise UnsupportedError("An opaque JSON expression needs raw_nft before text export")
    if rule.comment is not None:
        parts.append("comment " + quote(rule.comment))
    if not parts:
        raise UnsupportedError("Cannot serialize an empty rule")
    return " ".join(parts)


def generate_nft(ruleset: Ruleset) -> str:
    try:
        return _generate_nft(ruleset)
    except (TypeError, ValueError, KeyError) as exc:
        raise UnsupportedError(f"Malformed or unsupported nft expression: {exc}") from exc


def _generate_nft(ruleset: Ruleset) -> str:
    """Render a complete replacement batch, never silently skip an unknown field."""
    if ruleset.raw_nft is not None:
        return ruleset.raw_nft
    tables: dict[tuple[str, str], Table] = {}
    chains: dict[tuple[str, str, str], Chain] = {}
    named: set[tuple[str, str, str, str]] = set()
    for obj in ruleset.objects:
        if isinstance(obj, OpaqueObject):
            if set(obj.nft_object) == {"metainfo"}:
                continue
            raise UnsupportedError("Unmapped nft object is preserved in JSON; text export refused")
        if isinstance(obj, Table):
            table_key = (obj.family, obj.name)
            if table_key in tables:
                raise UnsupportedError("Duplicate table")
            tables[table_key] = obj
        elif isinstance(obj, Chain):
            chain_key = (obj.family, obj.table, obj.name)
            if chain_key in chains:
                raise UnsupportedError("Duplicate chain")
            chains[chain_key] = obj
        elif isinstance(obj, (Set, Map, Counter, Quota)):
            # Sets and maps share a namespace.
            kind = "set" if isinstance(obj, (Set, Map)) else obj.kind
            named_key = (obj.family, obj.table, kind, obj.name)
            if named_key in named:
                raise UnsupportedError("Duplicate named object")
            named.add(named_key)
    for obj in ruleset.objects:
        if isinstance(obj, (Chain, Rule, Set, Map, Counter, Quota)):
            if (obj.family, obj.table) not in tables:
                raise UnsupportedError("Object refers to a missing table")
        if isinstance(obj, Rule) and (obj.family, obj.table, obj.chain) not in chains:
            raise UnsupportedError("Rule refers to a missing chain")
    lines = ["# Generated by nft-gui: complete ruleset replacement", "flush ruleset", ""]
    for key, table in tables.items():
        props = _properties(table)
        if table.raw_nft is not None:
            raise UnsupportedError("Raw table source must be kept as a complete code document")
        lines.append(f"table {table.family} {quote(table.name)} {{")
        lines.extend("    " + p for p in props)
        if table.flags:
            if set(table.flags) - {"dormant"}:
                raise UnsupportedError("Process-owned tables cannot be safely snapshotted")
            lines.append("    flags " + ", ".join(table.flags) + ";")
        members = [o for o in ruleset.objects
                   if isinstance(o, (Chain, Rule, Set, Map, Counter, Quota))
                   and (o.family, o.table) == key]
        # Declare chains before maps (verdict targets), and objects before rules.
        declarations: list[NftObject] = [o for o in members if isinstance(o, Chain)]
        declarations += [o for o in members if isinstance(o, (Set, Map, Counter, Quota))]
        for declaration in declarations:
            lines.extend("    " + line for line in _object(declaration).splitlines())
        lines.append("}")
        # add rule preserves original per-chain order, including forward chains.
        for rule in members:
            if isinstance(rule, Rule):
                lines.append(f"add rule {rule.family} {quote(rule.table)} {quote(rule.chain)} {_rule(rule)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
