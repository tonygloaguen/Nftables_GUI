from __future__ import annotations

import copy
import json
from typing import Any

from pydantic import ValidationError

from nft_gui.errors import NftError, UnsupportedError
from nft_gui.models import Chain, Counter, Expr, Map, OpaqueObject, Quota, Rule, Ruleset, Set, Table

TYPES: dict[str, type[Table | Chain | Rule | Set | Map | Counter | Quota]] = {
         "table": Table, "chain": Chain, "rule": Rule, "set": Set,
         "map": Map, "counter": Counter, "quota": Quota}
IR_ONLY = {"kind", "raw_nft", "extra_fields", "source_fields"}


def from_nft_json(document: str | dict[str, Any]) -> Ruleset:
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError as exc:
            raise NftError("Invalid nft JSON", stderr=str(exc), code="invalid_json") from exc
    if not isinstance(document, dict) or set(document) != {"nftables"}:
        raise NftError("Expected an nftables JSON document", code="invalid_json")
    items = document["nftables"]
    if not isinstance(items, list):
        raise NftError("nftables must be an array", code="invalid_json")
    ruleset = Ruleset()
    for item in items:
        if not isinstance(item, dict) or len(item) != 1:
            raise NftError("Invalid ruleset entry", code="invalid_json")
        kind, fields = next(iter(item.items()))
        if kind not in TYPES or not isinstance(fields, dict):
            ruleset.objects.append(OpaqueObject(nft_object=copy.deepcopy(item)))
            continue
        model = TYPES[kind]
        known = set(model.model_fields) - IR_ONLY
        attrs = {k: copy.deepcopy(v) for k, v in fields.items() if k in known}
        attrs["extra_fields"] = {k: copy.deepcopy(v) for k, v in fields.items() if k not in known}
        attrs["source_fields"] = list(fields)
        if kind == "rule":
            expressions = fields.get("expr", [])
            if not isinstance(expressions, list):
                raise NftError("Rule expr must be an array", code="invalid_json")
            attrs["expr"] = [_expression(e) for e in expressions]
        try:
            ruleset.objects.append(model.model_validate(attrs))
        except ValidationError:
            # Future schema additions or unknown enum values are not discarded.
            ruleset.objects.append(OpaqueObject(nft_object=copy.deepcopy(item)))
    return ruleset


def _expression(data: Any) -> Expr:
    if not isinstance(data, dict) or len(data) != 1:
        raise NftError("Invalid rule expression", code="invalid_json")
    from nft_gui.generator.expressions import expression
    try:
        expression(data)
    except (UnsupportedError, TypeError, ValueError, KeyError):
        return Expr(unsupported_expr=copy.deepcopy(data))
    return Expr(statement=copy.deepcopy(data))


def to_nft_json(ruleset: Ruleset) -> dict[str, Any]:
    if ruleset.raw_nft is not None:
        raise UnsupportedError("Opaque code has no lossless nft JSON mapping; export its source")
    entries: list[dict[str, Any]] = []
    for obj in ruleset.objects:
        if isinstance(obj, OpaqueObject):
            entries.append(copy.deepcopy(obj.nft_object))
            continue
        if obj.raw_nft is not None:
            raise UnsupportedError("An object with edited raw_nft cannot export stale JSON")
        fields = obj.model_dump(exclude=IR_ONLY, exclude_none=True)
        if obj.source_fields is not None:
            for name in obj.source_fields:
                if name in type(obj).model_fields and name not in IR_ONLY and getattr(obj, name) is None:
                    fields[name] = None
            for name in list(fields):
                default = type(obj).model_fields[name].get_default(call_default_factory=True)
                if name not in obj.source_fields and getattr(obj, name) == default:
                    fields.pop(name)
        if isinstance(obj, Rule):
            fields["expr"] = []
            for expr in obj.expr:
                if expr.raw_nft is not None:
                    raise UnsupportedError("An expression with raw_nft cannot export stale JSON")
                fields["expr"].append(copy.deepcopy(
                    expr.statement if expr.statement is not None else expr.unsupported_expr))
        if set(fields) & set(obj.extra_fields):
            raise NftError("Extension field collides with a mapped field", code="invalid_ir")
        fields.update(copy.deepcopy(obj.extra_fields))
        entries.append({obj.kind: fields})
    return {"nftables": entries}
