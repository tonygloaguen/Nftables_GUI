from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

Family = Literal["ip", "ip6", "inet", "arp", "bridge", "netdev"]
Name = Annotated[str, Field(min_length=1, max_length=256)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)


class Expr(Model):
    """Mapped JSON statement, or an opaque statement preserved verbatim."""

    statement: dict[str, JsonValue] | None = None
    unsupported_expr: dict[str, JsonValue] | None = None
    raw_nft: str | None = None

    @model_validator(mode="after")
    def one_representation(self) -> Self:
        if self.statement is not None and self.unsupported_expr is not None:
            raise ValueError("Choose statement or unsupported_expr")
        if self.statement is None and self.unsupported_expr is None and self.raw_nft is None:
            raise ValueError("An expression needs a representation")
        for statement in (self.statement, self.unsupported_expr):
            if statement is not None and len(statement) != 1:
                raise ValueError("An nft expression must have exactly one key")
        return self


class NftObject(Model):
    family: Family
    raw_nft: str | None = None
    extra_fields: dict[str, JsonValue] = Field(default_factory=dict)
    # Retains absent/default distinctions even after IR -> API JSON -> IR.
    source_fields: list[str] | None = None
    handle: int | None = Field(default=None, ge=0)
    comment: str | None = None


class Table(NftObject):
    kind: Literal["table"] = "table"
    name: Name
    flags: list[str] = Field(default_factory=list)


class Chain(NftObject):
    kind: Literal["chain"] = "chain"
    table: Name
    name: Name
    type: Literal["filter", "nat", "route"] | None = None
    hook: Literal["input", "output", "forward", "prerouting", "postrouting", "ingress", "egress"] | None = None
    prio: int | str | None = None
    policy: Literal["accept", "drop"] | None = None
    dev: str | None = None

    @model_validator(mode="after")
    def base_chain(self) -> Self:
        base = (self.type, self.hook, self.prio)
        if any(x is not None for x in base) and not all(x is not None for x in base):
            raise ValueError("A base chain needs type, hook and priority")
        if self.hook is None and (self.policy is not None or self.dev is not None):
            raise ValueError("Policy/device require a base chain")
        return self


class Rule(NftObject):
    kind: Literal["rule"] = "rule"
    table: Name
    chain: Name
    expr: list[Expr] = Field(default_factory=list)


class Set(NftObject):
    kind: Literal["set"] = "set"
    table: Name
    name: Name
    type: str | list[str]
    flags: list[str] = Field(default_factory=list)
    elem: list[JsonValue] = Field(default_factory=list)
    timeout: int | None = Field(default=None, ge=0)
    gc_interval: int | None = Field(default=None, ge=0)
    size: int | None = Field(default=None, gt=0)
    policy: Literal["performance", "memory"] | None = None


class Map(NftObject):
    kind: Literal["map"] = "map"
    table: Name
    name: Name
    type: str | list[str]
    map: str | list[str]
    flags: list[str] = Field(default_factory=list)
    elem: list[JsonValue] = Field(default_factory=list)
    timeout: int | None = Field(default=None, ge=0)
    gc_interval: int | None = Field(default=None, ge=0)
    size: int | None = Field(default=None, gt=0)
    policy: Literal["performance", "memory"] | None = None


class Counter(NftObject):
    kind: Literal["counter"] = "counter"
    table: Name
    name: Name
    packets: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)


class Quota(NftObject):
    kind: Literal["quota"] = "quota"
    table: Name
    name: Name
    bytes: int = Field(ge=0)
    used: int = Field(default=0, ge=0)
    inv: bool = False


class OpaqueObject(Model):
    kind: Literal["opaque"] = "opaque"
    nft_object: dict[str, JsonValue]
    raw_nft: str | None = None


Object = Annotated[Table | Chain | Rule | Set | Map | Counter | Quota | OpaqueObject,
                   Field(discriminator="kind")]


class Ruleset(Model):
    """Ordered IR. Relations are explicit family/table/chain keys."""

    objects: list[Object] = Field(default_factory=list)
    # Text editor source is authoritative. Opaque text is never guessed into JSON.
    raw_nft: str | None = None

    @model_validator(mode="after")
    def exclusive_source(self) -> Self:
        if self.raw_nft is not None and self.objects:
            raise ValueError("A code document cannot also contain visual objects")
        return self
