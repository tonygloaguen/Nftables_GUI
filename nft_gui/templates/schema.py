from __future__ import annotations

from typing import Literal

from pydantic import Field

from nft_gui.models.ruleset import Model


class Parameter(Model):
    key: str
    label: str
    default: str
    kind: Literal["network4", "address4", "interface", "port", "ports", "networks4", "choice"]
    help: str = ""
    choices: list[str] = Field(default_factory=list)


class Reference(Model):
    id: str
    title: str
    location: str
    note: str


class SourceExcerpt(Model):
    source: str
    code: str
    explanation: str
    adaptation: str


class Template(Model):
    id: str
    title: str
    category: str
    summary: str
    prerequisites: list[str]
    caveats: list[str]
    parameters: list[Parameter]
    sources: list[str]
    recipe: str
    origin: Literal["classique", "formation"] = "classique"
    excerpts: list[SourceExcerpt] = Field(default_factory=list)


class PreviewRequest(Model):
    values: dict[str, str] = Field(default_factory=dict, max_length=32)
