from __future__ import annotations

from dataclasses import dataclass

from nft_gui.errors import NftError

MAX_SOURCE_BYTES = 2_000_000


@dataclass(frozen=True)
class Lexeme:
    value: str
    start: int
    end: int
    quoted: bool = False


def lex(source: str) -> list[Lexeme]:
    """Strict lexical scan for the execution boundary, independent of the UI parser."""
    result: list[Lexeme] = []
    i = 0
    while i < len(source):
        start = i
        c = source[i]
        if c == "#":
            i = source.find("\n", i)
            if i == -1:
                break
        elif c in " \t\r":
            i += 1
        elif c == '"':
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise NftError("Unterminated quoted string", code="unsafe_source")
            result.append(Lexeme(source[start:i], start, i, True))
        elif c == "\\":
            raise NftError("Unquoted escapes/continuations are unsupported", code="unsafe_source")
        elif c in "{};\n":
            i += 1
            result.append(Lexeme(c, start, i))
        else:
            while i < len(source) and source[i] not in ' \t\r\n{};#"\\':
                i += 1
            result.append(Lexeme(source[start:i], start, i))
    return result


def prepare_source(source: str) -> str:
    """Allow self-contained replacement rulesets, no files, scripts or queries.

    nft is still the semantic validator. This boundary prevents include-file
    disclosure and check/apply TOCTOU through external resources.
    """
    if len(source.encode()) > MAX_SOURCE_BYTES or "\x00" in source:
        raise NftError("Source is too large or contains NUL", code="unsafe_source")
    items = lex(source)
    if any(not t.quoted and t.value in {"include", "define", "redefine", "undefine"} for t in items):
        raise NftError("External includes and macros are not accepted", code="unsafe_source")
    statements: list[list[Lexeme]] = []
    current: list[Lexeme] = []
    depth = 0
    for item in items:
        if item.value in {";", "\n"} and not item.quoted and depth == 0:
            if current:
                statements.append(current)
                current = []
            continue
        current.append(item)
        if not item.quoted and item.value == "{":
            depth += 1
        if not item.quoted and item.value == "}":
            depth -= 1
            if depth < 0:
                raise NftError("Unbalanced braces", code="unsafe_source")
            if depth == 0 and current[0].value == "table":
                statements.append(current)
                current = []
    if depth:
        raise NftError("Unbalanced braces", code="unsafe_source")
    if current:
        statements.append(current)
    has_flush = False
    for index, stmt in enumerate(statements):
        words = [t.value for t in stmt]
        if words == ["flush", "ruleset"] and index == 0:
            has_flush = True
        elif len(words) >= 5 and words[0] == "table" and words[1] in {"ip", "ip6", "inet", "arp", "bridge", "netdev"} and words[3] == "{" and words[-1] == "}":
            pass
        elif len(words) >= 6 and words[:2] == ["add", "rule"] and words[2] in {"ip", "ip6", "inet", "arp", "bridge", "netdev"}:
            pass
        else:
            raise NftError("Only table declarations, add rule and an initial flush ruleset are allowed",
                           code="unsafe_source")
    # Prefixing the batch makes repeated apply/rollback idempotent and atomic.
    return source if has_flush else "flush ruleset\n" + source
