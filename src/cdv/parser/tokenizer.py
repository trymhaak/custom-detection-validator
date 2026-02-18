"""KQL tokenizer: strips comments, handles string literals."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TokenizedQuery:
    cleaned_text: str  # KQL with comments removed, string contents replaced
    original_text: str
    has_comments: bool
    string_literals: list[str]  # preserved original string values


def tokenize(kql_text: str) -> TokenizedQuery:
    """Preprocess KQL text: strip comments, neutralize string literals.

    Uses a character-by-character state machine to correctly handle:
    - Single-line comments: // ...
    - Multi-line comments: /* ... */
    - Single-quoted strings: '...'
    - Double-quoted strings: "..."
    - Escaped characters within strings
    """
    result: list[str] = []
    literals: list[str] = []
    has_comments = False
    i = 0
    n = len(kql_text)

    while i < n:
        c = kql_text[i]

        # Single-line comment
        if c == "/" and i + 1 < n and kql_text[i + 1] == "/":
            has_comments = True
            # Skip to end of line
            while i < n and kql_text[i] != "\n":
                i += 1
            # Keep the newline if present
            if i < n:
                result.append("\n")
                i += 1
            continue

        # Multi-line comment
        if c == "/" and i + 1 < n and kql_text[i + 1] == "*":
            has_comments = True
            i += 2
            while i < n:
                if kql_text[i] == "*" and i + 1 < n and kql_text[i + 1] == "/":
                    i += 2
                    break
                i += 1
            result.append(" ")  # replace comment with space
            continue

        # String literal (single or double quote)
        if c in ("'", '"'):
            quote = c
            i += 1
            literal_chars: list[str] = []
            while i < n:
                sc = kql_text[i]
                if sc == "\\":
                    # Escaped character
                    literal_chars.append(sc)
                    i += 1
                    if i < n:
                        literal_chars.append(kql_text[i])
                        i += 1
                    continue
                if sc == quote:
                    i += 1
                    break
                literal_chars.append(sc)
                i += 1

            literal_value = "".join(literal_chars)
            literals.append(literal_value)
            # Replace string content with placeholder to avoid false matches
            placeholder_idx = len(literals) - 1
            result.append(f"{quote}__STR{placeholder_idx}__{quote}")
            continue

        result.append(c)
        i += 1

    return TokenizedQuery(
        cleaned_text="".join(result),
        original_text=kql_text,
        has_comments=has_comments,
        string_literals=literals,
    )
