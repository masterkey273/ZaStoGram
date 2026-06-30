#!/usr/bin/env python3
"""Static guard for Android string format specifiers in base resources."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
STRINGS_XML = ROOT / "TMessagesProj/src/main/res/values/strings.xml"

STRING_RE = re.compile(r"<string\b(?P<attrs>[^>]*)>(?P<text>.*)</string>")
NAME_RE = re.compile(r'\bname="(?P<name>[^"]+)"')
FORMAT_RE = re.compile(
    r"%(?P<index>\d+\$)?(?P<flags>[-#+ 0,(<]*)?(?P<width>\d+)?"
    r"(?P<precision>\.\d+)?(?P<datetime>[tT])?(?P<conversion>[a-zA-Z%])"
)


@dataclass(frozen=True)
class FormatToken:
    raw: str
    consumes_argument: bool
    positional: bool


def extract_format_tokens(text: str) -> list[FormatToken]:
    tokens: list[FormatToken] = []
    index = 0
    while True:
        percent = text.find("%", index)
        if percent < 0:
            return tokens

        match = FORMAT_RE.match(text, percent)
        if not match:
            tokens.append(FormatToken(text[percent : percent + 1], True, False))
            index = percent + 1
            continue

        conversion = match.group("conversion")
        consumes_argument = conversion not in {"%", "n"}
        tokens.append(
            FormatToken(
                match.group(0),
                consumes_argument,
                match.group("index") is not None,
            )
        )
        index = match.end()


def main() -> int:
    errors: list[str] = []

    for line_number, line in enumerate(
        STRINGS_XML.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = STRING_RE.search(line)
        if not match:
            continue

        attrs = match.group("attrs")
        if 'formatted="false"' in attrs:
            continue

        name_match = NAME_RE.search(attrs)
        if not name_match:
            continue

        name = name_match.group("name")
        tokens = [
            token for token in extract_format_tokens(match.group("text"))
            if token.consumes_argument
        ]
        if len(tokens) > 1 and any(not token.positional for token in tokens):
            raw_tokens = ", ".join(token.raw for token in tokens)
            errors.append(
                f"line {line_number}: {name} has multiple non-positional "
                f"format arguments ({raw_tokens})"
            )

    if errors:
        print("Android string format contract failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Android string format contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
