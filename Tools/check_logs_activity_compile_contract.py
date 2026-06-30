#!/usr/bin/env python3
"""Static guard for LogsActivity patterns that must survive javac."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
LOGS_ACTIVITY = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/LogsActivity.java"


def extract_block(source: str, needle: str) -> str:
    start = source.find(needle)
    if start < 0:
        raise ValueError(f"missing block: {needle}")
    brace_start = source.find("{", start)
    if brace_start < 0:
        raise ValueError(f"missing opening brace for: {needle}")

    depth = 0
    for index in range(brace_start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace_start + 1:index]

    raise ValueError(f"unterminated block: {needle}")


def main() -> int:
    java = LOGS_ACTIVITY.read_text(encoding="utf-8")
    errors: list[str] = []

    try:
        constructor = extract_block(java, "LogCell(Context context)")
    except ValueError as exc:
        print(f"LogsActivity compile contract failed: {exc}")
        return 1

    assignment = constructor.find("checkBox = new CheckBox(context);")
    listener = constructor.find("checkContainer.setOnClickListener")
    set_checked = constructor.find("checkBox.setChecked(now);")

    if assignment < 0:
        errors.append("LogCell constructor must initialize checkBox")
    if listener < 0:
        errors.append("LogCell constructor must keep the checkbox click listener")
    if set_checked < 0:
        errors.append("LogCell click listener must update the checkbox state")
    if (
        assignment >= 0
        and listener >= 0
        and set_checked >= 0
        and not (assignment < listener < set_checked)
    ):
        errors.append(
            "LogCell must initialize checkBox before the click listener captures it"
        )

    if errors:
        print("LogsActivity compile contract failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("LogsActivity compile contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
