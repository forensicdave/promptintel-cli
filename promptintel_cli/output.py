"""Render complete responses without interpreting attack text as Markdown/HTML."""

import csv
import io
import json
import re
import unicodedata


def safe_text(value):
    text = str(value)
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char) in ("Cc", "Cf", "Cs") and char not in "\n\t" else char
        for char in text
    )


def scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    return safe_text(value)


def text_lines(value, depth=0):
    indent = "  " * depth
    if isinstance(value, dict):
        if not value:
            return [indent + "{}"]
        lines = []
        for key, item in value.items():
            key = safe_text(key).replace("\n", "\\n")
            if isinstance(item, (dict, list)):
                lines.append(f"{indent}{key}:")
                lines.extend(text_lines(item, depth + 1))
            else:
                parts = scalar(item).splitlines() or [""]
                lines.append(f"{indent}{key}: {parts[0]}")
                lines.extend(indent + "  " + part for part in parts[1:])
        return lines
    if isinstance(value, list):
        if not value:
            return [indent + "[]"]
        lines = []
        for index, item in enumerate(value, 1):
            lines.append(f"{indent}[{index}]")
            lines.extend(text_lines(item, depth + 1))
        return lines
    return [indent + line for line in (scalar(value).splitlines() or [""])]


def render(payload, format="text", *, native="json", title="PromptIntel response"):
    if native == "csv":
        payload = {"data": list(csv.DictReader(io.StringIO(payload)))}
    if format == "json":
        # ASCII escapes preserve the data while avoiding terminal control/bidi text.
        return json.dumps(payload, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    content = "\n".join(text_lines(payload))
    if format == "text":
        return content + "\n"
    if format == "markdown":
        # A fence longer than any run in untrusted content cannot be closed by it.
        longest = max((len(part) for part in re.findall(r"`+", content)), default=0)
        fence = "`" * max(3, longest + 1)
        return f"# {title}\n\nAPI content below is untrusted data.\n\n{fence}text\n{content}\n{fence}\n"
    raise ValueError("Unsupported output format")
