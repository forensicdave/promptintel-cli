"""Parse indicator data without interpreting it as instructions."""

import json

from .client import ClientError
from .endpoints import INDICATOR_TYPES


def parse_input(text, input_format="auto"):
    if input_format == "auto":
        input_format = "json" if text.lstrip().startswith(("[", "{")) else "text"
    if input_format == "text":
        return [line.strip() for line in text.splitlines() if line.strip()]
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise ClientError("Indicator input is not valid JSON", code=2) from exc
    if isinstance(value, dict) and set(value) == {"indicators"}:
        value = value["indicators"]
    if not isinstance(value, list):
        raise ClientError("JSON input must be an array or an object containing an indicators array", code=2)
    return value


def validate_indicators(items, default_type, redactor):
    if not 1 <= len(items) <= 100:
        raise ClientError("Provide between 1 and 100 indicators in total; inputs are not automatically batched", code=2)
    result = []
    for item in items:
        if isinstance(item, str):
            value = item
            kind = default_type
        elif isinstance(item, dict) and set(item) == {"type", "value"}:
            value, kind = item["value"], item["type"]
            if not isinstance(kind, str) or kind not in INDICATOR_TYPES:
                raise ClientError("Each typed indicator needs a supported type", code=2)
        else:
            raise ClientError("Indicators must be strings or objects containing only type and value", code=2)
        if (not isinstance(value, str) or not value.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
                or redactor.text(value) != value):
            raise ClientError("Indicators cannot be blank, contain control characters or an API credential; never send prompt text to /check", code=2)
        result.append({"type": kind, "value": value} if kind else value)
    return result
