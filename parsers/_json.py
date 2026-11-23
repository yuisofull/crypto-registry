"""Serialize dataclasses/enums to plain JSON values.

A dataclass field can rename its JSON key with `field(metadata={"json": "camelName"})`.
"""
from __future__ import annotations

import dataclasses
from enum import Enum

type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]


def to_json(obj: object) -> JsonValue:
    if isinstance(obj, Enum):  # before the scalar check: StrEnum/IntEnum are str/int subclasses
        value: object = obj.value
        return to_json(value)
    if obj is None or isinstance(obj, bool | str | int | float):
        return obj
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, JsonValue] = {}
        for f in dataclasses.fields(obj):
            key = str(f.metadata.get("json", f.name))
            out[key] = to_json(getattr(obj, f.name))
        return out
    if isinstance(obj, dict):
        return {str(to_json(k)): to_json(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple | set | frozenset):
        items = [to_json(v) for v in obj]
        if isinstance(obj, set | frozenset):
            items.sort(key=str)
        return items
    raise TypeError(f"cannot serialize {type(obj).__name__}")
