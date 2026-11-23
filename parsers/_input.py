"""Typed access to untrusted JSON/YAML.

Upstream files are parsed into `object` and must pass through `Obj` before any
value reaches a dataclass. Every getter checks the runtime type and raises
ParseError with the exact path on mismatch, so no `Any` leaks past this module.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import NewType

from ._errors import ParseError

Oid = NewType("Oid", str)
_OID_RE = re.compile(r"^\d+(\.\d+)*$")


def parse_oid(value: str, where: str) -> Oid:
    if not _OID_RE.match(value):
        raise ParseError(f"{where}: {value!r} is not a dotted OID")
    return Oid(value)


def parse_int_text(value: str | int, where: str) -> int:
    """Accept 513, '513', '0x0904'."""
    if isinstance(value, bool):
        raise ParseError(f"{where}: expected int, got bool")
    if isinstance(value, int):
        return value
    s = value.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError as e:
        raise ParseError(f"{where}: {value!r} is not an integer") from e


class Obj:
    """A JSON/YAML mapping with typed getters."""

    __slots__ = ("_data", "path")

    def __init__(self, data: object, path: str) -> None:
        if not isinstance(data, Mapping):
            raise ParseError(f"{path}: expected a mapping, got {type(data).__name__}")
        self._data: Mapping[object, object] = data
        self.path = path

    def _where(self, key: str) -> str:
        return f"{self.path}.{key}"

    def has(self, key: str) -> bool:
        return self._data.get(key) is not None

    def keys(self) -> list[str]:
        return [k for k in self._data if isinstance(k, str)]

    def raw(self, key: str) -> object:
        return self._data.get(key)

    # -- scalars --------------------------------------------------------------
    def get_str(self, key: str) -> str:
        v = self._data.get(key)
        if not isinstance(v, str):
            raise ParseError(f"{self._where(key)}: expected string, got {type(v).__name__}")
        return v

    def opt_str(self, key: str) -> str | None:
        v = self._data.get(key)
        if v is None:
            return None
        if not isinstance(v, str):
            raise ParseError(f"{self._where(key)}: expected string, got {type(v).__name__}")
        return v

    def get_int(self, key: str) -> int:
        v = self.opt_int(key)
        if v is None:
            raise ParseError(f"{self._where(key)}: missing integer")
        return v

    def opt_int(self, key: str) -> int | None:
        v = self._data.get(key)
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int | str):
            raise ParseError(f"{self._where(key)}: expected integer, got {type(v).__name__}")
        return parse_int_text(v, self._where(key))

    def get_bool(self, key: str, default: bool) -> bool:
        v = self._data.get(key)
        if v is None:
            return default
        if not isinstance(v, bool):
            raise ParseError(f"{self._where(key)}: expected bool, got {type(v).__name__}")
        return v

    def opt_bool(self, key: str) -> bool | None:
        v = self._data.get(key)
        if v is None:
            return None
        if not isinstance(v, bool):
            raise ParseError(f"{self._where(key)}: expected bool, got {type(v).__name__}")
        return v

    def opt_oid(self, key: str) -> Oid | None:
        s = self.opt_str(key)
        return parse_oid(s, self._where(key)) if s is not None else None

    # -- containers -----------------------------------------------------------
    def get_obj(self, key: str) -> Obj:
        return Obj(self._data.get(key), self._where(key))

    def opt_obj(self, key: str) -> Obj | None:
        v = self._data.get(key)
        return None if v is None else Obj(v, self._where(key))

    def _list(self, key: str) -> list[object]:
        v = self._data.get(key)
        if v is None:
            return []
        if not isinstance(v, list):
            raise ParseError(f"{self._where(key)}: expected list, got {type(v).__name__}")
        return v

    def objs(self, key: str) -> list[Obj]:
        return [Obj(item, f"{self._where(key)}[{i}]") for i, item in enumerate(self._list(key))]

    def strs(self, key: str) -> list[str]:
        out: list[str] = []
        for i, item in enumerate(self._list(key)):
            if not isinstance(item, str):
                raise ParseError(f"{self._where(key)}[{i}]: expected string, got {type(item).__name__}")
            out.append(item)
        return out

    def opt_strs(self, key: str) -> list[str | None]:
        out: list[str | None] = []
        for i, item in enumerate(self._list(key)):
            if item is not None and not isinstance(item, str):
                raise ParseError(f"{self._where(key)}[{i}]: expected string or null, got {type(item).__name__}")
            out.append(item)
        return out
