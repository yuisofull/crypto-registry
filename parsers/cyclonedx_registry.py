"""Parse the CycloneDX Cryptography Registry (schema/cryptography-defs.json).

Pattern syntax used by the registry (converted by `pattern_to_regex`):
  [x]        optional
  (a|b)      alternatives
  {name}     placeholder for a parameter (hash, key length, curve, ...)
  <name>     placeholder (used in HSS)
  )+         one or more of the preceding group
  a|b        top-level alternatives
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ._common import manifest_source, permalink, raw_text, write_output
from ._errors import ParseError
from ._input import Obj
from .models import Primitive, Ref, RegistryCurve, RegistryVariant, Standard

SOURCE_ID = "cyclonedx-registry"
PATH = "schema/cryptography-defs.json"

_PLACEHOLDER = r"([^\s]+?)"  # capturing, so classify() can score specificity


@dataclass(frozen=True, slots=True, kw_only=True)
class Registry:
    algorithms: tuple[RegistryVariant, ...]
    curves: tuple[RegistryCurve, ...]
    last_updated: str | None

    def families(self) -> set[str]:
        return {a.family for a in self.algorithms}

    def family_primitives(self, family: str) -> set[Primitive]:
        return {a.primitive for a in self.algorithms if a.family == family}


def pattern_to_regex(pattern: str) -> str:
    out: list[str] = []
    i = 0
    depth = 0
    while i < len(pattern):
        c = pattern[i]
        if c in "{<":
            j = pattern.index("}" if c == "{" else ">", i)
            out.append(_PLACEHOLDER)
            i = j + 1
            continue
        if c in "[(":
            out.append("(?:")
            depth += 1
        elif c == "]":
            out.append(")?")
            depth -= 1
        elif c == ")":
            out.append(")")
            depth -= 1
            if i + 1 < len(pattern) and pattern[i + 1] == "+":
                out.append("+")
                i += 1
        elif c == "|":
            out.append("|")
        else:
            out.append(re.escape(c))
        i += 1
    if depth != 0:
        raise ParseError(f"unbalanced pattern: {pattern!r}")
    return "^(?:" + "".join(out) + ")$"


def _standards(o: Obj) -> list[Standard]:
    return [Standard(name=s.get_str("name"), url=s.opt_str("url")) for s in o.objs("standard")]


def parse_registry(text: str, ref: Ref) -> Registry:
    doc = Obj(json.loads(text), "cryptography-defs.json")
    algorithms: list[RegistryVariant] = []
    for fam in doc.objs("algorithms"):
        fam_std = _standards(fam)
        for v in fam.objs("variant"):
            regex = pattern_to_regex(v.get_str("pattern"))
            re.compile(regex, re.IGNORECASE)  # fail early on a bad conversion
            try:
                prim = Primitive(v.get_str("primitive"))
            except ValueError as e:
                raise ParseError(f"{v.path}.primitive: {e}") from e
            algorithms.append(RegistryVariant(
                family=fam.get_str("family"), primitive=prim, pattern=v.get_str("pattern"),
                regex=regex, standards=tuple(_standards(v) + fam_std), ref=ref,
            ))
    curves: list[RegistryCurve] = []
    for group in doc.objs("ellipticCurves"):
        for c in group.objs("curves"):
            curves.append(RegistryCurve(
                name=c.get_str("name"), group=group.get_str("name"), oid=c.opt_oid("oid"),
                form=c.opt_str("form"), aliases=tuple(_curve_aliases(c)), ref=ref,
            ))
    return Registry(algorithms=tuple(algorithms), curves=tuple(curves), last_updated=doc.opt_str("lastUpdated"))


def _curve_aliases(c: Obj) -> list[str]:
    # aliases are objects {"category": ..., "name": ...} in the registry
    out: list[str] = []
    for a in c.objs("aliases"):
        out.append(a.get_str("name"))
    return out


def classify(name: str, algorithms: tuple[RegistryVariant, ...] | list[RegistryVariant]) -> list[RegistryVariant]:
    """Every registry variant whose pattern matches `name`, most specific first.

    Placeholders are untyped, so loose patterns also match: 'AES-256-CBC' fits the
    AEAD pattern with tagLength='CBC'. Candidates are ranked by how many
    characters placeholders had to absorb (fewer = more literal = better).
    """
    hits: list[tuple[int, RegistryVariant]] = []
    for a in algorithms:
        m = re.match(a.regex, name, re.IGNORECASE)
        if m:
            hits.append((sum(len(g) for g in m.groups() if g), a))
    return [a for _, a in sorted(hits, key=lambda h: h[0])]


def load() -> Registry:
    src = manifest_source(SOURCE_ID)
    return parse_registry(raw_text(SOURCE_ID, PATH), permalink(src.repo, src.commit, PATH))


def run() -> list[str]:
    src = manifest_source(SOURCE_ID)
    reg = load()
    extra: dict[str, object] = {"registry_last_updated": reg.last_updated}
    a = write_output("cyclonedx_algorithms", list(reg.algorithms), [src], extra=extra)
    c = write_output("cyclonedx_curves", list(reg.curves), [src], extra=extra)
    return [
        f"{a.name}: {len(reg.algorithms)} patterns in {len(reg.families())} families",
        f"{c.name}: {len(reg.curves)} curves ({sum(1 for x in reg.curves if x.oid)} with OID)",
    ]
