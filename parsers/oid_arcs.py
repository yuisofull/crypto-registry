"""Load curated/oid_arcs.yml: OID -> family/primitive rules with citations."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ._common import CURATED_DIR, DocumentSpec, load_sources
from ._errors import ParseError
from ._input import Obj, Oid, parse_oid
from .models import Primitive
from .nist_curated import Citation, resolve_cite

OID_ARCS = CURATED_DIR / "oid_arcs.yml"
KEY_TYPES = frozenset({"RSA", "EC", "DH"})


@dataclass(frozen=True, slots=True, kw_only=True)
class OidRule:
    oids: frozenset[Oid]
    subtree: Oid | None
    children: tuple[int, int] | None
    family: str | None
    primitive: Primitive | None
    key_type: bool
    curve: bool
    exclude: bool
    cite: Citation
    index: int  # position in the file, for error messages

    def matches(self, oid: Oid) -> bool:
        if oid in self.oids:
            return True
        if self.subtree is None or not oid.startswith(self.subtree + "."):
            return False
        if self.children is None:
            return True
        child = oid[len(self.subtree) + 1:].split(".", 1)[0]
        return child.isdigit() and self.children[0] <= int(child) <= self.children[1]

    def specificity(self, oid: Oid) -> int:
        """Exact match beats any subtree; longer subtree beats shorter."""
        if oid in self.oids:
            return 10_000
        assert self.subtree is not None
        return len(self.subtree.split(".")) * 10 + (1 if self.children else 0)


def _children(spec: str | None, where: str) -> tuple[int, int] | None:
    if spec is None:
        return None
    lo, _, hi = spec.partition("-")
    try:
        a, b = int(lo), int(hi or lo)
    except ValueError as e:
        raise ParseError(f"{where}: children {spec!r} must be 'N' or 'N-M'") from e
    if a > b:
        raise ParseError(f"{where}: children range {spec!r} is reversed")
    return a, b


def load_rules(path: Path = OID_ARCS, documents: dict[str, DocumentSpec] | None = None) -> tuple[OidRule, ...]:
    docs = documents if documents is not None else load_sources().documents
    root = Obj(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
    rules: list[OidRule] = []
    for i, r in enumerate(root.objs("rules")):
        oids = frozenset(parse_oid(s, f"{r.path}.oids") for s in r.strs("oids"))
        sub = r.opt_str("subtree")
        if bool(oids) == bool(sub):
            raise ParseError(f"{r.path}: set exactly one of `oids` or `subtree`")
        prim_s = r.opt_str("primitive")
        try:
            prim = Primitive(prim_s) if prim_s else None
        except ValueError as e:
            raise ParseError(f"{r.path}.primitive: {e}") from e
        rule = OidRule(
            oids=oids, subtree=parse_oid(sub, f"{r.path}.subtree") if sub else None,
            children=_children(r.opt_str("children"), r.path), family=r.opt_str("family"),
            primitive=prim, key_type=r.get_bool("key_type", False), curve=r.get_bool("curve", False),
            exclude=r.get_bool("exclude", False), cite=resolve_cite(r.get_obj("cite"), docs, True), index=i,
        )
        if rule.key_type and (rule.primitive is not None or rule.family not in KEY_TYPES):
            raise ParseError(f"{r.path}: key_type rules need family in {sorted(KEY_TYPES)} and no primitive")
        if not (rule.exclude or rule.curve or rule.family):
            raise ParseError(f"{r.path}: needs `family`, `curve: true` or `exclude: true`")
        rules.append(rule)
    return tuple(rules)


def match_rule(rules: tuple[OidRule, ...], oid: Oid) -> OidRule | None:
    hits = [r for r in rules if r.matches(oid)]
    return max(hits, key=lambda r: (r.specificity(oid), -r.index)) if hits else None
