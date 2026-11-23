"""Load curated/nist.yml into typed tables, validated and with resolved citations.

Helpers for the merge:
  strength_for_rsa(rows, modulus_bits)  -> classical bits (SP 800-57 Table 2)
  strength_for_ffc(rows, L_bits)
  strength_for_ecc(rows, order_bits)
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ._common import CURATED_DIR, DocumentSpec, load_sources, write_output
from ._errors import ParseError
from ._input import Obj
from .models import NistLevel, Primitive

CURATED = CURATED_DIR / "nist.yml"


@dataclass(frozen=True, slots=True, kw_only=True)
class Citation:
    doc: str
    title: str
    url: str
    table: str | None = None
    section: str | None = None
    locator: str | None = None
    verified: bool = False

    @property
    def where(self) -> str:
        parts = [p for p in (self.table, f"§{self.section}" if self.section else None, self.locator) if p]
        return ", ".join(parts)


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityCategory:
    category: NistLevel
    attack: str
    example: str
    cite: Citation


@dataclass(frozen=True, slots=True, kw_only=True)
class QuantumVulnerable:
    family: str
    registry_families: tuple[str, ...]
    primitive: Primitive
    standard: str | None
    note: str | None
    min_classical_bits: int
    deprecated_after: int | None
    disallowed_after: int | None
    nist_level: NistLevel
    cite: Citation


@dataclass(frozen=True, slots=True, kw_only=True)
class SymmetricLevel:
    """Block cipher or AEAD row (IR 8547 Tables 6, 7)."""

    algorithm: str
    family: str
    primitive: Primitive
    standard: str | None
    classical_bits: int
    nist_level: NistLevel
    cite: Citation


@dataclass(frozen=True, slots=True, kw_only=True)
class HashLevel:
    """Hash / XOF row (IR 8547 Table 8)."""

    algorithm: str
    family: str
    primitive: Primitive
    standard: str | None
    collision_bits: int | None     # None where NIST gives "< 80"
    collision_level: NistLevel
    preimage_bits: int
    preimage_level: NistLevel
    note: str | None
    cite: Citation


@dataclass(frozen=True, slots=True, kw_only=True)
class StrengthRow:
    """SP 800-57 Pt1 Rev5 Table 2: key sizes giving `bits` of classical security."""

    bits: int
    symmetric: str
    ffc_l: int
    ffc_n: int
    ifc_k: int
    ecc_f_min: int
    ecc_f_max: int | None
    cite: Citation


@dataclass(frozen=True, slots=True, kw_only=True)
class NamedCurveStrength:
    curve: str
    bits: int
    aliases: tuple[str, ...]
    cite: Citation
    aliases_cite: Citation | None


@dataclass(frozen=True, slots=True, kw_only=True)
class CuratedNist:
    security_categories: tuple[SecurityCategory, ...]
    quantum_vulnerable: tuple[QuantumVulnerable, ...]
    symmetric: tuple[SymmetricLevel, ...]
    hashes: tuple[HashLevel, ...]
    classical_strength: tuple[StrengthRow, ...]
    named_curves: tuple[NamedCurveStrength, ...]
    unverified_tables: tuple[str, ...]


def resolve_cite(o: Obj, documents: dict[str, DocumentSpec], verified: bool) -> Citation:
    doc_id = o.get_str("doc")
    doc = documents.get(doc_id)
    if doc is None:
        raise ParseError(f"{o.path}.doc: {doc_id!r} is not in sources.yml documents")
    return Citation(doc=doc_id, title=doc.title, url=doc.url, table=o.opt_str("table"),
                    section=o.opt_str("section"), locator=o.opt_str("locator"), verified=verified)


def _doc_cite(doc_id: str, documents: dict[str, DocumentSpec], where: str) -> Citation:
    doc = documents.get(doc_id)
    if doc is None:
        raise ParseError(f"{where}: {doc_id!r} is not in sources.yml documents")
    return Citation(doc=doc_id, title=doc.title, url=doc.url, verified=True)


def _level(o: Obj, key: str) -> NistLevel:
    v = o.get_int(key)
    try:
        return NistLevel(v)
    except ValueError as e:
        raise ParseError(f"{o.path}.{key}: {v} is not a NIST level 0..5") from e


def _prim(o: Obj) -> Primitive:
    try:
        return Primitive(o.get_str("primitive"))
    except ValueError as e:
        raise ParseError(f"{o.path}.primitive: {e}") from e


def load_curated(path: Path = CURATED, documents: dict[str, DocumentSpec] | None = None) -> CuratedNist:
    docs = documents if documents is not None else load_sources().documents
    root = Obj(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
    unverified: list[str] = []

    def table(name: str) -> tuple[list[Obj], Citation]:
        block = root.get_obj(name)
        verified = block.get_bool("verified", False)
        if not verified:
            unverified.append(name)
        return block.objs("rows"), resolve_cite(block.get_obj("cite"), docs, verified)

    rows, cite = table("security_categories")
    cats = tuple(SecurityCategory(category=_level(r, "category"), attack=r.get_str("attack"),
                                  example=r.get_str("example"), cite=cite) for r in rows)

    qv: list[QuantumVulnerable] = []
    for name in ("quantum_vulnerable_signatures", "quantum_vulnerable_key_establishment"):
        rows, cite = table(name)
        qv += [QuantumVulnerable(
            family=r.get_str("family"), registry_families=tuple(r.strs("registry_families")),
            primitive=_prim(r), standard=r.opt_str("standard"), note=r.opt_str("note"),
            min_classical_bits=r.get_int("min_classical_bits"), deprecated_after=r.opt_int("deprecated_after"),
            disallowed_after=r.opt_int("disallowed_after"), nist_level=_level(r, "nist_quantum_level"), cite=cite,
        ) for r in rows]

    sym: list[SymmetricLevel] = []
    for name in ("block_ciphers", "aead"):
        rows, cite = table(name)
        sym += [SymmetricLevel(
            algorithm=r.get_str("algorithm"), family=r.get_str("family"), primitive=_prim(r),
            standard=r.opt_str("standard"), classical_bits=r.get_int("classical_bits"),
            nist_level=_level(r, "nist_quantum_level"), cite=cite,
        ) for r in rows]

    rows, cite = table("hash_functions")
    hashes = tuple(HashLevel(
        algorithm=r.get_str("algorithm"), family=r.get_str("family"), primitive=_prim(r),
        standard=r.opt_str("standard"), collision_bits=r.opt_int("collision_bits"),
        collision_level=_level(r, "collision_level"), preimage_bits=r.get_int("preimage_bits"),
        preimage_level=_level(r, "preimage_level"), note=r.opt_str("note"), cite=cite,
    ) for r in rows)

    rows, cite = table("classical_strength")
    strength = tuple(StrengthRow(
        bits=r.get_int("bits"), symmetric=r.get_str("symmetric"), ffc_l=r.get_int("ffc_L"),
        ffc_n=r.get_int("ffc_N"), ifc_k=r.get_int("ifc_k"), ecc_f_min=r.get_int("ecc_f_min"),
        ecc_f_max=r.opt_int("ecc_f_max"), cite=cite,
    ) for r in rows)

    rows, cite = table("named_curves")
    curves = tuple(NamedCurveStrength(
        curve=r.get_str("curve"), bits=r.get_int("bits"), aliases=tuple(r.strs("aliases")), cite=cite,
        aliases_cite=_doc_cite(ac, docs, f"{r.path}.aliases_cite") if (ac := r.opt_str("aliases_cite")) else None,
    ) for r in rows)

    return CuratedNist(security_categories=cats, quantum_vulnerable=tuple(qv), symmetric=tuple(sym),
                       hashes=hashes, classical_strength=strength, named_curves=curves,
                       unverified_tables=tuple(unverified))


def _strength(rows: tuple[StrengthRow, ...], size: int, key: str) -> StrengthRow | None:
    best: StrengthRow | None = None
    for r in sorted(rows, key=lambda r: r.bits):
        threshold = {"ifc": r.ifc_k, "ffc": r.ffc_l, "ecc": r.ecc_f_min}[key]
        if size >= threshold:
            best = r
    return best


def strength_for_rsa(rows: tuple[StrengthRow, ...], modulus_bits: int) -> StrengthRow | None:
    return _strength(rows, modulus_bits, "ifc")


def strength_for_ffc(rows: tuple[StrengthRow, ...], l_bits: int) -> StrengthRow | None:
    return _strength(rows, l_bits, "ffc")


def strength_for_ecc(rows: tuple[StrengthRow, ...], order_bits: int) -> StrengthRow | None:
    return _strength(rows, order_bits, "ecc")


def run() -> list[str]:
    c = load_curated()
    records: list[object] = [*c.security_categories, *c.quantum_vulnerable, *c.symmetric,
                             *c.hashes, *c.classical_strength, *c.named_curves]
    docs = load_sources().documents
    used = sorted({d for d in ("nist-ir-8547", "nist-sp-800-57pt1r5", "nist-sp-800-186") if d in docs})
    out = write_output("nist_curated", records, [docs[d] for d in used])
    return [f"{out.name}: {len(records)} rows"] + [f"  warn: {t}: not yet verified against the PDF"
                                                   for t in c.unverified_tables]
