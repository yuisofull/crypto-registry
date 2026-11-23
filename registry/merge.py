"""Join the parsed sources into one registry.

Order (earlier steps win a field when sources disagree; the loser goes to `conflicts`):
  1. PQC: oqs-provider pure algorithms joined to liboqs on `oqs_id`, then liboqs-only sets
  2. oqs-provider hybrids (KEM) and composites (signature)
  3. OpenSSL objects: kept by curated/oid_arcs.yml rule, curve OID or registry name match
  4. CycloneDX curves
  5. Curated NIST: named-curve strengths, hash/symmetric levels, quantum-vulnerable families
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from parsers._common import match_key
from parsers._input import Oid
from parsers.cyclonedx_registry import Registry, classify
from parsers.models import (LiboqsParameterSet, OpenSslObject, OqsAlgorithm, OqsKind, Primitive, Ref,
                            RegistryVariant)
from parsers.nist_curated import Citation, CuratedNist, NamedCurveStrength, QuantumVulnerable, strength_for_rsa
from parsers.oid_arcs import OidRule, match_rule
from parsers.oqs_provider import default_ecp_curve

from .models import (Component, ComponentRole, Composition, Conflict, Excluded, ExcludeReason, Field, HashStrength,
                     Inclusion, Record, RecordType)


@dataclass(frozen=True, slots=True, kw_only=True)
class Inputs:
    openssl: tuple[OpenSslObject, ...]
    oqs: tuple[OqsAlgorithm, ...]
    liboqs: tuple[LiboqsParameterSet, ...]
    registry: Registry
    nist: CuratedNist
    oid_rules: tuple[OidRule, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class MergeResult:
    records: tuple[Record, ...]
    conflicts: tuple[Conflict, ...]
    excluded: tuple[Excluded, ...]
    skipped_pqc: tuple[str, ...]   # oqs-provider entries dropped: disabled and unknown to liboqs


def cite_ref(c: Citation) -> Ref:
    return Ref(url=c.url, locator=c.where or None)


_RSA_SIZE = re.compile(r"^rsa(?:pss)?(\d{3,5})$")


class Merger:
    def __init__(self, inp: Inputs) -> None:
        self.inp = inp
        self.records: dict[str, Record] = {}
        self.by_oid: dict[Oid, str] = {}
        self.by_key: dict[str, str] = {}
        self.conflicts: list[Conflict] = []
        self.excluded: list[Excluded] = []
        self.skipped_pqc: list[str] = []
        self.pq_by_oqs_id: dict[str, Record] = {}

        self.curve_by_key: dict[str, NamedCurveStrength] = {}
        for nc in inp.nist.named_curves:
            for n in (nc.curve, *nc.aliases):
                self.curve_by_key[match_key(n)] = nc

        self.vulnerable_by_family: dict[str, QuantumVulnerable] = {}
        for row in inp.nist.quantum_vulnerable:
            for fam in row.registry_families:
                if fam in self.vulnerable_by_family:
                    raise ValueError(f"family {fam!r} listed in two quantum-vulnerable rows")
                self.vulnerable_by_family[fam] = row

    # --- record store -----------------------------------------------------------------
    def get_or_create(self, *, name: str, oid: Oid | None, record_type: RecordType,
                      composition: Composition | None) -> Record:
        if oid is not None and oid in self.by_oid:
            return self.records[self.by_oid[oid]]
        name_key = f"{record_type.value}:{match_key(name)}"
        if oid is None and name_key in self.by_key:
            return self.records[self.by_key[name_key]]
        rid = f"oid:{oid}" if oid else name_key
        rec = Record(id=rid, name=name, record_type=record_type, composition=composition, oid=oid)
        self.records[rid] = rec
        if oid:
            self.by_oid[oid] = rid
        else:
            self.by_key[name_key] = rid
        return rec

    def resolve[T](self, rec: Record, f: Field, current: T | None, new: T | None, ref: Ref) -> T | None:
        """Keep the first value set for a field; record disagreements as conflicts."""
        if new is None:
            return current
        if current is None or current == new:
            rec.add_ref(f, ref)
            return new if current is None else current
        self.conflicts.append(Conflict(record_id=rec.id, field=f, kept=str(current), rejected=str(new),
                                       rejected_ref=ref))
        return current

    def alias_index(self) -> dict[str, list[Record]]:
        idx: dict[str, list[Record]] = {}
        for rec in self.records.values():
            for n in rec.all_names():
                lst = idx.setdefault(match_key(n), [])
                if rec not in lst:
                    lst.append(rec)
        return idx

    # --- 1. PQC -----------------------------------------------------------------------
    def add_pqc(self) -> None:
        by_id = {p.oqs_id: p for p in self.inp.liboqs if p.oqs_id}
        joined: set[str] = set()
        for a in self.inp.oqs:
            if a.kind is not OqsKind.PURE:
                continue
            ps = by_id.get(a.oqs_id)
            if ps is None and not a.enabled:
                self.skipped_pqc.append(a.pq_name)
                continue
            rec = self.get_or_create(name=ps.name if ps else (a.pretty_name or a.pq_name), oid=a.oid,
                                     record_type=RecordType.ALGORITHM, composition=Composition.SINGLE)
            rec.included_by.add(Inclusion.OQS_PROVIDER)
            rec.aliases.update(n for n in (a.pq_name, a.pretty_name, a.oqs_id) if n)
            rec.family = self.resolve(rec, Field.FAMILY, rec.family, a.family, a.ref)
            if ps:
                joined.add(a.oqs_id)
                self._apply_liboqs(rec, ps)
            rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, a.primitive, a.ref)
            if a.oid:
                rec.add_ref(Field.OID, a.ref)
            rec.tls_codepoint = self.resolve(rec, Field.TLS_CODEPOINT, rec.tls_codepoint, a.tls_codepoint, a.ref)
            rec.experimental_oid = rec.experimental_oid or a.experimental_oid
            self.pq_by_oqs_id[a.oqs_id] = rec

        for ps in self.inp.liboqs:
            if ps.oqs_id in joined:
                continue
            rec = self.get_or_create(name=ps.name, oid=None, record_type=RecordType.ALGORITHM,
                                     composition=Composition.SINGLE)
            rec.family = self.resolve(rec, Field.FAMILY, rec.family, ps.family, ps.ref)
            self._apply_liboqs(rec, ps)
            if ps.oqs_id:
                rec.aliases.add(ps.oqs_id)
                self.pq_by_oqs_id[ps.oqs_id] = rec

    def _apply_liboqs(self, rec: Record, ps: LiboqsParameterSet) -> None:
        rec.included_by.add(Inclusion.LIBOQS)
        rec.aliases.add(ps.name)
        rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, ps.primitive, ps.ref)
        rec.nist_quantum_security_level = self.resolve(rec, Field.NIST_LEVEL, rec.nist_quantum_security_level,
                                                       ps.nist_level, ps.ref)
        rec.parameter_set_identifier = self.resolve(rec, Field.PARAMETER_SET, rec.parameter_set_identifier,
                                                    ps.name, ps.ref)

    # --- 2. hybrids / composites ---------------------------------------------------------
    def add_hybrids(self) -> None:
        for a in self.inp.oqs:
            if a.kind is OqsKind.PURE:
                continue
            pq = self.pq_by_oqs_id.get(a.oqs_id)
            if pq is None:
                self.skipped_pqc.append(a.name or f"default-ecp_{a.pq_name}")
                continue
            classical = a.classical_name
            if a.default_ecp_hybrid:
                lvl = pq.nist_quantum_security_level
                classical = default_ecp_curve(lvl) if lvl is not None else None
            if classical is None:
                self.skipped_pqc.append(a.name or f"default-ecp_{a.pq_name}")
                continue
            comp = Composition.HYBRID if a.kind is OqsKind.HYBRID else Composition.COMPOSITE
            rec = self.get_or_create(name=a.name or f"{classical}_{a.pq_name}", oid=a.oid,
                                     record_type=RecordType.ALGORITHM, composition=comp)
            rec.included_by.add(Inclusion.OQS_PROVIDER)
            rec.aliases.update(n for n in (a.standard_name, a.pretty_name) if n)
            rec.family = self.resolve(rec, Field.FAMILY, rec.family, a.family, a.ref)
            rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, a.primitive, a.ref)
            if a.oid:
                rec.add_ref(Field.OID, a.ref)
            rec.tls_codepoint = self.resolve(rec, Field.TLS_CODEPOINT, rec.tls_codepoint, a.tls_codepoint, a.ref)
            rec.experimental_oid = rec.experimental_oid or a.experimental_oid
            # The hybrid is as quantum-safe as its PQ part.
            for ref in pq.refs.get(Field.NIST_LEVEL, []):
                rec.nist_quantum_security_level = self.resolve(
                    rec, Field.NIST_LEVEL, rec.nist_quantum_security_level, pq.nist_quantum_security_level, ref)
            rec.components = [
                self.classical_component(classical, comp),
                Component(name=pq.name, role=ComponentRole.POST_QUANTUM, family=pq.family, curve=None,
                          nist_quantum_security_level=pq.nist_quantum_security_level),
            ]
            rec.add_ref(Field.COMPONENTS, a.ref)

    def classical_component(self, name: str, comp: Composition) -> Component:
        n = name.lower()
        family: str
        bits: int | None = None
        curve: str | None = None
        m = _RSA_SIZE.match(n)
        if n.startswith("rsa"):
            family = "RSA"
            row = strength_for_rsa(self.inp.nist.classical_strength, int(m.group(1))) if m else None
            bits = row.bits if row else None
        else:
            if comp is Composition.HYBRID:
                family = "ECDH"
            elif n.startswith("ed"):
                family = "EdDSA"
            else:
                family = "ECDSA"
            nc = self.curve_by_key.get(match_key(name))
            if nc:
                curve, bits = nc.curve, nc.bits
        vuln = self.vulnerable_by_family.get(family)
        return Component(name=name, role=ComponentRole.CLASSICAL, family=family, curve=curve,
                         classical_security_level=bits, nist_quantum_security_level=vuln.nist_level if vuln else None)

    # --- 3. OpenSSL objects -------------------------------------------------------------
    def registry_primitive(self, family: str, names: list[str]) -> tuple[Primitive, Ref] | None:
        variants: list[RegistryVariant] = [v for v in self.inp.registry.algorithms if v.family == family]
        for n in names:
            hits = classify(n, variants)
            if hits:
                return hits[0].primitive, hits[0].ref
        prims = {v.primitive for v in variants}
        if len(prims) == 1:
            return variants[0].primitive, variants[0].ref
        return None

    def add_openssl(self) -> None:
        curve_oids = {c.oid for c in self.inp.registry.curves if c.oid}
        for o in self.inp.openssl:
            names = [o.short_name, o.long_name]
            rule = match_rule(self.inp.oid_rules, o.oid) if o.oid else None

            if o.oid and o.oid in self.by_oid:  # already known from PQC sources
                rec = self.records[self.by_oid[o.oid]]
                rec.aliases.update(names)
                rec.included_by.add(Inclusion.OPENSSL_PQC_OID)
                rec.add_ref(Field.OID, o.ref)
                if rule and rule.family and not rule.key_type:
                    rec.family = self.resolve(rec, Field.FAMILY, rec.family, rule.family, cite_ref(rule.cite))
                    rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, rule.primitive,
                                                 cite_ref(rule.cite))
                continue

            if rule and rule.exclude:
                self.excluded.append(Excluded(short_name=o.short_name, long_name=o.long_name, oid=o.oid,
                                              reason=ExcludeReason.EXCLUDE_RULE, ref=o.ref))
                continue

            if (rule and rule.curve) or (o.oid and o.oid in curve_oids):
                rec = self.get_or_create(name=o.short_name, oid=o.oid, record_type=RecordType.CURVE,
                                         composition=None)
                rec.aliases.add(o.long_name)
                rec.included_by.add(Inclusion.OPENSSL_ARC if rule else Inclusion.OPENSSL_CURVE_OID)
                rec.add_ref(Field.OID, o.ref)
                continue

            if rule:
                rec = self.get_or_create(name=o.short_name, oid=o.oid, record_type=RecordType.ALGORITHM,
                                         composition=Composition.SINGLE)
                rec.aliases.add(o.long_name)
                rec.included_by.add(Inclusion.OPENSSL_ARC)
                rec.add_ref(Field.OID, o.ref)
                rec.family = self.resolve(rec, Field.FAMILY, rec.family, rule.family, cite_ref(rule.cite))
                if rule.primitive:
                    rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, rule.primitive,
                                                 cite_ref(rule.cite))
                elif rule.family and not rule.key_type:
                    found = self.registry_primitive(rule.family, names)
                    if found:
                        rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, found[0], found[1])
                continue

            hits = classify(o.short_name, self.inp.registry.algorithms) or classify(
                o.long_name, self.inp.registry.algorithms)
            if hits:
                best = hits[0]
                rec = self.get_or_create(name=o.short_name, oid=o.oid, record_type=RecordType.ALGORITHM,
                                         composition=Composition.SINGLE)
                rec.aliases.add(o.long_name)
                rec.included_by.add(Inclusion.OPENSSL_NAME)
                if o.oid:
                    rec.add_ref(Field.OID, o.ref)
                else:
                    rec.add_ref(Field.NAME, o.ref)
                rec.family = self.resolve(rec, Field.FAMILY, rec.family, best.family, best.ref)
                rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, best.primitive, best.ref)
                continue

            self.excluded.append(Excluded(short_name=o.short_name, long_name=o.long_name, oid=o.oid,
                                          reason=ExcludeReason.NO_MATCH, ref=o.ref))

    # --- 4. CycloneDX curves ------------------------------------------------------------
    def add_curves(self) -> None:
        for c in self.inp.registry.curves:
            existing = self.records[self.by_oid[c.oid]] if c.oid and c.oid in self.by_oid else None
            if existing is not None and existing.record_type is RecordType.ALGORITHM:
                # Same OID names an algorithm and a curve (SM2): keep the algorithm, note its curve.
                existing.curve = self.resolve(existing, Field.CURVE, existing.curve, c.name, c.ref)
                existing.included_by.add(Inclusion.CYCLONEDX_CURVE)
                continue
            rec = existing or self.get_or_create(name=c.name, oid=c.oid, record_type=RecordType.CURVE,
                                                 composition=None)
            if rec.curve is not None and rec.curve != c.name:
                # The registry lists one curve under several groups (nist P-256, secg secp256r1,
                # x962 prime256v1) with the same OID. The first group seen (nist) stays canonical.
                rec.aliases.update((c.name, *c.aliases))
                rec.add_ref(Field.NAME, c.ref)
                continue
            if rec.name != c.name:  # registry name is canonical (P-256 over prime256v1)
                rec.aliases.add(rec.name)
                rec.name = c.name
            rec.add_ref(Field.NAME, c.ref)
            rec.aliases.update(c.aliases)
            rec.included_by.add(Inclusion.CYCLONEDX_CURVE)
            rec.curve = self.resolve(rec, Field.CURVE, rec.curve, c.name, c.ref)
            if c.oid:
                rec.add_ref(Field.OID, c.ref)

    # --- 5. curated NIST ------------------------------------------------------------------
    def apply_named_curves(self) -> None:
        idx = self.alias_index()
        for nc in self.inp.nist.named_curves:
            ref = cite_ref(nc.cite)
            seen: set[str] = set()
            for key in {match_key(n) for n in (nc.curve, *nc.aliases)}:
                for rec in idx.get(key, []):
                    if rec.id in seen or rec.composition in (Composition.HYBRID, Composition.COMPOSITE):
                        continue
                    seen.add(rec.id)
                    rec.classical_security_level = self.resolve(rec, Field.CLASSICAL_LEVEL,
                                                                rec.classical_security_level, nc.bits, ref)
                    if rec.record_type is RecordType.ALGORITHM:
                        rec.curve = self.resolve(rec, Field.CURVE, rec.curve, nc.curve,
                                                 cite_ref(nc.aliases_cite) if nc.aliases_cite else ref)

    def apply_hashes(self) -> None:
        idx = self.alias_index()
        for h in self.inp.nist.hashes:
            ref = cite_ref(h.cite)
            targets = [r for r in idx.get(match_key(h.algorithm), [])
                       if r.family == h.family and r.composition is Composition.SINGLE]
            if not targets:
                rec = self.get_or_create(name=h.algorithm, oid=None, record_type=RecordType.ALGORITHM,
                                         composition=Composition.SINGLE)
                rec.family = self.resolve(rec, Field.FAMILY, rec.family, h.family, ref)
                targets = [rec]
            for rec in targets:
                rec.aliases.add(h.algorithm)
                rec.included_by.add(Inclusion.NIST_CURATED)
                rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, h.primitive, ref)
                # For hashes, classicalSecurityLevel / nistQuantumSecurityLevel are the collision values;
                # preimage values are in hash_strength.
                rec.classical_security_level = self.resolve(rec, Field.CLASSICAL_LEVEL,
                                                            rec.classical_security_level, h.collision_bits, ref)
                rec.nist_quantum_security_level = self.resolve(rec, Field.NIST_LEVEL,
                                                               rec.nist_quantum_security_level, h.collision_level, ref)
                rec.hash_strength = HashStrength(collision_bits=h.collision_bits, collision_level=h.collision_level,
                                                 preimage_bits=h.preimage_bits, preimage_level=h.preimage_level)

    def apply_symmetric(self) -> None:
        idx = self.alias_index()
        for s in self.inp.nist.symmetric:
            ref = cite_ref(s.cite)
            key = match_key(s.algorithm)
            exact = [r for r in idx.get(key, []) if r.family == s.family]
            if not exact:
                rec = self.get_or_create(name=s.algorithm, oid=None, record_type=RecordType.ALGORITHM,
                                         composition=Composition.SINGLE)
                rec.family = self.resolve(rec, Field.FAMILY, rec.family, s.family, ref)
                rec.primitive = self.resolve(rec, Field.PRIMITIVE, rec.primitive, s.primitive, ref)
                exact = [rec]
            targets = list(exact)
            if s.primitive is Primitive.BLOCK_CIPHER:
                # Modes of a block cipher (AES-128-GCM, id-aes128-wrap) take the key size's level.
                targets += [r for r in self.records.values()
                            if r.family == s.family and r not in exact
                            and any(key in match_key(n) for n in r.all_names())]
            for rec in targets:
                rec.included_by.add(Inclusion.NIST_CURATED)
                rec.classical_security_level = self.resolve(rec, Field.CLASSICAL_LEVEL,
                                                            rec.classical_security_level, s.classical_bits, ref)
                rec.nist_quantum_security_level = self.resolve(rec, Field.NIST_LEVEL,
                                                               rec.nist_quantum_security_level, s.nist_level, ref)

    def apply_quantum_vulnerable(self) -> None:
        for rec in self.records.values():
            if rec.composition is not Composition.SINGLE or rec.family is None:
                continue
            row = self.vulnerable_by_family.get(rec.family)
            if row:
                rec.nist_quantum_security_level = self.resolve(rec, Field.NIST_LEVEL,
                                                               rec.nist_quantum_security_level, row.nist_level,
                                                               cite_ref(row.cite))

    # --- run ------------------------------------------------------------------------------
    def run(self) -> MergeResult:
        self.add_pqc()
        self.add_hybrids()
        self.add_openssl()
        self.add_curves()
        self.apply_named_curves()
        self.apply_hashes()
        self.apply_symmetric()
        self.apply_quantum_vulnerable()
        for rec in self.records.values():
            rec.aliases.discard(rec.name)
            rec.aliases.discard("")
        records = sorted(self.records.values(),
                         key=lambda r: (r.record_type.value, r.family or "~", r.name.lower()))
        return MergeResult(records=tuple(records), conflicts=tuple(self.conflicts),
                           excluded=tuple(self.excluded), skipped_pqc=tuple(self.skipped_pqc))


def merge(inp: Inputs) -> MergeResult:
    return Merger(inp).run()
