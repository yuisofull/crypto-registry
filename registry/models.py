"""Types of the merged registry.

JSON keys: fields that exist in CycloneDX algorithmProperties use its camelCase
names (parameterSetIdentifier, classicalSecurityLevel, nistQuantumSecurityLevel),
so a record maps to a CBOM component by copying fields. Registry-only fields
stay snake_case.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from parsers._input import Oid
from parsers.models import NistLevel, Primitive, Ref


class RecordType(StrEnum):
    ALGORITHM = "algorithm"
    CURVE = "curve"


class Composition(StrEnum):
    SINGLE = "single"
    HYBRID = "hybrid"          # PQ KEM + classical key exchange
    COMPOSITE = "composite"    # PQ signature + classical signature


class Inclusion(StrEnum):
    """Why a record is in the registry."""

    OQS_PROVIDER = "oqs-provider"
    LIBOQS = "liboqs"
    OPENSSL_PQC_OID = "openssl:pqc-oid"       # OpenSSL object with an OID already known from PQC sources
    OPENSSL_ARC = "openssl:oid-arc"           # matched a rule in curated/oid_arcs.yml
    OPENSSL_CURVE_OID = "openssl:curve-oid"   # OID is a CycloneDX curve OID
    OPENSSL_NAME = "openssl:registry-name"    # a name matched a CycloneDX registry pattern
    CYCLONEDX_CURVE = "cyclonedx:curve"
    NIST_CURATED = "nist-curated"


class Field(StrEnum):
    """Record fields that carry provenance in `refs`. Values are the JSON key names."""

    NAME = "name"
    OID = "oid"
    FAMILY = "family"
    PRIMITIVE = "primitive"
    PARAMETER_SET = "parameterSetIdentifier"
    CURVE = "curve"
    CLASSICAL_LEVEL = "classicalSecurityLevel"
    NIST_LEVEL = "nistQuantumSecurityLevel"
    TLS_CODEPOINT = "tls_codepoint"
    COMPONENTS = "components"


class ComponentRole(StrEnum):
    CLASSICAL = "classical"
    POST_QUANTUM = "post-quantum"


@dataclass(slots=True, kw_only=True)
class Component:
    name: str
    role: ComponentRole
    family: str | None
    curve: str | None
    classical_security_level: int | None = field(default=None, metadata={"json": "classicalSecurityLevel"})
    nist_quantum_security_level: NistLevel | None = field(default=None, metadata={"json": "nistQuantumSecurityLevel"})


@dataclass(frozen=True, slots=True, kw_only=True)
class HashStrength:
    collision_bits: int | None
    collision_level: NistLevel
    preimage_bits: int
    preimage_level: NistLevel


@dataclass(slots=True, kw_only=True)
class Record:
    id: str
    name: str
    record_type: RecordType
    composition: Composition | None
    family: str | None = None
    oid: Oid | None = None
    primitive: Primitive | None = None
    parameter_set_identifier: str | None = field(default=None, metadata={"json": "parameterSetIdentifier"})
    curve: str | None = None
    classical_security_level: int | None = field(default=None, metadata={"json": "classicalSecurityLevel"})
    nist_quantum_security_level: NistLevel | None = field(default=None, metadata={"json": "nistQuantumSecurityLevel"})
    aliases: set[str] = field(default_factory=set)
    tls_codepoint: int | None = None
    components: list[Component] = field(default_factory=list)
    hash_strength: HashStrength | None = None
    experimental_oid: bool = False
    included_by: set[Inclusion] = field(default_factory=set)
    refs: dict[Field, list[Ref]] = field(default_factory=dict)

    def add_ref(self, f: Field, ref: Ref) -> None:
        lst = self.refs.setdefault(f, [])
        if ref not in lst:
            lst.append(ref)

    def all_names(self) -> list[str]:
        return [self.name, *sorted(self.aliases)]


@dataclass(frozen=True, slots=True, kw_only=True)
class Conflict:
    """Two sources disagreed on a field. The value from the earlier (higher-precedence) source was kept."""

    record_id: str
    field: Field
    kept: str
    rejected: str
    rejected_ref: Ref


class ExcludeReason(StrEnum):
    EXCLUDE_RULE = "exclude-rule"     # curated/oid_arcs.yml marks it as a parameter, not an algorithm
    NO_MATCH = "no-match"             # no rule, not a curve OID, no registry name match


@dataclass(frozen=True, slots=True, kw_only=True)
class Excluded:
    short_name: str
    long_name: str
    oid: Oid | None
    reason: ExcludeReason
    ref: Ref
