"""Typed records produced by each parser.

All dataclasses are frozen: a parser builds them once and nothing mutates them.
Closed sets of values are enums, so a typo or an unexpected upstream value
fails at parse time instead of flowing into the output.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum

from ._input import Oid


class Primitive(StrEnum):
    """CycloneDX algorithmProperties.primitive (1.6, plus key-wrap from the 1.7 registry)."""

    DRBG = "drbg"
    MAC = "mac"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    SIGNATURE = "signature"
    HASH = "hash"
    PKE = "pke"
    XOF = "xof"
    KDF = "kdf"
    KEY_AGREE = "key-agree"
    KEM = "kem"
    AE = "ae"
    COMBINER = "combiner"
    KEY_WRAP = "key-wrap"
    OTHER = "other"
    UNKNOWN = "unknown"


class NistLevel(IntEnum):
    """NIST PQC security category. 0 = none of the categories are met (CycloneDX definition)."""

    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4
    L5 = 5


class OqsKind(StrEnum):
    PURE = "pure"
    HYBRID = "hybrid"          # KEM + classical key exchange group
    COMPOSITE = "composite"    # signature + classical signature


@dataclass(frozen=True, slots=True, kw_only=True)
class Ref:
    """Where a value came from: a permalink, or a document URL plus table/section."""

    url: str
    locator: str | None = None


# --- openssl objects.txt ------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class OpenSslObject:
    oid: Oid | None
    short_name: str
    long_name: str
    c_name: str | None
    module: str | None
    line: int
    ref: Ref


# --- oqs-provider generate.yml ------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class OqsAlgorithm:
    # None only for default ECP hybrids, whose curve depends on the NIST level.
    name: str | None
    kind: OqsKind
    family: str
    primitive: Primitive
    oqs_id: str
    pq_name: str                     # name of the PQ part (== name for pure)
    classical_name: str | None       # hybrid group / composite partner
    default_ecp_hybrid: bool
    pretty_name: str | None
    standard_name: str | None
    oid: Oid | None
    tls_codepoint: int | None
    iana: bool | None
    enabled: bool
    enabled_tls: bool
    experimental_oid: bool
    openssl_version: str | None
    ref: Ref


# --- liboqs cbom.json + headers -------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class LiboqsParameterSet:
    name: str
    family: str
    primitive: Primitive
    nist_level: NistLevel
    crypto_functions: tuple[str, ...]
    platforms: tuple[str, ...]
    oqs_id: str | None
    ref: Ref


# --- CycloneDX cryptography registry -------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class Standard:
    name: str
    url: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryVariant:
    family: str
    primitive: Primitive
    pattern: str
    regex: str
    standards: tuple[Standard, ...]
    ref: Ref


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryCurve:
    name: str
    group: str
    oid: Oid | None
    form: str | None
    aliases: tuple[str, ...]
    ref: Ref
