"""Merge tests on a small typed fixture, plus a smoke test on fetched data."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from parsers._input import Oid
from parsers.cyclonedx_registry import parse_registry
from parsers.models import LiboqsParameterSet, NistLevel, OpenSslObject, OqsAlgorithm, OqsKind, Primitive, Ref
from parsers.nist_curated import load_curated
from parsers.oid_arcs import load_rules
from registry.merge import Inputs, MergeResult, merge
from registry.models import Composition, ExcludeReason, Field, Inclusion, Record, RecordType

from .test_parsers import DOCS

REF = Ref(url="https://example.test/src")

REGISTRY = {
    "algorithms": [
        {"family": "AES", "standard": [], "variant": [
            {"pattern": "AES[-(128|192|256)][-(ECB|CBC|CTR)]", "primitive": "block-cipher"},
            {"pattern": "AES[-(128|192|256)][-(GCM|CCM)][-{tagLength}]", "primitive": "ae"}]},
        {"family": "ChaCha20", "standard": [], "variant": [{"pattern": "ChaCha20-Poly1305", "primitive": "ae"}]},
    ],
    "ellipticCurves": [
        {"name": "nist", "curves": [{"name": "P-256", "oid": "1.2.840.10045.3.1.7", "form": "Weierstrass",
                                     "aliases": [{"category": "secg", "name": "secp256r1"}]}]},
        {"name": "secg", "curves": [{"name": "secp256r1", "oid": "1.2.840.10045.3.1.7", "form": "Weierstrass"}]},
        {"name": "other", "curves": [{"name": "Curve25519", "oid": None, "form": "Montgomery"}]},
    ],
}


def obj(oid: str | None, sn: str, ln: str | None = None) -> OpenSslObject:
    return OpenSslObject(oid=Oid(oid) if oid else None, short_name=sn, long_name=ln or sn, c_name=None,
                         module=None, line=1, ref=Ref(url="https://example.test/objects.txt#L1"))


def oqs(name: str | None, kind: OqsKind, prim: Primitive, oqs_id: str, pq: str, *, oid: str | None = None,
        classical: str | None = None, default_ecp: bool = False, enabled: bool = True,
        standard_name: str | None = None) -> OqsAlgorithm:
    return OqsAlgorithm(
        name=name, kind=kind, family="ML-KEM" if prim is Primitive.KEM else "ML-DSA", primitive=prim,
        oqs_id=oqs_id, pq_name=pq, classical_name=classical, default_ecp_hybrid=default_ecp, pretty_name=None,
        standard_name=standard_name, oid=Oid(oid) if oid else None, tls_codepoint=513, iana=None,
        enabled=enabled, enabled_tls=True, experimental_oid=bool(oid and oid.startswith("1.3.9999.")),
        openssl_version=None, ref=REF)


def ps(name: str, prim: Primitive, level: NistLevel, oqs_id: str) -> LiboqsParameterSet:
    return LiboqsParameterSet(name=name, family=name.rsplit("-", 1)[0], primitive=prim, nist_level=level,
                              crypto_functions=(), platforms=(), oqs_id=oqs_id, ref=REF)


@pytest.fixture(scope="module")
def result() -> MergeResult:
    inputs = Inputs(
        openssl=(
            obj("2.16.840.1.101.3.4.4.2", "id-alg-ml-kem-768"),
            obj("1.2.840.113549.1.1.11", "RSA-SHA256", "sha256WithRSAEncryption"),
            obj("1.2.840.113549.1.1.1", "rsaEncryption"),
            obj("1.2.840.113549.1.1.8", "MGF1", "mgf1"),
            obj("1.3.101.110", "X25519"),
            obj("2.16.840.1.101.3.4.2.1", "SHA256", "sha256"),
            obj("2.16.840.1.101.3.4.1.6", "id-aes128-GCM", "aes-128-gcm"),
            obj("2.16.840.1.101.3.4.1.45", "id-aes256-wrap"),
            obj("1.2.840.10045.3.1.7", "prime256v1"),
            obj(None, "ChaCha20-Poly1305", "chacha20-poly1305"),
            obj("2.5.4.3", "CN", "commonName"),
        ),
        oqs=(
            oqs("mlkem768", OqsKind.PURE, Primitive.KEM, "OQS_KEM_alg_ml_kem_768", "mlkem768",
                oid="2.16.840.1.101.3.4.4.2"),
            oqs("x25519_mlkem768", OqsKind.HYBRID, Primitive.KEM, "OQS_KEM_alg_ml_kem_768", "mlkem768",
                classical="x25519", standard_name="X25519MLKEM768"),
            oqs(None, OqsKind.HYBRID, Primitive.KEM, "OQS_KEM_alg_ml_kem_768", "mlkem768", default_ecp=True),
            oqs("mldsa44", OqsKind.PURE, Primitive.SIGNATURE, "OQS_SIG_alg_ml_dsa_44", "mldsa44"),
            oqs("rsa3072_mldsa44", OqsKind.COMPOSITE, Primitive.SIGNATURE, "OQS_SIG_alg_ml_dsa_44", "mldsa44",
                classical="rsa3072", oid="1.3.9999.7.2"),
            oqs("kyber90s512", OqsKind.PURE, Primitive.KEM, "OQS_KEM_alg_kyber_512_90s", "kyber90s512",
                enabled=False),
        ),
        liboqs=(
            ps("ML-KEM-768", Primitive.KEM, NistLevel.L3, "OQS_KEM_alg_ml_kem_768"),
            # Disagrees with oqs-provider on purpose: must become a conflict, liboqs wins.
            ps("ML-DSA-44", Primitive.KEM, NistLevel.L2, "OQS_SIG_alg_ml_dsa_44"),
            ps("HQC-128", Primitive.KEM, NistLevel.L1, "OQS_KEM_alg_hqc_128"),
        ),
        registry=parse_registry(json.dumps(REGISTRY), REF),
        nist=load_curated(documents=DOCS),
        oid_rules=load_rules(documents=DOCS),
    )
    return merge(inputs)


def find(result: MergeResult, name: str) -> Record:
    hits = [r for r in result.records if r.name == name or name in r.aliases]
    assert len(hits) == 1, f"{name}: {len(hits)} matches"
    return hits[0]


def test_pqc_join_and_openssl_alias(result: MergeResult) -> None:
    r = find(result, "ML-KEM-768")
    assert r.oid == "2.16.840.1.101.3.4.4.2" and r.nist_quantum_security_level is NistLevel.L3
    assert {"mlkem768", "id-alg-ml-kem-768", "OQS_KEM_alg_ml_kem_768"} <= r.aliases
    assert {Inclusion.OQS_PROVIDER, Inclusion.LIBOQS, Inclusion.OPENSSL_PQC_OID} <= r.included_by
    assert len(r.refs[Field.OID]) == 2  # oqs-provider and objects.txt agree


def test_liboqs_only_and_skipped(result: MergeResult) -> None:
    assert find(result, "HQC-128").oid is None
    assert "kyber90s512" in result.skipped_pqc


def test_hybrid_and_default_ecp(result: MergeResult) -> None:
    h = find(result, "X25519MLKEM768")
    assert h.composition is Composition.HYBRID and h.nist_quantum_security_level is NistLevel.L3
    classical = h.components[0]
    assert classical.curve == "Curve25519" and classical.classical_security_level == 128
    assert classical.nist_quantum_security_level is NistLevel.L0
    assert find(result, "p384_mlkem768").composition is Composition.HYBRID  # level 3 -> p384


def test_composite_rsa_strength(result: MergeResult) -> None:
    c = find(result, "rsa3072_mldsa44")
    assert c.experimental_oid and c.components[0].classical_security_level == 128


def test_conflict_recorded_first_source_wins(result: MergeResult) -> None:
    r = find(result, "ML-DSA-44")
    assert r.primitive is Primitive.KEM  # liboqs applied first
    assert any(c.record_id == r.id and c.field is Field.PRIMITIVE for c in result.conflicts)


def test_classical_oid_rules_and_quantum_level(result: MergeResult) -> None:
    rsa = find(result, "RSA-SHA256")
    assert rsa.family == "RSASSA-PKCS1" and rsa.primitive is Primitive.SIGNATURE
    assert rsa.nist_quantum_security_level is NistLevel.L0
    assert rsa.refs[Field.NIST_LEVEL][0].locator == "Table 2, §4.1.1"
    key = find(result, "rsaEncryption")
    assert key.family == "RSA" and key.primitive is None and key.nist_quantum_security_level is NistLevel.L0
    x = find(result, "X25519")
    assert x.curve == "Curve25519" and x.classical_security_level == 128


def test_hash_and_aes_levels(result: MergeResult) -> None:
    sha = find(result, "SHA-256")
    assert sha.oid == "2.16.840.1.101.3.4.2.1" and sha.nist_quantum_security_level is NistLevel.L2
    assert sha.hash_strength is not None and sha.hash_strength.preimage_bits == 256
    gcm = find(result, "id-aes128-GCM")
    assert gcm.primitive is Primitive.AE and gcm.nist_quantum_security_level is NistLevel.L1
    wrap = find(result, "id-aes256-wrap")
    assert wrap.primitive is Primitive.KEY_WRAP and wrap.classical_security_level == 256
    assert find(result, "AES-192").oid is None  # standalone curated record


def test_curves_merge_without_false_conflicts(result: MergeResult) -> None:
    p = find(result, "P-256")
    assert p.record_type is RecordType.CURVE and {"prime256v1", "secp256r1"} <= p.aliases
    assert p.classical_security_level == 128
    assert not [c for c in result.conflicts if c.field is Field.CURVE]


def test_exclusions(result: MergeResult) -> None:
    reasons = {e.short_name: e.reason for e in result.excluded}
    assert reasons == {"MGF1": ExcludeReason.EXCLUDE_RULE, "CN": ExcludeReason.NO_MATCH}
    assert find(result, "ChaCha20-Poly1305").included_by == {Inclusion.OPENSSL_NAME}


# --- smoke test on real data ---------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(not (ROOT / "data" / "raw" / "manifest.json").exists(), reason="run fetch.py first")
def test_real_data_merges_cleanly() -> None:
    from parsers import cyclonedx_registry, liboqs, oid_arcs, openssl_objects, oqs_provider

    res = merge(Inputs(
        openssl=openssl_objects.load().objects, oqs=tuple(oqs_provider.load()), liboqs=tuple(liboqs.load()[0]),
        registry=cyclonedx_registry.load(), nist=load_curated(), oid_rules=oid_arcs.load_rules(),
    ))
    assert not res.conflicts, res.conflicts[:5]
    ids = {r.id for r in res.records}
    assert len(ids) == len(res.records)
    for name in ("ML-KEM-768", "X25519MLKEM768", "RSA-SHA256", "SHA-256", "P-256", "ED25519"):
        find(res, name)
