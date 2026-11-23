"""Parser tests on small inline fixtures. Run: python -m pytest -q"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import re
from pathlib import Path

import pytest

from parsers._common import DocumentSpec, match_key
from parsers._errors import ParseError
from parsers._input import Obj, Oid, parse_int_text
from parsers.cyclonedx_registry import classify, parse_registry, pattern_to_regex
from parsers.liboqs import parse_cbom, parse_headers
from parsers.models import NistLevel, OqsKind, Primitive, Ref
from parsers.nist_curated import load_curated, strength_for_ecc, strength_for_rsa
from parsers.oid_arcs import load_rules, match_rule
from parsers.openssl_objects import parse_objects_txt
from parsers.oqs_provider import default_ecp_curve, parse_generate_yml

ROOT = Path(__file__).resolve().parent.parent
REF = Ref(url="https://example.test")
DOCS = {d: DocumentSpec(id=d, title=d, url=f"https://example.test/{d}") for d in (
    "nist-ir-8547", "nist-sp-800-57pt1r5", "nist-sp-800-186", "nist-csor", "rfc8017", "rfc8018",
    "rfc3279", "rfc5758", "rfc8410", "rfc5753", "rfc7748", "rfc8032")}

OBJECTS_TXT = """\
# comment
1 2 840\t\t: ISO-US\t: ISO US Member Body
ISO-US 113549\t: rsadsi\t: RSA Data Security, Inc.
rsadsi 1\t: pkcs
pkcs 1\t\t: pkcs1
!Cname sha256WithRSAEncryption
pkcs1 11\t: RSA-SHA256\t: sha256WithRSAEncryption
ISO-US 10045\t: ansi-X9-62
!module X9-62
!Alias id-fieldType ansi-X9-62 1
X9-62_id-fieldType 1 : prime-field
!global
!Alias holdInstruction\tISO-US 10040 2
holdInstruction 3\t: holdInstructionReject\t: Hold Instruction Reject
pkcs 9 1\t: \t: emailAddress
\t\t: CAST5-ECB\t: cast5-ecb
"""


def test_objects_txt_resolves_names_aliases_and_modules() -> None:
    parsed = parse_objects_txt(OBJECTS_TXT)
    by_sn = {o.short_name: o for o in parsed.objects}
    assert by_sn["RSA-SHA256"].oid == "1.2.840.113549.1.1.11"
    assert by_sn["RSA-SHA256"].long_name == "sha256WithRSAEncryption"
    assert by_sn["prime-field"].oid == "1.2.840.10045.1.1"
    assert by_sn["holdInstructionReject"].oid == "1.2.840.10040.2.3"
    assert by_sn["pkcs"].long_name == "pkcs"                       # no LN -> LN = SN
    assert by_sn["emailAddress"].oid == "1.2.840.113549.1.9.1"     # empty SN -> SN = LN
    assert by_sn["CAST5-ECB"].oid is None
    assert parsed.aliases["X9-62_id-fieldType"] == "1.2.840.10045.1"


def test_objects_txt_undefined_identifier_fails() -> None:
    with pytest.raises(ParseError, match="undefined identifier"):
        parse_objects_txt("nope 1 : X : y\n")


GENERATE_YML = """\
kems:
  - family: ML-KEM
    name_group: mlkem768
    nid: '513'
    oid: 2.16.840.1.101.3.4.4.2
    oqs_alg: OQS_KEM_alg_ml_kem_768
    enable_kem: true
    enable_tls: true
    use_hybrid: true
    nid_hybrid: '0x2f81'
    extra_nids:
      current:
        - hybrid_group: x25519
          nid: '0x11EC'
          standard_name: X25519MLKEM768
      old:
        - implementation_version: x
          nist-round: 3
          nid: '0x2f39'
sigs:
  - family: ML-DSA
    variants:
      - name: mldsa44
        pretty_name: ML-DSA-44
        oqs_meth: OQS_SIG_alg_ml_dsa_44
        oid: 2.16.840.1.101.3.4.3.17
        code_point: '0x0904'
        enable: true
        enable_tls: true
        mix_with: [{'name': 'p256',
                    'pretty_name': 'ECDSA p256',
                    'oid': '1.3.9999.7.5',
                    'code_point': '0xff06'}]
"""


def test_generate_yml_records() -> None:
    algs = parse_generate_yml(GENERATE_YML, REF)
    assert sorted(a.kind.value for a in algs) == ["composite", "hybrid", "hybrid", "pure", "pure"]
    x = next(a for a in algs if a.standard_name == "X25519MLKEM768")
    assert x.name == "x25519_mlkem768" and x.tls_codepoint == 0x11EC and x.classical_name == "x25519"
    default = next(a for a in algs if a.default_ecp_hybrid)
    assert default.tls_codepoint == 0x2F81 and default.name is None
    comp = next(a for a in algs if a.kind is OqsKind.COMPOSITE)
    assert comp.name == "p256_mldsa44" and comp.experimental_oid and comp.pq_name == "mldsa44"
    assert {a.primitive for a in algs} == {Primitive.KEM, Primitive.SIGNATURE}
    assert default_ecp_curve(NistLevel.L3) == "p384"


def test_generate_yml_rejects_wrong_types() -> None:
    bad = GENERATE_YML.replace("enable_kem: true", "enable_kem: 'yes'")
    with pytest.raises(ParseError, match=r"kems\[0\]\.enable_kem: expected bool"):
        parse_generate_yml(bad, REF)


def _cbom(*comps: dict[str, object]) -> str:
    return json.dumps({"components": [{"type": "library", "name": "liboqs"}, *comps]})


def _asset(name: str, ps: str, prim: str, level: int, plat: str, fn: str) -> dict[str, object]:
    return {"type": "cryptographic-asset", "name": name, "bom-ref": f"{ps}:{plat}",
            "cryptoProperties": {"algorithmProperties": {
                "parameterSetIdentifier": ps, "primitive": prim, "nistQuantumSecurityLevel": level,
                "implementationPlatform": plat, "cryptoFunctions": [fn]}}}


def test_cbom_collapses_platforms_and_headers_map_ids() -> None:
    text = _cbom(_asset("UOV", "OV-Is", "signature", 1, "generic", "sign"),
                 _asset("UOV", "OV-Is", "signature", 1, "x86_64", "verify"),
                 {"type": "cryptographic-asset", "name": "aes",
                  "cryptoProperties": {"algorithmProperties": {"primitive": "block-cipher"}}})
    ids = parse_headers(['#define OQS_SIG_alg_uov_ov_Is "OV-Is"\n'])
    recs = parse_cbom(text, REF, ids)
    assert len(recs) == 1
    r = recs[0]
    assert r.platforms == ("generic", "x86_64") and r.crypto_functions == ("sign", "verify")
    assert r.nist_level is NistLevel.L1 and r.oqs_id == "OQS_SIG_alg_uov_ov_Is"


def test_cbom_rejects_unknown_primitive_and_bad_level() -> None:
    with pytest.raises(ParseError):
        parse_cbom(_cbom(_asset("X", "X-1", "teleport", 1, "g", "f")), REF)
    with pytest.raises(ParseError):
        parse_cbom(_cbom(_asset("X", "X-1", "kem", 7, "g", "f")), REF)


@pytest.mark.parametrize("pattern,name,ok", [
    ("ML-KEM-(512|768|1024)", "ML-KEM-768", True),
    ("ML-KEM-(512|768|1024)", "ML-KEM-769", False),
    ("ECDH[E][-{ellipticCurve}]", "ECDHE-P-256", True),
    ("x25519|x448", "X448", True),
    ("SPAKE2+[-{group}]", "SPAKE2+", True),
    ("HSS[_L{levels}][(_<LMS>_<LMOTS>)+]", "HSS_L2_a_b_c_d", True),
])
def test_pattern_to_regex(pattern: str, name: str, ok: bool) -> None:
    assert bool(re.match(pattern_to_regex(pattern), name, re.IGNORECASE)) is ok


def test_classify_prefers_literal_match() -> None:
    doc = {"algorithms": [{"family": "AES", "standard": [], "variant": [
        {"pattern": "AES[-(128|192|256)][-(ECB|CBC)][-{padding}]", "primitive": "block-cipher"},
        {"pattern": "AES[-(128|192|256)][-(GCM|CCM)][-{tagLength}]", "primitive": "ae"},
    ]}], "ellipticCurves": []}
    reg = parse_registry(json.dumps(doc), REF)
    assert classify("AES-256-CBC", reg.algorithms)[0].primitive is Primitive.BLOCK_CIPHER
    assert classify("AES-128-GCM", reg.algorithms)[0].primitive is Primitive.AE


def test_curated_tables_load_and_helpers_work() -> None:
    c = load_curated(documents=DOCS)
    cs = c.classical_strength
    assert (r := strength_for_rsa(cs, 2048)) is not None and r.bits == 112
    assert (r := strength_for_rsa(cs, 3072)) is not None and r.bits == 128
    assert strength_for_rsa(cs, 512) is None
    assert (r := strength_for_ecc(cs, 521)) is not None and r.bits == 256
    p256 = next(n for n in c.named_curves if n.curve == "P-256")
    assert p256.bits == 128 and "secp256_r1" in p256.aliases
    assert all(q.nist_level is NistLevel.L0 for q in c.quantum_vulnerable)


def test_oid_rules_exact_beats_subtree_and_children_range() -> None:
    rules = load_rules(documents=DOCS)
    wrap = match_rule(rules, Oid("2.16.840.1.101.3.4.1.5"))
    assert wrap is not None and wrap.primitive is Primitive.KEY_WRAP
    gcm = match_rule(rules, Oid("2.16.840.1.101.3.4.1.6"))
    assert gcm is not None and gcm.family == "AES" and gcm.primitive is None
    mldsa = match_rule(rules, Oid("2.16.840.1.101.3.4.3.18"))
    assert mldsa is not None and mldsa.family == "ML-DSA"
    assert match_rule(rules, Oid("2.16.840.1.101.3.4.3")) is None      # arc root itself
    excl = match_rule(rules, Oid("1.2.840.10045.1.1"))
    assert excl is not None and excl.exclude


def test_input_boundary() -> None:
    o = Obj({"a": "1", "b": True, "c": [1]}, "x")
    assert o.opt_int("a") == 1 and o.get_bool("b", False) is True
    with pytest.raises(ParseError, match=r"x\.c: expected string"):
        o.get_str("c")
    with pytest.raises(ParseError, match="not a dotted OID"):
        Obj({"oid": "1.2.x"}, "y").opt_oid("oid")
    assert match_key("OQS_KEM_alg_ml_kem_768") == match_key("ML-KEM-768") == "mlkem768"
    assert parse_int_text("0x0904", "t") == 0x904


# --- Optional: needs `python fetch.py` and a system libcrypto -------------------

RAW_OBJECTS = ROOT / "data" / "raw" / "openssl-objects" / "crypto" / "objects" / "objects.txt"


@pytest.mark.skipif(not RAW_OBJECTS.exists() or not ctypes.util.find_library("crypto"),
                    reason="needs fetched objects.txt and libcrypto")
def test_objects_txt_matches_system_openssl() -> None:
    """Every name the local OpenSSL knows must resolve to the same OID we computed."""
    lib = ctypes.util.find_library("crypto")
    assert lib is not None
    lc = ctypes.CDLL(lib)
    lc.OBJ_txt2obj.restype = ctypes.c_void_p
    lc.OBJ_txt2obj.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lc.OBJ_obj2txt.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    lc.ASN1_OBJECT_free.argtypes = [ctypes.c_void_p]

    parsed = parse_objects_txt(RAW_OBJECTS.read_text(encoding="utf-8"))
    checked, mismatches = 0, []
    for o in parsed.objects:
        if not o.oid or "." not in o.oid:  # single-arc roots cannot be DER-encoded
            continue
        handle = lc.OBJ_txt2obj(o.short_name.encode(), 0)
        if not handle:
            continue  # newer than the local OpenSSL
        buf = ctypes.create_string_buffer(256)
        lc.OBJ_obj2txt(buf, 256, handle, 1)
        lc.ASN1_OBJECT_free(handle)
        checked += 1
        if buf.value.decode() != o.oid:
            mismatches.append((o.short_name, o.oid, buf.value.decode()))
    assert checked > 500
    assert not mismatches, mismatches[:10]
