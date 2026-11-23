"""Parse oqs-provider oqs-template/generate.yml.

One record per algorithm the provider exposes:
  OqsKind.PURE       plain PQ KEM or signature
  OqsKind.HYBRID     KEM combined with a classical group (x25519_mlkem768, X25519MLKEM768)
  OqsKind.COMPOSITE  signature combined with a classical signature (p256_mldsa44)

Primitive comes from the section: `kems` -> KEM, `sigs` -> SIGNATURE.
The file has no NIST level: join on `oqs_id` with liboqs for that.

Not emitted: `extra_nids.old` (code points from earlier NIST rounds).
Default ECP hybrids (`use_hybrid` + `nid_hybrid`) get their curve from the NIST
level, which this file lacks; they carry `name=None, default_ecp_hybrid=True`
and the merge names them with `default_ecp_curve(level)`.
"""
from __future__ import annotations

import yaml

from ._common import manifest_source, permalink, raw_text, write_output
from ._input import Obj
from .models import NistLevel, OqsAlgorithm, OqsKind, Primitive, Ref

SOURCE_ID = "oqs-provider"
PATH = "oqs-template/generate.yml"

# Same mapping as oqs-provider generate.py (nist_to_bits + default ECP curves).
_DEFAULT_ECP: dict[NistLevel, str] = {
    NistLevel.L1: "p256", NistLevel.L2: "p256",
    NistLevel.L3: "p384", NistLevel.L4: "p384",
    NistLevel.L5: "p521",
}
_TEST_ARC = "1.3.9999."  # OQS private test arc, not registered OIDs


def default_ecp_curve(level: NistLevel) -> str | None:
    return _DEFAULT_ECP.get(level)


def parse_generate_yml(text: str, ref: Ref) -> list[OqsAlgorithm]:
    doc = Obj(yaml.safe_load(text), "generate.yml")
    out: list[OqsAlgorithm] = []

    for kem in doc.objs("kems"):
        base = kem.get_str("name_group")
        oqs_id = kem.get_str("oqs_alg")
        enabled = kem.get_bool("enable_kem", False)
        enabled_tls = kem.get_bool("enable_tls", False)
        oid = kem.opt_oid("oid")
        out.append(OqsAlgorithm(
            name=base, kind=OqsKind.PURE, family=kem.get_str("family"), primitive=Primitive.KEM,
            oqs_id=oqs_id, pq_name=base, classical_name=None, default_ecp_hybrid=False,
            pretty_name=None, standard_name=None, oid=oid, tls_codepoint=kem.opt_int("nid"),
            iana=kem.opt_bool("iana"), enabled=enabled, enabled_tls=enabled_tls,
            experimental_oid=bool(oid and oid.startswith(_TEST_ARC)),
            openssl_version=kem.opt_str("openssl_version"), ref=ref,
        ))
        if kem.get_bool("use_hybrid", False):
            hoid = kem.opt_oid("hybrid_oid")
            out.append(OqsAlgorithm(
                name=None, kind=OqsKind.HYBRID, family=kem.get_str("family"), primitive=Primitive.KEM,
                oqs_id=oqs_id, pq_name=base, classical_name=None, default_ecp_hybrid=True,
                pretty_name=None, standard_name=None, oid=hoid, tls_codepoint=kem.opt_int("nid_hybrid"),
                iana=None, enabled=enabled, enabled_tls=enabled_tls,
                experimental_oid=bool(hoid and hoid.startswith(_TEST_ARC)),
                openssl_version=None, ref=ref,
            ))
        extra = kem.opt_obj("extra_nids")
        for h in extra.objs("current") if extra else []:
            group = h.get_str("hybrid_group")
            hoid = h.opt_oid("hybrid_oid")
            out.append(OqsAlgorithm(
                name=f"{group}_{base}", kind=OqsKind.HYBRID, family=kem.get_str("family"),
                primitive=Primitive.KEM, oqs_id=oqs_id, pq_name=base, classical_name=group,
                default_ecp_hybrid=False, pretty_name=None, standard_name=h.opt_str("standard_name"),
                oid=hoid, tls_codepoint=h.opt_int("nid"), iana=h.opt_bool("iana"),
                enabled=enabled, enabled_tls=enabled_tls,
                experimental_oid=bool(hoid and hoid.startswith(_TEST_ARC)),
                openssl_version=h.opt_str("openssl_version"), ref=ref,
            ))

    for fam in doc.objs("sigs"):
        family = fam.get_str("family")
        for v in fam.objs("variants"):
            vname = v.get_str("name")
            pretty = v.opt_str("pretty_name")
            oqs_id = v.get_str("oqs_meth")
            enabled = v.get_bool("enable", False)
            enabled_tls = v.get_bool("enable_tls", False)
            oid = v.opt_oid("oid")
            out.append(OqsAlgorithm(
                name=vname, kind=OqsKind.PURE, family=family, primitive=Primitive.SIGNATURE,
                oqs_id=oqs_id, pq_name=vname, classical_name=None, default_ecp_hybrid=False,
                pretty_name=pretty, standard_name=None, oid=oid, tls_codepoint=v.opt_int("code_point"),
                iana=v.opt_bool("iana"), enabled=enabled, enabled_tls=enabled_tls,
                experimental_oid=bool(oid and oid.startswith(_TEST_ARC)),
                openssl_version=v.opt_str("openssl_version"), ref=ref,
            ))
            for m in v.objs("mix_with"):
                mname = m.get_str("name")
                moid = m.opt_oid("oid")
                out.append(OqsAlgorithm(
                    name=f"{mname}_{vname}", kind=OqsKind.COMPOSITE, family=family,
                    primitive=Primitive.SIGNATURE, oqs_id=oqs_id, pq_name=vname, classical_name=mname,
                    default_ecp_hybrid=False,
                    pretty_name=f"{m.opt_str('pretty_name') or mname} + {pretty or vname}",
                    standard_name=None, oid=moid, tls_codepoint=m.opt_int("code_point"), iana=None,
                    enabled=enabled, enabled_tls=enabled_tls,
                    experimental_oid=bool(moid and moid.startswith(_TEST_ARC)),
                    openssl_version=None, ref=ref,
                ))
    return out


def load() -> list[OqsAlgorithm]:
    src = manifest_source(SOURCE_ID)
    return parse_generate_yml(raw_text(SOURCE_ID, PATH), permalink(src.repo, src.commit, PATH))


def run() -> list[str]:
    src = manifest_source(SOURCE_ID)
    algs = load()
    out = write_output("oqs_provider", list(algs), [src])
    counts = {k.value: sum(1 for a in algs if a.kind is k) for k in OqsKind}
    return [f"{out.name}: {len(algs)} records " + ", ".join(f"{k}={n}" for k, n in sorted(counts.items()))]
