"""Parse liboqs docs/cbom.json (+ src/kem/kem.h, src/sig/sig.h).

cbom.json is a CycloneDX 1.6 BOM with one component per
(parameter set, implementation, platform). This collapses them into one record
per parameter set with its primitive and NIST quantum security level.

kem.h / sig.h map each C identifier to its name (OQS_SIG_alg_uov_ov_Is -> "OV-Is").
oqs-provider refers to algorithms by that C identifier, so `oqs_id` is the exact
join key. Name normalization alone fails for UOV, SNOVA, MQOM and SDitH.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ._common import manifest_source, permalink, raw_text, write_output
from ._errors import ParseError
from ._input import Obj
from .models import LiboqsParameterSet, NistLevel, Primitive, Ref

SOURCE_ID = "liboqs"
CBOM = "docs/cbom.json"
HEADERS = ("src/kem/kem.h", "src/sig/sig.h")

_DEFINE_RE = re.compile(r'^#define\s+(OQS_(?:KEM|SIG)_alg_\w+)\s+"([^"]+)"', re.MULTILINE)


@dataclass(slots=True)
class _Acc:
    family: str
    primitive: Primitive
    level: NistLevel
    functions: set[str] = field(default_factory=set)
    platforms: set[str] = field(default_factory=set)


def parse_headers(texts: list[str]) -> dict[str, str]:
    """Return {parameter set name: C identifier}."""
    out: dict[str, str] = {}
    for text in texts:
        for macro, name in _DEFINE_RE.findall(text):
            out[name] = macro
    return out


def parse_cbom(text: str, ref: Ref, oqs_ids: dict[str, str] | None = None) -> list[LiboqsParameterSet]:
    doc = Obj(json.loads(text), "cbom.json")
    acc: dict[str, _Acc] = {}
    for comp in doc.objs("components"):
        if comp.opt_str("type") != "cryptographic-asset":
            continue
        cp = comp.opt_obj("cryptoProperties")
        ap = cp.opt_obj("algorithmProperties") if cp else None
        if ap is None or not ap.has("parameterSetIdentifier"):
            continue  # liboqs also lists its internal 'aes' and 'sha3' with no parameter set
        ps = ap.get_str("parameterSetIdentifier")
        try:
            prim = Primitive(ap.get_str("primitive"))
            level = NistLevel(ap.get_int("nistQuantumSecurityLevel"))
        except ValueError as e:
            raise ParseError(f"{ap.path}: {e}") from e
        a = acc.setdefault(ps, _Acc(family=comp.get_str("name"), primitive=prim, level=level))
        if (a.primitive, a.level) != (prim, level):
            raise ParseError(f"{ps}: conflicting primitive/level across components")
        a.functions.update(ap.strs("cryptoFunctions"))
        plat = ap.opt_str("implementationPlatform")
        if plat:
            a.platforms.add(plat)

    ids = oqs_ids or {}
    return sorted(
        (LiboqsParameterSet(
            name=ps, family=a.family, primitive=a.primitive, nist_level=a.level,
            crypto_functions=tuple(sorted(a.functions)), platforms=tuple(sorted(a.platforms)),
            oqs_id=ids.get(ps), ref=ref,
        ) for ps, a in acc.items()),
        key=lambda r: (r.family, r.name),
    )


def load() -> tuple[list[LiboqsParameterSet], dict[str, str]]:
    src = manifest_source(SOURCE_ID)
    ids = parse_headers([raw_text(SOURCE_ID, h) for h in HEADERS])
    recs = parse_cbom(raw_text(SOURCE_ID, CBOM), permalink(src.repo, src.commit, CBOM), ids)
    return recs, ids


def run() -> list[str]:
    src = manifest_source(SOURCE_ID)
    recs, ids = load()
    in_cbom = {r.name for r in recs}
    header_only = sorted(n for n in ids if n not in in_cbom)
    no_id = sorted(r.name for r in recs if r.oqs_id is None)
    out = write_output("liboqs", list(recs), [src],
                       extra={"oqs_ids": dict(sorted(ids.items())), "header_names_missing_from_cbom": header_only})
    msgs = [f"{out.name}: {len(recs)} parameter sets, {len(ids)} C ids"]
    if header_only:
        msgs.append(f"  note: {len(header_only)} names in headers but not in cbom.json: {', '.join(header_only[:6])}")
    if no_id:
        msgs.append(f"  warn: {len(no_id)} cbom entries with no C id: {', '.join(no_id[:6])}")
    return msgs
