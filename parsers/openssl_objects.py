"""Parse OpenSSL crypto/objects/objects.txt into OID records.

File format (same rules as OpenSSL's own crypto/objects/objects.pl):

    # comment
    !module X9-62                 names defined below get the prefix "X9-62_"
    !global                       end of module
    !Alias pkcs1 pkcs 1           name for an OID arc, not an object
    !Cname rsaEncryption          C name for the next entry only
    1 2 840 113549 : rsadsi : RSA Data Security, Inc.
    pkcs1 11 : RSA-SHA256 : sha256WithRSAEncryption
    pkcs9 1 : : emailAddress      empty short name -> short name = long name
    iso 3 : identified-organization   no long name -> long name = short name
    : CAST5-ECB : cast5-ecb       object with no OID

An OID spec starts either with a number or with a previously defined name
(alias, C name, short name or long name) and continues with numbers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from ._common import manifest_source, permalink, raw_text, write_output
from ._errors import ParseError
from ._input import Oid, parse_oid
from .models import OpenSslObject, Ref

SOURCE_ID = "openssl-objects"
PATH = "crypto/objects/objects.txt"
_PLACEHOLDER_REF = Ref(url="")


@dataclass(frozen=True, slots=True, kw_only=True)
class ObjectsTxt:
    objects: tuple[OpenSslObject, ...]
    aliases: dict[str, Oid]


def _key(name: str) -> str:
    # objects.pl turns '-' and '.' into '_' when it builds C names.
    return re.sub(r"[-.]", "_", name.strip())


def parse_objects_txt(text: str) -> ObjectsTxt:
    names: dict[str, str] = {}  # C-name style key -> dotted OID
    aliases: dict[str, Oid] = {}
    objects: list[OpenSslObject] = []
    module = ""
    cname_next: str | None = None
    errors: list[str] = []

    def register(key: str, oid: str) -> None:
        k = _key(key)
        if module:
            names[_key(module + "_") + k] = oid
            names.setdefault(k, oid)
        else:
            names[k] = oid

    def resolve(spec: str, lineno: int) -> Oid | None:
        parts = spec.split()
        if not parts:
            return None
        head, tail = parts[0], parts[1:]
        if head.isdigit():
            arcs = [head]
        else:
            base = names.get(_key(head))
            if base is None:
                errors.append(f"line {lineno}: undefined identifier {head!r}")
                return None
            arcs = [base]
        for t in tail:
            if not t.isdigit():
                errors.append(f"line {lineno}: non-numeric arc {t!r} in {spec!r}")
                return None
            arcs.append(t)
        return parse_oid(".".join(arcs), f"objects.txt:{lineno}")

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith("!"):
            directive, *rest_ = line.split(None, 1)
            rest = rest_[0].strip() if rest_ else ""
            if directive == "!module":
                module = rest
            elif directive == "!global":
                module = ""
            elif directive == "!Cname":
                cname_next = rest
            elif directive == "!Alias":
                alias, _, spec = rest.replace("\t", " ").partition(" ")
                oid = resolve(spec, lineno)
                if oid:
                    register(alias, oid)
                    aliases[(module + "_" if module else "") + alias] = oid
            else:
                errors.append(f"line {lineno}: unknown directive {directive!r}")
            continue

        fields = [f.strip() for f in line.split(":", 2)]
        if len(fields) < 2:
            errors.append(f"line {lineno}: expected 'oid : sn [: ln]', got {line!r}")
            continue
        spec, sn = fields[0], fields[1]
        ln = fields[2] if len(fields) == 3 else ""
        if not sn and not ln:
            errors.append(f"line {lineno}: entry with no name")
            continue
        sn = sn or ln
        ln = ln or sn

        oid = resolve(spec, lineno) if spec else None
        if oid:
            # The C name is what later lines use to refer to this entry.
            register(cname_next or sn, oid)
            for n in (sn, ln):
                names.setdefault(_key(n), oid)

        objects.append(OpenSslObject(
            oid=oid, short_name=sn, long_name=ln, c_name=cname_next,
            module=module or None, line=lineno, ref=_PLACEHOLDER_REF,
        ))
        cname_next = None

    if errors:
        raise ParseError(f"{len(errors)} error(s) in objects.txt:\n  " + "\n  ".join(errors[:20]))
    return ObjectsTxt(objects=tuple(objects), aliases=aliases)


def load() -> ObjectsTxt:
    """Parse the fetched file and attach permalinks."""
    src = manifest_source(SOURCE_ID)
    parsed = parse_objects_txt(raw_text(SOURCE_ID, PATH))
    objs = tuple(replace(o, ref=permalink(src.repo, src.commit, PATH, o.line)) for o in parsed.objects)
    return ObjectsTxt(objects=objs, aliases=parsed.aliases)


def run() -> list[str]:
    src = manifest_source(SOURCE_ID)
    parsed = load()
    with_oid = sum(1 for o in parsed.objects if o.oid)
    out = write_output("openssl_objects", list(parsed.objects), [src],
                       extra={"aliases": parsed.aliases, "with_oid": with_oid})
    return [f"{out.name}: {len(parsed.objects)} objects ({with_oid} with OID), {len(parsed.aliases)} aliases"]
