#!/usr/bin/env python3
"""Build the merged registry: data/raw/ + curated/ -> data/merged/

    python merge.py                     # writes registry.json, registry.csv, conflicts.json, excluded_openssl.json
    python merge.py --fail-on-conflict  # exit 1 if two sources disagree on a field (for CI)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from parsers import cyclonedx_registry, liboqs, nist_curated, oid_arcs, openssl_objects, oqs_provider
from parsers._common import MERGED_DIR, load_manifest, load_sources
from parsers._errors import ParseError
from registry.export import write_all
from registry.merge import Inputs, merge


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=MERGED_DIR)
    ap.add_argument("--fail-on-conflict", action="store_true")
    args = ap.parse_args()

    try:
        docs = load_sources().documents
        curated = nist_curated.load_curated(documents=docs)
        inputs = Inputs(
            openssl=openssl_objects.load().objects,
            oqs=tuple(oqs_provider.load()),
            liboqs=tuple(liboqs.load()[0]),
            registry=cyclonedx_registry.load(),
            nist=curated,
            oid_rules=oid_arcs.load_rules(documents=docs),
        )
    except ParseError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1

    result = merge(inputs)
    paths = write_all(result, args.out, load_manifest(), docs, curated.unverified_tables)

    n = len(result.records)
    print(f"{n} records -> {', '.join(p.name for p in paths)}")
    print(f"  with OID: {sum(1 for r in result.records if r.oid)}, "
          f"primitive: {sum(1 for r in result.records if r.primitive)}, "
          f"NIST level: {sum(1 for r in result.records if r.nist_quantum_security_level is not None)}, "
          f"classical bits: {sum(1 for r in result.records if r.classical_security_level is not None)}")
    print(f"  OpenSSL objects excluded: {len(result.excluded)} (see excluded_openssl.json)")
    if result.skipped_pqc:
        print(f"  oqs-provider entries skipped (disabled, not in liboqs): {', '.join(result.skipped_pqc)}")
    if result.conflicts:
        print(f"  conflicts: {len(result.conflicts)} (see conflicts.json)")
    for t in curated.unverified_tables:
        print(f"  warn: curated table {t} not yet verified against the PDF")
    return 1 if (args.fail_on_conflict and result.conflicts) else 0


if __name__ == "__main__":
    raise SystemExit(main())
