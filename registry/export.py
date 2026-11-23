"""Write the merged registry as JSON and CSV."""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from parsers._common import DocumentSpec, ManifestSource, utc_now, write_json
from parsers._json import JsonValue, to_json

from .merge import MergeResult
from .models import Component, Record

CSV_COLUMNS = (
    "id", "name", "record_type", "composition", "family", "oid", "primitive", "parameterSetIdentifier",
    "curve", "classicalSecurityLevel", "nistQuantumSecurityLevel", "tls_codepoint", "aliases",
    "components", "included_by", "experimental_oid",
)


def _cell(v: object) -> str:
    return "" if v is None else str(v)


def _component_cell(c: Component) -> str:
    parts = [p for p in (
        f"{c.classical_security_level} bits" if c.classical_security_level is not None else None,
        f"L{int(c.nist_quantum_security_level)}" if c.nist_quantum_security_level is not None else None,
    ) if p]
    return f"{c.role.value}:{c.name}" + (f"({', '.join(parts)})" if parts else "")


def csv_row(r: Record) -> list[str]:
    return [
        r.id, r.name, r.record_type.value, _cell(r.composition), _cell(r.family), _cell(r.oid), _cell(r.primitive),
        _cell(r.parameter_set_identifier), _cell(r.curve), _cell(r.classical_security_level),
        _cell(None if r.nist_quantum_security_level is None else int(r.nist_quantum_security_level)),
        _cell(r.tls_codepoint), "|".join(sorted(r.aliases)), "; ".join(_component_cell(c) for c in r.components),
        "|".join(sorted(i.value for i in r.included_by)), "true" if r.experimental_oid else "",
    ]


def write_all(
    result: MergeResult,
    out_dir: Path,
    manifest: dict[str, ManifestSource],
    documents: dict[str, DocumentSpec],
    unverified_tables: tuple[str, ...],
) -> list[Path]:
    counts: dict[str, JsonValue] = {
        "records": len(result.records),
        "by_record_type": dict(Counter(r.record_type.value for r in result.records)),
        "by_composition": dict(Counter(r.composition.value for r in result.records if r.composition)),
        "by_inclusion": dict(Counter(i.value for r in result.records for i in r.included_by)),
        "with_oid": sum(1 for r in result.records if r.oid),
        "with_primitive": sum(1 for r in result.records if r.primitive),
        "with_nist_level": sum(1 for r in result.records if r.nist_quantum_security_level is not None),
        "with_classical_level": sum(1 for r in result.records if r.classical_security_level is not None),
        "conflicts": len(result.conflicts),
        "excluded_openssl": len(result.excluded),
    }
    header: dict[str, JsonValue] = {
        "generated_at_utc": utc_now(),
        "sources": to_json(list(manifest.values())),
        "documents": to_json(list(documents.values())),
        "unverified_curated_tables": list(unverified_tables),
        "counts": counts,
    }
    paths = [
        write_json(out_dir / "registry.json", {**header, "records": to_json(list(result.records))}),
        write_json(out_dir / "conflicts.json", {"generated_at_utc": header["generated_at_utc"],
                                                "count": len(result.conflicts),
                                                "conflicts": to_json(list(result.conflicts))}),
        write_json(out_dir / "excluded_openssl.json", {"generated_at_utc": header["generated_at_utc"],
                                                       "count": len(result.excluded),
                                                       "skipped_pqc": list(result.skipped_pqc),
                                                       "excluded": to_json(list(result.excluded))}),
    ]
    csv_path = out_dir / "registry.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for r in result.records:
            w.writerow(csv_row(r))
    paths.append(csv_path)
    return paths
