"""Shared paths, typed config (sources.yml, manifest.json) and output writer."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ._errors import ParseError
from ._input import Obj
from ._json import JsonValue, to_json
from .models import Ref

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "sources.yml"
CURATED_DIR = ROOT / "curated"
RAW_DIR = ROOT / "data" / "raw"
PARSED_DIR = ROOT / "data" / "parsed"
MERGED_DIR = ROOT / "data" / "merged"
MANIFEST_NAME = "manifest.json"

__all__ = ["ParseError", "ROOT", "SOURCES_FILE", "CURATED_DIR", "RAW_DIR", "PARSED_DIR", "MERGED_DIR"]


# --- sources.yml ------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class SourceSpec:
    id: str
    repo: str
    branch: str
    commit: str
    license: str | None
    files: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class DocumentSpec:
    id: str
    title: str
    url: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SourcesConfig:
    sources: dict[str, SourceSpec]
    documents: dict[str, DocumentSpec]


def load_sources(path: Path = SOURCES_FILE) -> SourcesConfig:
    root = Obj(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
    srcs = root.get_obj("sources")
    docs = root.opt_obj("documents") or Obj({}, f"{path.name}.documents")
    return SourcesConfig(
        sources={
            sid: SourceSpec(
                id=sid,
                repo=(s := srcs.get_obj(sid)).get_str("repo"),
                branch=s.get_str("branch"),
                commit=s.get_str("commit"),
                license=s.opt_str("license"),
                files=tuple(s.strs("files")),
            )
            for sid in srcs.keys()
        },
        documents={
            did: DocumentSpec(id=did, title=(d := docs.get_obj(did)).get_str("title"), url=d.get_str("url"))
            for did in docs.keys()
        },
    )


# --- manifest.json (written by fetch.py) --------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class ManifestFile:
    path: str
    url: str
    permalink: str
    sha256: str
    bytes: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ManifestSource:
    id: str
    repo: str
    branch: str
    commit: str
    files: tuple[ManifestFile, ...]


def load_manifest(raw_dir: Path = RAW_DIR) -> dict[str, ManifestSource]:
    path = raw_dir / MANIFEST_NAME
    if not path.exists():
        raise ParseError(f"{path} not found. Run `python fetch.py` first.")
    root = Obj(json.loads(path.read_text(encoding="utf-8")), MANIFEST_NAME)
    srcs = root.get_obj("sources")
    out: dict[str, ManifestSource] = {}
    for sid in srcs.keys():
        s = srcs.get_obj(sid)
        out[sid] = ManifestSource(
            id=sid,
            repo=s.get_str("repo"),
            branch=s.get_str("branch"),
            commit=s.get_str("commit"),
            files=tuple(
                ManifestFile(path=f.get_str("path"), url=f.get_str("url"), permalink=f.get_str("permalink"),
                             sha256=f.get_str("sha256"), bytes=f.get_int("bytes"))
                for f in s.objs("files")
            ),
        )
    return out


def manifest_source(source_id: str, raw_dir: Path = RAW_DIR) -> ManifestSource:
    m = load_manifest(raw_dir)
    if source_id not in m:
        raise ParseError(f"{source_id} missing from manifest. Run `python fetch.py --only {source_id}`.")
    return m[source_id]


def raw_text(source_id: str, path: str, raw_dir: Path = RAW_DIR) -> str:
    p = raw_dir / source_id / path
    if not p.exists():
        raise ParseError(f"{p} not found. Run `python fetch.py` first.")
    return p.read_text(encoding="utf-8")


def permalink(repo: str, commit: str, path: str, line: int | None = None) -> Ref:
    url = f"https://github.com/{repo}/blob/{commit}/{path}"
    return Ref(url=f"{url}#L{line}" if line else url)


# --- helpers ----------------------------------------------------------------------

def match_key(name: str) -> str:
    """Loose join key: 'ML-KEM-768', 'mlkem768', 'OQS_KEM_alg_ml_kem_768' -> 'mlkem768'."""
    n = re.sub(r"^oqs_(kem|sig|sig_stfl)_alg_", "", name.strip().lower())
    return re.sub(r"[^a-z0-9]", "", n)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, payload: JsonValue) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def write_output(
    name: str,
    records: list[object],
    sources: list[object],
    extra: dict[str, object] | None = None,
    out_dir: Path = PARSED_DIR,
) -> Path:
    payload: dict[str, JsonValue] = {
        "generated_at_utc": utc_now(),
        "sources": to_json(sources),
        "count": len(records),
    }
    for k, v in (extra or {}).items():
        payload[k] = to_json(v)
    payload["records"] = to_json(records)
    return write_json(out_dir / f"{name}.json", payload)
