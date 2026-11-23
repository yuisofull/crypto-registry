#!/usr/bin/env python3
"""Download the pinned upstream files listed in sources.yml.

    python fetch.py                 # download everything into data/raw/
    python fetch.py --only liboqs   # one source
    python fetch.py --check         # verify data/raw/ against the manifest, no network
    python fetch.py --bump          # move sources.yml to the latest commit on each branch, then fetch

Set GITHUB_TOKEN to raise the GitHub API rate limit used by --bump.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from parsers._common import (MANIFEST_NAME, RAW_DIR, SOURCES_FILE, SourcesConfig, load_manifest, load_sources,
                             permalink)

RAW_URL = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"
API_COMMIT_URL = "https://api.github.com/repos/{repo}/commits/{branch}"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _request(url: str, accept: str | None = None) -> bytes:
    headers = {"User-Agent": "crypto-registry-fetch"}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as resp:
                body: bytes = resp.read()
                return body
        except urllib.error.HTTPError as e:
            if e.code in (404, 401, 403):
                raise
            last_err = e
        except urllib.error.URLError as e:
            last_err = e
        time.sleep(2 ** attempt)
    raise RuntimeError(f"failed to download {url}: {last_err}")


def latest_commit(repo: str, branch: str) -> str:
    """Branch head via `git ls-remote` (no API rate limit), falling back to the GitHub API."""
    sha = ""
    try:
        out = subprocess.run(
            ["git", "ls-remote", f"https://github.com/{repo}", f"refs/heads/{branch}"],
            capture_output=True, text=True, timeout=60, check=True,
        ).stdout
        sha = out.split("\t", 1)[0].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    if not SHA_RE.match(sha):
        try:
            sha = _request(API_COMMIT_URL.format(repo=repo, branch=branch), accept="application/vnd.github.sha").decode().strip()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"cannot resolve {repo}@{branch}: GitHub API returned {e.code} (set GITHUB_TOKEN?)") from e
    if not SHA_RE.match(sha):
        raise RuntimeError(f"unexpected commit id for {repo}@{branch}: {sha!r}")
    return sha


def bump(sources_file: Path, only: set[str] | None) -> None:
    """Rewrite commit ids in place so comments and layout in sources.yml survive."""
    text = sources_file.read_text(encoding="utf-8")
    for sid, src in load_sources(sources_file).sources.items():
        if only and sid not in only:
            continue
        new = latest_commit(src.repo, src.branch)
        old = src.commit
        if new == old:
            print(f"  {sid}: up to date ({old[:12]})")
            continue
        text = text.replace(old, new)
        print(f"  {sid}: {old[:12]} -> {new[:12]}")
    sources_file.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(sources: SourcesConfig, raw_dir: Path, only: set[str] | None) -> None:
    manifest_file = raw_dir / MANIFEST_NAME
    entries: dict[str, object] = {}
    if manifest_file.exists():
        old = json.loads(manifest_file.read_text(encoding="utf-8"))
        if isinstance(old, dict) and isinstance(old.get("sources"), dict):
            entries.update(old["sources"])

    for sid, src in sources.sources.items():
        if only and sid not in only:
            continue
        repo, commit = src.repo, src.commit
        if not SHA_RE.match(commit):
            raise SystemExit(f"{sid}: commit must be a full 40-char sha, got {commit!r}")
        files: list[dict[str, object]] = []
        for path in src.files:
            url = RAW_URL.format(repo=repo, commit=commit, path=path)
            data = _request(url)
            if not data:
                raise RuntimeError(f"{sid}: empty file {url}")
            dest = raw_dir / sid / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            files.append({
                "path": path,
                "url": url,
                "permalink": permalink(repo, commit, path).url,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            })
            print(f"  {sid}: {path} ({len(data):,} bytes)")
        entries[sid] = {"repo": repo, "commit": commit, "branch": src.branch, "files": files}

    manifest = {
        "fetched_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "sources": entries,
    }
    manifest_file.parent.mkdir(parents=True, exist_ok=True)
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def check(sources: SourcesConfig, raw_dir: Path) -> int:
    if not (raw_dir / MANIFEST_NAME).exists():
        print("no manifest, run fetch first")
        return 1
    manifest = load_manifest(raw_dir)
    bad = 0
    for sid, src in sources.sources.items():
        entry = manifest.get(sid)
        if not entry:
            print(f"  MISSING {sid}")
            bad += 1
            continue
        if entry.commit != src.commit:
            print(f"  STALE   {sid}: manifest {entry.commit[:12]} != sources.yml {src.commit[:12]}")
            bad += 1
        listed = {f.path: f for f in entry.files}
        for path in src.files:
            f = listed.get(path)
            p = raw_dir / sid / path
            if not f or not p.exists():
                print(f"  MISSING {sid}: {path}")
                bad += 1
            elif sha256_file(p) != f.sha256:
                print(f"  CHANGED {sid}: {path}")
                bad += 1
    print("OK" if not bad else f"{bad} problem(s)")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", type=Path, default=SOURCES_FILE)
    ap.add_argument("--raw-dir", type=Path, default=RAW_DIR)
    ap.add_argument("--only", action="append", help="source id to process (repeatable)")
    ap.add_argument("--bump", action="store_true", help="update commits in sources.yml to branch heads, then fetch")
    ap.add_argument("--check", action="store_true", help="verify downloaded files, no network")
    args = ap.parse_args()
    only = set(args.only) if args.only else None

    if args.check:
        return check(load_sources(args.sources), args.raw_dir)
    if args.bump:
        print("bumping commits:")
        bump(args.sources, only)
    sources = load_sources(args.sources)
    unknown = (only or set()) - set(sources.sources)
    if unknown:
        print(f"unknown source id(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    print("fetching:")
    fetch(sources, args.raw_dir, only)
    print(f"manifest: {args.raw_dir / MANIFEST_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
