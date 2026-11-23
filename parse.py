#!/usr/bin/env python3
"""Run every parser: data/raw/ + curated/ -> data/parsed/*.json

    python parse.py                  # all parsers
    python parse.py liboqs           # just one (module name in parsers/)
"""
from __future__ import annotations

import importlib
import sys

from parsers._common import ParseError

PARSERS = [
    "openssl_objects",
    "oqs_provider",
    "liboqs",
    "cyclonedx_registry",
    "nist_curated",
]


def main(argv: list[str]) -> int:
    selected = argv or PARSERS
    unknown = [p for p in selected if p not in PARSERS]
    if unknown:
        print(f"unknown parser(s): {', '.join(unknown)}. Choose from: {', '.join(PARSERS)}", file=sys.stderr)
        return 2
    failed = 0
    for name in selected:
        try:
            for line in importlib.import_module(f"parsers.{name}").run():
                print(line)
        except ParseError as e:
            failed += 1
            print(f"FAILED {name}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
