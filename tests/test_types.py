"""Fail the test run if the code stops passing `mypy --strict` (config in pyproject.toml)."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_mypy_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    api = pytest.importorskip("mypy.api")
    monkeypatch.chdir(ROOT)  # `files` in pyproject.toml are relative to the repo root
    stdout, stderr, status = api.run(["--config-file", str(ROOT / "pyproject.toml")])
    assert status == 0, stdout + stderr
