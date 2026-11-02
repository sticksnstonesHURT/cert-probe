"""Guard against drift between APP_VERSION and pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

from app.main import APP_VERSION


def test_app_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert APP_VERSION == pyproject["project"]["version"], (
        f"APP_VERSION={APP_VERSION!r} does not match pyproject.toml "
        f"version={pyproject['project']['version']!r}"
    )
