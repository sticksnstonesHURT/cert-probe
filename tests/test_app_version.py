"""Guard against drift between APP_VERSION and pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from app.version import APP_VERSION
from cli.main import main


def test_app_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert APP_VERSION == pyproject["project"]["version"], (
        f"APP_VERSION={APP_VERSION!r} does not match pyproject.toml "
        f"version={pyproject['project']['version']!r}"
    )


def test_cli_version_matches_pyproject(capsys: pytest.CaptureFixture[str]) -> None:
    """``probe --version`` must report the same version as pyproject.toml."""
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert int(exc_info.value.code or 0) == 0
    assert capsys.readouterr().out.strip() == (
        f"probe (cert-probe) {pyproject['project']['version']}"
    )
