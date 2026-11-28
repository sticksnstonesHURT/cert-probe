"""Guard against drift between APP_VERSION, pyproject.toml and the release workflow."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from app.version import APP_VERSION
from cli.main import main

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"


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


def test_release_workflow_reads_app_version_from_its_own_source() -> None:
    """The release workflow must parse APP_VERSION from the file that defines it.

    v0.3.0 could not be released because the workflow still ran
    ``sed ... app/main.py`` after the literal moved to ``app/version.py``. The
    extraction returned an empty string, so the version comparison failed with
    the unhelpful message ``APP_VERSION () does not match pyproject version``.

    This test pins the coupling: moving the literal again breaks the suite
    instead of a release.
    """
    workflow = RELEASE_WORKFLOW.read_text()
    match = re.search(r"APP_VERSION = .*?/p'\s+([^\s)]+)\)", workflow)
    assert match is not None, (
        "could not locate the APP_VERSION extraction command in release.yml; "
        "update this test if the step was restructured"
    )

    relative_path = match.group(1)
    source = REPO_ROOT / relative_path
    assert source.is_file(), f"release.yml reads APP_VERSION from missing file {relative_path}"

    extracted = re.findall(r'^APP_VERSION = "([^"]+)"$', source.read_text(), re.MULTILINE)
    assert extracted == [APP_VERSION], (
        f"release.yml extracts APP_VERSION from {relative_path} and gets {extracted!r}, "
        f"but app.version.APP_VERSION is {APP_VERSION!r}"
    )
