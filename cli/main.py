"""Entry point for the ``probe`` command-line interface.

Scaffolding for the packaging stage: this establishes the console-script entry
point, the frozen-binary entry path and ``--version``. The inspection arguments
and the exit-code contract arrive with the CLI implementation.

Naming: the distribution is ``cert-probe``, the command is ``probe``. That split
is deliberate and is recorded in ``docs/cli.md`` section 1.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from app.version import APP_VERSION

PROG = "probe"
DISTRIBUTION = "cert-probe"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``probe`` command."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=f"Inspect the TLS certificate presented by a hostname ({DISTRIBUTION}).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} ({DISTRIBUTION}) {APP_VERSION}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    parser.parse_args(argv)
    # No inspection arguments exist yet, so every remaining invocation is a
    # usage error. The CLI implementation replaces this branch.
    parser.print_help(sys.stderr)
    return 2
