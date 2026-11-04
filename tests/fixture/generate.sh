#!/usr/bin/env bash
# Regenerate the test-CA and server certificates under tests/fixture/certs/.
# Runs from the project root so `uv run` finds pyproject.toml.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec uv run python tests/fixture/generate.py
