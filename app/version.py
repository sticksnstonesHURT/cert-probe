"""Single source of truth for the application version.

Deliberately a literal rather than a lookup of installed distribution metadata:
the container image is built with ``--no-install-project`` (see the Dockerfile),
so the distribution is not installed there and ``importlib.metadata`` would
raise. ``tests/test_app_version.py`` keeps this value in step with
``pyproject.toml``.

Kept in its own module so the API and the CLI can share one value without the
CLI importing anything FastAPI-related.
"""

from __future__ import annotations

APP_VERSION = "0.3.0"
