"""Run the CLI with ``python -m cli``.

The frozen binary uses this same module as its entry point, so the console
script, ``python -m cli`` and the PyInstaller executable all share one path.
"""

from __future__ import annotations

import sys

from cli.main import main

if __name__ == "__main__":
    sys.exit(main())
