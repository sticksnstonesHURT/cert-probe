# PyInstaller spec for the standalone `probe` executable.
#
# Built inside a manylinux_2_28 container on a native runner by
# packaging/build-cli.sh; see docs/cli.md sections 10 and 14.
#
# --onedir (COLLECT), not --onefile: the executable and its dependencies ship as
# a directory. There is no per-invocation extraction into a temporary directory,
# startup is faster, and it runs under a read-only root filesystem — which is how
# this project runs its own containers.
#
# The CLI must not carry the web stack: `cli` imports only app.checker,
# app.config, app.netguard, app.render, app.schemas and app.version, none of
# which reach FastAPI. The excludes below are a belt-and-braces assertion of
# that boundary, not something the import graph alone would pull in.

import os

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))

a = Analysis(
    [os.path.join(ROOT, "cli", "__main__.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "fastapi",
        "starlette",
        "uvicorn",
        "pytest",
        "mypy",
        "ruff",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="probe",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="probe",
)
