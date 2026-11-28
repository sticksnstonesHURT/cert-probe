#!/usr/bin/env bash
# Build the standalone `probe` executable inside a manylinux_2_28 container.
#
# Run by the `cli-binaries` job in .github/workflows/release.yml, and runnable
# locally with the same command:
#
#   uv export --frozen --no-dev --no-emit-project --no-hashes \
#       --format requirements-txt -o /tmp/requirements-build.txt
#   docker run --rm --user "$(id -u):$(id -g)" \
#       -v "$PWD:/src" -v /tmp/requirements-build.txt:/tmp/requirements-build.txt:ro \
#       -w /src quay.io/pypa/manylinux_2_28_aarch64@sha256:<digest> \
#       bash packaging/build-cli.sh arm64
#
# Why manylinux_2_28 rather than the runner's own glibc: a PyInstaller build
# carries its build environment's glibc requirement, so building on
# ubuntu-24.04 (glibc 2.39) would produce binaries that fail on Debian 12
# (glibc 2.36). manylinux_2_28 pins the floor at 2.28, which is also the floor
# cryptography itself ships against. docs/cli.md section 10.
#
# Requirements come from uv.lock (exported by the caller), so the dependencies
# baked into the binary are the same ones the test suite validated.
set -euo pipefail

arch="${1:?usage: build-cli.sh <amd64|arm64>}"
readonly PYINSTALLER_VERSION="6.22.3"
readonly UV_VERSION="0.13.6"
readonly GLIBC_FLOOR="2.28"
readonly SYSTEM_PYTHON="/opt/python/cp312-cp312/bin/python"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

requirements="${REQUIREMENTS_FILE:-/tmp/requirements-build.txt}"
dist_dir="${DIST_DIR:-$root/dist}"
venv="/tmp/pyi-venv"
if [ ! -f "$requirements" ]; then
    echo "::error::requirements file not found: $requirements" >&2
    exit 1
fi

echo "== building probe for linux/$arch =="
"$SYSTEM_PYTHON" --version

# manylinux's /opt/python interpreters are compiled WITHOUT --enable-shared, and
# PyInstaller requires a shared libpython. Bootstrap uv (pinned to the version CI
# uses) and make it provision a managed CPython 3.12 instead; --managed-python is
# required, or uv would satisfy "3.12" with the unusable system interpreter. The
# venv also keeps the build independent of the image's site-packages, so the
# container can run as the invoking user and the output is not root-owned.
bootstrap=/tmp/uv-bootstrap
"$SYSTEM_PYTHON" -m venv "$bootstrap"
"$bootstrap/bin/python" -m pip install --quiet --no-cache-dir --disable-pip-version-check \
    "uv==${UV_VERSION}"

export UV_PYTHON_INSTALL_DIR=/tmp/uv-python
export UV_CACHE_DIR=/tmp/uv-cache
"$bootstrap/bin/uv" venv --managed-python --python 3.12 /tmp/pyi-venv
"$bootstrap/bin/uv" pip install --quiet \
    --python /tmp/pyi-venv/bin/python \
    -r "$requirements" "pyinstaller==${PYINSTALLER_VERSION}"

echo "== build interpreter =="
/tmp/pyi-venv/bin/python --version

version="$(PYTHONPATH="$root" "$venv/bin/python" -c \
    'from app.version import APP_VERSION; print(APP_VERSION)')"
echo "== version $version =="

rm -rf /tmp/pyi-dist /tmp/pyi-build
if ! "$venv/bin/python" -m PyInstaller --noconfirm --clean \
    --distpath /tmp/pyi-dist \
    --workpath /tmp/pyi-build \
    packaging/probe.spec >/tmp/pyinstaller.log 2>&1; then
    echo "::error::PyInstaller failed" >&2
    tail -60 /tmp/pyinstaller.log >&2
    exit 1
fi

# The artifact must actually run: proves the freeze is complete and that the
# web stack was not pulled in.
echo "== smoke: built binary =="
/tmp/pyi-dist/probe/probe --version

# glibc floor, checked across every ELF file in the tree rather than only the
# entry point: the interpreter and extension modules carry most of the symbols.
# objdump exits non-zero for the non-ELF files that ship alongside them, so each
# invocation is tolerated individually and only the collected symbols are judged.
echo "== glibc floor (<= $GLIBC_FLOOR) =="
symbols=/tmp/glibc-symbols.txt
: >"$symbols"
while IFS= read -r -d '' file; do
    objdump -T "$file" >>"$symbols" 2>/dev/null || true
done < <(find /tmp/pyi-dist/probe -type f -print0)

max_glibc="$(
    { grep -o 'GLIBC_[0-9][0-9.]*' "$symbols" || true; } \
        | sed 's/^GLIBC_//' \
        | sort -u -V \
        | tail -1 || true
)"
if [ -z "$max_glibc" ]; then
    echo "::error::could not determine the artifact's glibc requirement" >&2
    exit 1
fi
highest="$(printf '%s\n%s\n' "$GLIBC_FLOOR" "$max_glibc" | sort -V | tail -1)"
if [ "$highest" != "$GLIBC_FLOOR" ]; then
    echo "::error::artifact requires GLIBC_$max_glibc, above the $GLIBC_FLOOR floor" >&2
    exit 1
fi
echo "ok: highest required symbol is GLIBC_$max_glibc"

mkdir -p "$dist_dir"
tarball="$dist_dir/cert-probe-${version}-linux-${arch}.tar.gz"
tar -C /tmp/pyi-dist -czf "$tarball" probe

echo "== artifact =="
ls -l "$tarball"
sha256sum "$tarball"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### CLI binary ($arch)"
        echo
        echo "| Field | Value |"
        echo "|---|---|"
        echo "| Version | \`$version\` |"
        echo "| Artifact | \`$(basename "$tarball")\` |"
        echo "| Size | $(stat -c '%s' "$tarball") bytes |"
        echo "| glibc floor | \`GLIBC_$max_glibc\` |"
    } >>"$GITHUB_STEP_SUMMARY"
fi
