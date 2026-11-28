# Cert Probe CLI (`probe`)

**Status: Planned.** No CLI exists yet. This document records the decisions taken
before implementation and is the reference for the CLI milestone. Everything here
describes agreed scope, not verified behaviour. The one exception is the shared TLS
inspection engine, which is implemented and verified — see §4.

Related: `CERT_PROBE_HANDOVER.md` §18/§25 (scope and acceptance criteria),
`docs/ci-cd.md` (existing pipeline that this document extends).

---

## 1. Naming: distribution versus command

Two names are in play and they are deliberately different.

| Layer | Name | Where it appears |
|---|---|---|
| Python distribution / project | `cert-probe` | `pyproject.toml` `[project].name`, `uv.lock`, wheel metadata |
| Console script / executable | `probe` | `[project.scripts]`, the PyInstaller output, what users type |

```
probe facebook.com
probe example.com --port 8443
probe localhost --allow-private
probe example.com --json
probe --version
```

This is a standard and permitted arrangement: a distribution name does not have to
match its entry points. It costs nothing at build time.

Two consequences are worth stating plainly, because they are the only places a user
sees both names at once:

- **PATH shadowing.** `probe` is short and generic. It may collide with a tool the user
  has installed, and documentation elsewhere will not disambiguate it. Mitigation:
  `probe --version` prints both names (§7.4), so ambiguity resolves itself in one
  command.
- **Release assets** are named after the product and contain a directory named after the
  command (§10). This is the one place where a reader meets `cert-probe-<version>-...`
  and `probe/` side by side; §10 states the mapping explicitly.

---

## 2. Scope of this milestone

Delivered here:

- A Linux AMD64 and ARM64 standalone executable, no Python required at runtime.
- Reuses the existing TLS inspection engine; no second implementation of TLS logic.
- Direct local inspection. The CLI does not call the HTTP API.
- Published as GitHub Release assets with checksums.
- `docs/cli.md` (this file) plus a README section.

Not in scope: Windows, hosted service integration, `--verbose`/`--quiet`, shell
completion, config files. See §16.

---

## 3. Architecture and import graph

```
                     Cert Probe core
                    /               \
              FastAPI API         Linux CLI
                    \               /
                  app.checker (shared TLS engine)
```

The CLI is a thin renderer: parse arguments, validate, call
`app.checker.check_certificate`, map the result to an exit code, render.

**The CLI may import:** `app.checker`, `app.netguard`, `app.config`, `app.schemas`,
`app.render`, `app.version`.

**The CLI must never import:** `app.main`, `app.errors`. Both import FastAPI
(`app/main.py:11`, `app/errors.py:25-30`), and pulling either one into a frozen binary
drags FastAPI, Starlette and Uvicorn in with it.

This is enforced by the module layout, not by convention: `to_response()` lives in
`app/render.py`, which imports only `app.checker` and `app.schemas`. That is why the
result mapping can be shared without breaking the rule above.

Runtime dependency set of the frozen binary: Python standard library plus `cryptography`
and `pydantic`. Nothing else.

---

## 4. Inspection engine reuse

The CLI calls, unchanged in substance:

```python
check_certificate(
    hostname,
    settings,
    *,
    port=443,
    policy=DestinationPolicy.PUBLIC_ONLY,
) -> CheckResult
```

Two parameters are added to the engine for this milestone:

- `port` — default `443`, replacing the internal use of `DEFAULT_TLS_PORT`
  (`app/checker.py:34`). The default keeps every existing caller's behaviour identical.
- `policy` — default `DestinationPolicy.PUBLIC_ONLY`, the current behaviour. See §6.

Both are keyword-only with safe defaults, so `app/main.py` and all existing tests keep
working without modification.

Nothing else about the engine changes. Deadline handling, verified handshake, the
metadata-only unverified fallback, DER parsing and error classification are all reused
as-is.

---

## 5. Invocation and options

```
probe <hostname> [options]
```

| Option | Behaviour |
|---|---|
| `<hostname>` | Required. Validated with `validate_hostname` from `app.schemas` — the same function the API uses. |
| `--port N` | TCP port to connect to. Default `443`. Range `1-65535`; anything else exits `2`. |
| `--allow-private` | Select `DestinationPolicy.LOCAL_ALLOWED`. See §6. |
| `--json` | Emit the API response document on stdout. See §8. |
| `--version` | Print `probe (cert-probe) <version>` and exit `0`. |
| `--help` | Standard usage text. Exit `0`. |

### 5.1 Hostname rules

Validation is `app.schemas.validate_hostname`, reused verbatim:

- Lowercased; one trailing dot stripped; 253 characters total after normalisation.
- 63 characters per label; no empty labels; no leading or trailing hyphen; ASCII only
  (punycode form required for internationalised names).
- Rejected: URL schemes, `/`, `@`, whitespace, brackets, and `:` (`app/schemas.py:44`) —
  which is why the port is a separate flag and `example.com:8443` is not accepted as a
  hostname.
- **IP literals are rejected** (`app/schemas.py:51-59`), with the same reasoning the API
  gives: there is no SNI and no separate certificate-matching path. `probe 192.0.2.1`
  exits `2`.

Validation happens **before** anything is logged. No raw argument value is ever written
to a log line; only the normalised hostname reaches diagnostics (§9).

---

## 6. Security boundaries

### 6.1 Destination policy

The SSRF policy is a server-side control. A CLI user inspecting their own network is the
operator, not an attacker, so the CLI needs a way to reach local destinations — but the
default must not change.

```python
class DestinationPolicy(Enum):
    PUBLIC_ONLY = "public_only"  # default; today's behaviour
    LOCAL_ALLOWED = "local_allowed"  # explicit opt-in, CLI only
```

| Policy | Permits | Still rejects |
|---|---|---|
| `PUBLIC_ONLY` | globally-routable addresses only | loopback, link-local, multicast, unspecified, CGNAT (`100.64.0.0/10`), private, reserved, any `is_global == false` |
| `LOCAL_ALLOWED` | all of the above **plus** loopback, link-local, CGNAT, private, reserved, non-global | **multicast and unspecified** — never a valid TLS target, so permitting them buys nothing |

IPv4-mapped IPv6 addresses are unwrapped before classification in both policies, so
`::ffff:127.0.0.1` cannot slip past the IPv4 checks.

`--allow-private` selects `LOCAL_ALLOWED`. Without it, `probe localhost` exits `3` with
`blocked_destination`, exactly as the API would.

### 6.2 Policy is a call-level argument, never an environment variable

There is deliberately **no** `TLS_CHECKER_ALLOW_PRIVATE`. An environment variable would
be a server-side control that a misconfigured deployment could flip, silently turning the
API into an SSRF pivot. As a keyword argument, weakening the server requires editing
`app/main.py` on purpose.

`app/main.py` passes `policy=DestinationPolicy.PUBLIC_ONLY` **explicitly**, not by
relying on the default, so the security-critical choice is visible at the call site
(`app/main.py:94`) and greppable in review.

### 6.3 Never bypass `netguard`

The CLI does not implement its own resolution. It does not connect by name. It goes
through `app.netguard.resolve_and_validate` in both policies, preserving the property the
module exists for: **one resolution per request, every address classified, connect to the
validated sockaddr**, so a DNS answer that changes between validation and connection
cannot redirect the request.

Loopback targets are also why the CLI still uses the unverified-metadata path correctly:
it reports what a local service presents, and never promotes that to `verified`.

### 6.4 Custom ports are CLI-only in this milestone

| Surface | Port behaviour |
|---|---|
| Shared engine | accepts any port |
| CLI | `--port` |
| API / `POST /check` | **fixed at 443** |

If the API ever accepted an arbitrary port it would become a TCP-connect scanner against
any globally-routable address: the SSRF policy governs *where* a connection goes, not
*what* it talks to, and 443-only is currently doing real work. API custom-port support
needs an explicit port allowlist and an abuse-control design before it can be
reconsidered. Nothing in this milestone exposes it.

---

## 7. Exit codes

| Code | Meaning | `ErrorKind` values |
|---|---|---|
| `0` | Verified certificate | `verified == True`, no error |
| `1` | Certificate finding — a definitive answer, not a failure | `expired`, `hostname_mismatch`, `certificate_invalid` |
| `2` | Usage or configuration error | argparse failure, `HostnameError`, `ConfigError` |
| `3` | Network or destination error | `blocked_destination`, `dns_failure`, `dns_timeout`, `dns_capacity_exceeded`, `connection_failure`, `connection_timeout`, `tls_timeout` |
| `4` | Unexpected internal error | `unknown_error` |

Exit `1` deliberately mirrors the API, where a certificate finding is an HTTP `200`
because it is a *successful answer* (`_STATUS_BY_KIND`, `app/main.py:27`). An expired
certificate is not an error; it is the result.

`CERTIFICATE_ERROR_KINDS` (`app/checker.py:54`) is the single definition of the exit-`1`
set. It is public for exactly this reason.

### 7.1 Completeness is enforced, not documented

A test asserts that **every** member of `ErrorKind` has both an HTTP status mapping and an
exit-code mapping, enumerating kinds with `typing.get_args(ErrorKind)`. Adding a new error
kind without deciding its exit code fails the suite, rather than silently falling through
to `4`.

### 7.2 Timeout classification

`connection_timeout` and `tls_timeout` are distinct and must stay distinct: a TCP connect
that exhausts its budget is `connection_timeout`, a TLS handshake that exhausts its budget
is `tls_timeout`. Both exit `3`, but the message a human reads must name the phase that
actually ran out. The engine's phase-timeout helper takes the kind from the calling phase
rather than hard-coding one.

### 7.3 What exit codes are not

They are not a stable API for scripts to parse *findings*. A caller that needs the finding
should use `--json` and read `error.kind`, which is the same string the API returns. Exit
codes are for shell control flow.

### 7.4 `--version`

Prints both names and the one shared version literal:

```
probe (cert-probe) 0.2.0
```

The literal lives in `app/version.py` and is the same value the API reports in its OpenAPI
document. It is not read via `importlib.metadata`: the container image is built with
`--no-install-project`, so the distribution is not installed there and metadata lookup
would raise.

---

## 8. Output contract

### 8.1 One mapping, two surfaces

`app/render.py::to_response(CheckResult) -> CheckResponse` is the single mapping from
engine result to wire shape. The API and the CLI both call it. There is no second JSON
representation anywhere in the project, and adding one is a design error, not a shortcut.

`--json` therefore emits exactly the `CheckResponse` document (`app/schemas.py:99`):
`hostname`, `verified`, `hostname_verified`, `subject`, `issuer`, `not_before`,
`not_after`, `days_remaining`, `error {kind, message}`.

**Not included:** `address_count` and `dns_duration_ms`. They exist on `CheckResult` for
server-side telemetry (`app/main.py` logs them) and are deliberately absent from the API
document. `--json` matches the API document, not the internal dataclass, so the two
surfaces stay byte-comparable.

### 8.2 Tri-state honesty

`verified` and `hostname_verified` are tri-state: `true`, `false`, or **`null`**. `null`
means "not determined" — for example a DNS or connection failure where no certificate was
ever seen. It is not `false`. Both renderers must show this distinction; text output
prints `unknown` rather than `no`, and JSON emits `null`.

### 8.3 Default text output

Human-readable, one result per line plus indented detail:

```
example.com
  verified:        yes
  hostname:        yes
  subject:         CN=example.com
  issuer:          CN=Example CA
  valid:           2025-01-01T00:00:00Z .. 2035-12-31T23:59:59Z
  expires in:      3283 days
```

A finding prints the same fields it could obtain plus the classified failure:

```
expired.example.com
  verified:        no
  hostname:        unknown
  subject:         CN=expired.example.com
  issuer:          CN=Example CA
  valid:           2020-01-01T00:00:00Z .. 2021-01-01T00:00:00Z
  expires in:      -1800 days
  finding:         expired
```

Certificate metadata on a failed verification comes from the engine's unverified fallback
connection and is **informational only** — it can be influenced by a man-in-the-middle and
never affects `verified`. See §11.

### 8.4 `days_remaining` means whole days

`days_remaining` is a floor of the remaining lifetime, not a rounded figure and not a count
of calendar days. A certificate that expired twelve hours ago reports `-1`, because one
whole day has already elapsed. `0` means fewer than 24 hours remain and the certificate is
still valid. Text output must not label it "days remaining" without that meaning being
clear.

---

## 9. Stream contract

| Stream | Contents |
|---|---|
| stdout | results only: the text rendering, or the `--json` document, or `--version` |
| stderr | diagnostics, warnings, errors, usage text when arguments are invalid |

JSON output is never contaminated by log lines. This is a hard requirement, not a
preference: a single stray diagnostic line makes `probe x --json | jq` fail.

Consequently the CLI **does not call `app.logging.configure_logging()`**. That function
installs its handler on `sys.stdout` (`app/logging.py:80`), which is correct for the API
and wrong here. `app/logging.py` is left unchanged.

The CLI reads no log-level configuration. CLI-specific `--verbose` and `--quiet` may be
added later; they are out of scope for this milestone.

---

## 10. Linux compatibility and release assets

### 10.1 Supported baseline

Binaries are built inside **`manylinux_2_28`** containers on both architectures, which pins
the glibc floor at **2.28**.

| Distribution | glibc | Supported |
|---|---|---|
| Debian 11 (bullseye) | 2.31 | yes |
| Debian 12 (bookworm) | 2.36 | yes |
| Debian 13 (trixie) | 2.41 | yes |
| Ubuntu 20.04 | 2.31 | yes |
| Ubuntu 22.04 | 2.35 | yes |
| Ubuntu 24.04 | 2.39 | yes |
| Alpine / musl | — | **no** |

Why this matters: a PyInstaller binary carries the interpreter and native extensions from
its build environment, so it requires that environment's glibc or newer. Building on
`ubuntu-24.04` would have produced binaries that fail on Debian 12 with
`GLIBC_2.39 not found` — the distribution this project's infrastructure work targets.
`manylinux_2_28` is also the floor `cryptography` itself ships against, so the two agree.

**CI asserts the floor** rather than assuming it: the build job inspects the resulting
binary's dynamic symbol requirements and fails if any `GLIBC_` version above `2.28` is
required, and the binary is executed once inside the oldest supported base image.

musl/Alpine is explicitly unsupported. There is no static or musllinux build.

### 10.2 Release assets

Each release carries, per architecture:

| Asset | Contents |
|---|---|
| `cert-probe-<version>-linux-amd64.tar.gz` | `probe/` directory: the `probe` executable plus its bundled dependencies |
| `cert-probe-<version>-linux-arm64.tar.gz` | same, for ARM64 |
| `SHA256SUMS` | checksums for both archives, generated in one pass so both appear in one file |

Asset names carry the **product** name; the archive contains a directory named after the
**command**. Extraction therefore looks like:

```bash
tar xzf cert-probe-0.3.0-linux-amd64.tar.gz
sudo install -m 0755 probe/probe /usr/local/bin/probe
```

`--onedir` packaging is used, not `--onefile`. The executable and its dependencies ship as
a directory: no per-invocation extraction to a temporary directory, faster startup, and it
works under a read-only root filesystem — which this project's own containers use
(`compose.yaml:14`). A `--onefile` binary would need a writable `$TMPDIR` and could not
honestly claim to run in the hardened container this project ships.

### 10.3 Verification

```bash
sha256sum --check SHA256SUMS
./probe/probe --version
```

Checksums are regenerated in the same job that produces the archives, so they always
describe the bytes actually published.

---

## 11. Inherited limitations

These are properties of the shared engine, not of the CLI, and they carry over unchanged:

- **The unverified fallback proves nothing.** Metadata reported alongside a certificate
  finding comes from a second, explicitly unverified connection that can be steered by a
  MITM. It never influences `verified` or `hostname_verified`.
- **No HTTP is sent to the target.** The TLS handshake is the entire interaction.
- **Overall deadline cap.** The total per-inspection budget is capped at 30 seconds
  (`app/config.py:46`). That cap exists to bound server worker occupancy; the CLI honours
  the same limit rather than removing a control for convenience.
- **A stuck resolver cannot be killed.** `getaddrinfo` runs in a bounded pool; a worker that
  outlives its timeout window cannot be forcibly terminated, though the caller is freed
  immediately.
- **Single-resolution, first-success connection.** Validated addresses are tried in order;
  the first successful connect wins.

---

## 12. Timeouts

The CLI reuses the existing configuration and its validation rules exactly; there is no
CLI-specific timeout model.

| Variable | Default | Meaning |
|---|---|---|
| `TLS_CHECKER_DNS_TIMEOUT` | `3.0` | resolution budget |
| `TLS_CHECKER_CONNECT_TIMEOUT` | `5.0` | per-address TCP connect budget |
| `TLS_CHECKER_TLS_HANDSHAKE_TIMEOUT` | `5.0` | handshake budget |
| `TLS_CHECKER_OVERALL_DEADLINE` | `10.0` | total per-inspection budget |

Invariants enforced by `app/config.py`, all failing as exit `2`:

- every value finite and strictly positive;
- `overall >= max(dns, connect, handshake)`;
- `overall <= 30`.

Every phase runs under `min(phase_timeout, remaining)` against a monotonic deadline, so no
phase can overrun the total.

Command-line timeout flags mirror these variables, with unset flags falling back to the
environment and then to the defaults. The exact flag names are the one detail still open
within the CLI implementation step; they will be recorded here when finalised.

**Deferred:** the environment variables keep the `TLS_CHECKER_` prefix throughout this
milestone, even though the distribution is now `cert-probe`. Renaming them to
`CERT_PROBE_*` is a breaking change for operators and is tracked as a separate task to
complete **before Phase D (hosted deployment)**, when nothing external depends on them. It
is deliberately not part of the CLI work.

---

## 13. Testing

CLI tests live in `tests/` and run under the existing `make check` gate.

- **In-process, always.** Tests call `cli.main.main(argv)` and capture streams with
  `capsys`. They never invoke the installed `probe` console script. The script exists in
  the CI virtualenv (where `uv sync --locked` installs the project) but not in the
  container image (built with `--no-install-project`) — a subprocess-based test would pass
  in CI and fail everywhere else.
- **Exit-code coverage** is asserted per `ErrorKind`, including the §7.1 completeness test
  over `typing.get_args(ErrorKind)`.
- **JSON parity** is asserted against `to_response()` output, not against a hand-written
  expectation, so the two surfaces cannot drift.
- **Stream separation** is asserted: `--json` stdout parses as JSON with diagnostics
  directed to stderr.
- **Phase classification** includes a test that a handshake-deadline exhaustion is
  `tls_timeout`, alongside the existing pre-connect case which remains
  `connection_timeout`.
- **Version parity** extends the existing `APP_VERSION` / `pyproject.toml` test to cover
  `probe --version`.

`mypy` covers `cli/`; `ruff` already covers the whole tree; `pytest` already targets
`tests/`.

---

## 14. Packaging

For reference; the implementation detail lives in `pyproject.toml`.

```toml
[project]
name = "cert-probe"

[project.scripts]
probe = "cli.main:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["app", "cli"]
```

The explicit `packages` list is required: hatchling otherwise infers a package named after
the project (`cert_probe/`), finds nothing, and fails the build. `cli` is listed because it
is a top-level package alongside `app`.

`uv.lock` is regenerated in the same commit as this change. Both `--locked` gates — CI's
`uv sync --locked` and the Docker build — fail until it is.

The Docker image is unaffected: it builds with `--no-install-project`, so the distribution
is never built or installed there and no `probe` binary exists in the container. The
container is the API; the CLI ships as release assets.

`main() -> int` returns the exit code, which the console-script wrapper converts with
`sys.exit()`. The frozen entry point is `cli/__main__.py`, which does the same explicitly,
so `python -m cli`, the `probe` script and the PyInstaller binary all share one entry path.

---

## 15. Release automation

A `cli-binaries` job is added to the existing release workflow.

- Matrix: AMD64 on `ubuntu-24.04`, ARM64 on `ubuntu-24.04-arm`, both building inside
  `manylinux_2_28` containers (§10.1).
- PyInstaller `--onedir`, per-architecture `tar.gz`, uploaded as job artifacts.
- The release job downloads both, generates one combined `SHA256SUMS`, and attaches all
  three assets to the GitHub Release.
- The binaries are built from the tagged commit. Nothing is rebuilt that the existing
  pipeline already produced.

**Rerun handling.** The current release step exits early when the Release already exists,
which would leave a release with a failed asset upload permanently incomplete. That branch
uploads with `gh release upload --clobber` instead of exiting, so a rerun repairs the
release. The Docker image build and promotion logic is untouched; CLI binaries are an
additional deliverable, not a replacement.

Because the binaries gate the Release and the Release gates image promotion, a failed
binary build blocks a release rather than publishing a partial one. No image is rebuilt at
any point, preserving the invariant that promotion never rebuilds.

---

## 16. Out of scope

- Windows binaries.
- musl / Alpine builds.
- `--verbose` / `--quiet`.
- Shell completion, configuration files, profiles.
- API custom-port support (§6.4).
- `CERT_PROBE_*` environment variable migration (§12).
- Any CLI behaviour that duplicates TLS logic, hostname validation, destination policy or
  response mapping. All four are shared with the API by construction.
