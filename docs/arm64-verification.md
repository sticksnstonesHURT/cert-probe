# ARM64 verification — TLS Checker

Evidence record for the native linux/arm64 build of the TLS Checker image.

Phase 8.5 closes out the ARM64 work performed across Phase 8.1 (multi-stage Dockerfile), 8.2 (non-root runtime) and 8.4 (container hardening). 

No new build or implementation work was performed for 8.5. 

*Note: This document records the verified state; the operational runbook (build, run, verify per arch, digest refresh) is deferred to README.md under Phase 8.9.*

<br>

AMD64 native verification is a separate deliverable (Phase 8.6) and will be recorded in `docs/amd64-verification.md` when the Debian x86_64 VM is available. Application code, 

Dockerfile and `compose.yaml` are unchanged from Phase 8.4 for this document.

Environment: Ubuntu 24.04 LTS on WSL2, architecture `linux/arm64/v8`. 

The image was built natively on this ARM64 WSL host. 

---

## 1. Build configuration

- Multi-stage Dockerfile. 

- Base images are pinned by manifest-list digest. 

- The same file is intended to produce a native linux/arm64 build on this host and a native linux/amd64 build on the Debian x86_64 VM (Phase 8.6), each via the host's default architecture, without a `--platform` override.

<br>

| ARG | Pinned value |
|---|---|
| `PYTHON_IMAGE` | `python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159` |
| `UV_IMAGE` | `ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0` |

<br>

Three stages, evidenced by direct grep of the Dockerfile:

| Line | Instruction |
|---|---|
| 21 | `ARG PYTHON_IMAGE=…` |
| 22 | `ARG UV_IMAGE=…` |
| 29 | `FROM ${UV_IMAGE} AS uv_source` |
| 32 | `FROM ${PYTHON_IMAGE} AS builder` |
| 50 | `FROM ${PYTHON_IMAGE} AS runtime` |
| 77 | `USER app` |
| 79 | `CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]` |

<br>

- **`uv_source`** — file-only source stage for `/uv` and `/uvx`. 
Exists because `COPY --from=${VAR}` does not expand at BuildKit parse time.

- **`builder`** — installs dependencies with `uv sync --locked --no-dev--no-install-project`, then `COPY app ./app`.

- **`runtime`** — copies `/app/.venv` and `/app/app` from `builder`; runs as non-root `app`.

<br>

**Native build.** 

No `--platform` flag was passed at any stage and no `PLATFORM` ARG exists in the Dockerfile. 

The resulting image's `.Architecture` field is `arm64`, consistent with a native build on this ARM64 host. 

Whether any specific build mechanism (BuildKit builder, containerd snapshotter, or QEMU emulation) participated at any layer was not separately verified by this evidence; what is verified is that the image produced on this host reports `.Architecture = arm64`.

---

## 2. Image identity

From `docker image inspect tls-checker:dev`:

| Field | Value |
|---|---|
| `.Id` (image configuration digest) | `sha256:8b1cf6ad5a9ff0dbe468367b6e28233f4b7763a3476407f945cce29939505afe` |
| `.RepoDigests` | `["tls-checker@sha256:8b1cf6ad5a9ff0dbe468367b6e28233f4b7763a3476407f945cce29939505afe"]` |
| `.Architecture` | `arm64` |
| `.Os` | `linux` |
| `.Variant` | `v8` |
| `.Created` | `2026-11-02T10:42:03.813354082Z` |
| `.Size` | `52,031,773` bytes — cumulative uncompressed image-layer size |

<br>

Local tags, from `docker images --digests`:

| Tag | DIGEST column | SIZE column |
|---|---|---|
| `tls-checker:dev` | `sha256:8b1cf6ad5a9ff0dbe468367b6e28233f4b7763a3476407f945cce29939505afe` | `239 MB` |
| `tls-checker:dev-arm64-nonroot` | `sha256:1d8bd01024f2df4894e7eabbb88ce0887f55f1f1af7044d510e9530e241616e6` | `239 MB` |
| `tls-checker:dev-arm64` | `sha256:a030197ef9fa8dde783dcaf77406c813cde60627722a22a744200945883c07dd` | `239 MB` |

<br>

**Notes on the digest fields:**

- `.Id` is the image **configuration digest**, not a manifest-list digest.

- `.RepoDigests` and the DIGEST column of `docker images --digests` show the same value, matching `.Id`.

- No registry-distribution assertions are made in this document. Publishing (per-arch tags, then a combined multi-platform manifest) is Phase 10 scope.

<br>

**Notes on the size measurements — two independent figures are recorded verbatim; no interpretation is offered:**

- `.Size` from `docker image inspect` = `52,031,773` bytes. Docker documents this field as the cumulative uncompressed image-layer size.

- `SIZE` column of `docker images --digests` = `239 MB`.

<br>

**Note on `.Created`: this timestamp precedes the Phase 8.3 Compose build.** 

- The 8.3 build reported every layer `CACHED` with an unchanged configuration hash and relinked the image under the `tls-checker:dev` tag without re-running any build step. 

- The image content under `tls-checker:dev` is therefore the same as the Phase 8.2 image built for the same source; the `.Created` timestamp records the 8.2 build time.

<br>

`tls-checker:dev` is the current image — referenced by `compose.yaml`, hardened at Phase 8.4, and the subject of the endpoint and resource evidence. 

The `dev-arm64` and `dev-arm64-nonroot` tags are historical artifacts of Phase 8.1 and 8.2.

---

## 3. Runtime identity

From `docker exec tls-checker-tls-checker-1 id` and `docker image inspect`:

| Property | Value |
|---|---|
| Image `Config.User` | `app` |
| Running UID / GID | `10001` / `10001` |
| Groups | `10001(app)` |
| Working directory | `/app` |
| `$HOME` | `/home/app` |
| `PATH` prefix | `/app/.venv/bin` |
| Python version | `3.12.16` |
| CA bundle | `/etc/ssl/certs/ca-certificates.crt`, 222,073 bytes |

The runtime user `app` is created in the Dockerfile with `--create-home --shell /usr/sbin/nologin`. Application code and the virtual environment remain owned by root; `/app` is not writable by the runtime
process.

<br>

#### **Writability under 8.4 hardening.** 

Under the hardened Compose configuration (`read_only: true`), only `/tmp` (tmpfs, size 64 MB) is writable inside the container. `/home/app` resides on the read-only rootfs and is **not** writable, verified directly:

    $ docker exec tls-checker-tls-checker-1 sh -c 'touch /home/app/probe && rm /home/app/probe && echo writable'
    touch: cannot touch '/home/app/probe': Read-only file system

This supersedes the earlier 8.2 observation (recorded before `read_only: true` was introduced in 8.4) in which `/home/app` was writable. The application does not require write access to `$HOME`: all endpoint behaviours remain correct with `/home/app` read-only.

<br>

**Entrypoint from `Config.Cmd`:**
```python
    python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

`0.0.0.0` inside the container is required for the Docker port-publish path to reach the process. External reachability is constrained by Compose, which binds host loopback only.


---

## 4. Security settings

Two independent layers, both required.
<br>

**Image level**

| Control | Value |
|---|---|
| Runtime user | `app` (UID/GID 10001) |
| Shell | `/usr/sbin/nologin` |
| `/app` writable by runtime user | No (root-owned) |
| Image `HEALTHCHECK` | None (deferred to Compose — environmental dependency) |
| Init process in image | None (Compose `init: true`) |

<br>

**Compose level** (`compose.yaml`, verified with `docker inspect` on the running container):

| Control | Config value | Runtime observed |
|---|---|---|
| Read-only root filesystem | `read_only: true` | `ReadonlyRootfs = true` |
| Bounded writable `/tmp` | `tmpfs: /tmp:size=64m` | `Tmpfs = map[/tmp:size=64m]` |
| Dropped capabilities | `cap_drop: [ALL]` | `CapDrop = [ALL]` |
| No privilege escalation | `security_opt: [no-new-privileges:true]` | `SecurityOpt = [no-new-privileges:true]` |
| Memory ceiling | `mem_limit: 256m` | `Memory = 268435456` |
| CPU ceiling | `cpus: 1.0` | `NanoCpus = 1000000000` |
| Process ceiling | `pids_limit: 128` | `PidsLimit = 128` |
| Init process | `init: true` | `Init = true` |
| Host port binding | `127.0.0.1:8000:8000` | `host_ip=127.0.0.1, published=8000, target=8000/tcp` |

<br>

**Health check (Compose level, Python stdlib only — no `curl`/`wget` in image):**

```docker
healthcheck:
  test: ["CMD", "python", "-c", "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]
  interval: 10s
  timeout: 3s
  retries: 3
  start_period: 5s
```

---

## 5. Validation results

### 5.1 Build

The Compose build at Phase 8.3 completed in 8.1 s with `21/21 FINISHED`.

Every build step reported `CACHED`, including both base-image `FROM` steps, `COPY pyproject.toml uv.lock .python-version …`, `uv sync`, and `COPY app ./app`. All build steps were served from cache; the build relinked the existing image configuration under the `tls-checker:dev` tag rather than producing new layers.

Base-image metadata was resolved by the builder at 8.3 (both pinned digests appear in the build log's `load metadata` step).

A `docker compose build --no-cache` rebuild was not performed during Phase 8.5. The evidence recorded in §2–§4 corresponds to the cached image.

<br>

### 5.2 Health-check probes

From `docker inspect tls-checker-tls-checker-1 --format '{{json .State.Health.Log}}'`(five most recent probes):

| Probe | Start (UTC) | Duration | Exit |
|---|---|---|---|
| 1 | 2026-11-03T05:15:15.730 | 275 ms | 0 |
| 2 | 2026-11-03T05:15:26.006 | 211 ms | 0 |
| 3 | 2026-11-03T05:15:36.219 | 216 ms | 0 |
| 4 | 2026-11-03T05:15:46.437 | 218 ms | 0 |
| 5 | 2026-11-03T05:15:56.656 | 198 ms | 0 |

Cadence ≈ 10.2 s (within `interval: 10s`); each probe returned in under 275 ms (well within `timeout: 3s`). Every recorded probe exited 0.

<br>

### 5.3 Endpoint behaviour

The same endpoint set was exercised across Phases 8.1, 8.2, 8.3 and 8.4. The 8.4 hardened results are the primary hardening evidence. 

Where the 8.4 run was impaired by external flakiness, the 8.3 pre-hardening run is recorded alongside it; the two are distinguished per-request below.


| Request | Phase | HTTP | Behaviour |
|---|---|---|---|
| `GET /health` | 8.3, 8.4 | 200 | `{"status":"ok"}` |
| `POST /check {"hostname":"example.com"}` | 8.3, 8.4 | 200 | `verified=true`, `hostname_verified=true`, `subject`/`issuer`/`not_before`/`not_after` populated, `days_remaining=53` at time of test, `error=null` |
| `POST /check {"hostname":"expired.badssl.com"}` | 8.3 | 200 | `verified=false`, `hostname_verified=null`, `error.kind="expired"`, `error.message="[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1011)"`. Cert metadata populated via Phase 5 unverified fallback: `subject="CN=*.badssl.com,OU=PositiveSSL Wildcard,OU=Domain Control Validated"`, `issuer="CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB"`, `not_before="2015-04-09T00:00:00Z"`, `not_after="2015-04-12T23:59:59Z"`, `days_remaining=-4222` |
| `POST /check {"hostname":"expired.badssl.com"}` | 8.4 | 200 (after retry) | `verified=false`, `error.kind="expired"`. **Cert metadata was `null` on this attempt** — the unverified fallback connection also failed to retrieve the cert. First attempt returned `502 connection_failure` (`[Errno 104] Connection reset by peer`) due to external flakiness; the retry reproduced the expired classification but not the fallback metadata |
| `POST /check {"hostname":"self-signed.badssl.com"}` | 8.4 | 200 | `verified=false`, `hostname_verified=null`, `error.kind="certificate_invalid"`, `subject`/`issuer` populated via the unverified fallback — this is the direct evidence that the Phase 5 fallback path works under 8.4 hardening |
| `POST /check {"hostname":"localhost"}` | 8.3, 8.4 | 403 | `verified=null`, `error.kind="blocked_destination"`, message names `loopback` — Phase 6 SSRF guard intact in the container |

<br>

Two tri-state invariants were preserved throughout:

- `verified` is `true` (chain + hostname verified), `false` (findings from verification), or `null` (verification never ran).
- `hostname_verified` remains `null` for expired and self-signed — the invariant that `false` is reserved for `hostname_mismatch` was not violated.

<br>

The expired-certificate metadata divergence between 8.3 and 8.4 is attributed to badssl.com's flaky reachability, not to any hardening change:

- The container returned the same error classification (`expired`) in both runs, and the fallback path itself was re-verified under 8.4 via the self-signed host. 

- **The expired host is retained in this record as evidence of the correct error classification under hardening, not as evidence of fallback metadata.**

<br>

### 5.4 Structured logging (Phase 7)

`app.main` per-request log line appeared inside the container, in the field order pinned by `tests/test_request_logging.py`:

```bash
ts=2026-11-02T11:24:13.064Z level=INFO logger=app.main msg=check hostname=example.com outcome=ok verified=True status=200 duration_ms=279 address_count=4 dns_duration_ms=105 method=POST path=/check
```
Confirmed for `outcome=ok`, `outcome=expired` and `outcome=blocked_destination`
(the last with `verified=None status=403 address_count=None`).

<br>

### 5.5 Compose teardown

`docker compose down` completed successfully: the service container was removed in 0.5 s and the project network in 0.2 s, exit code 0. 

No residual containers or networks remained, verified by:
```bash
    docker ps -a --filter "name=tls-checker"
    docker network ls --filter "name=tls-checker"
```

Both returned empty lists.

- This evidence confirms that `docker compose down` orchestrates container and network removal cleanly. 

- It does **not** verify graceful SIGTERM handling by the uvicorn process under load (for example, in-flight requests, open TLS handshakes, or the DNS executor's shutdown). 

- Graceful shutdown is **not yet formally verified** and remains **Phase 8.7**. 
The teardown evidence here is limited to Docker Compose lifecycle behaviour.

<br>

### 5.6 Resource usage — idle baseline

Measured with `docker stats --no-stream tls-checker-tls-checker-1`, collected three times at Phase 8.5 close-out while the container was idle, with no application load intentionally applied (health probe only).

Results were consistent across the three samples:

| Sample | CPU % | Memory (`USAGE / LIMIT`) | Memory % | PIDs |
|---|---|---|---|---|
| 1 | 0.15% | 57.09 MiB / 256 MiB | 22.30% | 3 |
| 2 | 0.16% | 57.07 MiB / 256 MiB | 22.29% | 3 |
| 3 | 0.20% | 57.07 MiB / 256 MiB | 22.29% | 3 |

<br>

- Block I/O on each sample: `50.5 MB read / 0 B write`. 

- The zero write figure is consistent with the read-only root filesystem and the tmpfs-backed `/tmp`; no writable block-backed storage is present in the container's namespace. 

- Block read volume reflects image-layer reads since container start, not runtime activity on the app path.

These are **idle baseline** figures. They are not load-test results, not sustained-throughput figures, and not peak figures.
<br>

**Supplementary observations from earlier in Phase 8, labelled for context:**

- **Earlier idle sample at 8.4:** 47.68 – 47.93 MiB memory, 0.19 – 0.32% CPU, 4 – 5 PIDs. The ~9 MiB difference from the 8.5 idle baseline is not investigated here; both readings are within the configured limits.

- **CPU peak during the 8.4 badssl.com endpoint sequence:** 16.94% of one core. This is a load observation, recorded separately from the idle baseline table above.

- **Peak memory under sustained load was not measured.** The container has not been subjected to a continuous-request workload in Phase 8; the `mem_limit: 256m` headroom under sustained load is therefore not evidenced by this record.

---

## 6. Known limitations

- **Phase 8.6 (AMD64) not performed.** This document covers ARM64 only. 
Portability of the Dockerfile to AMD64 is asserted by design (same file, same digest pins, no `--platform`), but is not evidenced by execution on an x86_64 host until `docs/amd64-verification.md` exists.

- **External test hosts are flaky.** `badssl.com` endpoints reset connections intermittently (`[Errno 104] Connection reset by peer`), returning `connection_failure` / HTTP 502. 
Retrying produces the expected `verified=false` / `error.kind` outcome without any container change; this is external network behaviour, not a hardening regression. 
In one case (8.4, expired host) the retry reproduced the error classification but the unverified fallback connection also failed, leaving metadata `null`. 
Phase 10 CI must not use `badssl.com` as a stability gate; a local expired-cert fixture is the correct approach.

- **Layer-by-layer history not captured.** 
`docker history --no-human-readable` is not supported on Docker 29.6.1. 
The three build stages are evidenced directly by the Dockerfile inspection; a layer listing was not necessary for Phase 8.5.

- **Single uvicorn worker.** 
No `--workers`, no rate limiting, no concurrency limits. These are Phase 9 scope and deliberately not addressed here.

- **Graceful shutdown not verified.**

- **Sustained-load resource profile not measured.** 
Only idle baseline (three samples) and one CPU peak observation are recorded.
