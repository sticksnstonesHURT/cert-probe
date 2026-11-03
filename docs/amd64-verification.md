# AMD64 verification — TLS Checker

Evidence record for the native linux/amd64 build of the TLS Checker image, verified on a Debian VM.

- Phase 8.6 closes out the AMD64 side of Phase 8: native build, Compose deployment, hardening enforcement, endpoint correctness, restart recovery. 

- No application code, Dockerfile or compose.yaml change was required for 8.6 — the same Dockerfile and the same pinned base-image digests that produced the ARM64 image at Phase 8.5 produced this image.
<br>

**Environment:** 
Debian GNU/Linux on VMware Fusion, guest hostname`debian-mgmt`, architecture `linux/amd64`.

**Docker Engine 29.9.2, Docker Compose 5.7.0** (Compose version independently confirmed via the `com.docker.compose.version` label on the running image). 

---

## 1. Build configuration

**Same Dockerfile as ARM64. Base images pinned by manifest-list digest, so the same file produces a native linux/amd64 build on this host and a native linux/arm64 build on the WSL host.**

<br>

| ARG | Pinned value |
|---|---|
| `PYTHON_IMAGE` | `python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159` |
| `UV_IMAGE` | `ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0` |

Three stages (`uv_source`, `builder`, `runtime`), unchanged from ARM64; see `docs/arm64-verification.md` for the stage breakdown.
<br>

**Build command actually used.** 
- On this host the plain `docker build` form was used. 

- Both are BuildKit-backed and produce an equivalent image on this Docker version.
	```bash
	sudo docker build -t tls-checker:amd64 .
	```

- The image was built natively on this AMD64 host. 
No `--platform` flag was passed and no `PLATFORM` ARG exists in the Dockerfile. The resulting image
reports `.Architecture = amd64`.

---

## 2. Image identity

**Two images were produced on this host. `tls-checker:amd64` was built with plain `docker build` for validation; `tls-checker:dev` is the tag Compose references and the tag of the running container.**
<br>

`tls-checker:amd64` — from `sudo docker build -t tls-checker:amd64 .`:

| Field | Value |
|---|---|
| Tag | `tls-checker:amd64` |
| Single-manifest digest | `sha256:a6250f603397c245d6d32f6689588243563a1e6c89170a4dc91b501964ade781` |
| Manifest-list digest | `sha256:8d6093791ec6f29f49ac0e00162593fb8bb9ad5eb77d95b352fa8e24feda7114` |
| Config digest (`.Id`) | `sha256:406a8fd9ef8583634ec7e87742cf17c488e8c9da4aa3e5383d7712411db0fc16` |
| `.Architecture` | `amd64` (verified by `docker image inspect --format 'OS={{.Os}} Architecture={{.Architecture}}'`) |
| `.Os` | `linux` |
| `.Size` | `214,831,435` bytes — cumulative uncompressed image-layer size |
| `.Config.Labels` | `null` |
<br>

`tls-checker:dev` — from `sudo docker compose up -d --build`:

| Field | Value |
|---|---|
| Tag | `tls-checker:dev` |
| Single-manifest digest | `sha256:f115adaba7a36542e16fbcdec99b07133601bd09f1da3e643d484c1ed623272f` |
| Manifest-list digest | `sha256:c531c336112fa34b01f438266c41a9b29962642405e75beaf50fceb03296d3c4` |
| Config digest (`.Id`) | `sha256:4e83aeefcc5a9f65a7a6b86ae9e197a54d317415f1ffd22acd6c226d1b304dd1` |
| `.Size` | `214,831,569` bytes — cumulative uncompressed image-layer size |
| `.Config.Labels` | `{"com.docker.compose.project":"tls-checker","com.docker.compose.service":"tls-checker","com.docker.compose.version":"5.7.0"}` |
<br>

**Compose metadata labels — confirmed present on `tls-checker:dev`.**

Direct `docker image inspect` comparison:
```docker
    Tag=[tls-checker:amd64] Size=214831435 Labels=null
    Tag=[tls-checker:dev]   Size=214831569 Labels={"com.docker.compose.project":"tls-checker","com.docker.compose.service":"tls-checker","com.docker.compose.version":"5.7.0"}
```

- The Compose tag carries three additional label metadata keys that the plain-`docker build` tag does not. Image configuration metadata is included in the config digest (`.Id`) and propagates into every parent manifest digest. 

- This is the mechanism by which two tags built from identical source with identical base-image pins resolve to different digests: the config bytes differ because the labels differ.

- All actual build steps in the Compose build reported `CACHED`, including both base-image `FROM`s, `uv sync`, and `COPY app`. BuildKit reused cached outputs; no build step was re-executed from source.
- Byte-for-byte layer identity between the two tags was not independently verified.
<br>

The `com.docker.compose.version` label is also the direct evidence for Docker Compose 5.7.0 on this host (see document header).
<br>

**134-byte `.Size` difference — recorded, not explained.** 
The two tags differ by `214,831,569 − 214,831,435 = 134` bytes in `.Size`. 
This difference is observed and reported verbatim. Its cause is **not** established by the collected evidence: `.

`Size` is documented by Docker as cumulative uncompressed image-layer size, whereas labels are stored in the image configuration rather than in image layers. 
The labels therefore explain the digest divergence but cannot be assumed to explain the `.Size`
divergence. No further investigation was performed.
<br>

**Architecture-adjusted size — unresolved observation.** 

The ARM64 image `.Size` was `52,031,773` bytes (`docs/arm64-verification.md`). 

The AMD64 image `.Size` is `214,831,435` bytes — roughly 4.1× the ARM64 figure. 

- Both values are reported by `docker image inspect .Size` on their respective
hosts. 

- The two hosts run different Docker engine versions (`29.6.1` on WSL, `29.9.2` on Debian), and the ARM64 host also reported a divergent-size figure from `docker images` (`239 MB`) for the same image. 

- The cause of the cross-architecture size divergence is not established. 
<br>

**ARM64 historical tags.** 

`tls-checker:dev-arm64` and`tls-checker:dev-arm64-nonroot` do not appear in any Debian evidence collected in this session; they are not part of Phase 8.6. 

Their record is in `docs/arm64-verification.md`.
<br>

**Relationship to the ARM64 image.** 
Both images were built from the same Dockerfile against the same digest-pinned base images on hosts of the corresponding architecture. 

The build graph, layer ordering, runtime identity (`uid=10001(app)`, `gid=10001(app)`), startup command, and hardening configuration are identical between them.

---

## 3. Runtime identity

From `docker exec tls-checker-tls-checker-1 id` and
`docker exec tls-checker-tls-checker-1 python --version`:
<br>

| Property | Value |
|---|---|
| Running UID / GID | `10001` / `10001` |
| Groups | `10001(app)` |
| Python version | `3.12.16` (directly verified via `python --version` inside the running container) |
| Working directory | `/app` (from image config) |
| `$HOME` | `/home/app` (read-only under hardening) |
| Writeable tmpfs | `/tmp` (verified writable) |
| Read-only rootfs | enforced by `read_only: true` (verified) |

The runtime Python version `3.12.16` matches the ARM64 image and the digest-pinned `python:3.12-slim` base. 

---

## 4. Security settings

Both layers applied, values identical to Phase 8.4 on ARM64. 

Verified with `docker inspect` on the running Compose container.
<br>

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
| Restart policy | `unless-stopped` | `RestartPolicy.Name = unless-stopped` |

Cgroup enforcement confirmed from inside the container, establishing that these are kernel-enforced limits rather than only Docker daemon awareness:
<br>

| Cgroup path | Value |
|---|---|
| `/sys/fs/cgroup/memory.max` | `268435456` |
| `/sys/fs/cgroup/pids.max` | `128` |

Image-level controls (`Config.User = app`, UID/GID 10001, `/app` root-owned) are inherited unchanged from the image; see `docs/arm64-verification.md`.

---

## 5. Validation results

### 5.1 Test surface — DNS-tested hosts vs `/check`-tested hosts

Two overlapping but distinct test sets were executed. 

They are recorded separately below and their results are kept strictly separate in the rest of the document.
<br>

**Dual-stack DNS resolution** 

- (hostname → IP addresses; executed inside the running container via Python `socket.getaddrinfo` with `AF_UNSPEC`).
- Tested and successful: `example.com`, `google.com`, `facebook.com`, `github.com`, `microsoft.com`, `cloudflare.com`, `badssl.com`, `expired.badssl.com` 8 hosts, all resolving successfully in 0.043 s – 0.119 s.
<br>

**Application-level `/check` API** 

- (hostname → TLS certificate inspection and structured response). Tested through the running service:
`google.com`, `facebook.com`, `github.com`, `microsoft.com`, `cloudflare.com`, `badssl.com`, `expired.badssl.com`;  7 hosts.
<br>

`example.com` is in the DNS-tested set but **not** in the `/check`-tested set. 
Its initial `/check` attempt (in the pre-Compose `docker run` container) returned `504 dns_timeout`. 

It was not retried via `/check` after the Compose deployment. 

This document does not claim that `example.com` passed the application-level TLS test.

`localhost` is tested via `/check` for SSRF-guard behaviour, not for certificate validation; it is separate from both sets above.
<br>

### 5.2 Build

```bash
sudo docker build -t tls-checker:amd64 .
```

Completed with `24.7s (19/19) FINISHED`. Both base-image pins resolved per-arch on this host.

Subsequent Compose build:
```bash
sudo docker compose up -d --build
```

Reported `5.2s (21/21) FINISHED` with every build step `CACHED`; the two additional top-level steps compared to the plain build are `load local bake definitions` and `resolving provenance for metadata file`, both BuildKit bake plumbing rather than build work. 

**The Compose build reused the layers from the plain build and relinked the image under the `tls-checker:dev` tag with the Compose metadata labels described.**
<br>

### 5.3 Health-check probes

`docker compose ps` reports `healthy` for the running container:
```
    NAME                        IMAGE             SERVICE       STATUS                    PORTS
    tls-checker-tls-checker-1   tls-checker:dev   tls-checker   Up 31 seconds (healthy)   127.0.0.1:8000->8000/tcp
```

`docker inspect .State.Health.Status` returns `healthy`.

Compose probe configuration, unchanged from Phase 8.3: `interval: 10s`, `timeout: 3s`, `retries: 3`, `start_period: 5s`, execution via `python -c` using stdlib `urllib.request`. 

No `curl`/`wget` in the image.

Probe traffic from the container's own network namespace is visible in the container logs as `INFO: 127.0.0.1:<port> - "GET /health HTTP/1.1" 200 OK`, confirming the loopback path the probe uses.
<br>

### 5.4 Endpoint behaviour — `/check` API

All `/check` requests were sent to `127.0.0.1:8000` on the Debian host (the port is bound to host loopback by Compose) with`Content-Type: application/json`. 

Responses below are verbatim from the evidence supplied; where the full JSON response contains additional populated fields not fully transcribed in the evidence excerpt, that is noted.

The 7 hosts tested at the application layer are listed first. `/health` and `localhost` (SSRF guard) are listed after for completeness.
<br>

| Request | HTTP | Behaviour |
|---|---|---|
| `POST /check {"hostname":"google.com"}` | 200 | `verified=true`, `hostname_verified=true`, `error=null`, `days_remaining=57` at time of test; `issuer` belongs to Google Trust Services |
| `POST /check {"hostname":"facebook.com"}` | 200 | `verified=true`, `hostname_verified=true`, `subject="CN=*.facebook.com,O=Meta Platforms\, Inc.,L=Menlo Park,ST=California,C=US"`, `issuer="CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US"`, `days_remaining=7` at time of test, `error=null` |
| `POST /check {"hostname":"github.com"}` | 200 | `verified=true`, `hostname_verified=true`, `subject="CN=github.com"`, `issuer="CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB"`, `days_remaining=85`, `error=null` |
| `POST /check {"hostname":"microsoft.com"}` | 200 | `verified=true`, `hostname_verified=true`, `subject="CN=microsoft.com,O=Microsoft Corporation,L=Redmond,ST=WA,C=US"`, `issuer="CN=Microsoft TLS G2 RSA CA OCSP 04,O=Microsoft Corporation,C=US"`, `days_remaining=88`, `error=null` |
| `POST /check {"hostname":"cloudflare.com"}` | 200 | `verified=true`, `hostname_verified=true`, `subject="CN=cloudflare.com"`, `issuer="CN=WE1,O=Google Trust Services,C=US"`, `days_remaining=31`, `error=null` |
| `POST /check {"hostname":"badssl.com"}` | 200 | `verified=true`, `hostname_verified=true`, `subject="CN=*.badssl.com"`, `issuer="CN=YR1,O=Let's Encrypt,C=US"`, `days_remaining=55`, `error=null` |
| `POST /check {"hostname":"expired.badssl.com"}` | 200 | `verified=false`, `hostname_verified=null`, `error.kind="expired"`, `error.message="[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1011)"`, and `subject`/`issuer`/`not_before`/`not_after` populated via the Phase 5 unverified fallback (see callout below) |
| `GET /health` | 200 | `{"status":"ok"}` |
| `POST /check {"hostname":"localhost"}` | 403 | `verified=null`, `error.kind="blocked_destination"`, message names `loopback` — Phase 6 SSRF guard intact in the container. Verified in the initial `docker run` container of the same image (`tls-checker:amd64`); the Compose container runs the same image and code with the same hardening configuration, and the SSRF guard is image-level, not container-instance-level |
<br>

Tri-state invariants preserved throughout:

- `verified` is `true` (chain + hostname verified), `false` (findings from verification), or `null` (verification never ran).
- `hostname_verified` is `null` for the expired host — confirming that `false` remains reserved for `hostname_mismatch`.
<br>

**Expired-certificate fallback — direct evidence on AMD64.** 
- The `expired.badssl.com` result above is the crispest single observation across all of Phase 8 that the Phase 5 unverified-fallback path works under 8.4 hardening on either architecture. `verified=false` was returned together with fully populated certificate metadata:
	```bash
	"subject":"CN=*.badssl.com,OU=PositiveSSL Wildcard,OU=Domain Control Validated",
	"issuer":"CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB",
	"not_before":"2015-04-09T00:00:00Z",
	"not_after":"2015-04-12T23:59:59Z",
	"days_remaining":-4223
	```

- On ARM64 at Phase 8.4 the corresponding expired-host retry returned `null` metadata — the fallback itself failing due to badssl.com flakiness (see `docs/arm64-verification.md`). AMD64 did not experience that flakiness and therefore provides the direct evidence. 
The two observations are not in conflict: they record the same code path under different external-network conditions.

***Note on `example.com`.**: `example.com` was DNS-tested but not `/check`-tested post-deployment. It is absent from this table by design.*
<br>

### 5.5 Structured logging (Phase 7)

Field order and semantic fields preserved, evidenced from the initial `docker run` container during the DNS incident and from the running Compose container:
```bash
    ts=2026-11-03T10:46:53.022Z level=INFO logger=app.main msg=check
      hostname=example.com outcome=dns_timeout verified=None status=504
      duration_ms=3001 address_count=None dns_duration_ms=3001
      method=POST path=/check

    ts=2026-11-03T10:46:56.068Z level=INFO logger=app.main msg=check
      hostname=localhost outcome=blocked_destination verified=None status=403
      duration_ms=0 address_count=None dns_duration_ms=0
      method=POST path=/check
```

Both preserve the pinned field order. `address_count=None` on both the DNS failure and the SSRF block; `dns_duration_ms=3001` populated on DNS failure as specified at handoff. `dns_duration_ms=0` on the 

SSRF block matches the ARM64 observation; (see ARM64 doc)
<br>

Configuration-load log from the Compose container startup:

    ts=2026-11-03T10:59:17.167Z level=INFO logger=app.main
      msg=configuration loaded dns_timeout=3.0 connect_timeout=5.0
      tls_handshake_timeout=5.0 overall_deadline=10.0

Confirms Phase 7 lifespan logging is active and produces identical phase-budget values on AMD64.
<br>

**`init: true` in effect.** 

The Compose container logs begin:
```docker
    INFO:     Started server process [7]
```

Uvicorn runs as PID 7, not PID 1 — the Docker init process (from `init: true`, D4) is PID 1 and forwards signals. 

This is direct evidence that the D4 decision is working on AMD64, and it is the foundation for Phase 8.7's graceful-shutdown test.
<br>

### 5.6 Restart recovery

```bash
sudo docker compose restart
```
Container restarted. Health status transitioned:
```
    Attempt 1: starting
    Attempt 2: starting
    Attempt 3: starting
    Attempt 4: healthy
```

Each attempt is 2 s apart, so approximately 8 s from restart command to `healthy`. Subsequent `/health` returned `{"status":"ok"}` (HTTP 200) and `docker compose ps` reported `Up 6 seconds (healthy)`.

The observed restart policy is `unless-stopped`.

The container restarted and returned to `healthy` status under the configured hardening and resource limits.

The shutdown signal and whether graceful termination completed were not verified. This remains part of Phase 8.7.
<br>

### 5.7 Resource usage — idle baseline

Measured with `sudo docker stats --no-stream tls-checker-tls-checker-1`.
Two samples taken after restart, both idle-baseline (not load test):
<br>

| Sample | CPU % | Memory (USAGE / LIMIT) | Memory % | NET I/O | BLOCK I/O | PIDs |
|---|---|---|---|---|---|---|
| 1 | 0.60% | 42.09 MiB / 256 MiB | 16.44% | 1.9 kB / 646 B | 0 B / 0 B | 3 |
| 2 | 0.73% | 41.87 MiB / 256 MiB | 16.36% | 1.79 kB / 688 B | 0 B / 0 B | 3 |

***Note: This is an idle baseline figures; not load-test, not sustained-throughput, not peak.***

- Block I/O write is `0 B` on both samples; consistent with the read-only rootfs and tmpfs-backed `/tmp`.

- Memory is approximately 15 MiB lower than the ARM64 Phase 8.5 idle baseline (57.07–57.09 MiB). 
The two hosts differ in architecture and in the amount of pre-warmed state inside the container; the difference is not investigated here and both readings are well within the configured 256 MiB.

Sustained-load resource profile is not measured; same limitation as the ARM64 record (`docs/arm64-verification.md`).
<br>

### 5.8 Filesystem enforcement

Direct in-container tests against the running Compose container:
```bash
    $ sudo docker exec tls-checker-tls-checker-1 sh -c 'touch /rootfs-test 2>&1 || true'
    touch: cannot touch '/rootfs-test': Read-only file system

    $ sudo docker exec tls-checker-tls-checker-1 sh -c 'touch /tmp/write-test && ls -l /tmp/write-test && rm /tmp/write-test'
    -rw-r--r-- 1 app app 0 Nov  3 11:04 /tmp/write-test
```

- Confirms the two-sided design: rootfs is read-only, `/tmp` is writable under `app:app` ownership. `/home/app` writability was verified as **read-only** on ARM64 under 8.4 hardening (`docs/arm64-verification.md`); the same `read_only: true` configuration applies here by construction.
<br>

### 5.9 Compose teardown

Not performed at 8.6. Graceful shutdown and clean teardown (residual containers, networks, port bindings) are Phase 8.7 scope. 

Compose-level `down` was verified on ARM64 at Phase 8.3 (`docs/arm64-verification.md`); the same command's behaviour on AMD64 will be captured at 8.7.

---

## 6. Known limitations

- **AMD64 `.Size` is ~4.1× the ARM64 `.Size`.** 
The two readings are from Docker's `.Size` field on two hosts running different Docker engine versions (29.6.1 vs 29.9.2); direct comparability across hosts is not established. Not investigated.

- **134-byte `.Size` difference between `tls-checker:amd64` and `tls-checker:dev` on the same host** observed, cause not established.

- **Sustained-load resource profile not measured.**

- **Graceful shutdown not verified.**

- **External test hosts are flaky.**
`badssl.com` and its subdomains intermittently reset connections; retries generally succeed. Recorded at ARM64 as well. 
Phase 10 CI must not rely on `badssl.com` as a stability gate; a local expired-cert fixture is the correct approach.
`expired.badssl.com` succeeded on AMD64 on this run without flake; contrasting the ARM64 Phase 8.4 experience.

- **Layer-by-layer history not captured.** 
The three build stages are evidenced by the Dockerfile (the ARM64 doc) and the build log. 
`docker history` was not invoked.

- **`example.com` not re-verified at the application layer.**. 
Its `/check` behaviour post-Compose-deployment was not re-tested; the DNS layer was verified independently.

- The full `/check` response for `google.com` was summarised in the session record with `verified`, `hostname_verified`, `issuer`, `days_remaining` and `error`; the remaining schema fields were present in the response but not captured individually in the evidence excerpt. 
Recorded here so the summary is not mistaken for a complete field-by-field transcription.

---

## 7. Incident log — initial DNS timeouts on first deployment

While the image was being exercised through a direct `docker run` container (default bridge network), two `/check` requests returned `504 dns_timeout`. Structured log lines from that container:
```
    ts=2026-11-03T10:46:53.022Z level=INFO logger=app.main msg=check
      hostname=example.com outcome=dns_timeout verified=None status=504
      duration_ms=3001 address_count=None dns_duration_ms=3001
      method=POST path=/check

    ts=2026-11-03T10:46:56.050Z level=INFO logger=app.main msg=check
      hostname=expired.badssl.com outcome=dns_timeout verified=None
      status=504 duration_ms=3001 address_count=None dns_duration_ms=3001
      method=POST path=/check
```
<br>

Same container, same host, `localhost` correctly short-circuited:
```
    ts=2026-11-03T10:46:56.068Z level=INFO logger=app.main msg=check
      hostname=localhost outcome=blocked_destination verified=None
      status=403 duration_ms=0 address_count=None dns_duration_ms=0
      method=POST path=/check
```

`dns_timeout` exceeded the 3.0 s configured DNS budget; the response was `504 Gateway Timeout`, delivered via the protocol-error envelope.
<br>

**Observed symptom fingerprint in the affected container.** Same-host, same-container, direct comparison of address-family behaviour:
<br>

| Resolver call | `example.com` | `expired.badssl.com` |
|---|---|---|
| `AF_INET` (IPv4 only) | 0.089 s | 0.086 s |
| `AF_UNSPEC` (dual stack) | 5.127 s | 0.136 s |

The delay is hostname-specific and only appears under dual-stack resolution.
<br>

**Subsequent tests — Compose container on the user-defined bridge network, after `docker rm -f` of the direct-run container.**

- Dual-stack DNS resolution for all eight public hostnames resolved successfully in approximately 0.043 s - 0.119 s.

- The application-level `/check` results for the seven hosts listed in all returned expected responses. `example.com` was not re-tested at the application layer; only its DNS behaviour was re-verified after the deployment moved to Compose.
<br>

**Status: not currently reproducible; root cause not established.**

The collected evidence does not distinguish between the following possible explanations:

- difference in DNS-forwarding behaviour for dual-stack queries between the default `docker0` bridge and the user-defined bridge network;

- resolver-level AAAA handling in the VMware Fusion NAT DNS path (hostname-specific, hence the `expired.badssl.com` discrepancy);

- transient or cached state in the affected container's resolver path.
<br>

**What is established:**

- The application's DNS timeout and error mapping behaved exactly as specified. `dns_timeout` mapped to `504` per `_STATUS_BY_KIND`;`verified` remained `null` (verification never ran); `address_count` was
`null`; `dns_duration_ms` was populated. 
Phase 7 metadata is intact on the failure path.

- No security control regressed during the incident. The SSRF guard short-circuited `localhost` correctly inside the same container that was timing out on external hostnames.

- The 3.0 s DNS budget (`app/config.py::DEFAULT_DNS_TIMEOUT_SECONDS`) was not changed. No application and no hardening configuration was modified to resolve the incident.
<br>

**Diagnostic-container note.** 

The direct `docker run` container that carried the incident was started with `-p 8000:8000` (host-bound to `0.0.0.0`) for quick iteration. 

It was ephemeral; removed with `docker rm -f tls-checker` before the Compose deployment. The enduring container is `tls-checker-tls-checker-1`, bound to host loopback `127.0.0.1:8000` by the Compose port mapping. 
Host-port binding on the enduring service is loopback-only, as required by design.
<br>

**Handling.** 

Recorded for reference. 

DNS behaviour is not being investigated further in Phase 8; if it recurs in a specific environment, that environment is the subject of a separate workstream rather than of this containerisation phase.
