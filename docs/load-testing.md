
## Phase 9 capacity evaluation: controlled load tests against a local TLS fixture and an external reference target, with the supporting test environment built during Phase 8.5.

**Status:** measurements complete.

*Note: Every measurement below was produced against the tree committed at `99bebf8`.*

---

## 1. Scope and environment

### 1.1 Host and versions

| Item | Value |
|---|---|
| Host | Ubuntu 24.04 LTS on WSL2, `linux/arm64/v8` |
| Docker Engine | 29.6.1 |
| Docker Compose | v5.3.1 |
| App image | `tls-checker:dev` |
| Fixture image | `tls-checker-fixture:dev` |
| Host-side probe interpreter | Python 3.12 (WSL host) |
| In-container interpreter | Python 3.12.16 (image) |
<br>


### 1.2 Container resource limits

Inherited unchanged from Phase 8.4 (commit `47ba0dd`):

| Limit | Value |
|---|---|
| `NanoCpus` | 1.0 |
| `Memory` | 268,435,456 bytes (256 MiB) |
| `PidsLimit` | 128 |
| `ReadonlyRootfs` | true |
| `CapDrop` | ALL |
| `tmpfs` | `/tmp:size=64m` |
| `SecurityOpt` | `no-new-privileges:true` |
| `Init` | true |
<br>

### 1.3 Out of scope

Deliberately excluded from Phase 9:

- Metrics endpoint (`/metrics`)
- OpenTelemetry
- Prometheus / Grafana
- Per-IP quotas
- WAF patterns
- Application code changes, tuning or optimisation
<br>

### 1.4 State verification

`git log --oneline -- compose.yaml` → last committed change `47ba0dd` (Phase 8.4 hardening). 

`git log --oneline -- Dockerfile` → last committed change `91e0856` (Phase 8.2 non-root).

These commit histories show no committed changes to either file during Phase 9. 

A clean working-tree check is required to establish whether there were any uncommitted modifications.

---

## 2. Test environment preparation (Phase 8.5)

### 2.1 Why a separate fixture environment was required

**The application's SSRF protection blocks every non-globally-routable destination; loopback, link-local, RFC1918, CGNAT, TEST-NET, reserved and multicast. That is the correct production posture and must not be weakened for testing.**
<br>

A controlled TLS fixture necessarily runs on a private Docker network. 

Two consequences follow:

1. Reaching the fixture requires a **precise** exception, not a policy relaxation. Relaxing `classify_ip()` would remove protection from every destination, including hostile ones.

2. An external target cannot substitute. `badssl.com` endpoints are intermittent (documented in the Phase 8 evidence records), their certificate states are not under our control, and handshake-delay scenarios cannot be constructed against them at all.

**The result is a single, narrowly scoped, test-only exemption that is disabled by default in normal deployment.**
<br>

### 2.2 Configuration surface — `app/config.py` (+94 lines)

**Four new optional fields on `Settings`:**

| Field | Env var | Meaning |
|---|---|---|
| `test_mode` | `TLS_CHECKER_TEST_MODE` | literal `"1"` enables; anything else is a `ConfigError` |
| `fixture_hostname` | `TLS_CHECKER_FIXTURE_HOSTNAME` | exact hostname exempt from SSRF classification |
| `fixture_ip` | `TLS_CHECKER_FIXTURE_IP` | RFC1918 IPv4 the hostname must resolve to |
| `additional_ca_file` | `TLS_CHECKER_ADDITIONAL_CA_FILE` | PEM CA added to the trust store (test only) |
<br>

**Fail-closed validation** in `Settings.__post_init__`:

| Condition | Outcome |
|---|---|
| Any fixture field set while `test_mode` false | `ConfigError` |
| `test_mode` true and `fixture_hostname` missing | `ConfigError` |
| `test_mode` true and `fixture_ip` missing | `ConfigError` |
| `fixture_ip` not a valid IP literal | `ConfigError` |
| `fixture_ip` not IPv4 | `ConfigError` |
| `fixture_ip` outside `10/8`, `172.16/12`, `192.168/16` | `ConfigError` |
| `additional_ca_file` not a regular file | `ConfigError` |
| `additional_ca_file` not loadable as a PEM bundle | `ConfigError` |
| `TLS_CHECKER_TEST_MODE` set to anything other than `"1"` | `ConfigError` |
<br>

**The RFC1918 restriction is enforced through a module-level `_RFC1918_NETWORKS` tuple; loopback, link-local, CGNAT, TEST-NET, ULA and public addresses are all rejected. `_validate_ca_file()` performs both a filesystem check and a real `ssl.SSLContext.load_verify_locations()` probe, so a corrupt bundle aborts startup rather than surfacing at the first
request.**

Normal deployment sets none of the four variables, so test mode remains disabled and the fixture-specific exception is not activated.
<br>

### 2.3 Test-only SSRF exception — `app/netguard.py` (+22 lines)

The exception lives inside `resolve_and_validate()`. 

**`classify_ip()` is unchanged** and remains a pure IP classifier with no knowledge of hostnames; the diff shows additions only, no modification to that function or its ordering of category checks.
<br>

Exception condition, all three required:

1. `settings.test_mode` is true

2. `settings.fixture_hostname == hostname` (exact string match)

3. every resolved address equals `settings.fixture_ip` after IPv4-mapped IPv6 unwrapping
<br>

**If any resolved address differs from the fixture IP, the entire resolution is rejected with BlockedDestination(..., "non-fixture");  including the case where the extra address would itself have been globally routable.**
<br>

Exclusivity is the security property, not merely private-IP avoidance.

Everything else continues through `classify_ip()` exactly as before. 

- The `ValidatedAddress` list returned has the same shape as today, so `_connect_to_validated()` and the direct-socket connect path are unchanged: no code below `resolve_and_validate()` can tell whether the exemption fired.
<br>

### 2.4 Test-only CA trust : `app/checker.py` (+2 lines)

Two lines inside `_collect_verified()`, immediately after `ctx.minimum_version = _MIN_TLS_VERSION`:

```python
if settings.additional_ca_file is not None:
    ctx.load_verify_locations(cafile=settings.additional_ca_file)
```

`load_verify_locations()` is **additive**. The system CA bundle loaded by `create_default_context()` remains trusted:

`example.com` still returns `verified: true` under the test overlay.

Verification policy is unchanged: 
- `check_hostname=True`, `verify_mode=CERT_REQUIRED`. 

The unverified fallback path (`_inspect_unverified()`) is untouched — still `CERT_NONE`, still never influences `verified` or `hostname_verified`.
<br>

### 2.5 Compose overlay : `compose.test.yaml`

Invoked as:

```bash
docker compose -f compose.yaml -f compose.test.yaml <command>
```

The overlay adds the fixture service, a dedicated bridge network at `172.30.0.0/24`, the four test-mode environment variables, and a read-only mount of the test CA into the app container. **`compose.yaml` itself is unchanged**; normal `docker compose up` continues to work identically.
<br>

The fixture service has no published host port. 

It is reachable only from `tls-fixture-net`, which only the app container joins.
<br>

### 2.6 Fixture container: `tests/fixture/`

| File | Purpose |
|---|---|
| `server.py` (67 lines) | stdlib TLS server, port 443, one thread per connection, configurable pre-handshake delay via `FIXTURE_HANDSHAKE_DELAY_MS` |
| `generate.py` (282 lines) | test CA plus four leaves; all invariants asserted in-script |
| `generate.sh` (6 lines) | wrapper that runs the generator via `uv run` |
| `Dockerfile` (9 lines) | `python:3.12-slim`, single-file copy |

- `server.py` performs only the TLS handshake and reads the peer certificate. 

- It does not implement HTTP; the application's check path calls `getpeercert(binary_form=True)` and never sends an application-level request, so an HTTP stack would have been dead weight.
<br>

### 2.7 Certificate generation and verified properties

**`generate.py` produces four leaf certificates plus a test CA, with `cryptography` (already present in dev dependencies — no new dependency).**

| File | `not_after` | Issuer | SAN | Scenario |
|---|---|---|---|---|
| `valid.pem` | 2027-11-04 | `CN=tls-checker-test-ca` | `tls-fixture` | chain and hostname both good |
| `expired.pem` | 2026-11-02 (in the past) | `CN=tls-checker-test-ca` | `tls-fixture` | chronologically expired |
| `wrong-cn.pem` | 2027-11-04 | `CN=tls-checker-test-ca` | `wrong-name` | SAN mismatch with valid chain |
| `self-signed.pem` | 2027-11-04 | `CN=tls-fixture` (== subject) | `tls-fixture` | not signed by the test CA |
<br>

- Expiry is produced by explicit `not_before`/`not_valid_after` dates computed from `datetime.now()`, not by a negative `-days` trick. 

- The generator asserts `expired.not_valid_after_utc < now` before writing anything, so a
misgenerated "expired" certificate fails the script rather than the test.

- `wrong-cn.pem` was deliberately built with `CN=tls-fixture` and `SAN=wrong-name`. 
Modern hostname verification ignores CN in favour of SAN, so this exercises the SAN mismatch path specifically rather than relying on legacy CN behaviour.
<br>

All leaves carry `basicConstraints CA:FALSE`, `keyUsage`, `extendedKeyUsage=serverAuth` and `subjectAltName`. 

The CA carries `basicConstraints CA:TRUE, pathlen:0` and `keyUsage keyCertSign+cRLSign`.

Generation prints every certificate's subject, issuer, validity window, SAN and EKU, ending with `All invariant assertions passed.`
<br>

### 2.8 Test-path verification results

**Both containers reached `healthy` at t=6 s under the test overlay.**

| Request | Result |
|---|---|
| `{"hostname":"tls-fixture"}` | `200`, `verified=true`, `hostname_verified=true`, `subject:"CN=tls-fixture"`, `issuer:"CN=tls-checker-test-ca"`, `error=null` |
| `{"hostname":"localhost"}` | `403`, `verified=null`, `error.kind="blocked_destination"`, message names `loopback` |
| `{"hostname":"example.com"}` | `200`, `verified=true`, Cloudflare issuer — normal path unaffected |
<br>

**Certificate-scenario verification, with the tri-state invariant preserved:**

| Fixture cert | HTTP | `verified` | `hostname_verified` | `error.kind` |
|---|---|---|---|---|
| `expired.pem` | 200 | `false` | `null` | `expired` |
| `wrong-cn.pem` | 200 | `false` | `false` | `hostname_mismatch` |
| `self-signed.pem` | 200 | `false` | `null` | `certificate_invalid` |
<br>

- `hostname_verified` is `false` **only** for `hostname_mismatch`.  
The other two fail at chain verification before any hostname check runs, which is why they report `null` rather than `false`.  
**This matches the invariant documented at Phase 5 and confirmed again at Phase 8.**

- Handshake-delay scenario: fixture recreated with `FIXTURE_HANDSHAKE_DELAY_MS=8000`, request returned `504 tls_timeout` in `real 0m5.052s`. 

- The 5 s elapsed is the configured `tls_handshake_timeout_seconds`, not the 10 s overall deadline and not the 8 s fixture delay; confirming the phase budget fires at the correct layer.

- Ten startup-probe runs, each with a deliberately broken configuration, returned container exit code `3` with a `ConfigError` traceback. 

- **No probe returned `124` (which would have indicated the process was still running; i.e. the invalid config had been accepted). 
Every invalid configuration aborts startup rather than serving traffic**.
<br>

### 2.9 Fixture capacity: verified as non-bottleneck

**Measured independently of the application, from a container attached only to `tls-fixture-net`, sharing one `SSLContext` to isolate fixture cost from client context setup:**

| Concurrency | Total handshakes | Successful | Failed | Wall | Handshakes/s |
|---|---|---|---|---|---|
| 50 | 500 | 500 | 0 | 0.28 s | 1758 |
| 100 | 1,000 | 1,000 | 0 | 0.48 s | 2074 |
| 200 | 2,000 | 2,000 | 0 | 0.93 s | **2146** |
| 500 | 5,000 | 5,000 | 0 | 3.02 s | 1654 |
<br>

Zero failures at every level.

**The c=500 throughput reduction (2146 → 1654 handshakes/s) may reflect client-side thread scheduling in the probe; 500 Python threads were contending on a 4-core host. This attribution was not independently verified.**

The fixture demonstrated approximately 1,650–2,150 successful handshakes/s in these tests, with zero failures. 

This provides substantial observed headroom over the application's approximately 117 RPS TLS throughput. 

**These measurements establish that the fixture was not a bottleneck in the application tests; they do not establish a hard fixture capacity ceiling.**
<br>

### 2.10 Commits

| Commit | Purpose |
|---|---|
| `289d421` | Test-mode configuration, SSRF exemption, additional CA trust (5 files, +346 lines) |
| `4887743` | Fixture container, certificate generator, Compose overlay (6 files, +425 lines) |
| `99bebf8` | Git placeholder for the ignored generated-certificate directory |

`99bebf8` exists because the root `.gitignore` covers `tests/fixture/certs/` as a whole path, which caused `git add` to skip the nested `.gitignore`; `git add -f` was used to track it explicitly so a fresh clone has the directory present with its defensive ignore rules.

----

## 3. Tools and method

### 3.1 Tools used

Custom Python probes. No external load-testing tool (`hey`, `vegeta`, `wrk`, `ab`, `locust`) was installed.

| Probe | Mode | Location | Purpose |
|---|---|---|---|
| `probe.py sweep` | fixed concurrency levels, fixed request count | WSL host | Step 1: concurrency sweep |
| `probe.py behavioural` | single batch at c=100 | WSL host | pool-size discrimination |
| `probe2.py sustained` | fixed concurrency, fixed wall-clock duration | WSL host, and once via `docker exec` | Steps 3a / 3b |
<br>

`hey`/`vegeta` were deferred until a test genuinely required rate-controlled mode. 

None did: a fixed-concurrency closed-loop probe answers the capacity question directly, and a rate-controlled probe would
have added a tool without changing the conclusion.
<br>

### 3.2 Methodological caveats

**Fresh connection per request.** 
- Every probe request opens a new HTTP connection. `hey`, `vegeta` and `wrk` pool connections by default. 
Results here are therefore **not directly comparable** to a pooled-client benchmark; pooled clients see lower per-request overhead and higher apparent throughput at the same server cost.
<br>

**Client location matters.**
-  A probe running on the host consumes host CPU.
A probe running via `docker exec` inside the app container consumes the same `NanoCpus: 1.0` budget that the server needs. 
This is called out explicitly wherever it applies.
<br>

**Measured versus derived.** 

Distinguishing them:

| Type | Examples |
|---|---|
| **Measured** | RPS, latency percentiles, HTTP status counts, `docker stats` samples, fixture handshake throughput, microbenchmark component timings |
| **Derived** | per-request cost (~8.5 ms), TLS-path delta (~7.2 ms), percentage attribution to `create_default_context` |

Every derived figure in this document is labelled as such at the point of use. 
None of them is instrumented per-request CPU measurement.

---

## 4. Verified concurrency model

Checked before any load was applied, because the predicted shape of the results depends on it.

| Property | Verified value | How |
|---|---|---|
| Uvicorn workers | **1** | `docker top`: PID 1 = `docker-init`, single `python -m uvicorn` child |
| `--workers` flag | absent | Dockerfile CMD |
| AnyIO default thread limiter | **40** | queried inside the running container via `asyncio.run(...)` wrapper |
| App-side thread pool overrides | **none** | `grep` across `app/` and `tests/` for `to_thread`, `thread_limiter`, `run_in_threadpool`, `CapacityLimiter` |
| DNS executor | 8 workers, 24 queue, 32 total pending | `app/netguard.py` constants |

`/check` is defined as a synchronous `def`, so Starlette dispatches it to the AnyIO worker thread pool rather than running it on the event loop.

Implication: at any concurrency above ~40, requests beyond the 40th are queued at the Starlette layer before reaching application code. 
Below 40, the pool is not the constraint.

---

## 5. Concurrency sweep (c = 1 … 100)

Each level used a fixed request count (`max(level × 20, 30)`), fresh connection per request, target `tls-fixture` with the valid certificate and no handshake delay.

| Concurrency | Requests | Wall | RPS | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | Errors |
|---|---|---|---|---|---|---|---|---|
| 1 | 30 | 0.26 s | 114 | 8.6 | 9.3 | 9.9 | 10.1 | 0 |
| 2 | 40 | 0.28 s | 142 | 11.3 | 35.5 | 42.1 | 42.5 | 0 |
| 5 | 100 | 0.85 s | 118 | 21.5 | 81.9 | 87.7 | 89.3 | 0 |
| 10 | 200 | 1.60 s | 125 | 89.1 | 106.8 | 165.7 | 190.6 | 0 |
| 20 | 400 | 3.32 s | 121 | 185.9 | 207.2 | 215.5 | 264.0 | 0 |
| 40 | 800 | 6.78 s | 118 | 325.8 | 502.0 | 567.8 | 584.9 | 0 |
| 60 | 1,200 | 10.08 s | 119 | 499.8 | 592.2 | 689.5 | 788.2 | 0 |
| 100 | 2,000 | 16.79 s | 119 | 817.6 | 986.7 | 1,086.5 | 1,194.4 | 0 |

The c=1 and c=2 results are based on small sample sizes and may reflect warm-up or measurement variability. 

The reason for the higher c=2 result was not isolated. From c=5 onward, throughput remains relatively stable.
<br>

### 5.1 Observation

**Throughput is flat at approximately 118–125 RPS across c=5 to c=100.** 

Adding concurrency beyond c=5 does not increase throughput; it increases latency approximately in proportion to the added concurrency. 

p50 rises from 21.5 ms at c=5 to 817.6 ms at c=100; a 38× latency increase for effectively zero throughput gain.
<br>

### 5.2 Interpretation: what the data supports and what it does not

**Supported:** the application reaches a throughput plateau at roughly 118–125 RPS on this container, and every concurrent request beyond the point of saturation is served later rather than faster.

**Supported:** the plateau is consistent with **CPU saturation at the container's `NanoCpus: 1.0` limit**. §6 confirms this directly; the app container's measured CPU utilisation is at or near 100% throughout the fixture and localhost tests. 

The plateaus for two different workloads (TLS-path ~117 RPS, HTTP-path ~750 RPS) are consistent with different per-request CPU costs under a one-CPU limit.
<br>

**Not supported and not claimed:** that requests are processed strictly one-at-a-time.

Multiple requests are in flight within the AnyIO worker pool throughout the sweep. What the data shows is that aggregate forward progress is bounded by one CPU share, and the resulting behaviour *resembles* single-service-point queuing at the level of the whole system.

The measurements support CPU saturation as the primary constraint. 
GIL contention may contribute, but was not independently measured. 

The precise location and mechanism of contention were not isolated.
<br>

**Not localised:** these measurements do not identify *where* queuing occurs. 
It could be in uvicorn's accept loop, in the AnyIO thread pool before dispatch, in GIL acquisition inside application code, or purely in the kernel scheduler. 

Distinguishing those would require profiling, which is out of Phase 9 scope.
<br>

### 5.3 Derived per-request cost

Arithmetic ceiling at CPU saturation:

```
1 CPU-second ÷ (1000 ms ÷ RPS-at-plateau)
= 1000 ms ÷ 119 RPS
= ~8.4 ms of CPU work per request
```

This is a **derived estimate from saturated throughput**, not an instrumented per-request CPU measurement. It is labelled `~8.5 ms` where it appears elsewhere in this document, and it is used only for order-of-magnitude comparison.

---

## 6. Target comparison: three different bottleneck classes

Same probe, same concurrency (c=50, or c=20 for the external target), four different request targets.
`docker stats` sampled during each run.

| Target | c | RPS | p50 (ms) | CPU | Status distribution | Bottleneck class |
|---|---|---|---|---|---|---|
| `tls-fixture` (local TLS) | 50 | **117** | 412 | **100–107%** | all 200 | CPU-bound at container limit |
| `localhost` (SSRF-blocked) | 50 | **750** | 64 | **101–103%** | all 403 `blocked_destination` | CPU-bound at container limit |
| `does-not-exist.invalid` (NXDOMAIN) | 50 | **746** | 23 | not sampled | 502 `dns_failure`: 3,216; 503 `dns_capacity_exceeded`: 11,837 | DNS capacity exhaustion observed; CPU utilisation not sampled |
| `example.com` (external TLS) | 20 | **85** | 215 | **78–91%** | all 200 | CPU headroom observed; network/latency contribution plausible but not isolated |
<br>

### 6.1 What this establishes

**The local paths are CPU-bound at the container limit.** 
Both the TLS path (`tls-fixture`) and the HTTP-only path (`localhost`) drive the container to 100% CPU. 

Two different workloads with different per-request costs produce two different plateaus — 117 RPS and 750 RPS — which is what a CPU-bound system does: plateau = 1 CPU-second ÷ per-request cost.

Derived per-request cost from these figures:

```
tls-fixture path:  1000 ms ÷ 117 RPS ≈ 8.5 ms  (derived)
localhost path:    1000 ms ÷ 750 RPS ≈ 1.33 ms (derived)
difference:                            ≈ 7.2 ms (derived)
```

Again: derived from throughput, not instrumented. 
Used to bracket where the TLS work sits, and taken up.
<br>

**The external path is not demonstrably CPU-bound at c=20.**
- `example.com` at c=20 produced 85 RPS against 78–91% CPU — the container had CPU headroom.
- This is consistent with network round-trip time and jitter contributing to the observed throughput and latency. The network was not independently isolated as the bottleneck.

**NXDOMAIN exposes DNS capacity behaviour**.
<br>

### 6.2 What this does not establish

These figures do not decompose per-request CPU into components. 
They also do not tell us whether 117 RPS is a "good" number; that is a product question, not a measurement question. 

---

## 7. TLS path component breakdown (microbenchmark)

A read-only microbenchmark run inside the app container against the fixture.
Single-threaded, no concurrent load, no application traffic. 

It measures the cost of individual TLS-path operations in isolation.

| Component | Operation measured | p50 (ms) | min | max | n |
|---|---|---|---|---|---|
| **A** `create_default_context` | construct `SSLContext` with the system CA bundle (~222 KB) loaded | **3.75** | 3.70 | 5.74 | 20 |
| **B** `load_verify_locations` | load the test CA PEM onto a fresh context | 0.14 | 0.13 | 2.53 | 20 |
| **C** full handshake | construct context + load CA + TCP connect + `wrap_socket` + `getpeercert` | 5.54 | 5.35 | 45.66 | 10 |
| **D** `parse_der` + extract | `x509.load_der_x509_certificate` then read subject, issuer, validity | **0.01** | 0.00 | 3.76 | 100 |
| **E** connect only | TCP connect to the fixture, no TLS | 0.44 | 0.30 | 6.27 | 20 |
<br>

Max values are dominated by first-call effects (lazy initialisation inside `cryptography` and OpenSSL, first-opened file descriptors). p50 is the meaningful figure.
<br>

### 7.1 Arithmetic decomposition of the measured handshake

The measured composite time can be expressed as:

```
A + B + (C − E − A − B) + E  
= 3.75 + 0.14 + 1.21 + 0.44  
= 5.54 ms

Observed C = 5.54 ms
```



Component D (DER parsing) is measured separately and is not part of C.

The 1.21 ms handshake remainder is calculated by subtracting A, B and E from C. It is not an independently measured component.
<br>

### 7.2 Headline finding

**`create_default_context()` at ~3.75 ms p50 is a significant per-request cost.** 

- The application calls it once per `/check` in `_collect_verified()` and then calls `wrap_socket` on it. 

- There is no caching: every request constructs a fresh `SSLContext`, which parses the system CA bundle from
scratch.

Against the derived 7.2 ms TLS-path delta from §6, `create_default_context` accounts for approximately 52%; but this percentage is an **estimate** built from one measured figure (3.75 ms in isolation) and one derived figure (7.2 ms from throughput). 

**Neither is an instrumented per-request measurement, and single-threaded microbenchmark cost is not necessarily the
same as the same operation's cost under thread contention.**
<br>

### 7.3 Unaccounted remainder

The microbenchmark components do not fully explain the derived 7.2 ms TLS-path delta. 

Approximately **1.65 ms remains unexplained**; about 23% of the delta.
<br>

Candidate contributors, listed without ranking and without evidence as to which (if any) dominate:

- HTTP-layer differences between a `200` response with populated certificate fields and a `403` response with all-null fields; richer Pydantic construction, a longer Phase 7 structured log line

- `netguard.resolve_and_validate()` including the fixture-exemption branch; the probe did not measure this at all

- GIL contention: the microbenchmark ran single-threaded, the application path runs in the AnyIO worker pool.

- Per-request object churn not represented in any component above.

- **Decomposing the remainder would require profiling, which is out of Phase 9 scope.** 
It is recorded here so the gap is visible rather than rounded away.
<br>

### 7.4 Correction to a prior estimate

Before running the microbenchmark, DER parsing was predicted to cost roughly 0.5–1.5 ms per request. 

Measured p50: **0.01 ms**. 

**That is 50–150× lower than predicted.**

The prediction was wrong; recorded as a correction, not as variance. 

`cryptography`'s DER parsing is effectively free at this scale, and any future optimisation effort should not start there.
<br>

### 7.5 Explicit non-conclusion

The finding in **7.2** does not justify a code change during Phase 9. 

`create_default_context()` is rebuilt per request by design at present, and any caching scheme would need to preserve the property that fixture certificate swaps are picked up on the next request without a restart; the expired/wrong-SAN/self-signed tests in **2.8** depend on that. 

A safe cache would likely need to be keyed on `additional_ca_file` path plus file mtime.

Not Phase 9 work; noted in **14** for future consideration.

---

## 8. Sustained load: 300 s at c=5 against tls-fixture

| Metric | Value |
|---|---|
| Duration | 300.02 s |
| Requests | 31,575 |
| RPS | **105** |
| p50 | 20.9 ms |
| p95 | 84.9 ms |
| p99 | 92.1 ms |
| min | 8.1 ms |
| max | 329.8 ms |
| Status distribution | all `200` |
| Errors | **0** |

Compared with the §5 sweep at the same concurrency (c=5 → 118 RPS,
p50 21.5 ms), throughput is ~11% lower and p50 is within 3%.
<br>

### 8.1 Two methodology caveats, stated plainly

**The probe ran via `docker exec` inside the app container.** 

Client threads and sockets therefore competed with the server for the same `NanoCpus: 1.0` budget. 

The client running inside the container may partly explain the ~11% RPS shortfall. The effect was not independently measured, so application degradation cannot be conclusively ruled out.

**§5**'s host-side probe result (118 RPS at c=5) is the cleaner figure for that concurrency.
<br>

**The resource sampler did not overlap the probe for the full window.** 

Background `docker stats` was started as part of the same block, but only 2 of 30 samples were captured while the probe was running; the remaining 28 were after the probe had returned. 

The samples that did capture load show ~98–99% CPU, 75.4–75.8 MiB memory and 22 PIDs. **This test therefore does
not provide a continuous 300-second resource curve.** 

Stated so the record does not imply a smoother measurement than was actually taken.
<br>

### 8.2 What this test does establish

- No error class appeared across 31,575 requests over five minutes.
  Not a `500`, not a `503`, not a `502`, not a timeout.

- Aggregate latency percentiles remained in the range consistent with §5's c=5 result.

- The test did not produce an observed container restart or application failure.
<br>

### 8.3 What this test does not establish

It does not establish the absence of a slow leak over hours. 

It does not establish a continuously-monitored resource envelope. It does not establish steady-state behaviour beyond five minutes. 

Each of those would require a longer test with continuous sampling, which was outside Phase 9's budget.

---

## 9. Overload and recovery

Two phases, back to back, no pause between them.

### **Phase 1: overload.** 

2,500 requests attempted through 25 sequential batches of 100 concurrent `curl` invocations. The command completed in 23 s, giving approximately 109 attempted requests/s.

The burst command discarded response bodies and HTTP status codes. Therefore, the test records 2,500 attempted requests and their completion time, but does not establish that all 2,500 returned HTTP 200.

The small shortfall against the 117–125 RPS plateau may reflect `curl` process fork overhead: 100 process spawns per batch. This attribution was not independently verified.
<br>

### **Phase 2:  immediate recovery.** 

Ten serial requests, started as soon as Phase 1 returned.

| Request | Latency | vs baseline (~8.6 ms, §5 c=1 p50) |
|---|---|---|
| 1 | 10.4 ms | +21% |
| 2 | 9.6 ms | +11% |
| 3 | 9.5 ms | +10% |
| 4 | 18.7 ms | +117% (outlier) |
| 5 | 10.1 ms | +18% |
| 6 | 10.3 ms | +20% |
| 7 | 12.0 ms | +40% |
| 8 | 9.9 ms | +15% |
| 9 | 10.2 ms | +19% |
| 10 | 9.8 ms | +14% |
<br>

All ten returned `200`. Container state before and after:

| Field | Before Phase 1 | After Phase 2 |
|---|---|---|
| Both containers | healthy | healthy |
| CPU | 0.16% | 0.16% |
| PIDs | 11 | 11 |
| Memory | 56.12 MiB | 62.56 MiB |
<br>

### 9.1 What this demonstrates

Recovery is immediate in the behavioural sense: the first request after the overload burst completed in 10.4 ms, providing evidence of immediate behavioural recovery.

The PID count returned to its pre-burst value of 11, indicating no observed lingering process/thread accumulation. File descriptor usage was not measured, so this test does not establish the absence of an FD leak.

Memory did not return to its pre-burst value; it increased from 56.12 MiB to 62.56 MiB.
<br>

### 9.2 What this does not demonstrate

**It does not demonstrate the absence of long-term resource retention.** 

A single burst followed by ten requests cannot distinguish "no retention" from "retention that would only matter after hours of repeated bursts". 

A proper soak or repeated-burst test would be required, and was not performed.
<br>

### 9.3 The CPU limit does not prevent overload

An important clarification, because it is easy to misread the earlier sections. 

`NanoCpus: 1.0` limits **processing throughput**. It does not prevent **incoming overload**. 

If a client sends a large number of concurrent requests, processing capacity remains bounded by the CPU allocation. 

Requests may queue, and latency can increase substantially. 

The exact number accepted and their eventual HTTP responses were not established by this test.

The container being "healthy" is not the same as the container keeping up.

---

## 10. DNS capacity behaviour

The NXDOMAIN test in §6 (`does-not-exist.invalid` at c=50) produced a mixed error profile across 15,053 requests:

| Status | Error kind | Count | Percentage |
|---|---|---|---|
| 502 | `dns_failure` | 3,216 | 21.4% |
| 503 | `dns_capacity_exceeded` | 11,837 | 78.6% |
<br>

### 10.1 This is designed behaviour

- `app/netguard.py` bounds DNS execution with a shared `ThreadPoolExecutor` (8 workers) and a `BoundedSemaphore` capped at 32 total pending operations (8 running + 24 queued). 
- Beyond 32 in-flight lookups, `_submit_dns()` raises `DnsCapacityExceeded` rather than allowing the queue to grow without bound.

	That maps to `503` via `_STATUS_BY_KIND`.

- The 78.6% figure reflects the ratio of requests arriving when the executor was already saturated. 

	At c=50, only 32 can be in flight; the other 18 concurrent requests, plus the sub-millisecond turnaround creating new ones, found the semaphore exhausted most of the time.
<br>

### 10.2 Error taxonomy for this document

Throughout this document, "error" is treated with a distinction that would otherwise be lost:

| Category | Examples | Meaning |
|---|---|---|
| **Designed capacity rejection** | `503 dns_capacity_exceeded` | DNS executor has reached its configured pending-operation limit |
| **Expected operational error responses** | `403 blocked_destination`, `502 dns_failure`, `504 tls_timeout` | Defined responses for blocked destinations, DNS failures or TLS timeouts |
| **Unexpected failure** | `500 unknown_error` | Unhandled application failure |


**No unexpected failure occurred in any test in this document.** 

Every non-200 response observed was a designed response.

---

## 11. Memory observations

Idle and under-load memory across the Phase 9 session:

| Context | Memory | Notes |
|---|---|---|
| Idle, session start | 46.2 MiB | before any load |
| Under load, c=50 fixture (§6) | 93.1–94.1 MiB | five samples |
| Under load, c=50 localhost (§6) | 90.4–94.8 MiB | five samples |
| Under load, c=20 external (§6) | 96.3–96.8 MiB | three samples |
| Under load, 300 s c=5 (§8) | 75.4–75.8 MiB | two captured samples |
| Idle, after §8 | 56.12 MiB | 28 idle samples, stable to 2 decimal places |
| Idle, after §9 | 62.56 MiB | single sample |

The trend is a rising idle baseline across the session: 46.2 → 56.1 → 62.6 MiB after successive load episodes. 

Under load, peaks sat at 90–97 MiB against the 256 MiB limit; maximum observed utilisation ~38%.
<br>

### 11.1 Recorded as an observation, with unresolved cause

**This is not a demonstrated memory leak.** 

The highest observed memory usage was approximately 97 MiB against the 256 MiB limit, leaving substantial observed headroom.

However, the idle floor moves upward across load episodes by 6–10 MiB each time and does not return fully to its prior value.
<br>

Candidate explanations, listed without claim of which (if any) applies:

- Python heap allocator (`pymalloc`) retaining freed small-object arenas  rather than returning them to the OS ; a well-known behaviour of CPython's allocator under bursty small-object workloads.

- Some genuine per-request retention; an object graph the application holds a reference to across requests.

- Non-Python allocations (OpenSSL context state, thread stacks) that are released slowly or not at all.

- Measurement artifacts: `docker stats` memory reporting is cgroup-level and can lag actual freed memory.
<br>

**Nothing in Phase 9 distinguishes these.**
 A targeted test; sustained load for hours with continuous sampling, or a garbage-collection probe; would be
required to establish a cause or a rate. 

That test was not performed and is recorded in **14** as an open question for future phases.

**No fix, no tuning, no code change proposed.**

---

## 12. Findings

### 12.1 CPU-bound throughput ceiling

Under `NanoCpus: 1.0`, the TLS-check path sustains approximately 118–125 RPS across all tested concurrency levels from c=5 to c=100, with latency increasing approximately in proportion to concurrency beyond the saturation point. 

This is a CPU-saturation plateau, not a serialisation lock: multiple requests are in flight throughout, and the plateau height scales with per-request cost (117 RPS for the TLS path, 750 RPS for the HTTP-only path).
<br>

### 12.2 `create_default_context()` is a significant per-request cost

Measured in isolation at ~3.75 ms p50. 

The application constructs a fresh `SSLContext` per `/check`, which parses the system CA bundle from scratch each time. 

**This is the single largest identified component of the TLS path, though the attribution of ~52% of the derived 7.2 ms delta is an estimate built from one measured and one derived figure, not a per-request
instrumented measurement.**
<br>

### 12.3 Approximately 1.65 ms of the TLS-path delta remains unexplained

The measured handshake time is 5.54 ms, while the throughput-derived TLS-path delta is approximately 7.2 ms. The microbenchmark does not independently account for the full delta.

Candidates are listed in §7.3; none is proven. Decomposing further would require profiling.
<br>

### 12.4 No unexpected error class appeared in any test

Observed non-200 responses fell into two expected categories: designed DNS capacity rejection (`503 dns_capacity_exceeded`) and operational error responses (`403 blocked_destination`, `502 dns_failure`, `504 tls_timeout`). 

No `500 unknown_error` was observed. See §10.2 for the classification.

The error-handling paths behaved as specified under load.
<br>

### 12.5 The container is CPU-throttled, not immune to overload

`NanoCpus: 1.0` bounds throughput. 

It does not prevent incoming requests from queueing or experiencing increased latency. 

The exact number of requests accepted and their eventual responses under a large concurrent burst were not established by Phase 9.

Server health and client-perceived latency are different signals.
<br>

### 12.6 External targets hit a different constraint

At c=20 against `example.com`, the container ran at 78–91% CPU — headroom remained. 


The observed CPU headroom is consistent with network round-trip time and jitter contributing to the external test's throughput and latency. The network was not independently isolated as the bottleneck.

The operational throughput for external checks may therefore differ from the internal-fixture results.
<br>

### 12.7 Recovery after overload is immediate in the behavioural sense

The first request after a 2,500-request burst completed in 10.4 ms with no error. 

This is evidence of immediate behavioural recovery in the observed requests, but does not establish the absence of all residual application or resource state.

It is not evidence of no *resource* carry-over; see **9.2** and **11**.

---

## 13. Rate limiting decision

**Not implemented during Phase 9.**

### 13.1 Reasoning grounded in measurement

- CPU at `NanoCpus: 1.0` already bounds processing throughput. The measured local TLS-check workload plateaued at approximately 118–125 RPS under the one-CPU limit. This is workload-specific, not a universal application throughput ceiling.

- DNS capacity already fails fast at 32 pending with `503`; this bounds pending DNS operations specifically, not overall application load.

- Overload recovery was immediate in the observed window, with no persistent behavioural degradation observed.

- Adding rate limiting now would impose a policy on a system without measurement showing a stability problem under the tested conditions.
<br>

### 13.2 Explicitly acknowledged gap

**Multi-client fairness was not tested.** 

Every test in this document used a single client from a single source address. Whether one aggressive client can starve other clients of the CPU budget under concurrent use is an open question. 

If it can, rate limiting becomes a fairness argument rather than a stability argument; but Phase 9 did not measure that case and this document does not claim it either way.
<br>

### 13.3 Recorded as a Phase 10 candidate

The fairness consideration is stated so the decision is revisitable on different evidence. 

The Phase 9 conclusion is narrow: **rate limiting is not required for stability under the measured conditions.** 

It is not a claim that rate limiting is never appropriate.

---

## 14. Open questions for later phases / further development

1. **Can `SSLContext` be cached safely?** 
	
	Would need a key that includes `additional_ca_file` path and its mtime, so that fixture certificate swaps are still picked up live. 

	Any cache that breaks the expired /  wrong-SAN / self-signed tests in **2.8** is incorrect.

2. **What causes the idle-memory drift?**
	
	46 → 56 → 63 MiB across load episodes. 
	
	A soak test with continuous sampling, or a GC probe, would distinguish allocator high-water-mark behaviour from a real leak.

3. **Does a longer soak reveal retention?** 
	
	The 300 s test in §8 was too short and the sampler did not overlap it fully. 
	
	A multi-hour run with continuous sampling would close both gaps.

4. **Multi-client fairness.** 
	
	What does one client's c=1,000 traffic do to a concurrent client running at c=5? 
	Not tested.

5. **What is the 1.65 ms unaccounted remainder in the TLS path?** 
	
	Requires profiling. Out of Phase 9 scope.

6. **Fixture SIGTERM handling.** 
	
	`docker compose down` takes the full 10 s grace period before SIGKILL (observed repeatedly during fixture work).

	Not a Phase 9 blocker; cert swaps use `--force-recreate` and bypass that path entirely; but a three-line signal handler in `server.py` would eliminate the 10 s cost whenever the fixture is next touched.

---

## 15. Appendix: evidence index

**Which measurement came from which run, and which figures are derived rather
than measured.**

| Section | Evidence source | Type |
|---|---|---|
| §1.4 | `git log --oneline -- compose.yaml` and `-- Dockerfile` | measured |
| §2.2–2.4 | `git show 289d421 -- app/`, line counts from `git show --stat` | measured |
| §2.7 | `tests/fixture/generate.sh` output, generator assertions | measured |
| §2.8 | `curl` against the running overlay, `real 0m5.052s` from `time` | measured |
| §2.8 (fails closed) | 10 `docker run` probes, exit code 3 | measured |
| §2.9 | Fixture capacity probe inside `tls-fixture-net` | measured |
| §4 | `docker top`, in-container `anyio` query, `grep` | measured |
| §5 | `probe.py sweep` from the WSL host | measured |
| §5.3 | 1000 ms ÷ 119 RPS | **derived** |
| §6 | `probe2.py sustained`, `docker stats` sampled concurrently | measured |
| §6.1 per-request costs | 1000 ms ÷ observed RPS | **derived** |
| §7 | Microbenchmark, five one-liner runs in the container | measured |
| §7.2 percentage | 3.75 ÷ 7.2 | **derived** (one measured ÷ one derived) |
| §8 | `probe2.py sustained` at c=5 for 300 s, via `docker exec` | measured (client in-container) |
| §8 resource envelope | `docker stats` — **only 2 of 30 samples captured load** | partial |
| §9 | `curl` batches, then 10 serial `curl` requests | measured |
| §10 | `probe2.py sustained` at c=50 against `does-not-exist.invalid` | measured |
| §11 | `docker stats` samples across the session | measured, single-timepoint |
<br>

#### **Known evidence gaps, stated so they are not mistaken for complete data:**

- The 300 s sustained-load resource curve is partial (§8.1).

- The unaccounted 1.65 ms TLS-path remainder has no measurement (§7.3).

- Memory cause is unresolved (§11.1).

- Multi-client fairness was never exercised (§13.2).
