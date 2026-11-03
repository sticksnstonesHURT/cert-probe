# Graceful shutdown: TLS Checker

Documentation of container shutdown behaviour.

Covers the signal path from `docker stop` to the uvicorn process, the behaviour of in-flight requests, the observable shutdown log sequence, and operational implications for the Compose-level stop timeout.

**Environment:** 
Ubuntu 24.04 LTS on WSL2, architecture `linux/arm64/v8`.

Container `tls-checker-tls-checker-1`, image `tls-checker:dev`, run under Compose with `init: true` and `restart: unless-stopped`. 

---

## 1. Signal path: from `docker stop` to uvicorn

The sequence serving `docker stop <container>`:
```
    docker stop
      |
      |--- dockerd sends SIGTERM to PID 1 (docker-init)
      |         |
      |         |--- docker-init forwards SIGTERM to its child (uvicorn)
      |                    |
      |                    |--- uvicorn's signal handler runs
      |                    |      -> stops accepting new connections
      |                    |      -> waits for connections to close ("drain")
      |                    |      -> runs FastAPI lifespan __aexit__
      |                    |      -> exits
      |                    |
      |                    |--- docker-init exits
      v
    dockerd waits up to stop timeout (default 10 s)
      |
      |--- if process has already exited: reports exit
      v
    if stop timeout expires before exit: send SIGKILL
      |
      v
    SIGKILL terminates remaining processes; container exits with code 137
```
<br>

Two points worth stating explicitly:

- **No `STOPSIGNAL` in the Dockerfile.** 
The image does not override the default stop signal, so `docker stop` sends SIGTERM. Verified by inspection of Dockerfile lines 21–79 in `docs/arm64-verification.md`  no `STOPSIGNAL` instruction present.

- **No `stop_signal:` override in `compose.yaml`.** 
Verified by direct inspection of the file at `8.3` commit (`8c5f58a`) plus the hardening additions (`47ba0dd`); neither added a `stop_signal:` key. 
Default SIGTERM applies.

---

## 2. PID 1 identity: non-root

From Test A (`docker top tls-checker-tls-checker-1`):
<br>

| UID | PID | PPID | CMD |
|---|---|---|---|
| 10001 | 685 | 662 | `/sbin/docker-init -- python -m uvicorn app.main:app --host 0.0.0.0 --port 8000` |
| 10001 | 731 | 685 | `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000` |

`/proc/1/comm` returns `docker-init`; `/proc/1/status` shows `Pid: 1`.
<br>

**PID 1 runs as UID 10001 (`app`), not as root.** Docker's `init: true` executes `docker-init` under the image's `USER` directive unless explicitly overridden. Since the runtime stage ends with `USER app` and Compose does not override `user:`, docker-init inherits UID 10001. 

Confirmed by `docker exec` inside the container:
```bash
    uid=10001(app) gid=10001(app) groups=10001(app)
```

This is stricter than the Phase 8.4 assumption. docker-init needs no privileges — its job is to be PID 1 (reap orphans, forward signals), which requires no capabilities. 

**Running as non-root preserves the`no-new-privileges:true` and `cap_drop: [ALL]` posture at PID 1 as well as at the app process.**
<br>

**Correction to handoff D4.** D4 text states *"Uvicorn is running as PID 2"*. In fact:

- Init is PID 1.

- Uvicorn is **PID 7** inside the container (from `Started server process [7]` in the log), which corresponds to **PID 731 on the WSL host**.

- PID 2 is never assigned to uvicorn; the kernel assigns process IDs based on the container's PID namespace at process spawn, and the init-plus-child fork gives the child PIDs 2 or higher depending on other transient forks during startup.

The *ordering* in D4 is correct (init is parent, uvicorn is child); only the specific PID number is wrong. 

Corrected here for the runbook.

---

## 3. Test A: process-tree baseline

Pre-shutdown state, before any stop test:
<br>

| Field | Observed |
|---|---|
| `state` | `running` |
| `health` | `healthy` |
| `StartedAt` | `2026-11-03T13:48:41.133519071Z` |
| `ExitCode` | `0` (running process reports 0 until exit) |
| `Init` | `true` |
| `RestartPolicy.Name` | `unless-stopped` |


**Baseline established: init is PID 1 (`docker-init`), uvicorn is the sole child, both under UID 10001, container healthy. All stop measurements compare against this topology.**

---

## 4. Test B: idle `docker stop`, default 10 s grace

**Setup:** 
fresh `docker compose up -d --no-build`, wait-for-healthy loop reached `healthy` at t=6 s, then a single `docker stop` with default `-t 10`.

**No concurrent load.**
<br>

| Field | Value |
|---|---|
| Pre-stop `State` / `Health` | `running` / `healthy` |
| `StartedAt` | `2026-11-03T13:55:54.167216956Z` |
| `stop_duration_s` | **0.530** |
| `ExitCode` | **143** |
| `OOMKilled` | `false` |
| `FinishedAt` | `2026-11-03T13:56:00.091414793Z` |
<br>

**Log sequence from the idle stop (verbatim, last four lines):**
```bash
    INFO:     Shutting down
    INFO:     Waiting for application shutdown.
    INFO:     Application shutdown complete.
    INFO:     Finished server process [7]
```

No `Waiting for connections to close` line — uvicorn only emits that when there are in-flight connections to drain. On an idle container there are none, so uvicorn proceeds directly from `Shutting down` to `Waiting for application shutdown`.

**Interpretation:** the container exited in 0.530 s, well within the 10 s grace period. SIGKILL was not needed. Uvicorn's signal handler ran to completion (four-line sequence present). This is the idle baseline against which Tests C and D measure the loaded case.

---

## 5. Test C: three concurrent requests, default 10 s grace

**Setup:** fresh start, wait-for-healthy, three concurrent `POST /check {"hostname":"expired.badssl.com"}` fired in the background, 1 s sleep, then `docker stop` (default `-t 10`) sent to the container.

Requests were still in-flight when SIGTERM arrived.
<br>

### Timing (Unix epoch)

| Event | Time | Delta from SIGTERM |
|---|---|---|
| Requests launched | 1793714339.418 | −1.005 s |
| SIGTERM (`stop_start`) | 1793714340.423 | 0.000 s |
| Last request completed | 1793714341.679 | **+1.256 s** |
| Uvicorn exited (`stop_end`) | 1793714341.968 | **+1.545 s** |
<br>

### Request outcomes

All three requests returned `rc=0`, `http_code=200`, and a complete response body. `duration_ms` values from the structured log: **2211, 2212, 2213 ms** — sub-millisecond spread, confirming parallel
in-flight processing.
<br>

Body content (head of the JSON, identical across all three requests):
```bash
    {"hostname":"expired.badssl.com","verified":false,
     "hostname_verified":null,
     "subject":"CN=*.badssl.com,OU=PositiveSSL Wildcard,OU=Domain Control Validated",
     "issuer":"CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB",
     "not_before":"2015-04-09T00:
    ...
```
<br>

Phase 5 unverified-fallback produced the cert metadata successfully under load, and Phase 6 SSRF protection did not interfere (badssl.com resolves to a globally-routable address, so no block).
<br>

### Container exit state

| Field | Value |
|---|---|
| `State` | `exited` |
| `ExitCode` | **143** |
| `OOMKilled` | `false` |
| `start_duration_s` | **1.545** |
<br>

### Log sequence
```bash
    INFO:     Shutting down
    INFO:     Waiting for connections to close. (CTRL+C to force quit)
    ts=2026-11-03T13:59:01.669Z level=INFO logger=app.main msg=check
      hostname=expired.badssl.com outcome=expired verified=False status=200
      duration_ms=2211 address_count=1 dns_duration_ms=161 method=POST path=/check
    ts=2026-11-03T13:59:01.670Z level=INFO logger=app.main msg=check
      hostname=expired.badssl.com outcome=expired verified=False status=200
      duration_ms=2212 address_count=1 dns_duration_ms=161 method=POST path=/check
    ts=2026-11-03T13:59:01.671Z level=INFO logger=app.main msg=check
      hostname=expired.badssl.com outcome=expired verified=False status=200
      duration_ms=2213 address_count=1 dns_duration_ms=161 method=POST path=/check
    INFO:     172.23.0.1:53094 - "POST /check HTTP/1.1" 200 OK
    INFO:     172.23.0.1:53076 - "POST /check HTTP/1.1" 200 OK
    INFO:     172.23.0.1:53078 - "POST /check HTTP/1.1" 200 OK
    INFO:     Waiting for application shutdown.
    INFO:     Application shutdown complete.
    INFO:     Finished server process [7]
```

The `Waiting for connections to close. (CTRL+C to force quit)` line is uvicorn's explicit drain-active signal; it appears between `Shutting down` and the completion of in-flight request processing, and does **not** appear in the idle case. 

Its presence is the direct evidence of drain in-progress.
<br>

**Interpretation:** 

SIGTERM arrived mid-request; uvicorn did not abort. 

Uvicorn waited 1.256 s for all three parallel requests to complete, then ran FastAPI lifespan `__aexit__`, then exited. 

Total `docker stop` duration 1.545 sl well within 10 s grace. SIGKILL not needed.

---

## 6. Test D: three concurrent requests, 2 s grace

**Setup:** identical to Test C — three concurrent `expired.badssl.com` requests fired, 1 s sleep, then `docker stop -t 2` (reduced grace). 

Purpose: probe the boundary between drain-succeeds and SIGKILL-escalation.
<br>

### Timing (Unix epoch)

| Event | Time | Delta from SIGTERM |
|---|---|---|
| Requests launched | 1793714572.704 | −1.005 s |
| SIGTERM (`stop_start`) | 1793714573.709 | 0.000 s |
| Last request completed | 1793714574.443 | **+0.734 s** |
| Uvicorn exited (`stop_end`) | 1793714574.710 | **+1.001 s** |
<br>

### Request outcomes

All three requests returned `rc=0`, `http_code=200`, complete bodies. `duration_ms` values: **1656, 1658, 1697 ms** — parallel, spread ~40 ms.
<br>

### Container exit state

| Field | Value |
|---|---|
| `State` | `exited` |
| `ExitCode` | **143** |
| `OOMKilled` | `false` |
| `stop_duration_s` | **1.001** |
<br>

### Log sequence
```bash
    INFO:     Shutting down
    INFO:     Waiting for connections to close. (CTRL+C to force quit)
    ... (three check log lines + three 200 OK lines) ...
    INFO:     Waiting for application shutdown.
    INFO:     Application shutdown complete.
    INFO:     Finished server process [7]
```

**Interpretation:** a 2 s grace period was sufficient for the tested workload. All three in-flight requests completed 0.734 s after SIGTERM, leaving ~1 s of unused grace. Exit code `143`, no SIGKILL. 
The `Waiting for connections to close` line again confirms drain-in-progress.

**Test D alone does not establish that 2 s is safe in general**; it establishes that it was sufficient for this specific run of this specific workload (`expired.badssl.com` with observed request duration ~1.7 s).
A slower external host or heavier concurrency would change the boundary.

---

## 7. Test D2 and D3: invalid for the intended purpose, recorded as startup-interruption

Two additional attempts were made to demonstrate SIGKILL escalation:

- **Test D2:** `docker stop -t 1` (1 s grace).

- **Test D3:** `docker stop -t 0` (0 s grace, meaning SIGTERM followed by immediate SIGKILL per Docker's `-t 0` semantics).
<br>

**Both were invalid as graceful-shutdown or SIGKILL-escalation tests.** 
They are recorded here as a distinct observation because what they actually demonstrate is informative, in its own right.
<br>

### What actually happened

In both D2 and D3, `docker compose up -d --no-build` was issued, then `docker compose ps` was queried, then `docker stop` was issued **without a wait-for-healthy step and without any in-flight load**. `docker compose ps` at the moment of stop reported:

```docker
    STATUS
    Up Less than a second (health: starting)
```

`docker stop` completed in **0.321 s** for D2 (measured via shell `time`), which is ~⅓ of the 1 s grace period — well before the timeout could be exceeded.
<br>

Post-stop state in both cases:

| Field | Value |
|---|---|
| `Status` | `exited` |
| `ExitCode` | **143** |
| `OOMKilled` | `false` |
| New lines in `docker logs` | **none** — the tail showed only Test D's 14:02 log lines |

The absence of any new shutdown log lines is decisive. 

- Uvicorn's signal handler installs `SIGTERM` handling during its startup sequence (before `Application startup complete`). In D2 and D3 the container was stopped before that handler was active. 
- The signal killed the Python process through the **default action for SIGTERM** — the process is terminated by the kernel, no Python code runs, no log output is produced. `docker-init` relays the child's exit and exits, `dockerd` reports `ExitCode=143`.
<br>

### What D2 and D3 actually demonstrate

- **SIGTERM during startup → immediate termination, no graceful shutdown log sequence.** 
The four-line sequence  (`Shutting down` → `Waiting for application shutdown.` → `Application shutdown complete.` → `Finished server process`) is entirely absent.

- **`docker stop -t 0` does not reliably produce SIGKILL.** In D3 the process exited on SIGTERM before SIGKILL could win the race. 
Exceeding the grace period requires the process to still be alive at grace-expiry; Python's default SIGTERM action killed it in 0.321 s, well before the zero-second grace period's SIGKILL step.
<br>

### Why they are not SIGKILL demonstrations

SIGKILL escalation requires:

1. Container healthy, **in-flight request active**.
2. SIGTERM sent.
3. Uvicorn enters `Waiting for connections to close` (drain phase).
4. Drain duration **exceeds** grace period.
5. SIGKILL fires at grace-expiry, producing `ExitCode=137` and a truncated log.

D2 and D3 never reached step 3. They are startup-interruption cases, not drain-exceeding cases. 

They inform the runbook (**do not `docker stop` a container within ~2 s of `docker compose up`** unless non-graceful termination is acceptable) but do not contribute evidence to SIGKILL escalation.

---

## 8. SIGKILL escalation — not demonstrated

**No SIGKILL was observed in any Phase 8.7 test.** 
Every observed exit produced `ExitCode=143`, and every graceful case (B, C, D) produced the full four-line shutdown sequence.

The structural reason SIGKILL was not demonstrated:

- Uvicorn drains in-flight requests quickly under the tested workload. 
Observed drain times after SIGTERM: **1.256 s** (Test C) and **0.734 s** (Test D).

- Grace periods shorter than drain time are rare; the drain is bounded by the request itself, and current request durations are ~1.7–2.2 s.

- Grace periods shorter than startup time (D2, D3) produce **startup-interruption**, not SIGKILL escalation, because Python's default SIGTERM action kills the process in ~0.3 s.

- The reliable window where SIGKILL wins requires: healthy container + slow-draining workload + grace period tightly between drain-time and worst-case-drain. 
That window was not reproducible in Phase 8.7.
<br>

**Demonstration options not taken:**

- `docker kill --signal=SIGKILL tls-checker-tls-checker-1` would show what a SIGKILL looks like (exit code, truncated log, in-flight request failures) but not Docker's escalation path; the escalation is what matters operationally, and that is what we cannot trigger reliably.
   
- A deliberately slow-draining workload (a test endpoint that holds the connection open) would allow deterministic escalation but requires application code change, which is out of Phase 8 scope (D10).
<br>

**Operational implication of not having demonstrated it:** the failure signature is documented from theory, and the passing cases (B, C, D) establish that SIGKILL is not *currently* needed under tested
load. 

If the deployment workload changes substantially; heavier concurrency, slower destinations; the observation should be re-established.

---

## 9. Exit code semantics — why 143 alone is insufficient

Exit code arithmetic: `docker stop` sends SIGTERM (signal 15); the container's exit code is `128 + signal_number = 128 + 15 = 143`. SIGKILL (signal 9) would yield `128 + 9 = 137`.

**However, exit code 143 does not distinguish graceful from non-graceful under SIGTERM.** 
<br>

Compare the three observed cases:

| Test | Exit | Shutdown log sequence |
|---|---|---|
| B (idle) | 143 | full four-line sequence present |
| C (2 concurrent in-flight) | 143 | full four-line sequence present |
| D (3 concurrent in-flight, 2 s grace) | 143 | full four-line sequence present |
| D2 (startup, 1 s grace) | 143 | **no shutdown lines** — died on default SIGTERM action |
| D3 (startup, 0 s grace) | 143 | **no shutdown lines** |

- In B, C, and D the process exited *after* uvicorn's SIGTERM handler ran. 

- In D2 and D3 the process exited *before* the handler was installed. 
Both produce 143 because the terminating signal is the same. **The log sequence is the discriminator, not the exit code.**
<br>

**The discriminating log lines:**

- `Shutting down` present → uvicorn's SIGTERM handler started.

- `Waiting for application shutdown.` present → drain finished (or none was needed), lifespan shutdown started.

- `Application shutdown complete.` present → FastAPI lifespan `__aexit__`  completed.

- `Finished server process [N]` present → uvicorn has fully exited.

If none of these appear but exit code is 143, the process was killed non-gracefully (startup race, or a signal arriving before uvicorn installed its handler). If exit code is 137, SIGKILL fired; drain exceeded grace.
<br>

*"container exits 0 within the stop timeout"*. 

**Actual graceful-exit code is `143`, not `0`.** 

The intent is satisfied; clean shutdown, no SIGKILL. 

The `0` expectation is not achievable with uvicorn's shutdown semantics (uvicorn re-raises SIGTERM after handler completion so the process's terminating signal is preserved in the exit status).

---

## 10. Operational implications

### 10.1 Default 10 s grace vs 10 s `overall_deadline`

Current compose configuration does **not** specify `stop_grace_period`. Docker's implicit default therefore applies: **10 seconds**; `dockerd` will send SIGKILL 10 s after SIGTERM if the process has not exited.

Application `overall_deadline` (per `app/config.py`, handoff): **10.0 seconds**. 

Each `/check` request can consume up to that budget on a fully-loaded path (three DNS/connect/handshake phases, total bounded by `min(phase, remaining)`).
<br>

**Worst-case shutdown: a `/check` request that entered just before SIGTERM
has up to 10.0 s of remaining work + practical overhead:**

| Component | Worst-case duration |
|---|---|
| Remaining `/check` work at moment of SIGTERM | up to 10.0 s |
| Uvicorn drain completion after last request finishes | ~0.1–0.3 s |
| FastAPI lifespan `__aexit__` | ~0.05 s |
| docker-init relay + dockerd bookkeeping | ~0.05 s |
| **Total worst case** | **~10.4–10.5 s** |
| **Docker grace period** | **10.0 s** |
<br>

**Consequence: at the exact worst-case boundary, SIGKILL could fire ~0.5 s before natural exit.** 
In every observed test the actual drain was far under this boundary (1.5 s in C, 1.0 s in D), so SIGKILL did not occur. 
But the theoretical worst case is that the default grace period is tight.
<br>

### 10.2 Documentation consideration; not a compose change request

This is a runbook note, not a request to modify `compose.yaml` at Phase 8. 
Phase 9 (deployment/runtime hardening) is the correct scope for a decision about `stop_grace_period` if one is to be made.
<br>

**Operational guidance to be recorded in the runbook (Phase 8.9):**

- The default `docker stop` grace period (10 s) is compatible with the application's `overall_deadline` (10.0 s) in normal operation, evidenced by Tests B, C, D.

- For a production deployment where `expired.badssl.com`-class latency overlaps with active requests at stop time, either:
  - increase `stop_grace_period` (e.g. `15s`) to give ≥4 s of headroom beyond the app's `overall_deadline`; **or**
  - reduce `/check` request concurrency expectation such that drain completes within the default.
- Never set `stop_grace_period` below `overall_deadline` (10 s). Anything shorter risks SIGKILL truncating active requests at grace-expiry.
- Compose default when `stop_grace_period` is not set: 10 s. 
Confirmed by Docker's documented default for `docker stop`, not by observing an untriggered timeout.
<br>

### 10.3 Startup-window note

Tests D2 and D3 show that `docker stop` within roughly the first 2 s after `docker compose up` produces non-graceful termination (container is still `health: starting`, uvicorn's SIGTERM handler is not yet installed).

For deployments or CI, this means:

- Wait for `docker inspect .State.Health.Status == "healthy"` before attempts to stop the container gracefully. `start_period: 5s` + `retries × interval` = ~35 s before an unhealthy container would be marked unhealthy; healthy is typically reached in ~6 s (observed consistently across B, C, D).

- Automated teardown should never `docker stop` a container that has been
  up less than the observed startup time (~6 s in this environment).

---

## 11. Auxiliary observation: restart policy survived VM power-off

**Not a controlled test; recorded as a side observation.**

> The container's `CREATED` timestamp was 26 hours prior to Test A, while `StartedAt` was ~1 minute previous. 

> The cause was reported by the operator as a WSL host power cycle (WSL VM shut down and restarted). 

> On WSL bring-up, `docker compose` state was retained and the container came up
under `restart: unless-stopped`, reaching `healthy`.
<br>

WSL VM shutdown is closer to a hard host kill than a graceful Docker daemon stop. 

Restart-policy recovery after VM-level shutdown is stronger evidence than recovery after `systemctl restart docker`, because it exercises the harder path. 

**This does not substitute for a graceful-shutdown test (which executes when `docker stop` is applied to a healthy container) but it corroborates that `restart: unless-stopped` recovers from unexpected host termination.**
<br>

Not re-verified: whether the container was gracefully stopped before the WSL shutdown (in which case `unless-stopped` would not have restarted it), or whether WSL/shutdown sent SIGTERM/SIGKILL through dockerd. 

**The observed result;  container running after power-cycle; is what `unless stopped` should produce either way, so this is consistent state, not diagnostic evidence.**

---

## 12. Known limitations

- **SIGKILL escalation not demonstrated.** No test produced `ExitCode=137`.

- **Only ARM64 WSL tested.** 
Graceful shutdown is architecture-agnostic (Docker's signal handling + Python's signal handling, not CPU-specific), so this is expected to be identical on AMD64. Not verified by re-running A–D on Debian.

- **Only `expired.badssl.com` used as the load request target.** 
Observed request durations 1.7–2.2 s. 
A slow external destination could extend drain duration and shift the boundary relative to default-grace analysis.

- **Only 3 concurrent requests tested.** 
Higher concurrency would extend drain because uvicorn's `Waiting for connections to close` completes only when the last connection finishes.

- **`google.com` / `example.com` / other fast destinations not used in shutdown tests.** 
Badssl.com was chosen because it exercises the unverified-fallback path; the slowest observed code path; which is approximately the worst case for drain. 
Faster destinations would drain faster but would not test the boundary.

- **Test D2 and D3 are invalid for their intended purpose.** 
Recorded in as startup-interruption cases, superseded by the SIGKILL-not-demonstrated status. 

- **Handoff corrections recorded.** (PID 1 non-root; PID number wrong); (exit code 143, not 0). 
These should be reflected in the Phase 8.9 runbook's handoff-accuracy section alongside the previously recorded `dns_duration_ms` discrepancy.

---

## 13. Summary table
<br>

| Test | Grace | Load | Exit | Shutdown log | Outcome |
|---|---|---|---|---|---|
| A | — | — | — | — | Baseline: init PID 1, non-root |
| B | 10 s (default) | idle | 143 | full four-line | Graceful, 0.530 s |
| C | 10 s (default) | 3× mid-flight | 143 | full four-line | Graceful, drain 1.256 s, total 1.545 s |
| D | 2 s (`-t 2`) | 3× mid-flight | 143 | full four-line | Graceful, drain 0.734 s, total 1.001 s |
| D2 | 1 s (`-t 1`) | none, startup | 143 | **none** | Startup-interruption, invalid for intended purpose |
| D3 | 0 s (`-t 0`) | none, startup | 143 | **none** | Startup-interruption, invalid for intended purpose |

*SIGKILL escalation (`ExitCode=137`): **not observed**.*
