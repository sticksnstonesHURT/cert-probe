# Cert Probe : development Makefile.
# Run `make` or `make help` for the target list.
#
# WORKFLOW
#   WSL Ubuntu ARM64 is the canonical development host and Git repository.
#   The Debian AMD64 VM is a simple deployment/validation target and has no Git.
#   `docker` is expected on PATH without sudo (member of the docker group).
#   Refer to `docs` for more relevant info.
#
# RECIPE PREFIX
#   `.RECIPEPREFIX := >` below switches the recipe prefix from TAB to `>`.
#   Copy-paste through shells and editors silently converts tabs to spaces,
#   producing "missing separator" errors. Using `>` makes the file immune.
#   To convert to standard tabs later: drop this line and run
#   `sed -i 's/^>/\t/' Makefile`.

.RECIPEPREFIX := >
.DEFAULT_GOAL  := help

SHELL   := /bin/bash
COMPOSE ?= docker compose
SERVICE := cert-probe
IMAGE   := cert-probe:dev

.PHONY: help check format test build rebuild up down restart ps logs shell \
        stats inspect smoke smoke-full verify clean nuke

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help:
>@echo ""
>@echo "Cert Probe — development commands"
>@echo ""
>@echo "Quality:"
>@echo "  make check        Lint, type-check, run tests"
>@echo "  make format       Auto-format (ruff format + ruff check --fix)"
>@echo "  make test         Run test suite only (excludes live tests)"
>@echo ""
>@echo "Image:"
>@echo "  make build        Build container image (cached)"
>@echo "  make rebuild      Build container image (no cache)"
>@echo ""
>@echo "Lifecycle:"
>@echo "  make up           Start service, wait for healthy"
>@echo "  make down         Stop and remove container + network"
>@echo "  make restart      Restart container, wait for healthy"
>@echo "  make ps           Container status"
>@echo ""
>@echo "Observability:"
>@echo "  make logs         Follow container logs"
>@echo "  make shell        Interactive shell inside container"
>@echo "  make stats        Single-snapshot resource usage"
>@echo "  make inspect      Show hardening settings"
>@echo ""
>@echo "Verification:"
>@echo "  make smoke        Deterministic endpoint checks (health, SSRF, 422)"
>@echo "  make smoke-full   smoke + one external host (informational, never fails)"
>@echo "  make verify       Full gate: check + build + up + smoke + down"
>@echo ""
>@echo "Cleanup:"
>@echo "  make clean        Remove container, network, compose image"
>@echo "  make nuke         Remove ALL cert-probe:* images (prompts for confirmation)"
>@echo ""

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

check:
>uv run ruff format --check .
>uv run ruff check .
>uv run mypy
>uv run pytest -q

format:
>uv run ruff format .
>uv run ruff check --fix .

test:
>uv run pytest -q

# ---------------------------------------------------------------------------
# Image
# ---------------------------------------------------------------------------

build:
>$(COMPOSE) build

rebuild:
>$(COMPOSE) build --no-cache

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

up:
>$(COMPOSE) up -d --no-build
>@printf 'waiting for healthy'
>@for i in $$(seq 1 30); do \
>  cid=$$($(COMPOSE) ps -q $(SERVICE) 2>/dev/null || true); \
>  if [ -z "$$cid" ]; then printf '.'; sleep 1; continue; fi; \
>  s=$$(docker inspect --format '{{.State.Health.Status}}' "$$cid" 2>/dev/null || echo missing); \
>  if [ "$$s" = healthy ]; then printf ' ok after %ss\n' "$$i"; exit 0; fi; \
>  printf '.'; sleep 1; \
>done; printf '\n'; echo 'FAILED: not healthy within 30 s' >&2; exit 1

down:
>$(COMPOSE) down

restart:
>$(COMPOSE) restart
>@printf 'waiting for healthy'
>@for i in $$(seq 1 30); do \
>  cid=$$($(COMPOSE) ps -q $(SERVICE) 2>/dev/null || true); \
>  if [ -z "$$cid" ]; then printf '.'; sleep 1; continue; fi; \
>  s=$$(docker inspect --format '{{.State.Health.Status}}' "$$cid" 2>/dev/null || echo missing); \
>  if [ "$$s" = healthy ]; then printf ' ok after %ss\n' "$$i"; exit 0; fi; \
>  printf '.'; sleep 1; \
>done; printf '\n'; echo 'FAILED: not healthy within 30 s' >&2; exit 1

ps:
>$(COMPOSE) ps

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

logs:
>$(COMPOSE) logs -f --tail=50 $(SERVICE)

shell:
>$(COMPOSE) exec $(SERVICE) sh

stats:
>@docker stats --no-stream $$($(COMPOSE) ps -q $(SERVICE))

inspect:
>@cid=$$($(COMPOSE) ps -q $(SERVICE) 2>/dev/null || true); \
>  if [ -z "$$cid" ]; then echo "no running container for service '$(SERVICE)'; run 'make up' first" >&2; exit 1; fi; \
>  docker inspect "$$cid" --format 'ReadonlyRootfs = {{.HostConfig.ReadonlyRootfs}}{{"\n"}}Memory         = {{.HostConfig.Memory}}{{"\n"}}NanoCpus       = {{.HostConfig.NanoCpus}}{{"\n"}}PidsLimit      = {{.HostConfig.PidsLimit}}{{"\n"}}CapDrop        = {{.HostConfig.CapDrop}}{{"\n"}}SecurityOpt    = {{.HostConfig.SecurityOpt}}{{"\n"}}Tmpfs          = {{.HostConfig.Tmpfs}}{{"\n"}}Init           = {{.HostConfig.Init}}{{"\n"}}RestartPolicy  = {{.HostConfig.RestartPolicy.Name}}{{"\n"}}User           = {{.Config.User}}{{"\n"}}Image          = {{.Config.Image}}'

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

smoke:
>@printf 'health... '
>@code=$$(curl -sS -o /tmp/cert-probe-smoke-health.json -w '%{http_code}' http://127.0.0.1:8000/health 2>/dev/null) || code=CONN_FAILED; \
>  if [ "$$code" = "200" ] && grep -q '"status":"ok"' /tmp/cert-probe-smoke-health.json; then \
>    echo 'OK (200, status:ok)'; \
>  else \
>    echo "FAIL (http=$$code)"; cat /tmp/cert-probe-smoke-health.json 2>/dev/null; echo; exit 1; \
>  fi
>@printf 'ssrf-guard (localhost)... '
>@code=$$(curl -sS -o /tmp/cert-probe-smoke-ssrf.json -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"hostname":"localhost"}' http://127.0.0.1:8000/check 2>/dev/null) || code=CONN_FAILED; \
>  if [ "$$code" = "403" ] && grep -q '"kind":"blocked_destination"' /tmp/cert-probe-smoke-ssrf.json; then \
>    echo 'OK (403, blocked_destination)'; \
>  else \
>    echo "FAIL (http=$$code)"; cat /tmp/cert-probe-smoke-ssrf.json 2>/dev/null; echo; exit 1; \
>  fi
>@printf 'validation (http://example.com)... '
>@code=$$(curl -sS -o /tmp/cert-probe-smoke-422.json -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"hostname":"http://example.com"}' http://127.0.0.1:8000/check 2>/dev/null) || code=CONN_FAILED; \
>  if [ "$$code" = "422" ] && grep -q '"kind":"validation_error"' /tmp/cert-probe-smoke-422.json; then \
>    echo 'OK (422, validation_error)'; \
>  else \
>    echo "FAIL (http=$$code)"; cat /tmp/cert-probe-smoke-422.json 2>/dev/null; echo; exit 1; \
>  fi

smoke-full: smoke
>@printf 'example.com (external TLS, informational)... '
>@out=$$(curl -sS --max-time 15 -X POST -H 'Content-Type: application/json' -d '{"hostname":"example.com"}' http://127.0.0.1:8000/check 2>&1); \
>  if echo "$$out" | grep -q '"verified":true'; then \
>    echo 'OBSERVED — external TLS returned verified:true'; \
>  else \
>    echo 'INFORMATIONAL — external TLS did not return verified:true'; \
>    echo '  smoke (deterministic, above) passed; this line does not gate.'; \
>    echo '  likely causes: badssl.com-class flake, DNS timeout, offline external network.'; \
>    echo "  response: $$(echo "$$out" | head -c 300)"; \
>  fi
>@echo 'smoke-full: informational target — exit code 0 regardless of external result'

verify:
>@echo "verify: stops at first failing step."
>@echo "verify: on success, container is cleaned up (make down) unless KEEP=1."
>@echo ""
>@echo ">>> [1/5] check"
>@$(MAKE) --no-print-directory check || { echo "verify: check failed — container not touched by verify"; exit 1; }
>@echo ">>> [2/5] build"
>@$(MAKE) --no-print-directory build || { echo "verify: build failed — container not touched by verify"; exit 1; }
>@echo ">>> [3/5] up"
>@$(MAKE) --no-print-directory up    || { echo "verify: up failed — container exists but is not healthy; run 'make ps' and 'make logs'"; exit 1; }
>@echo ">>> [4/5] smoke"
>@$(MAKE) --no-print-directory smoke || { echo "verify: smoke failed — container is running; run 'make logs' to inspect, 'make down' to clean up"; exit 1; }
>@echo ">>> [5/5] down"
>@if [ "$$KEEP" = "1" ]; then echo ">>> KEEP=1 — leaving container running"; else $(MAKE) --no-print-directory down; fi
>@echo ""
>@echo ">>> verify: PASS"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean:
>-$(COMPOSE) down --remove-orphans
>-docker rmi $(IMAGE)

nuke:
>@echo "WARNING: 'make nuke' will perform destructive cleanup on this host."
>@echo ""
>@echo "  Step 1 — docker compose down --remove-orphans"
>@echo "           removes containers belonging to this Compose project"
>@echo "           removes the project's Docker network"
>@echo "           does NOT touch containers/networks of other projects"
>@echo ""
>@echo "  Step 2 — docker rmi"
>@echo "           removes ALL images with repository name exactly 'cert-probe', any tag"
>@echo "           NOT removed: my-cert-probe:*, cert-probe-prod:*, foo/cert-probe:*"
>@echo ""
>@echo "Containers in project '$(SERVICE)':"
>@$(COMPOSE) ps -a --format '  {{.Name}}  {{.Status}}' || { echo "ABORT: preview failed — 'docker compose ps -a' returned an error" >&2; exit 1; }
>@echo ""
>@echo "Images matching 'cert-probe:*':"
>@imgs_all=$$(docker images --format '{{.Repository}}:{{.Tag}}') || { echo "ABORT: preview failed — 'docker images' returned an error" >&2; exit 1; }; imgs=$$(printf '%s\n' "$$imgs_all" | grep -E '^cert-probe:' || true); if [ -z "$$imgs" ]; then echo "  (none)"; else printf '%s\n' "$$imgs" | sed 's/^/  /'; fi
>@echo ""
>@if [ "$$FORCE" != "1" ]; then read -p "Continue? [y/N] " ans; [ "$$ans" = "y" ] || { echo "aborted — no changes made"; exit 0; }; fi; teardown_fail=""; echo ""; echo ">>> docker compose down --remove-orphans"; if ! $(COMPOSE) down --remove-orphans; then teardown_fail=1; echo "  WARNING: compose teardown failed — continuing to image cleanup"; fi; echo ""; echo ">>> docker rmi — cert-probe:*"; imgs_all=$$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null); imgs_rc=$$?; img_fail=""; if [ $$imgs_rc -ne 0 ]; then echo "  ERROR: 'docker images' failed (rc=$$imgs_rc)"; img_fail=" docker-images-unavailable"; else imgs=$$(printf '%s\n' "$$imgs_all" | grep -E '^cert-probe:' || true); if [ -z "$$imgs" ]; then echo "  (no matching images)"; else for img in $$imgs; do if docker rmi "$$img" >/dev/null 2>&1; then echo "  removed: $$img"; else echo "  FAILED:  $$img"; img_fail="$$img_fail $$img"; fi; done; fi; fi; echo ""; if [ -n "$$teardown_fail" ] || [ -n "$$img_fail" ]; then echo "nuke: INCOMPLETE"; if [ -n "$$teardown_fail" ]; then echo "  cause: compose teardown failed"; fi; if [ -n "$$img_fail" ]; then echo "  cause: failed image operations:$$img_fail"; fi; exit 1; fi; echo "nuke: complete"
