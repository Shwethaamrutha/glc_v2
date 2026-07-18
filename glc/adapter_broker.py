"""Adapter broker — the gateway side of the adapter-isolation boundary.

`RemoteAdapter` presents the same surface the gateway already calls on a
ChannelAdapter (`on_message(raw)`, `send(reply)`) but holds NO channel secret
and runs NONE of the adapter's code in-process. Each call is dispatched to an
isolated adapter worker that holds exactly that adapter's secret, over one of
two backends:

  * subprocess backend (default, locally deployable + testable): spawns
    `python -m glc.adapter_worker` with only that adapter's secret in its env
    (sourced from a per-adapter secret dir the gateway is NOT given as env).
    Proves the gateway process never imports or runs the adapter's code.

  * modal backend (production): calls a per-adapter Modal Sandbox Function,
    deployed with a single Secret and its own egress allowlist. Selected with
    GLC_ADAPTER_BACKEND=modal.

This closes the "multiple third-party adapters share one process" risk: a
malicious adapter can no longer read a sibling's token, the gateway's files,
or signal the gateway's PID, because it doesn't live in the gateway's process.
Its blast radius is its own container.

Enable with GLC_ISOLATED_ADAPTERS=1; the isolated set is declared explicitly
(the gateway has no secrets to probe) via GLC_ISOLATED_ADAPTER_LIST.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Per-adapter isolation registry. One entry per contributed adapter, declaring:
#   secrets: the credential env var(s) THAT adapter needs — only these are ever
#            handed to its worker, never a sibling's;
#   egress:  the hosts that adapter's worker may reach (its channel's API only);
#   pip:     extra deps beyond the base set (httpx/pydantic/pyyaml/jsonschema),
#            so a bug in one adapter never pulls in another's dependencies.
# This is the single source of truth for both the subprocess backend and the
# Modal Sandbox deploy (infra/modal_adapters.py imports it).
# ─────────────────────────────────────────────────────────────────────────────
ADAPTER_REGISTRY: dict[str, dict[str, Any]] = {
    "gmail": {
        "secrets": ["GMAIL_OAUTH_CLIENT_ID", "GMAIL_OAUTH_CLIENT_SECRET", "GMAIL_BOT_ADDRESS",
                    "GMAIL_PUBSUB_TOPIC", "GLC_GMAIL_OWNER"],
        "egress": "gmail.googleapis.com,oauth2.googleapis.com,www.googleapis.com,accounts.google.com",
        "pip": ["google-api-python-client>=2.0", "google-auth>=2.0", "google-auth-oauthlib>=1.0"],
    },
    "telegram": {
        "secrets": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_OWNER_ID"],
        "egress": "api.telegram.org",
        "pip": [],
    },
    "discord": {
        "secrets": ["DISCORD_BOT_TOKEN", "DISCORD_TEST_CHANNEL_ID", "DISCORD_TEST_USER_ID"],
        "egress": "discord.com,gateway.discord.gg",
        "pip": [],
    },
    "slack": {
        "secrets": ["SLACK_BOT_TOKEN", "SLACK_SIGNING_SECRET"],
        "egress": "api.slack.com,slack.com",
        "pip": [],
    },
    "whatsapp": {
        "secrets": ["WHATSAPP_TOKEN", "WHATSAPP_APP_SECRET", "WHATSAPP_VERIFY_TOKEN",
                    "WHATSAPP_PHONE_NUMBER_ID", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN",
                    "TWILIO_WHATSAPP_FROM"],
        "egress": "graph.facebook.com,api.twilio.com",
        "pip": ["python-dotenv>=1.0"],
    },
    "twilio_sms": {
        "secrets": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_PHONE_NUMBER",
                    "TWILIO_OWNER_NUMBER"],
        "egress": "api.twilio.com",
        "pip": ["python-dotenv>=1.0", "twilio>=9.0"],
    },
    "twilio_voice": {
        "secrets": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"],
        "egress": "api.twilio.com",
        "pip": ["twilio>=9.0"],
    },
    "line": {
        "secrets": ["LINE_CHANNEL_ACCESS_TOKEN", "LINE_CHANNEL_SECRET", "LINE_OWNER_USER_ID"],
        "egress": "api.line.me",
        "pip": [],
    },
    "teams": {
        "secrets": ["TEAMS_APP_ID", "TEAMS_APP_PASSWORD", "TEAMS_TENANT_ID"],
        "egress": "api.botframework.com,login.microsoftonline.com,smba.trafficmanager.net",
        "pip": [],
    },
    "matrix": {
        "secrets": ["MATRIX_HOMESERVER", "MATRIX_ACCESS_TOKEN", "MATRIX_BOT_MXID"],
        "egress": "matrix.org",
        "pip": [],
    },
    "signal": {
        "secrets": ["SIGNAL_CLI_URL", "SIGNAL_PHONE_NUMBER"],
        "egress": "",  # local signal-cli daemon; no fixed public host
        "pip": [],
    },
    "imap": {
        "secrets": ["IMAP_HOST", "IMAP_USER", "IMAP_PASSWORD", "SMTP_HOST", "SMTP_USER",
                    "SMTP_PASSWORD"],
        "egress": "",  # user-configured mail hosts; set per deployment
        "pip": [],
    },
    "webhook": {
        "secrets": ["WEBHOOK_SHARED_SECRET", "WEBHOOK_DEFAULT_TARGET_URL"],
        "egress": "",  # target host is per-deployment; set explicitly
        "pip": [],
    },
    "webui": {
        "secrets": [],
        "egress": "",  # browser client; no outbound
        "pip": [],
    },
    "local_mic": {
        "secrets": [],
        "egress": "",  # local audio device; no outbound
        "pip": [],
    },
}

# Back-compat views derived from the registry.
_ADAPTER_SECRET_ENV = {name: cfg["secrets"] for name, cfg in ADAPTER_REGISTRY.items()}
ADAPTER_EGRESS = {name: cfg["egress"] for name, cfg in ADAPTER_REGISTRY.items()}


def isolated_adapters() -> list[str]:
    raw = os.getenv("GLC_ISOLATED_ADAPTER_LIST", "").strip()
    if raw:
        return [a.strip() for a in raw.split(",") if a.strip()]
    return list(ADAPTER_REGISTRY.keys())


class RemoteAdapter:
    """Keyless stand-in for a ChannelAdapter. Same call surface, no secret,
    runs no adapter code in the gateway process."""

    def __init__(self, name: str) -> None:
        self.name = name

    async def on_message(self, raw: Any):
        from glc.channels.envelope import ChannelMessage

        resp = await _dispatch(self.name, {"adapter": self.name, "op": "on_message", "raw": raw})
        msg = resp.get("message")
        return ChannelMessage.model_validate(msg) if msg is not None else None

    async def send(self, reply) -> Any:
        payload = reply.model_dump(mode="json") if hasattr(reply, "model_dump") else reply
        resp = await _dispatch(self.name, {"adapter": self.name, "op": "send", "reply": payload})
        return resp.get("result")


class RemoteAdapterError(Exception):
    pass


async def _dispatch(adapter: str, req: dict) -> dict:
    backend = os.getenv("GLC_ADAPTER_BACKEND", "subprocess").strip()
    if backend == "modal":
        return await _dispatch_modal(adapter, req)
    return await _dispatch_subprocess(adapter, req)


def _read_adapter_secrets(adapter: str) -> dict[str, str]:
    """Read this adapter's secret(s) from a per-adapter secret directory the
    gateway is NOT given as env. Under Modal this is a per-adapter Secret
    mounted only into that adapter's Sandbox; locally it is files under
    GLC_ADAPTER_SECRETS_DIR/<adapter>/<ENV_NAME>. Absent -> empty (dev/mock)."""
    out: dict[str, str] = {}
    base = os.getenv("GLC_ADAPTER_SECRETS_DIR")
    if not base:
        return out
    d = Path(base) / adapter
    for env_name in _ADAPTER_SECRET_ENV.get(adapter, []):
        f = d / env_name
        if f.exists():
            out[env_name] = f.read_text().strip()
    return out


async def _dispatch_subprocess(adapter: str, req: dict) -> dict:
    child_env = {"PATH": os.getenv("PATH", ""), "HOME": os.getenv("HOME", "")}
    # Pass config dir (for pairing/trust lookups the adapter does) but NEVER
    # another adapter's secret and NEVER provider keys.
    if os.getenv("GLC_CONFIG_DIR"):
        child_env["GLC_CONFIG_DIR"] = os.environ["GLC_CONFIG_DIR"]
    # Confine the worker's own egress at the app layer too.
    child_env["GLC_EGRESS_ALLOWLIST"] = ADAPTER_EGRESS.get(adapter, "")
    child_env.update(_read_adapter_secrets(adapter))

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "glc.adapter_worker",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env=child_env,
    )
    out, err = await proc.communicate(json.dumps(req).encode())
    if proc.returncode != 0 and not out:
        raise RemoteAdapterError(f"adapter worker crashed: {err.decode()[:200]}")
    resp = json.loads(out.decode())
    if not resp.get("ok"):
        raise RemoteAdapterError(resp.get("error", "adapter worker error"))
    return resp


async def _dispatch_modal(adapter: str, req: dict) -> dict:
    import modal

    fn = modal.Function.from_name("glc-channel-adapters", f"adapter_{adapter}")
    resp = await fn.remote.aio(req)
    if not resp.get("ok"):
        raise RemoteAdapterError(resp.get("error", "adapter worker error"))
    return resp


def build_remote_adapters() -> dict[str, RemoteAdapter]:
    """Isolated-mode adapter registry: keyless RemoteAdapters. The gateway
    imports and runs none of the adapter code here."""
    return {name: RemoteAdapter(name) for name in isolated_adapters()}
