"""Isolated channel-adapter worker (invariant 1, weak-isolation hardening).

Adapters are third-party/contributed code (one PR per group) that glc_v1 runs
*inside the gateway's own process*: registry.discover() imports every adapter
module at boot and instantiate() constructs them in-process. That means a
malicious or buggy adapter runs with the gateway's authority — it can read
sibling adapters' in-memory state and channel tokens, read the gateway's files
(install token, pairing/audit DBs), signal the gateway's PID, or exhaust its
resources. None of that is stoppable from inside the same Python process.

This worker is the other side of an adapter-isolation boundary, built to the
same shape as glc.provider_worker: it runs as a SEPARATE process (a subprocess
locally, a Modal Sandbox with gVisor + egress allowlist in production), holds
ONLY that one adapter's channel secret (e.g. Gmail OAuth), and exposes the two
ChannelAdapter operations over a JSON stdin/stdout protocol:

  request  = {"adapter": "gmail", "op": "on_message", "raw": {...}}
           | {"adapter": "gmail", "op": "send", "reply": {...ChannelReply...}}
  response = {"ok": true, "message": {...ChannelMessage...} | null}   # on_message
           | {"ok": true, "result": <native send result>}            # send
           | {"ok": false, "error": "..."}

Because the adapter runs here and not in the gateway, its OAuth token, its
imported module code, and any bug in it are confined to this box.

Run as:  python -m glc.adapter_worker
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any


def _instantiate(adapter_name: str):
    """Build the one adapter this worker is for. Config is intentionally empty
    so the adapter uses its real (env/secret-backed) client, not a mock."""
    from glc.channels import registry

    return registry.instantiate(adapter_name)


async def _run(req: dict[str, Any]) -> dict[str, Any]:
    from glc.channels.envelope import ChannelReply

    adapter_name = req["adapter"]
    op = req["op"]
    try:
        adapter = _instantiate(adapter_name)
        if op == "on_message":
            msg = await adapter.on_message(req.get("raw"))
            return {"ok": True, "message": (msg.model_dump(mode="json") if msg is not None else None)}
        if op == "send":
            reply = ChannelReply.model_validate(req["reply"])
            result = await adapter.send(reply)
            return {"ok": True, "result": result}
        return {"ok": False, "error": f"unknown op {op!r}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def main() -> None:
    raw = sys.stdin.read()
    try:
        req = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        sys.stdout.write(json.dumps({"ok": False, "error": f"bad request json: {e}"}))
        return
    resp = asyncio.run(_run(req))
    sys.stdout.write(json.dumps(resp, default=str))


if __name__ == "__main__":
    main()
