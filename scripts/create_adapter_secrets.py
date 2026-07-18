"""Create one Modal Secret per adapter with mock values (assignment mode).

Each adapter gets glc-adapter-<name> holding ONLY that adapter's credential
env vars, sourced from glc.adapter_broker.ADAPTER_REGISTRY (single source of
truth). Mock values keep real creds off the cloud, per the assignment.

Usage:
    uv run python scripts/create_adapter_secrets.py           # print commands
    uv run python scripts/create_adapter_secrets.py --run     # create them
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from glc.adapter_broker import ADAPTER_REGISTRY  # noqa: E402

# A few fields want a non-"mock-not-real" shape to satisfy light validation.
_SHAPED = {
    "TELEGRAM_OWNER_ID": "0",
    "GMAIL_BOT_ADDRESS": "bot@example.com",
    "MATRIX_HOMESERVER": "https://matrix.org",
    "SIGNAL_CLI_URL": "http://localhost:8080",
    "IMAP_HOST": "imap.example.com",
    "SMTP_HOST": "smtp.example.com",
    "WEBHOOK_DEFAULT_TARGET_URL": "https://example.com/hook",
}


def _mock_for(env_name: str) -> str:
    return _SHAPED.get(env_name, "mock-not-real")


def main() -> None:
    run = "--run" in sys.argv
    for name, cfg in ADAPTER_REGISTRY.items():
        secret_name = f"glc-adapter-{name}"
        pairs = [f"{k}={_mock_for(k)}" for k in cfg["secrets"]]
        # Modal requires at least one key; adapters with no secret get a marker.
        if not pairs:
            pairs = ["GLC_ADAPTER_NOOP=1"]
        cmd = ["modal", "secret", "create", "--force", secret_name, *pairs]
        print(" ".join(cmd))
        if run:
            subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
