"""Data-plane rate limit + hard spend budget (finding C5, invariant 8).

The public data plane (/v1/chat, /vision, /embed, /batch, ...) had no per-caller
rate limit and no budget ceiling after the migration, so anyone with the URL
(and, once auth is on, anyone with the key) could drive unbounded requests and
run up cost on a shared account — DoS and denial-of-wallet. Invariant 8: every
run must have hard limits on time, tokens, tool calls, and cost.

Two independent guards, both in-process (single-writer gateway):

  * a sliding-60s request rate limit per caller (default 60/min), and
  * a hard daily request budget across the whole data plane (default 5000/day),

configurable via GLC_DATAPLANE_RPM and GLC_DATAPLANE_DAILY_BUDGET. When the
budget is exhausted the gateway returns 429 until the day rolls over. This is
the request-count ceiling; the token/cost ceiling rides on the per-call
validation in glc.db and the per-provider worker quotas.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class DataPlaneBudget:
    def __init__(self, rpm: int, daily_budget: int) -> None:
        self.rpm = rpm
        self.daily_budget = daily_budget
        self._per_caller: dict[str, deque[float]] = defaultdict(deque)
        self._day_start = self._today()
        self._day_count = 0
        self._lock = threading.Lock()

    @staticmethod
    def _today() -> float:
        now = time.time()
        return now - (now % 86400)

    def check(self, caller: str) -> None:
        now = time.time()
        with self._lock:
            # Daily budget rollover.
            if now - self._day_start >= 86400:
                self._day_start = self._today()
                self._day_count = 0
            if self._day_count >= self.daily_budget:
                raise HTTPException(
                    429, "data-plane daily budget exhausted; try again after reset"
                )
            # Per-caller sliding-minute rate.
            dq = self._per_caller[caller]
            cutoff = now - 60
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.rpm:
                raise HTTPException(429, f"rate limit {self.rpm}/min exceeded")
            dq.append(now)
            self._day_count += 1


_budget: DataPlaneBudget | None = None


def _get_budget() -> DataPlaneBudget:
    global _budget
    if _budget is None:
        _budget = DataPlaneBudget(
            rpm=int(os.getenv("GLC_DATAPLANE_RPM", "60")),
            daily_budget=int(os.getenv("GLC_DATAPLANE_DAILY_BUDGET", "5000")),
        )
    return _budget


def reset_budget_for_tests() -> None:
    global _budget
    _budget = None


async def enforce_budget(request: Request) -> None:
    """FastAPI dependency applied to the data plane. Caller identity is the
    bearer key (when auth is on) else the client host — enough to bound a
    single abuser without a full identity system."""
    if os.getenv("GLC_DATAPLANE_LIMITS", "1").strip() == "0":
        return
    auth = request.headers.get("authorization", "")
    caller = auth[-16:] if auth.startswith("Bearer ") else (request.client.host if request.client else "anon")
    _get_budget().check(caller)
