"""C5 (invariant 8): the data plane enforces a per-caller rate limit and a hard
daily request budget."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from glc.security.budget import DataPlaneBudget


def test_per_caller_rate_limit():
    b = DataPlaneBudget(rpm=3, daily_budget=1000)
    for _ in range(3):
        b.check("caller-1")
    with pytest.raises(HTTPException) as ei:
        b.check("caller-1")
    assert ei.value.status_code == 429


def test_callers_are_independent():
    b = DataPlaneBudget(rpm=2, daily_budget=1000)
    b.check("a")
    b.check("a")
    # A different caller still has its own budget.
    b.check("b")


def test_daily_budget_ceiling():
    b = DataPlaneBudget(rpm=1000, daily_budget=5)
    for _ in range(5):
        b.check(f"caller-{_}")  # spread across callers so rpm never trips
    with pytest.raises(HTTPException) as ei:
        b.check("caller-x")
    assert "daily budget" in str(ei.value.detail)
