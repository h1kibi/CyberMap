"""Pacing and Retry-After policy shared by every asset search engine.

Only the pieces whose semantics must not drift between engines live here. Each
engine keeps its own retry loop because the error surfaces differ (FOFA answers
with `errmsg` payloads, Shodan with an `error` string on a non-200 status).
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

MAX_RETRY_DELAY = 30.0


class RateLimiter:
    """Serialize request starts so the engine never exceeds a fixed rate."""

    def __init__(self, requests_per_second: float):
        self._interval = 1.0 / requests_per_second
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if self._next > now:
                await asyncio.sleep(self._next - now)
            self._next = max(now, self._next) + self._interval


def retry_after_seconds(value: str | None, fallback: float) -> float:
    """Honor a Retry-After header as seconds or HTTP date, capped and never negative."""
    if value:
        try:
            return min(MAX_RETRY_DELAY, max(0.0, float(value.strip())))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(value)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                delay = (retry_at - datetime.now(timezone.utc)).total_seconds()
                return min(MAX_RETRY_DELAY, max(0.0, delay))
            except (TypeError, ValueError, OverflowError):
                pass
    return min(MAX_RETRY_DELAY, max(0.0, fallback))
