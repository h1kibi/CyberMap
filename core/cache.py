"""Durable page cache: never pay the same engine twice for the same page.

Every engine here bills per request (FOFA quota, Shodan credits, Hunter points, Censys credits),
and a run that dies mid-flight - Ctrl-C, a crashed agent, a killed MCP host - used to lose
everything it had already paid for. Each fetched page is written to SQLite **as soon as it
arrives**, so a re-run with the same request reuses it instead of spending quota again.

Design notes:
- the key covers everything that changes the response (engine, query, page/size, cursor, and the
  engine-specific extras such as the requested fields and `full`), so different requests never
  share an entry;
- a hit is returned with ``consumed=0`` and ``metadata.cached=true`` so callers can show that no
  quota was burned, and ``metadata.cached_at`` keeps the original fetch time visible;
- entries expire after ``ttl_hours`` and the table is bounded by ``max_entries``;
- the cache stores only engine responses (never credentials or request parameters that carry a
  key), and the file is created with the same permissions as the job store.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.models import SearchPage, SearchRequest

DEFAULT_TTL_HOURS = 24.0
DEFAULT_MAX_ENTRIES = 5000
CACHE_FILENAME = "cybermap-cache.sqlite3"


@dataclass(frozen=True)
class CacheKey:
    """Everything that makes two requests interchangeable."""

    engine: str
    query: str
    page: int
    size: int
    extra: str = ""

    def digest(self) -> str:
        canonical = json.dumps(
            [self.engine, self.query, self.page, self.size, self.extra],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def request_cache_key(engine: str, request: SearchRequest, *, extra: str = "") -> CacheKey:
    """Key for one search page: page/cursor, size and the request-shaping extras."""
    page = 0 if request.cursor else request.page
    return CacheKey(
        engine=engine,
        query=request.query,
        page=page,
        size=request.size,
        extra=f"{request.cursor or ''}|{','.join(request.fields)}|{int(request.full)}|{extra}",
    )


def cached_page(page: dict[str, Any], *, cached_at: float) -> SearchPage:
    """Rebuild a stored page as a cache hit: no quota spent, age made visible."""
    restored = SearchPage.model_validate(page)
    metadata = dict(restored.metadata)
    metadata.update({"cached": True, "cached_at": cached_at})
    restored.metadata = metadata
    restored.consumed = 0
    return restored


class PageCache:
    """Small SQLite-backed page cache (one row per fetched page)."""

    def __init__(self, path: str | Path, *, ttl_hours: float = DEFAULT_TTL_HOURS, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self.path = Path(path).expanduser()
        self.ttl_seconds = max(60.0, float(ttl_hours) * 3600.0)
        self.max_entries = max(1, int(max_entries))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
        self.purge_expired()

    def _connect(self) -> sqlite3.Connection:
        # A connection per operation keeps this usable from any event loop/thread without a lock.
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        return connection

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS page_cache (
                    key TEXT PRIMARY KEY,
                    engine TEXT NOT NULL,
                    query TEXT NOT NULL,
                    page INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    cached_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS page_cache_expiry ON page_cache (expires_at)")

    def get_blob(self, key: CacheKey) -> tuple[dict[str, Any], float] | None:
        """Return the stored JSON payload and its fetch time, or None when absent/expired."""
        digest = key.digest()
        try:
            with self._connect() as connection:
                row = connection.execute("SELECT payload, cached_at, expires_at FROM page_cache WHERE key = ?", (digest,)).fetchone()
                if row is None:
                    return None
                if float(row["expires_at"]) <= time.time():
                    connection.execute("DELETE FROM page_cache WHERE key = ?", (digest,))
                    return None
        except sqlite3.Error:
            # A broken cache must never break a search: miss and continue.
            return None
        try:
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            self.delete(key)
            return None
        if not isinstance(payload, dict):
            self.delete(key)
            return None
        return payload, float(row["cached_at"])

    def get(self, key: CacheKey) -> SearchPage | None:
        """Return the stored page as a cache hit (``consumed=0``), or None."""
        blob = self.get_blob(key)
        if blob is None:
            return None
        payload, cached_at = blob
        try:
            return cached_page(payload, cached_at=cached_at)
        except ValueError:
            self.delete(key)
            return None

    def put(self, key: CacheKey, page: SearchPage) -> None:
        """Store one page immediately after it is fetched."""
        self.put_blob(key, page.model_dump(mode="json"))

    def put_blob(self, key: CacheKey, payload: dict[str, Any]) -> None:
        """Store one fetched payload immediately after it arrives."""
        now = time.time()
        payload = json.dumps(payload, ensure_ascii=False)
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO page_cache (key, engine, query, page, payload, cached_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        payload = excluded.payload,
                        cached_at = excluded.cached_at,
                        expires_at = excluded.expires_at
                    """,
                    (key.digest(), key.engine, key.query, key.page, payload, now, now + self.ttl_seconds),
                )
                self._trim(connection)
        except sqlite3.Error:
            return

    def delete(self, key: CacheKey) -> None:
        try:
            with self._connect() as connection:
                connection.execute("DELETE FROM page_cache WHERE key = ?", (key.digest(),))
        except sqlite3.Error:
            return

    def _trim(self, connection: sqlite3.Connection) -> None:
        """Keep the file bounded: drop the oldest rows beyond max_entries."""
        count = connection.execute("SELECT COUNT(*) FROM page_cache").fetchone()[0]
        if count <= self.max_entries:
            return
        connection.execute(
            """
            DELETE FROM page_cache WHERE key IN (
                SELECT key FROM page_cache ORDER BY cached_at ASC LIMIT ?
            )
            """,
            (count - self.max_entries,),
        )

    def clear(self) -> int:
        """Drop every entry (used by `--cache-clear`)."""
        try:
            with self._connect() as connection:
                cursor = connection.execute("DELETE FROM page_cache")
                return int(cursor.rowcount or 0)
        except sqlite3.Error:
            return 0

    def purge_expired(self) -> int:
        try:
            with self._connect() as connection:
                cursor = connection.execute("DELETE FROM page_cache WHERE expires_at <= ?", (time.time(),))
                return int(cursor.rowcount or 0)
        except sqlite3.Error:
            return 0

    def stats(self) -> dict[str, Any]:
        try:
            with self._connect() as connection:
                row = connection.execute("SELECT COUNT(*), MIN(cached_at), MAX(cached_at) FROM page_cache").fetchone()
        except sqlite3.Error:
            return {"entries": 0, "path": str(self.path)}
        return {
            "entries": int(row[0] or 0),
            "path": str(self.path),
            "oldest": row[1],
            "newest": row[2],
            "ttl_hours": round(self.ttl_seconds / 3600.0, 2),
        }


def disable_cache() -> None:
    """Turn the process-wide cache off (`--no-cache`): engines resolve None from then on."""
    global _CACHE, _CACHE_KEY
    from config import settings

    settings.cache.enabled = False
    _CACHE = None
    _CACHE_KEY = None


_CACHE: PageCache | None = None
_CACHE_KEY: str | None = None


def resolve_cache() -> PageCache | None:
    """Process-wide cache from `settings.cache` (None when disabled or unusable)."""
    global _CACHE, _CACHE_KEY
    from config import settings

    cache_settings = settings.cache
    if not cache_settings.enabled:
        return None
    path = cache_settings.path or CACHE_FILENAME
    key = f"{path}|{cache_settings.ttl_hours}|{cache_settings.max_entries}"
    if _CACHE is not None and _CACHE_KEY == key:
        return _CACHE
    try:
        _CACHE = PageCache(path, ttl_hours=cache_settings.ttl_hours, max_entries=cache_settings.max_entries)
        _CACHE_KEY = key
    except OSError:
        _CACHE = None
        _CACHE_KEY = None
    return _CACHE
