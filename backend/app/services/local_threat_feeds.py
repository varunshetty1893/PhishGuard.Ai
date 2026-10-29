import asyncio
import logging
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.services.threat_types import ThreatProviderResult

logger = logging.getLogger("phishguard.local_threat_feeds")

_FEEDS = {
    "openphish_urls": (
        "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
        "url",
    ),
    "phishing_database_urls": (
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "url",
    ),
    "phishing_database_domains": (
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "domain",
    ),
}
_REFRESH_INTERVAL_SECONDS = 6 * 60 * 60
_REFRESH_RETRY_SECONDS = 15 * 60
_MAX_FEED_AGE_SECONDS = 24 * 60 * 60
_DB_PATH = Path(__file__).resolve().parents[2] / "threat-feeds.sqlite3"
_refresh_task: Optional[asyncio.Task] = None
_last_refresh_attempt = 0.0
_refresh_status: Dict[str, str] = {}


def _url_key(value: str) -> Optional[str]:
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return None
        hostname = parsed.hostname.lower().rstrip(".")
        port = parsed.port
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        if port and port != (80 if parsed.scheme.lower() == "http" else 443):
            netloc = f"{netloc}:{port}"
        path = parsed.path or "/"
        if path == "/" and not parsed.query:
            path = ""
        return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    except ValueError:
        return None


def _domain_key(value: str) -> Optional[str]:
    candidate = value.strip().lower().rstrip(".")
    if "://" in candidate:
        try:
            candidate = urlsplit(candidate).hostname or ""
        except ValueError:
            return None
    candidate = candidate.removeprefix("*.").removeprefix(".")
    if not candidate or any(char.isspace() for char in candidate) or "/" in candidate:
        return None
    return candidate


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(_DB_PATH, timeout=30)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS feed_entries (feed_key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (feed_key, value))"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS feed_metadata (feed_key TEXT PRIMARY KEY, etag TEXT, refreshed_at REAL NOT NULL, entry_count INTEGER NOT NULL)"
    )
    return connection


def _cached_feed_metadata() -> Dict[str, Tuple[Optional[str], float, int]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT feed_key, etag, refreshed_at, entry_count FROM feed_metadata"
        ).fetchall()
    return {key: (etag, timestamp, count) for key, etag, timestamp, count in rows}


def _refresh_one(client: httpx.Client, feed_key: str, url: str, kind: str) -> None:
    metadata = _cached_feed_metadata().get(feed_key)
    headers = {"If-None-Match": metadata[0]} if metadata and metadata[0] else {}
    with client.stream("GET", url, headers=headers) as response:
        if response.status_code == 304 and metadata:
            with _connect() as connection:
                connection.execute(
                    "UPDATE feed_metadata SET refreshed_at = ? WHERE feed_key = ?",
                    (time.time(), feed_key),
                )
            _refresh_status[feed_key] = f"Ready ({metadata[2]:,} entries; unchanged)"
            return
        response.raise_for_status()
        etag = response.headers.get("ETag")
        with _connect() as connection:
            connection.execute("CREATE TEMP TABLE feed_staging (value TEXT PRIMARY KEY)")
            pending = []
            for line in response.iter_lines():
                if not line or line.lstrip().startswith("#"):
                    continue
                normalized = _url_key(line) if kind == "url" else _domain_key(line)
                if normalized:
                    pending.append((normalized,))
                if len(pending) >= 5000:
                    connection.executemany(
                        "INSERT OR IGNORE INTO feed_staging (value) VALUES (?)", pending
                    )
                    pending.clear()
            if pending:
                connection.executemany(
                    "INSERT OR IGNORE INTO feed_staging (value) VALUES (?)", pending
                )
            actual_count = connection.execute(
                "SELECT COUNT(*) FROM feed_staging"
            ).fetchone()[0]
            if actual_count == 0:
                raise ValueError(f"{feed_key} feed was empty or had no valid entries")
            connection.commit()
            connection.execute("BEGIN")
            connection.execute("DELETE FROM feed_entries WHERE feed_key = ?", (feed_key,))
            connection.execute(
                "INSERT INTO feed_entries (feed_key, value) SELECT ?, value FROM feed_staging",
                (feed_key,),
            )
            connection.execute(
                "INSERT OR REPLACE INTO feed_metadata (feed_key, etag, refreshed_at, entry_count) VALUES (?, ?, ?, ?)",
                (feed_key, etag, time.time(), actual_count),
            )
        _refresh_status[feed_key] = f"Ready ({actual_count:,} entries)"


def _refresh_feeds() -> None:
    timeout = httpx.Timeout(connect=10, read=90, write=10, pool=10)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for feed_key, (url, kind) in _FEEDS.items():
            try:
                _refresh_one(client, feed_key, url, kind)
            except Exception as error:
                logger.warning("Failed to refresh %s feed: %s", feed_key, error)
                _refresh_status[feed_key] = "Unavailable"


def _schedule_refresh() -> None:
    global _refresh_task, _last_refresh_attempt
    now = time.time()
    if _refresh_task is not None and not _refresh_task.done():
        return
    if now - _last_refresh_attempt < _REFRESH_RETRY_SECONDS:
        return
    metadata = _cached_feed_metadata()
    if metadata and all(
        key in metadata and now - metadata[key][1] < _REFRESH_INTERVAL_SECONDS
        for key in _FEEDS
    ):
        return
    _last_refresh_attempt = now
    for key in _FEEDS:
        _refresh_status[key] = "Refreshing"
    _refresh_task = asyncio.create_task(asyncio.to_thread(_refresh_feeds))


def start_feed_refresh() -> None:
    """Begin refreshing public feeds during application startup."""
    _schedule_refresh()


def _lookup(feed_keys: Tuple[str, ...], url: str, host: str) -> Tuple[bool, bool, str]:
    try:
        metadata = _cached_feed_metadata()
    except sqlite3.Error as error:
        logger.error("Could not read local phishing-feed cache: %s", error)
        return False, False, "Local feed cache is unavailable."
    available_keys = [key for key in feed_keys if key in metadata]
    if not available_keys:
        return False, False, "Threat feed is still downloading or unavailable."

    placeholders = ",".join("?" for _ in available_keys)
    candidates = []
    current_host = host.lower().rstrip(".")
    while current_host and "." in current_host:
        candidates.append(current_host)
        current_host = current_host.partition(".")[2]
    with _connect() as connection:
        url_match = connection.execute(
            f"SELECT 1 FROM feed_entries WHERE feed_key IN ({placeholders}) AND value = ? LIMIT 1",
            (*available_keys, url),
        ).fetchone()
        if url_match:
            return True, True, "Exact URL match in the downloaded threat feed."
        domain_keys = [key for key in available_keys if key.endswith("_domains")]
        if domain_keys and candidates:
            domain_placeholders = ",".join("?" for _ in domain_keys)
            domain_match = connection.execute(
                f"SELECT value FROM feed_entries WHERE feed_key IN ({domain_placeholders}) AND value IN ({','.join('?' for _ in candidates)}) LIMIT 1",
                (*domain_keys, *candidates),
            ).fetchone()
            if domain_match:
                return True, True, f"Domain match in the downloaded threat feed: {domain_match[0]}."

    oldest_refresh = min(metadata[key][1] for key in available_keys)
    if len(available_keys) != len(feed_keys) or time.time() - oldest_refresh > _MAX_FEED_AGE_SECONDS:
        return False, False, "Threat feed cache is incomplete or too old to confirm a clean result."
    counts = ", ".join(f"{key}: {metadata[key][2]:,}" for key in available_keys)
    return False, True, f"No match in local feed cache ({counts})."


async def check_openphish(url: str) -> ThreatProviderResult:
    _schedule_refresh()
    normalized_url = _url_key(url)
    if not normalized_url:
        return ThreatProviderResult("Inconclusive", details="URL could not be normalized for feed lookup.")
    parts = urlsplit(normalized_url)
    match, available, details = await asyncio.to_thread(
        _lookup, ("openphish_urls",), normalized_url, parts.hostname or ""
    )
    return ThreatProviderResult(
        status="Threat Reported" if match else "No Match Reported" if available else "Unavailable",
        threat_found=match,
        category="PHISHING" if match else None,
        details=details,
    )


async def check_phishing_database(url: str) -> ThreatProviderResult:
    _schedule_refresh()
    normalized_url = _url_key(url)
    if not normalized_url:
        return ThreatProviderResult("Inconclusive", details="URL could not be normalized for feed lookup.")
    parts = urlsplit(normalized_url)
    match, available, details = await asyncio.to_thread(
        _lookup,
        ("phishing_database_urls", "phishing_database_domains"),
        normalized_url,
        parts.hostname or "",
    )
    return ThreatProviderResult(
        status="Threat Reported" if match else "No Match Reported" if available else "Unavailable",
        threat_found=match,
        category="PHISHING" if match else None,
        details=details,
    )


def get_feed_status() -> Dict[str, str]:
    try:
        metadata = _cached_feed_metadata()
    except sqlite3.Error:
        metadata = {}
    result = {}
    for key in _FEEDS:
        if _refresh_status.get(key) == "Refreshing":
            result[key] = "Refreshing"
        elif key in metadata:
            age = time.time() - metadata[key][1]
            result[key] = (
                f"Ready ({metadata[key][2]:,} entries)"
                if age <= _MAX_FEED_AGE_SECONDS
                else "Stale (refresh pending)"
            )
        else:
            result[key] = _refresh_status.get(key, "Not Loaded")
    return result
