"""Full-text search over generated newspaper articles.

Indexes only article text (headline, blurb, section) from archived editions —
not the much larger operational data (bans, logs) stored alongside them — using
SQLite FTS5. The index is rebuilt lazily when the archive index file is newer
than the stored search database, which happens once per day after the archive
worker writes a new edition.
"""

import logging
import os
import sqlite3
from typing import Any

from storage import load_json


log = logging.getLogger(__name__)


def ensure_index(db_path: str, archive_dir: str, archive_index_path: str) -> None:
    """Rebuild DB_PATH's article index when ARCHIVE_INDEX_PATH is newer than it."""
    index = load_json(archive_index_path)
    if not index:
        return
    try:
        if os.path.exists(db_path) and os.path.getmtime(db_path) >= os.path.getmtime(archive_index_path):
            return
    except OSError as error:
        log.warning("Failed to stat search index at %s: %s", db_path, error)
    try:
        _rebuild_index(db_path, archive_dir, index)
    except (OSError, sqlite3.Error) as error:
        log.warning("Failed to rebuild search index at %s: %s", db_path, error)


def _rebuild_index(db_path: str, archive_dir: str, index: list[dict]) -> None:
    temp_path = f"{db_path}.tmp"
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass
    connection = sqlite3.connect(temp_path)
    try:
        connection.execute("CREATE VIRTUAL TABLE articles USING fts5(date, headline, blurb, section)")
        for entry in index:
            date = entry.get("date")
            if not date:
                continue
            record = load_json(os.path.join(archive_dir, f"{date}.json")) or {}
            for article in record.get("newspaper") or []:
                connection.execute(
                    "INSERT INTO articles (date, headline, blurb, section) VALUES (?, ?, ?, ?)",
                    (date, article.get("headline", ""), article.get("blurb", ""), article.get("section", "")),
                )
        connection.commit()
    finally:
        connection.close()
    os.replace(temp_path, db_path)


def _fts_query(query: str) -> str:
    """Turn free text into a safe FTS5 MATCH expression (AND of quoted terms)."""
    terms = query.split()
    return " AND ".join('"' + term.replace('"', '""') + '"' for term in terms)


def search_archive(db_path: str, query: str, limit: int = 25) -> list[dict[str, Any]]:
    """Return archived articles matching QUERY, most recent edition first."""
    if not query.strip() or not os.path.exists(db_path):
        return []
    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT date, headline, blurb, section FROM articles "
            "WHERE articles MATCH ? ORDER BY date DESC LIMIT ?",
            (_fts_query(query), limit),
        ).fetchall()
    except sqlite3.OperationalError as error:
        log.warning("Search query failed against %s: %s", db_path, error)
        return []
    finally:
        connection.close()
    return [{"date": r[0], "headline": r[1], "blurb": r[2], "section": r[3]} for r in rows]


def search_current_articles(articles: list[dict], query: str) -> list[dict]:
    """Return ARTICLES whose headline, blurb, or section contains QUERY (case-insensitive)."""
    needle = query.strip().lower()
    if not needle:
        return []
    return [
        article for article in articles
        if needle in str(article.get("headline", "")).lower()
        or needle in str(article.get("blurb", "")).lower()
        or needle in str(article.get("section", "")).lower()
    ]
