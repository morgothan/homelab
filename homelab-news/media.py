"""Media-domain operations and the hourly recent-media snapshot worker.

The first half of this module is the portable media domain: Seerr event loading,
Radarr/Sonarr/Jellyfin recent-media discovery, library-addition article assembly,
and Jellyfin link resolution. The second half is the supervisord ``media`` worker
that refreshes the Entertainment page's recent-media snapshot once per hour.
"""

import asyncio
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from config import (
    JELLYFIN_KEY, JELLYFIN_URL, JELLYFIN_WEB_URL,
    MEDIA_EVENTS_FILE, MEDIA_LINKS_FILE, RADARR_API_KEY, RADARR_URL,
    RECENT_MEDIA_FILE, SEERR_SETTINGS_FILE, SONARR_API_KEY, SONARR_URL,
)
from homelab_news.jellyfin import authorization_headers as jellyfin_auth_headers
from storage import load_json, save_json

log = logging.getLogger(__name__)


def load_media_events(since: datetime) -> list[dict]:
    """Return Seerr webhook events received within the requested news window."""
    events = load_json(MEDIA_EVENTS_FILE) or []
    since_utc = since.astimezone(timezone.utc)
    recent: list[dict] = []
    for event in events:
        try:
            received = datetime.fromisoformat(event["received_at"].replace("Z", "+00:00"))
            if received.tzinfo is None:
                received = received.replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            continue
        if received >= since_utc:
            recent.append(event)
    return recent


def _jellyfin_item_subject(item: dict) -> str:
    """Return a human-readable title for a Jellyfin movie or episode."""
    name = str(item.get("Name") or "Untitled").strip()
    if item.get("Type") == "Episode":
        series = str(item.get("SeriesName") or "Unknown series").strip()
        season = item.get("ParentIndexNumber")
        episode = item.get("IndexNumber")
        number = ""
        if isinstance(season, int) and isinstance(episode, int):
            number = f" S{season:02d}E{episode:02d}"
        return f"{series}{number} — {name}"
    year = item.get("ProductionYear")
    return f"{name} ({year})" if isinstance(year, int) else name


async def _fetch_recent_jellyfin_media(since: datetime) -> list[dict]:
    """Query Jellyfin by DateCreated as a fallback media source.

    Seerr availability notifications do not cover new episodes, direct imports,
    or items Seerr already considered available. Jellyfin's DateCreated is the
    authoritative timestamp for when an item entered the library.
    """
    if not JELLYFIN_URL or not JELLYFIN_KEY:
        return load_media_events(since)

    since_utc = since.astimezone(timezone.utc)
    headers = jellyfin_auth_headers(JELLYFIN_KEY)
    params = {
        "Recursive": "true",
        "IncludeItemTypes": "Movie,Episode",
        "Fields": "DateCreated,ProductionYear,SeriesName,ParentIndexNumber,IndexNumber",
        "SortBy": "DateCreated",
        "SortOrder": "Descending",
        "StartIndex": 0,
        "Limit": 500,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            info = await client.get(f"{JELLYFIN_URL}/System/Info", headers=headers)
            info.raise_for_status()
            server_id = str(info.json().get("Id") or "")
            response = await client.get(
                f"{JELLYFIN_URL}/Items", headers=headers, params=params,
            )
            response.raise_for_status()
            items = response.json().get("Items", [])
    except Exception as e:
        log.warning("Recent Jellyfin media query failed; using Seerr events: %s", e)
        return load_media_events(since)

    recent: list[dict] = []
    for item in items:
        try:
            created = datetime.fromisoformat(
                str(item["DateCreated"]).replace("Z", "+00:00")
            )
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            continue
        if created < since_utc:
            continue
        recent.append({
            "received_at": created.astimezone(timezone.utc).isoformat(),
            "notification_type": "MEDIA_AVAILABLE",
            "event": "Jellyfin Library Item Added",
            "subject": _jellyfin_item_subject(item),
            "item_id": str(item.get("Id") or ""),
            "server_id": server_id,
            "media": {"mediaType": str(item.get("Type") or "").lower()},
        })
    return recent


async def _fetch_arr_history(
    base_url: str, api_key: str, since: datetime, kind: str,
) -> list[dict]:
    """Return non-upgrade import records from one Radarr/Sonarr history."""
    since_utc = since.astimezone(timezone.utc)
    records: list[dict] = []
    page = 1
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            params = {
                "page": page,
                "pageSize": 500,
                "sortKey": "date",
                "sortDirection": "descending",
            }
            if kind == "movie":
                params["includeMovie"] = "true"
            else:
                params["includeSeries"] = "true"
                params["includeEpisode"] = "true"
            response = await client.get(
                f"{base_url}/api/v3/history",
                headers={"X-Api-Key": api_key},
                params=params,
            )
            response.raise_for_status()
            batch = response.json().get("records", [])
            if not batch:
                break
            reached_window_start = False
            for record in batch:
                try:
                    event_date = datetime.fromisoformat(
                        str(record["date"]).replace("Z", "+00:00")
                    )
                    if event_date.tzinfo is None:
                        event_date = event_date.replace(tzinfo=timezone.utc)
                except (KeyError, TypeError, ValueError):
                    continue
                if event_date < since_utc:
                    reached_window_start = True
                    continue
                records.append(record)
            if reached_window_start or len(batch) < 500:
                break
            page += 1

    id_key = "movieId" if kind == "movie" else "episodeId"
    delete_type = "movieFileDeleted" if kind == "movie" else "episodeFileDeleted"
    upgrades = {
        (record.get(id_key), record.get("date"))
        for record in records
        if record.get("eventType") == delete_type
        and str((record.get("data") or {}).get("reason", "")).lower() == "upgrade"
    }

    # History is newest first. Replacing a value as we iterate leaves the first
    # genuine import in the window when duplicate/redownload events exist.
    additions: dict[object, dict] = {}
    for record in records:
        if record.get("eventType") != "downloadFolderImported":
            continue
        identity = record.get(id_key)
        if not identity or (identity, record.get("date")) in upgrades:
            continue
        if kind == "movie":
            movie = record.get("movie") or {}
            title = str(movie.get("title") or record.get("sourceTitle") or "Untitled").strip()
            year = movie.get("year")
            subject = f"{title} ({year})" if isinstance(year, int) else title
            lookup_title = title
        else:
            series = record.get("series") or {}
            episode = record.get("episode") or {}
            series_title = str(series.get("title") or "Unknown series").strip()
            episode_title = str(episode.get("title") or record.get("sourceTitle") or "Untitled").strip()
            season = episode.get("seasonNumber")
            number = episode.get("episodeNumber")
            code = f" S{season:02d}E{number:02d}" if isinstance(season, int) and isinstance(number, int) else ""
            subject = f"{series_title}{code} — {episode_title}"
            lookup_title = series_title
        additions[identity] = {
            "received_at": record.get("date"),
            "notification_type": "MEDIA_AVAILABLE",
            "event": f"{kind.title()} Download Imported",
            "subject": subject,
            "lookup_title": lookup_title,
            "media": {"mediaType": kind},
        }
    return list(additions.values())


async def fetch_recent_media(since: datetime) -> list[dict]:
    """Return genuinely new Radarr/Sonarr imports, with safe fallbacks."""
    radarr_url, radarr_key = RADARR_URL, RADARR_API_KEY
    sonarr_url, sonarr_key = SONARR_URL, SONARR_API_KEY
    if SEERR_SETTINGS_FILE and (not radarr_key or not sonarr_key):
        settings = load_json(SEERR_SETTINGS_FILE) or {}
        for kind in ("radarr", "sonarr"):
            entries = settings.get(kind) or []
            if not entries or not isinstance(entries[0], dict):
                continue
            config = entries[0]
            scheme = "https" if config.get("useSsl") else "http"
            base = str(config.get("baseUrl") or "").strip("/")
            url = f'{scheme}://{config.get("hostname")}:{config.get("port")}'
            if base:
                url += f"/{base}"
            if kind == "radarr" and not radarr_key:
                radarr_url, radarr_key = url, str(config.get("apiKey") or "")
            elif kind == "sonarr" and not sonarr_key:
                sonarr_url, sonarr_key = url, str(config.get("apiKey") or "")
    sources = []
    if radarr_url and radarr_key:
        sources.append(_fetch_arr_history(radarr_url, radarr_key, since, "movie"))
    if sonarr_url and sonarr_key:
        sources.append(_fetch_arr_history(sonarr_url, sonarr_key, since, "episode"))
    if not sources:
        return await _fetch_recent_jellyfin_media(since)

    results = await asyncio.gather(*sources, return_exceptions=True)
    events: list[dict] = []
    for result in results:
        if isinstance(result, Exception):
            log.warning("Radarr/Sonarr history query failed: %s", result)
        else:
            events.extend(result)
    if not events and all(isinstance(result, Exception) for result in results):
        return await _fetch_recent_jellyfin_media(since)
    return sorted(events, key=lambda event: str(event.get("received_at") or ""), reverse=True)


def build_library_additions_article(media_events: list[dict]) -> Optional[dict]:
    """Build one deterministic Arts & Entertainment story from availability events."""
    titles = library_addition_titles(media_events)
    if not titles:
        return None

    count = len(titles)
    summaries = library_addition_summaries(media_events)
    return {
        "headline": f"{count} New Library Addition{'s' if count != 1 else ''}",
        "blurb": "Now available: " + "; ".join(summaries) + ".",
        "media_additions": summaries,
        "section": "Arts & Entertainment",
        "source": "seerr-library-additions",
    }


def library_addition_titles(media_events: list[dict]) -> list[str]:
    """Return unique titles from Seerr availability events, in arrival order."""
    titles: list[str] = []
    seen: set[str] = set()
    for event in media_events:
        event_type = " ".join((
            str(event.get("notification_type", "")),
            str(event.get("event", "")),
        )).lower()
        if "available" not in event_type and "imported" not in event_type:
            continue
        title = str(event.get("subject", "")).strip()
        if not title or title.casefold() in seen:
            continue
        seen.add(title.casefold())
        titles.append(title)
    return titles


def library_addition_summaries(media_events: list[dict]) -> list[str]:
    """Compact multiple episode additions from one series for bulletin cards."""
    entries: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    for event in media_events:
        event_type = " ".join((
            str(event.get("notification_type", "")),
            str(event.get("event", "")),
        )).lower()
        if "available" not in event_type and "imported" not in event_type:
            continue
        title = str(event.get("subject") or "").strip()
        if not title or title.casefold() in seen:
            continue
        seen.add(title.casefold())
        media_type = str((event.get("media") or {}).get("mediaType") or "").lower()
        series = str(event.get("lookup_title") or "").strip()
        entries.append((title, series, media_type == "episode" and bool(series)))

    episode_counts: dict[str, int] = defaultdict(int)
    for _, series, is_episode in entries:
        if is_episode:
            key = series.casefold()
            episode_counts[key] += 1

    summaries: list[str] = []
    emitted_series: set[str] = set()
    for title, series, is_episode in entries:
        if not is_episode:
            summaries.append(title)
            continue
        key = series.casefold()
        if key in emitted_series:
            continue
        emitted_series.add(key)
        count = episode_counts[key]
        summaries.append(
            f"{count} new episodes of {series}" if count > 1 else title
        )
    return summaries


async def resolve_jellyfin_links(media_events: list[dict]) -> dict[str, str]:
    """Resolve availability-event titles to cached Jellyfin web detail URLs."""
    titles = library_addition_titles(media_events)
    if not titles or not JELLYFIN_URL or not JELLYFIN_KEY or not JELLYFIN_WEB_URL:
        return {}

    cache = load_json(MEDIA_LINKS_FILE) or {}
    if not isinstance(cache, dict):
        cache = {}
    links: dict[str, str] = {}
    unresolved: list[str] = []
    events_by_title = {
        str(event.get("subject") or "").strip(): event for event in media_events
    }
    for title in titles:
        event = events_by_title.get(title, {})
        if event.get("item_id") and event.get("server_id"):
            links[title] = (
                f'{JELLYFIN_WEB_URL}/web/#/details?id={event["item_id"]}'
                f'&serverId={event["server_id"]}'
            )
            continue
        cached = cache.get(title.casefold())
        if isinstance(cached, dict) and cached.get("item_id") and cached.get("server_id"):
            links[title] = (
                f'{JELLYFIN_WEB_URL}/web/#/details?id={cached["item_id"]}'
                f'&serverId={cached["server_id"]}'
            )
        else:
            unresolved.append(title)
    if not unresolved:
        return links

    headers = jellyfin_auth_headers(JELLYFIN_KEY)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            info_response = await client.get(f"{JELLYFIN_URL}/System/Info", headers=headers)
            info_response.raise_for_status()
            server_id = str(info_response.json().get("Id") or "")
            if not server_id:
                return links

            for subject in unresolved:
                event = events_by_title.get(subject, {})
                lookup_title = str(event.get("lookup_title") or subject).strip()
                match = re.fullmatch(r"(.+?)\s*\((\d{4})\)", lookup_title)
                episode_match = re.fullmatch(
                    r"(.+?)\s+S(\d+)E(\d+)\s+[—-]\s+(.+)", subject,
                    flags=re.IGNORECASE,
                )
                search_title = (
                    episode_match.group(4).strip() if episode_match
                    else match.group(1).strip() if match else lookup_title
                )
                expected_year = int(match.group(2)) if match else None
                response = await client.get(
                    f"{JELLYFIN_URL}/Items",
                    headers=headers,
                    params={
                        "SearchTerm": search_title,
                        "Recursive": "true",
                        "IncludeItemTypes": "Movie,Series,Episode",
                        "Fields": (
                            "ProductionYear,SeriesName,ParentIndexNumber,IndexNumber"
                        ),
                        "Limit": "25",
                    },
                )
                response.raise_for_status()
                if episode_match:
                    expected_series = episode_match.group(1).strip().casefold()
                    expected_season = int(episode_match.group(2))
                    expected_episode = int(episode_match.group(3))
                    candidates = [
                        item for item in response.json().get("Items", [])
                        if item.get("Type") == "Episode"
                        and str(item.get("SeriesName") or "").strip().casefold()
                        == expected_series
                        and item.get("ParentIndexNumber") == expected_season
                        and item.get("IndexNumber") == expected_episode
                    ]
                    # Some libraries contain episodes with broken Name metadata
                    # (for example, several NOVA specials are named only "NOVA").
                    # When a title search cannot find them, locate the unique
                    # series and retrieve the episode by its season coordinates.
                    if not candidates:
                        series_response = await client.get(
                            f"{JELLYFIN_URL}/Items",
                            headers=headers,
                            params={
                                "SearchTerm": episode_match.group(1).strip(),
                                "Recursive": "true",
                                "IncludeItemTypes": "Series",
                                "Fields": "ProductionYear",
                                "Limit": "25",
                            },
                        )
                        series_response.raise_for_status()
                        series_candidates = [
                            item for item in series_response.json().get("Items", [])
                            if item.get("Type") == "Series"
                            and str(item.get("Name") or "").strip().casefold()
                            == expected_series
                            and item.get("Id")
                        ]
                        if len(series_candidates) == 1:
                            episode_response = await client.get(
                                f"{JELLYFIN_URL}/Shows/{series_candidates[0]['Id']}/Episodes",
                                headers=headers,
                                params={
                                    "Fields": "SeriesName,ParentIndexNumber,IndexNumber",
                                    "Season": expected_season,
                                    "Limit": "1000",
                                },
                            )
                            episode_response.raise_for_status()
                            candidates = [
                                item for item in episode_response.json().get("Items", [])
                                if item.get("Type") == "Episode"
                                and item.get("ParentIndexNumber") == expected_season
                                and item.get("IndexNumber") == expected_episode
                            ]
                else:
                    candidates = [
                        item for item in response.json().get("Items", [])
                        if str(item.get("Name") or "").strip().casefold()
                        == search_title.casefold()
                    ]
                if expected_year is not None:
                    year_matches = [item for item in candidates
                                    if item.get("ProductionYear") == expected_year]
                    if year_matches:
                        candidates = year_matches
                if len(candidates) != 1 or not candidates[0].get("Id"):
                    log.info("Jellyfin link unresolved or ambiguous for %r (%d matches)",
                             subject, len(candidates))
                    continue
                item_id = str(candidates[0]["Id"])
                cache[subject.casefold()] = {
                    "item_id": item_id,
                    "server_id": server_id,
                    "resolved_at": datetime.now(timezone.utc).isoformat(),
                }
                links[subject] = (
                    f"{JELLYFIN_WEB_URL}/web/#/details?id={item_id}&serverId={server_id}"
                )
    except Exception as e:
        log.warning("Jellyfin link resolution failed: %s", e)
        return links

    save_json(MEDIA_LINKS_FILE, cache)
    return links


def merge_library_additions(articles: list[dict], media_events: list[dict]) -> list[dict]:
    """Replace the prior additions card and put the current one first in Arts."""
    merged = [a for a in articles if a.get("source") != "seerr-library-additions"]
    addition = build_library_additions_article(media_events)
    if addition:
        insert_at = next(
            (i for i, article in enumerate(merged)
             if article.get("section", "").strip() == "Arts & Entertainment"),
            len(merged),
        )
        merged.insert(insert_at, addition)
    return merged


# ── Hourly recent-media snapshot worker (supervisord: media) ──────────────────


async def refresh_recent_media() -> None:
    """Fetch the rolling seven-day list and atomically publish its snapshot."""
    started = datetime.now(timezone.utc)
    events = await fetch_recent_media(started - timedelta(days=7))
    links = await resolve_jellyfin_links(events)
    save_json(RECENT_MEDIA_FILE, {
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "media_events": events,
        "media_links": links,
    })
    log.info("Recent-media snapshot refreshed (%d items, %d links)",
             len(events), len(links))


def seconds_until_next_hour(now: datetime | None = None) -> float:
    """Return seconds until the next UTC hour boundary."""
    current = now or datetime.now(timezone.utc)
    next_hour = current.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    return (next_hour - current).total_seconds()


async def main() -> None:
    from homelab_news.configuration import APP_SETTINGS

    if not APP_SETTINGS.features.media:
        log.info("Media feature disabled by configuration")
        await asyncio.Event().wait()
        return
    try:
        await refresh_recent_media()
    except Exception:
        log.exception("Initial recent-media refresh failed")

    while True:
        await asyncio.sleep(seconds_until_next_hour())
        try:
            await refresh_recent_media()
        except Exception:
            # Keep the last good snapshot available and try again next hour.
            log.exception("Recent-media refresh failed; retaining previous snapshot")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncio.run(main())
