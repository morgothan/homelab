"""Complete, boundary-safe Loki range collection."""

from datetime import datetime
from typing import Any

import httpx

from .base import CollectionResult


class LokiCollector:
    name = "loki"

    def __init__(self, base_url: str, query: str, *, page_size: int = 5000,
                 max_depth: int = 64, max_requests: int = 4096):
        self.base_url = base_url.rstrip("/")
        self.query = query
        self.page_size = page_size
        self.max_depth = max_depth
        self.max_requests = max_requests

    async def collect(self, start: datetime, end: datetime) -> CollectionResult:
        """Collect an inclusive datetime window using a managed HTTP client."""
        start_ns = int(start.timestamp() * 1_000_000_000)
        end_ns = int(end.timestamp() * 1_000_000_000)
        async with httpx.AsyncClient(timeout=30) as client:
            return await self.collect_ns(client, start_ns, end_ns)

    async def collect_ns(self, client: httpx.AsyncClient, start_ns: int, end_ns: int) -> CollectionResult:
        entries: list[tuple[dict, str, str]] = []
        metadata: dict[str, Any] = {
            "requests": 0, "split_windows": 0, "truncated_slices": [], "errors": []
        }

        async def fetch_slice(slice_start: int, slice_end: int, depth: int) -> None:
            if metadata["requests"] >= self.max_requests:
                metadata["truncated_slices"].append({"start_ns": slice_start, "end_ns": slice_end})
                return
            metadata["requests"] += 1
            try:
                response = await client.get(
                    f"{self.base_url}/loki/api/v1/query_range",
                    params={"query": self.query, "start": str(slice_start), "end": str(slice_end),
                            "limit": str(self.page_size), "direction": "forward"},
                )
                response.raise_for_status()
            except Exception as error:
                metadata["truncated_slices"].append({"start_ns": slice_start, "end_ns": slice_end})
                metadata["errors"].append(str(error)[:300])
                return
            result = response.json().get("data", {}).get("result", [])
            count = sum(len(stream.get("values", [])) for stream in result)
            if count < self.page_size:
                for stream in result:
                    labels = stream.get("stream", {})
                    entries.extend((labels, ts, line) for ts, line in stream.get("values", []))
                return
            if slice_start >= slice_end or depth >= self.max_depth:
                for stream in result:
                    labels = stream.get("stream", {})
                    entries.extend((labels, ts, line) for ts, line in stream.get("values", []))
                metadata["truncated_slices"].append({"start_ns": slice_start, "end_ns": slice_end})
                return
            metadata["split_windows"] += 1
            midpoint = (slice_start + slice_end) // 2
            await fetch_slice(slice_start, midpoint, depth + 1)
            await fetch_slice(midpoint + 1, slice_end, depth + 1)

        await fetch_slice(start_ns, end_ns, 0)
        metadata["raw_entries"] = len(entries)
        metadata["collection_complete"] = not metadata["truncated_slices"]
        return CollectionResult(events=entries, metadata=metadata)
