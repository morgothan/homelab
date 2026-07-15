#!/usr/bin/env python3
"""
_trickplay_hash — runs on the Jellyfin host. Given a JSON payload on stdin,
computes a dHash (mode "hash") or a 3-point byte-size fingerprint (mode
"fingerprint") for each item's pre-generated trickplay thumbnail(s), using
the local ffmpeg install to decode the sprite-sheet JPEG and crop out one
tile. Never touches the source video file directly.

stdin payload: {"token": "...", "base": "http://localhost:8096",
                 "items": [[jellyfin_item_id, label], ...]}
argv[1]: "hash" (default) or "fingerprint"
stdout: {label: dhash_int_or_null, ...} or {label: [fp1, fp2, fp3], ...}
"""
import json, shutil, subprocess, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

FFMPEG = shutil.which("ffmpeg") or "/usr/lib/jellyfin-ffmpeg/ffmpeg"


def make_client(token, base):
    def jget(path):
        req = urllib.request.Request(f"{base}{path}", headers={"X-Emby-Token": token})
        return json.loads(urllib.request.urlopen(req, timeout=15).read())

    def jget_bytes(path):
        req = urllib.request.Request(f"{base}{path}", headers={"X-Emby-Token": token})
        return urllib.request.urlopen(req, timeout=15).read()

    return jget, jget_bytes


def dhash_from_gray(raw):
    if len(raw) != 72:
        return None
    bits = 0
    for r in range(8):
        for c in range(8):
            bits = (bits << 1) | (1 if raw[r * 9 + c] > raw[r * 9 + c + 1] else 0)
    return bits


def tile_coords(jget, user_id, item_id, pct):
    item = jget(f"/Users/{user_id}/Items/{item_id}?Fields=Trickplay")
    tp = item.get("Trickplay", {}).get(item_id)
    if not tp:
        return None
    res_key = next(iter(tp))
    info = tp[res_key]
    tile_w, tile_h = info["TileWidth"], info["TileHeight"]
    per_sheet = tile_w * tile_h
    thumb_count = info["ThumbnailCount"]
    if not thumb_count:
        return None
    thumb_w, thumb_h = info["Width"], info["Height"]
    thumb_idx = min(int(thumb_count * pct), thumb_count - 1)
    page, local_idx = divmod(thumb_idx, per_sheet)
    row, col = divmod(local_idx, tile_w)
    return res_key, page, col * thumb_w, row * thumb_h, thumb_w, thumb_h


def crop_tile(jget, jget_bytes, user_id, item_id, pct, output_args):
    coords = tile_coords(jget, user_id, item_id, pct)
    if not coords:
        return None
    res_key, page, x, y, w, h = coords
    jpg = jget_bytes(f"/Videos/{item_id}/Trickplay/{res_key}/{page}.jpg")
    proc = subprocess.run(
        [FFMPEG, "-v", "error", "-i", "pipe:0", "-vf", f"crop={w}:{h}:{x}:{y}" + output_args[0],
         *output_args[1], "-frames:v", "1", "-"],
        input=jpg, capture_output=True, timeout=20,
    )
    return proc.stdout


def process(jget, jget_bytes, user_id, item_id, mode):
    if mode == "fingerprint":
        return [len(crop_tile(jget, jget_bytes, user_id, item_id, pct,
                               (",", ["-q:v", "3", "-f", "image2"])) or b"")
                for pct in (0.2, 0.5, 0.8)]
    raw = crop_tile(jget, jget_bytes, user_id, item_id, 0.5,
                     (",scale=9:8,format=gray", ["-f", "rawvideo"]))
    return dhash_from_gray(raw or b"")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "hash"
    payload = json.loads(sys.stdin.read())
    jget, jget_bytes = make_client(payload["token"], payload.get("base", "http://localhost:8096"))
    users = jget("/Users")
    user_id = users[0]["Id"]

    def worker(item_id, label):
        try:
            return label, process(jget, jget_bytes, user_id, item_id, mode)
        except Exception as e:
            return label, f"ERR: {e}"

    results = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(worker, item_id, label) for item_id, label in payload["items"]]
        for fut in as_completed(futs):
            label, val = fut.result()
            results[label] = val
    print(json.dumps(results))
