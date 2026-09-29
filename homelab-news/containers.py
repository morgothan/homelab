"""Docker container and image management.

Fetches local and remote container state (for status cards) and resolves image
update information (digests, published tags, latest semver) for the Wire Reports
worker. Kept free of newspaper orchestration so both ``web`` and ``updates`` can
share it without pulling in the LLM pipeline.
"""

import asyncio
import json
import logging
import os
import re
import shlex
from typing import Optional

import docker
from ssh_transport import ssh_arguments

from config import (
    DOCKER_AUTH, SKOPEO_TIMEOUT, SSH_KEY,
)

log = logging.getLogger(__name__)


# Containers that may legitimately be stopped/absent because a blue/green twin
# of the same service is running. A stopped member of one of these groups is not
# "unhealthy".
_EDGE_STANDBY_GROUPS = [
    {"traefik", "traefik-blue", "traefik-green"},
    {"cf_tunnel", "cf-tunnel-blue", "cf-tunnel-green"},
]


def get_container_status() -> tuple[list, list, int]:
    try:
        dc = docker.from_env()
        all_c = dc.containers.list(all=True)
        running = dc.containers.list()
        running_names = {c.name for c in running}

        def is_expected_edge_standby(c) -> bool:
            for group in _EDGE_STANDBY_GROUPS:
                if c.name in group:
                    return bool(running_names & group)
            return False

        unhealthy = [
            c for c in all_c
            if (c.status != "running" and not is_expected_edge_standby(c))
            or (c.status == "running"
                and c.attrs.get("State", {}).get("Health", {}).get("Status") == "unhealthy")
        ]
        starting = [
            c for c in all_c
            if c.status == "running"
            and c.attrs.get("State", {}).get("Health", {}).get("Status") == "starting"
        ]
        return unhealthy, starting, len(running)
    except Exception:
        return [], [], 0


async def get_container_status_async() -> tuple[list, list, int]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_container_status)


def parse_image_ref(raw: str) -> str:
    if "@sha256:" in raw:
        raw = raw.split("@")[0]
    if ":" not in raw.split("/")[-1]:
        raw += ":latest"
    return raw


async def remote_digest(image_ref: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (digest, oci_source_url, oci_version_label) for an image, trying auth then no-creds.

    Registries (esp. Docker Hub) mutate the manifest-list digest after the fact when they
    attach build attestations/SBOMs to an already-published tag — same content, new digest.
    That makes digest equality unreliable as the sole "is there a newer version" signal, so
    callers should prefer the version label when the registry provides one.
    """
    has_auth = os.path.exists(DOCKER_AUTH)
    attempts = [["--authfile", DOCKER_AUTH]] if has_auth else []
    attempts.append(["--no-creds"])
    for auth_args in attempts:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "skopeo", "inspect",
                "--override-arch", "amd64", "--override-os", "linux",
                *auth_args, f"docker://{image_ref}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=SKOPEO_TIMEOUT)
            if proc.returncode == 0:
                data = json.loads(out)
                labels = data.get("Labels") or {}
                source = labels.get("org.opencontainers.image.source")
                version = labels.get("org.opencontainers.image.version")
                return data.get("Digest"), source, version
        except Exception:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
    return None, None, None


def _semver_sort_key(tag: str) -> tuple:
    """Numeric sort key from the leading vX.Y[.Z] of a tag, plus a trailing Alpine
    package revision if present ('2.8.5-r1' -> (2, 8, 5, 1)). Any other suffix is
    ignored ('3.4.4-alpine' -> (3, 4, 4)). Non-semver tags sort lowest."""
    match = re.match(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-r(\d+))?", tag)
    if not match:
        return (0,)
    return tuple(int(x) for x in match.groups() if x is not None)


def _semver_tag_pattern(tag: str) -> Optional[re.Pattern]:
    """Regex matching tags with the same shape as `tag` — component count, v-prefix,
    AND any trailing suffix. '3.4.4-alpine' only matches other '-alpine' patch tags,
    never the bare '3.4.4' variant (a different image, not a newer version). Exception:
    an Alpine package-revision suffix ('-r1') is an ordered version part, not a
    variant, so '2.8.3-r4' matches any 'X.Y.Z-rN' and tracks later revisions."""
    match = re.match(r"^(v?)(\d+)\.(\d+)(?:\.(\d+))?(.*)$", tag)
    if not match:
        return None
    prefix, _, _, patch, suffix = match.groups()
    n = r"\d+"
    suffix_pat = r"-r\d+" if re.fullmatch(r"-r\d+", suffix) else re.escape(suffix)
    core = rf"{n}\.{n}\.{n}" if patch is not None else rf"{n}\.{n}"
    return re.compile(rf"^{prefix}{core}{suffix_pat}$")


async def _skopeo_list_tags(image: str) -> list[str]:
    has_auth = os.path.exists(DOCKER_AUTH)
    attempts = [["--authfile", DOCKER_AUTH]] if has_auth else []
    attempts.append(["--no-creds"])
    for auth_args in attempts:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "skopeo", "list-tags", *auth_args, f"docker://{image}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=SKOPEO_TIMEOUT)
            if proc.returncode == 0:
                try:
                    return json.loads(out).get("Tags") or []
                except json.JSONDecodeError:
                    return []
        except Exception:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
    return []


async def latest_semver_tag(name: str, current: str) -> Optional[str]:
    """Return the newest published tag for `name` if it's a real version bump over
    `current`, else None.

    Lists actual published tags via skopeo (same method as bin/update-images) rather
    than comparing against :latest's digest/version-label — that heuristic is unreliable
    since many images don't set org.opencontainers.image.version on :latest, or set it
    to something unrelated to the app's own version scheme (see remote_digest docstring).
    """
    pat = _semver_tag_pattern(current)
    if not pat:
        return None
    tags = await _skopeo_list_tags(name)
    matching = [t for t in tags if pat.match(t)]
    if not matching:
        return None
    # Guard against date-stamped nightly build tags outranking conventional semver tags.
    if _semver_sort_key(current)[0] < 10_000:
        matching = [t for t in matching if _semver_sort_key(t)[0] < 10_000]
    if not matching:
        return None
    best = max(matching, key=_semver_sort_key)
    if _semver_sort_key(best) <= _semver_sort_key(current):
        return None
    # Confirm the tag has a valid, pullable manifest before reporting it as an update.
    digest, _, _ = await remote_digest(f"{name}:{best}")
    if digest is None:
        return None
    return best


def _repo_digest_set(repo_digests: list[str]) -> set[str]:
    """An image can accumulate multiple RepoDigests entries when Docker Hub
    re-signs or re-pushes a manifest without changing the image content.
    Comparing only index 0 causes false-positive stale detection."""
    return {d.split("@")[1] for d in repo_digests if "@" in d}


def get_containers_local() -> list[dict]:
    dc = docker.from_env()
    out = []
    for c in dc.containers.list():
        ref = parse_image_ref(c.attrs["Config"]["Image"])
        try:
            img = dc.images.get(c.attrs["Image"])
            local_digests = _repo_digest_set(img.attrs.get("RepoDigests", []))
        except Exception:
            local_digests = set()
        out.append({"name": c.name, "image": ref, "local_digests": local_digests})
    return out


def get_containers_tcp(url: str) -> list[dict]:
    dc = docker.DockerClient(base_url=url, timeout=10)
    out = []
    try:
        for c in dc.containers.list():
            ref = parse_image_ref(c.attrs["Config"]["Image"])
            try:
                img = dc.images.get(c.attrs["Image"])
                local_digests = _repo_digest_set(img.attrs.get("RepoDigests", []))
            except Exception:
                local_digests = set()
            out.append({"name": c.name, "image": ref, "local_digests": local_digests})
    finally:
        dc.close()
    return out


_DETECT_CONTAINERS_CMD = (
    "docker_bin=$(which docker 2>/dev/null || "
    "for p in /usr/local/bin/docker /usr/bin/docker; do [ -x $p ] && echo $p && break; done); "
    r'$docker_bin ps --format "{{.Names}}\t{{.Image}}" 2>/dev/null | '
    r"while IFS=$(printf '\t') read name image; do "
    r'  digests=$($docker_bin image inspect "$image" --format "{{json .RepoDigests}}" 2>/dev/null || echo "[]"); '
    r'  printf "%s\t%s\t%s\n" "$name" "$image" "$digests"; '
    r"done"
)


def _parse_container_ls(out: bytes) -> list[dict]:
    containers = []
    for line in out.decode(errors="replace").splitlines():
        parts = line.strip().split("\t", 2)
        if len(parts) < 3:
            continue
        name, image, digests_json = parts
        name = name.lstrip("/")
        try:
            local_digests = _repo_digest_set(json.loads(digests_json))
        except Exception:
            local_digests = set()
        containers.append({"name": name, "image": parse_image_ref(image), "local_digests": local_digests})
    return containers


async def _run_ssh_detect(argv: list[str], desc: str) -> list[dict]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=40)
    except asyncio.TimeoutError:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
        return []
    if proc.returncode != 0:
        log.warning("SSH to %s failed: %s", desc, err.decode(errors="replace")[:200])
        return []
    return _parse_container_ls(out)


async def get_containers_ssh(url: str) -> list[dict]:
    target = url[len("ssh://"):]
    argv = [
        *ssh_arguments(), target, _DETECT_CONTAINERS_CMD,
    ]
    return await _run_ssh_detect(argv, target)


async def get_containers_pct(host: str, ctid: str) -> list[dict]:
    """Like get_containers_ssh, but for an LXC with no direct SSH access — relays
    through the Proxmox host's `pct exec`. shlex.quote handles the nested-quoting since _DETECT_CONTAINERS_CMD
    itself contains single quotes."""
    if not re.fullmatch(r"[0-9]+", ctid):
        raise ValueError("LXC identifier must be numeric")
    relay_cmd = f"sudo -n /usr/sbin/pct exec {ctid} -- bash -c {shlex.quote(_DETECT_CONTAINERS_CMD)}"
    argv = [
        *ssh_arguments(), host, relay_cmd,
    ]
    return await _run_ssh_detect(argv, f"pct/{ctid}@{host}")
