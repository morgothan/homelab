"""Shared SSH transport policy with explicitly pinned server identities."""

import asyncio
import logging

from config import SSH_KEY, SSH_KNOWN_HOSTS

log = logging.getLogger(__name__)


async def ssh_run(host: str, command: str, timeout: int = 45) -> tuple[bool, str]:
    """Run COMMAND over SSH and return (success, stdout-or-error)."""
    process = await asyncio.create_subprocess_exec(
        *ssh_arguments(), host, command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        if process.returncode == 0:
            return True, stdout.decode(errors="replace")
        log.warning(
            "SSH %s failed (rc=%d): %s",
            host, process.returncode, stderr.decode(errors="replace")[:200],
        )
        return False, stderr.decode(errors="replace")[:200]
    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.communicate()
        except Exception:
            pass
        return False, "SSH timeout"


def ssh_arguments() -> list[str]:
    """Require a trusted host key rather than accepting an impersonated server."""
    return [
        "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY,
    ]
