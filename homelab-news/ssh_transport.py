"""Shared SSH transport policy with explicitly pinned server identities."""

from config import SSH_KEY, SSH_KNOWN_HOSTS


def ssh_arguments() -> list[str]:
    """Require a trusted host key rather than accepting an impersonated server."""
    return [
        "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY,
    ]
