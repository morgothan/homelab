"""Shared Jellyfin API request conventions."""


def authorization_headers(api_key: str) -> dict[str, str]:
    """Return Jellyfin's current standard API-key authorization header.

    Jellyfin 12 disables the legacy X-Emby-Token header by default.  The
    MediaBrowser authorization scheme remains compatible with older servers.
    """
    return {
        "Authorization": (
            f'MediaBrowser Token="{api_key}", Client="Homelab News", '
            'Device="lab-monitor", DeviceId="lab-monitor", Version="1.0"'
        )
    }
