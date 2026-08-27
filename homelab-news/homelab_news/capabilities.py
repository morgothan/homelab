"""Runtime capability states for configured integrations."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Capability:
    name: str
    enabled: bool
    healthy: bool | None = None
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def configured_capabilities(features) -> dict[str, dict]:
    """Describe feature enablement without exposing connection secrets."""
    return {
        name: Capability(name=name, enabled=enabled).as_dict()
        for name, enabled in vars(features).items()
    }
