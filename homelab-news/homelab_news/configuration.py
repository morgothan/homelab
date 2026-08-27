"""Typed, file-backed application feature configuration.

Connection details remain compatible with the historical environment variables.
Feature policy can be supplied in ``/config/homelab-news.toml`` (or
``NEWS_CONFIG_FILE``) and overridden with ``NEWS_FEATURE_<NAME>`` variables.
"""

import os
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path


def _boolean(value: object, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


@dataclass(frozen=True)
class FeatureSettings:
    loki: bool = True
    docker: bool = True
    security: bool = True
    prometheus: bool = True
    backups: bool = True
    host_monitoring: bool = True
    media: bool = True
    updates: bool = True
    trend_intelligence: bool = True


@dataclass(frozen=True)
class AppSettings:
    config_file: str
    features: FeatureSettings = field(default_factory=FeatureSettings)

    def public_dict(self) -> dict:
        """Return configuration safe to persist or expose diagnostically."""
        return {"config_file": self.config_file, "features": asdict(self.features)}


def load_settings(path: str | None = None, environ: dict[str, str] | None = None) -> AppSettings:
    environment = os.environ if environ is None else environ
    config_path = path if path is not None else environment.get(
        "NEWS_CONFIG_FILE", "/data/config.toml"
    )
    raw_features: dict[str, object] = {}
    candidate = Path(config_path)
    if candidate.is_file():
        with candidate.open("rb") as source:
            document = tomllib.load(source)
        configured = document.get("features", {})
        if not isinstance(configured, dict):
            raise ValueError("[features] must be a TOML table")
        raw_features = configured

    defaults = FeatureSettings()
    values = {}
    for name in defaults.__dataclass_fields__:
        configured = raw_features.get(name, getattr(defaults, name))
        override = environment.get(f"NEWS_FEATURE_{name.upper()}")
        values[name] = _boolean(override if override is not None else configured, getattr(defaults, name))
    unknown = sorted(set(raw_features) - set(values))
    if unknown:
        raise ValueError(f"unknown feature setting(s): {', '.join(unknown)}")
    return AppSettings(config_file=config_path, features=FeatureSettings(**values))


APP_SETTINGS = load_settings()
