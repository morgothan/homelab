"""Typed, file-backed application feature configuration.

Connection details remain compatible with the historical environment variables.
Feature policy can be supplied in ``/config/homelab-news.toml`` (or
``NEWS_CONFIG_FILE``) and overridden with ``NEWS_FEATURE_<NAME>`` variables.

Host-monitoring policy lives under ``[beszel]``; the expected-high-memory host
allowlist can be supplied with ``BESZEL_EXPECTED_HIGH_MEMORY_HOSTS`` (CSV) and
the threshold with ``BESZEL_MEMORY_WARN_PCT``.
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
    investigations: bool = True


@dataclass(frozen=True)
class BeszelSettings:
    """Host-monitoring policy applied to Beszel system records.

    ``expected_high_memory_hosts`` names hosts whose memory percentage is
    routinely near the ceiling by design (for example an inference host's
    preallocated working set). They still receive HOST DOWN and DISK alerts;
    only the memory-percentage warning is suppressed.
    """

    memory_warn_pct: float = 92.0
    expected_high_memory_hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class AppSettings:
    config_file: str
    features: FeatureSettings = field(default_factory=FeatureSettings)
    beszel: BeszelSettings = field(default_factory=BeszelSettings)

    def public_dict(self) -> dict:
        """Return configuration safe to persist or expose diagnostically."""
        return {
            "config_file": self.config_file,
            "features": asdict(self.features),
            "beszel": asdict(self.beszel),
        }


def _percentage(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number between 0 and 100")
    number = float(value)
    if not 0 <= number <= 100:
        raise ValueError(f"{name} must be between 0 and 100")
    return number


def _host_names(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be a list of host names")
    names: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a list of host names")
        name_value = item.strip()
        if not name_value:
            raise ValueError(f"{name} must not contain empty host names")
        names.append(name_value)
    return tuple(names)


def load_settings(path: str | None = None, environ: dict[str, str] | None = None) -> AppSettings:
    environment = os.environ if environ is None else environ
    config_path = path if path is not None else environment.get(
        "NEWS_CONFIG_FILE", "/data/config.toml"
    )
    raw_features: dict[str, object] = {}
    raw_beszel: dict[str, object] = {}
    candidate = Path(config_path)
    if candidate.is_file():
        with candidate.open("rb") as source:
            document = tomllib.load(source)
        configured = document.get("features", {})
        if not isinstance(configured, dict):
            raise ValueError("[features] must be a TOML table")
        raw_features = configured
        configured_beszel = document.get("beszel", {})
        if not isinstance(configured_beszel, dict):
            raise ValueError("[beszel] must be a TOML table")
        raw_beszel = configured_beszel

    defaults = FeatureSettings()
    values = {}
    for name in defaults.__dataclass_fields__:
        configured = raw_features.get(name, getattr(defaults, name))
        override = environment.get(f"NEWS_FEATURE_{name.upper()}")
        values[name] = _boolean(override if override is not None else configured, getattr(defaults, name))
    unknown = sorted(set(raw_features) - set(values))
    if unknown:
        raise ValueError(f"unknown feature setting(s): {', '.join(unknown)}")

    beszel_defaults = BeszelSettings()
    beszel_values = {}
    for name in beszel_defaults.__dataclass_fields__:
        configured = raw_beszel.get(name, getattr(beszel_defaults, name))
        if name == "memory_warn_pct":
            beszel_values[name] = _percentage(configured, name)
        else:
            beszel_values[name] = _host_names(configured, name)
    unknown_beszel = sorted(set(raw_beszel) - set(beszel_values))
    if unknown_beszel:
        raise ValueError(f"unknown beszel setting(s): {', '.join(unknown_beszel)}")

    memory_override = environment.get("BESZEL_MEMORY_WARN_PCT")
    if memory_override is not None and memory_override.strip():
        try:
            memory_warn_pct = float(memory_override)
        except (TypeError, ValueError):
            raise ValueError(
                "BESZEL_MEMORY_WARN_PCT must be a number between 0 and 100"
            ) from None
        beszel_values["memory_warn_pct"] = _percentage(
            memory_warn_pct, "BESZEL_MEMORY_WARN_PCT"
        )

    hosts_override = environment.get("BESZEL_EXPECTED_HIGH_MEMORY_HOSTS")
    if hosts_override is not None:
        names = [part.strip() for part in hosts_override.split(",") if part.strip()]
        beszel_values["expected_high_memory_hosts"] = _host_names(
            names, "BESZEL_EXPECTED_HIGH_MEMORY_HOSTS"
        )

    return AppSettings(
        config_file=config_path,
        features=FeatureSettings(**values),
        beszel=BeszelSettings(**beszel_values),
    )


APP_SETTINGS = load_settings()
