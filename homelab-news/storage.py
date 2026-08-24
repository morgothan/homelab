"""JSON persistence primitives used by web and worker processes."""

import json
import logging
import os
from typing import Any


log = logging.getLogger(__name__)


def load_json(path: str) -> Any | None:
    """Load JSON from PATH, returning ``None`` when it is absent or invalid."""
    try:
        with open(path, encoding="utf-8") as source:
            return json.load(source)
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        log.warning("Failed to load %s: %s", path, error)
        return None


def save_json(path: str, data: Any) -> None:
    """Atomically replace PATH with a UTF-8 JSON representation of DATA.

    Errors are logged and suppressed for compatibility with the historical worker
    behavior: a transient persistence failure must not terminate a long-running
    collector process.
    """
    temporary_path = f"{path}.tmp"
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(temporary_path, "w", encoding="utf-8") as destination:
            json.dump(data, destination, ensure_ascii=False)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_path, path)
    except (OSError, TypeError, ValueError) as error:
        log.warning("Failed to save %s: %s", path, error)
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            log.debug("Failed to remove temporary file %s: %s", temporary_path, cleanup_error)
