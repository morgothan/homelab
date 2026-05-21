"""
Fetch all secrets from OpenBao KV v2 into a flat dict.

Usage:
    from _openbao import fetch_secrets
    secrets = fetch_secrets(env_file)   # env_file: path to .env.openbao
    cfg_dict.update(secrets)

Returns an empty dict silently on any error (network down, sealed, bad creds).
The caller's existing die() / missing-var checks handle the error case.
"""

import json
import urllib.request
import urllib.error
from pathlib import Path


def _load_dotenv(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env


def _get(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("X-Vault-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _post(url, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def fetch_secrets(env_file=None):
    """Return all kv secrets from OpenBao as a flat dict, or {} on any failure."""
    if env_file is None:
        env_file = Path(__file__).resolve().parent.parent / ".env.openbao"

    cfg = _load_dotenv(env_file)
    bao_addr  = cfg.get("BAO_ADDR",       "http://localhost:8200")
    role_id   = cfg.get("BAO_ROLE_ID",    "")
    secret_id = cfg.get("BAO_SECRET_ID",  "")
    kv_prefix = cfg.get("BAO_KV_PREFIX",  "docker")

    if not role_id or not secret_id:
        return {}

    result = _post(
        f"{bao_addr}/v1/auth/approle/login",
        {"role_id": role_id, "secret_id": secret_id},
    )
    if not result or "auth" not in result:
        return {}
    token = result["auth"]["client_token"]

    list_result = _get(f"{bao_addr}/v1/kv/metadata/{kv_prefix}?list=true", token)
    if not list_result:
        return {}
    services = list_result.get("data", {}).get("keys", [])

    secrets = {}
    for svc in services:
        svc = svc.rstrip("/")
        data = _get(f"{bao_addr}/v1/kv/data/{kv_prefix}/{svc}", token)
        if data and "data" in data:
            secrets.update(data["data"].get("data", {}))

    return secrets
