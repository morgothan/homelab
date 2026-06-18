---
title: Termix Migration — Replace ttyd + Guacamole
date: 2026-06-18
status: approved
---

Replace the three-container ttyd stack and the unused Guacamole container with Termix, a single modern SSH management tool. The auto-tmux behavior on the traefik.hirschnet host terminal is preserved via Termix's per-host SSH command config.

## Context

**Current state:**
- `guacamole` — Java-based remote desktop gateway (256–768 MB heap), OIDC via implicit grant (PKCE not supported, GUACAMOLE-1966). Unused since ttyd was set up.
- `ttyd-user` — privileged container that `nsenter`s into the host's PID/mount/user/IPC/network namespaces, then `su`s to the right user and runs `~/bin/start-tmux.sh`.
- `ttyd-router` — nginx that reads the `Remote-User` header set by Authelia and routes to the per-user `ttyd-*` instance. Unknown users get 403. Currently only maps `nat → ttyd-user`.
- `bin/ttyd-shell` — wrapper script that performs the `nsenter` + `su` + tmux invocation.

**Key constraint:** The auto-tmux startup must fire only when connecting via the web interface, not on regular SSH logins. Termix satisfies this via per-host SSH command config.

## Architecture

**What gets removed:**
- Containers: `guacamole`, `ttyd-user`, `ttyd-router`
- Files: `ttyd/nginx.conf`, `bin/ttyd-shell`, `guac/` config directory
- Authelia OIDC client: `guacamole`
- OpenBao secrets: guacamole OIDC credentials at `kv/docker/authelia`

**What gets added:**
- Container: `termix` (single image, no guacd sidecar — SSH only)
- Authelia OIDC client: `termix`
- OpenBao secrets: Termix OIDC credentials at `kv/docker/termix`

**Why the nsenter approach is no longer needed:** ttyd ran inside a Docker container and needed to escape into the host namespace via `nsenter`. Termix SSH-connects directly to the host's SSH daemon, so you get a host shell naturally — no privilege escalation required.

## Container Config

```yaml
termix:
  image: ghcr.io/lukegus/termix:latest
  container_name: termix
  restart: unless-stopped
  logging: *logging
  networks:
    - ${DOCKERNET}
  volumes:
    - /etc/localtime:/etc/localtime:ro
    - /etc/timezone:/etc/timezone:ro
    - ${DOCKERDIR}/termix:/app/data
  environment:
    - PORT=8080
    - OIDC_CLIENT_ID=${TERMIX_OIDC_CLIENT_ID}
    - OIDC_CLIENT_SECRET=${TERMIX_OIDC_CLIENT_SECRET}
    - OIDC_ISSUER_URL=https://auth.${DOMAIN}
    - OIDC_AUTHORIZATION_URL=https://auth.${DOMAIN}/api/oidc/authorization
    - OIDC_TOKEN_URL=https://auth.${DOMAIN}/api/oidc/token
    - OIDC_USERINFO_URL=https://auth.${DOMAIN}/api/oidc/userinfo
    - OIDC_SCOPES=openid email profile groups
    - OIDC_SYSTEM_SECRET=${TERMIX_OIDC_SYSTEM_SECRET}
  labels:
    - traefik.enable=true
    - traefik.http.routers.termix.entrypoints=https
    - traefik.http.routers.termix.rule=Host(`termix.${DOMAIN}`)
    - traefik.http.routers.termix.middlewares=chain-authelia-nowaf@file
    - traefik.http.routers.termix.tls.certresolver=letsencrypt
    - traefik.http.routers.termix.tls.domains[0].main=${DOMAIN}
    - traefik.http.routers.termix.tls.domains[0].sans=*.${DOMAIN}
    - traefik.http.services.termix.loadBalancer.server.port=8080
```

`ENABLE_SSL` is left at its default (`false`) — Traefik terminates TLS.

## Auth Integration

Termix is placed behind `chain-authelia-nowaf` (same as Mealie and other OIDC services). Authelia's forward auth passes silently for users with an active session; the Termix OIDC flow then auto-completes using that session. Net result: one login step.

**Authelia OIDC client entry** (`authelia/configuration.yml`):
```yaml
- client_id: '{{ env "OIDC_TERMIX_CLIENT_ID" }}'
  client_name: Termix
  client_secret: '{{ env "OIDC_TERMIX_CLIENT_SECRET" }}'
  public: false
  authorization_policy: two_factor
  pkce_challenge_method: 'S256'
  redirect_uris:
    - 'https://termix.{{ env "DOMAIN" }}/users/oidc/callback'
  scopes:
    - openid
    - email
    - profile
    - groups
  response_types:
    - code
  grant_types:
    - authorization_code
  token_endpoint_auth_method: 'client_secret_basic'
  userinfo_signed_response_alg: none
```

Add `OIDC_TERMIX_CLIENT_ID` and `OIDC_TERMIX_CLIENT_SECRET` to the authelia service's `environment:` block in `docker-compose.yml` (same pattern as all other OIDC clients).

Generate credentials with:
```bash
docker run authelia/authelia:latest authelia crypto hash generate pbkdf2 \
  --random --random.length 64 --random.charset alphanumeric
```
Run twice. Each invocation prints a random string and its pbkdf2 digest. Use the **random string** from run 1 as `OIDC_TERMIX_CLIENT_ID` (stored in `kv/docker/authelia`). Use the **random string** from run 2 as the plaintext client_secret (stored in `kv/docker/termix` as `TERMIX_OIDC_CLIENT_SECRET` for Termix to present), and the **pbkdf2 digest** from run 2 as `OIDC_TERMIX_CLIENT_SECRET` in `kv/docker/authelia` (what Authelia verifies against). Also store the client_id plaintext in `kv/docker/termix` as `TERMIX_OIDC_CLIENT_ID`. Generate a separate random 32+ char string for `TERMIX_OIDC_SYSTEM_SECRET` and store in `kv/docker/termix`.

Remove the existing guacamole OIDC client entry and its secrets from `kv/docker/authelia`.

## SSH Host Configuration

**traefik.hirschnet (primary host):**
Add as a saved SSH host in Termix with startup command `~/bin/start-tmux.sh`. This fires the tmux layout only when connecting through the Termix web UI, not on direct SSH logins. The `ttyd-shell` nsenter wrapper is retired — SSH already lands you in the host environment as the right user.

The `~/bin/start-tmux.sh` script on the host requires no changes (it sets up tmux panes that SSH into other homelab hosts). Termix connects to the host's existing SSH server on port 22.

**SSH authentication:** Generate a dedicated SSH keypair for Termix. Store the private key in Termix's credential store. Add the public key to `~/.ssh/authorized_keys` on each managed host. This avoids storing passwords in Termix and creates a clear audit trail.

**Other homelab hosts:** Add spark.hirschnet, Proxmox, NAS, and any other key hosts as standard saved SSH entries (no custom startup command). These replace the host catalog that was previously in Guacamole.

## Files to Remove

| Path | Reason |
|------|--------|
| `ttyd/nginx.conf` | ttyd-router nginx config |
| `bin/ttyd-shell` | nsenter+su wrapper, no longer needed |
| `guac/` (entire directory) | Guacamole config, fonts, database |

## Cloudflare Tunnel

`cf-tunnel-sync` will automatically pick up `termix.${DOMAIN}` from the Traefik API and add it to the tunnel. No manual action required. The `guac.${DOMAIN}` entry will be removed automatically once the guacamole router label is gone.

## Migration Order

1. Provision OpenBao secrets for Termix OIDC
2. Add Termix OIDC client to `authelia/configuration.yml`, remove guacamole client
3. Add `termix` service to `docker-compose.yml`
4. Bring up Termix, verify OIDC login works
5. Generate SSH keypair, configure traefik.hirschnet host entry in Termix UI with startup command
6. Test auto-tmux behavior end-to-end
7. Add remaining homelab hosts to Termix
8. Remove `guacamole`, `ttyd-user`, `ttyd-router` from `docker-compose.yml`
9. Delete `ttyd/nginx.conf`, `bin/ttyd-shell`, `guac/` directory
10. Commit
