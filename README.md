# Homelab Docker Stack

A self-hosted homelab running on a Proxmox LXC. All services are exposed through Traefik as a reverse proxy, with Authelia providing SSO + 2FA and acting as an OIDC provider. All secrets are stored in OpenBao (open-source Vault fork).

---

## Hardware

| Host | Role | Notes |
|------|------|-------|
| Proxmox | Hypervisor | Intel Core Ultra 7 155H, 94 GB RAM, Intel Arc iGPU |
| Docker LXC | Runs this stack | Main Proxmox LXC |
| Raspberry Pi (primary DNS) | Primary DNS | AdGuard Home + Unbound + Chrony NTP |
| Raspberry Pi (kids DNS) | Kids DNS | AdGuard Home with child-safety filters |
| Raspberry Pi (monitoring) | Monitoring hub | Beszel — independent of Proxmox |
| Intel NUC | Media server | Plex as systemd service, Intel Arc iGPU for HW transcoding |
| TrueNAS | Primary NAS | Xeon Silver, 251 GB RAM, 218 TB pool |
| Synology | Legacy NAS | Still online, not primary |
| HA Yellow | Home automation | IoT VLAN; voice pipeline, B&O speakers, 3D printer |
| Ollama LXC | Local LLM inference | CPU-only; serves HA voice + homelab news |

---

## Architecture

### Traffic Flow

```
Internet → Cloudflare → cloudflared ─(cftunnel-transport)─► Traefik
                                                                │
                                      ┌─────────────────────────┤
                                   (proxy)                   (dmz)
                                      │                         │
                               Authenticated              Public services
                               services (2FA)          (no auth, WAF only)
```

All external HTTPS traffic arrives via Cloudflare Tunnel — no ports are exposed to the internet. `cloudflared` is isolated on its own Docker network and can only reach Traefik.

### Docker Networks

| Network | Env var | Purpose |
|---------|---------|---------|
| `proxy` | `${DOCKERNET}` | All authenticated services |
| `dmz` | `${DMZNET}` | Public-facing unauthenticated containers |
| `cftunnel-transport` | — | Cloudflare Tunnel ↔ Traefik only |

### Domains

| Pattern | Access | Transport |
|---------|--------|-----------|
| `*.${DOMAIN}` | External | HTTPS via Cloudflare Tunnel |
| `*.${LOCAL}` | LAN only | HTTP, local DNS |
| `*.iot.${LOCAL}` | IoT VLAN | HTTP, isolated |
| `*.kids.${LOCAL}` | Kids VLAN | HTTP, isolated |

---

## Security Model

### Middleware Chains

Every external route uses one of these chains. The WAF is intentionally skipped post-auth — Authelia 2FA is the security gate; WAF after auth produces false positives on complex SPAs without meaningful security benefit.

| Chain | Used by |
|-------|---------|
| `chain-authelia-nowaf` | All authenticated services |
| `chain-no-auth` | Public services (WAF + geoblock, no Authelia) |
| `chain-no-auth-no-waf` | Public services, no WAF |
| `chain-no-auth-no-cs` | Authelia itself |

Each chain includes: `error-pages → realip → robotstxt → secure-headers → rate-limit → fail2ban → [WAF] → [Authelia forwardAuth]`

### Scanner Blocking

A high-priority Traefik router (priority 500) intercepts known-malicious paths (`.env`, `.git`, `wp-admin`, `phpmyadmin`, etc.) across all external subdomains **before** any service router or forwardAuth fires. Returns 403 directly, which fail2ban counts toward a ban. Without this, scanners get a 302 to Authelia — which fail2ban ignores — and accumulate zero ban points.

### Brute-Force Protection (three layers)

| Layer | Trigger | Action |
|-------|---------|--------|
| Traefik rate limit | >10 rapid requests to `/api/firstfactor` or `/api/secondfactor` | HTTP 429 |
| Traefik fail2ban-auth | 3 rate-limit 429s within 5 min | 24h ban + Cloudflare edge block |
| Authelia regulation | 3 failed logins within 10 min | 12h account lockout |

### Cloudflare Edge Propagation

`cf-fail2ban` (cron, every minute) reads Traefik logs, parses fail2ban plugin events, and creates account-level Cloudflare IP Access Rules. Bans escalate per offense: 24h → 7d → 30d → 365d → permanent.

---

## Secrets Management (OpenBao)

All service secrets are stored in **OpenBao** (open-source Vault fork, MPL-2.0). This replaced Infisical in May 2026.

- **Stack:** `docker-compose.openbao.yml` (project name `openbao`) with an auto-unseal sidecar
- **KV paths:** `kv/docker/{authelia,cloudflare,db,grafana,smtp,misc}`
- **Injection:** `dc.sh` authenticates via AppRole, fetches all secrets, exports them, then `exec docker compose "$@"` — pure `curl`+`jq`, no binary dependency
- **Credentials file:** `.env.openbao` (gitignored, `chmod 600`) holds `BAO_ADDR`, `BAO_ROLE_ID`, `BAO_SECRET_ID`

### Adding a new secret

1. Log in to OpenBao (Authelia OIDC required)
2. Navigate to `kv/docker/{service}` (use `kv/docker/misc` for one-offs)
3. Add the key/value pair
4. Reference as `${VAR_NAME}` in `docker-compose.yml` — `dc.sh` injects it automatically

---

## Operations

### Common Commands

```bash
# Start all services
./dc.sh up -d

# Restart a single service
./dc.sh restart <service>

# Pull latest image and restart
./dc.sh pull <service> && ./dc.sh up -d <service>

# Bounce main stack only (OpenBao stays up)
./dc.sh down && ./dc.sh up -d

# Bounce everything (main stack + OpenBao)
./dc.sh down --full && ./dc.sh up -d

# Check container health
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -v healthy

# View logs
./dc.sh logs -f <service>
```

### Adding a New Docker Service

Add to `docker-compose.yml` with Traefik labels:

```yaml
your-service:
  image: example/image:latest
  container_name: your-service
  restart: unless-stopped
  networks:
    - ${DOCKERNET}
  labels:
    - traefik.enable=true
    - traefik.http.routers.your-service-local.entrypoints=http
    - traefik.http.routers.your-service-local.rule=Host(`your-service.${LOCAL}`)
    - traefik.http.routers.your-service-local.middlewares=chain-no-auth-no-waf@file
    - traefik.http.routers.your-service-rtr.entrypoints=https
    - traefik.http.routers.your-service-rtr.rule=Host(`your-service.${DOMAIN}`)
    - traefik.http.routers.your-service-rtr.middlewares=chain-authelia-nowaf@file
    - traefik.http.services.your-service.loadbalancer.server.port=8080
```

### Adding a New External (non-Docker) Service

Create `traefik/configs/site-your-service.yml` — hot-reloaded automatically:

```yaml
http:
  routers:
    your-service-https:
      entryPoints: ["https"]
      rule: Host(`your-service.${DOMAIN}`)
      middlewares: [chain-authelia-nowaf@file]
      service: your-service-svc
  services:
    your-service-svc:
      loadBalancer:
        servers:
          - url: "http://your-service.${LOCAL}:8080"
```

Cloudflare Tunnel ingress is kept in sync automatically by `cf-tunnel-sync` — no manual dashboard update needed.

### Adding a New Authelia OIDC Client

```bash
# Generate client_id (run once)
docker run authelia/authelia:latest authelia crypto hash generate pbkdf2 \
  --random --random.length 64 --random.charset alphanumeric

# Generate client_secret (run again — save the plaintext AND the digest)
docker run authelia/authelia:latest authelia crypto hash generate pbkdf2 \
  --random --random.length 64 --random.charset alphanumeric
```

1. Add the client block to `authelia/configuration.yml` under `identity_providers.oidc.clients`
   - Use the **pbkdf2 digest** as `client_secret` in the config file
2. Store the **plaintext** `client_id` and `client_secret` in OpenBao at `kv/docker/authelia`
3. Add the env var names to the `authelia` service's `environment:` block in `docker-compose.yml`

---

## Service Catalog

### Infrastructure

| Service | Purpose |
|---------|---------|
| Traefik | Reverse proxy, TLS termination, middleware chains |
| Authelia | SSO, 2FA, OIDC provider |
| OpenBao | Secrets management (KV v2, AppRole auth) |
| Cloudflare Tunnel | External HTTPS ingress — zero open ports |
| Redis | Authelia session store (db 0), Traefik store (db 1) |
| error-pages | Styled error pages (400/401/403/404/5xx) |
| ModSecurity WAF | OWASP CRS; sidecar to Traefik |

### Monitoring

| Service | Purpose |
|---------|---------|
| Prometheus | Metrics collection; scrapes 15+ exporters |
| Grafana | Dashboards; Authelia OIDC login |
| Loki | Log aggregation |
| Promtail | Log shipper (Docker socket) |
| Beszel | Infrastructure monitoring hub (9 hosts) |
| Dozzle | Live Docker log viewer; remote agents on NAS + Beszel |
| Various exporters | PVE, Unifi, NUT, Redis, AdGuard, Tdarr, NZBGet, *arr, Postgres, Smokeping, node |

### Media

| Service | Purpose |
|---------|---------|
| Plex | Media server (NUC, systemd — not Docker) |
| Jellyfin | Secondary media server |
| Sonarr | TV automation |
| Radarr | Movie automation |
| NZBGet | Usenet downloader |
| Tdarr | Video transcoding |
| Overseerr | Media requests |
| Tautulli | Plex stats |
| ErsatzTV | Virtual TV channels (IoT VLAN LXC) |

### Services

| Service | Purpose |
|---------|---------|
| Homepage | Dashboard |
| Portainer | Docker management UI |
| Guacamole | Remote desktop gateway (OIDC, implicit grant) |
| Outline | Wiki / knowledge base |
| Mealie | Recipe manager |
| Immich | Photo management |
| Open WebUI | Local LLM chat (backed by Ollama) |
| Beszel | Infrastructure monitoring |
| Kopia | Backups |
| Gotify | Push notifications |
| ntfy | Push notifications (disabled — pending OIDC validation) |
| ttyd | Browser terminal (two-container: shell + nginx router) |
| NUT + peaNUT | UPS monitoring and web UI |
| AdGuard Home | DNS + ad blocking (two instances: main + kids) |
| Homelab News | Self-hosted daily digest; LLM-generated newspaper from Docker/Loki logs |

### Public Services

| Service | Notes |
|---------|-------|
| heyshutup.com | Node.js/Express app; no auth, `dmz` network |
| steph.${DOMAIN} | Static site; no auth, `dmz` network |

---

## Notable Files

| Path | Purpose |
|------|---------|
| `dc.sh` | Docker Compose wrapper; injects OpenBao secrets at launch |
| `docker-compose.yml` | Main stack |
| `docker-compose.openbao.yml` | OpenBao + auto-unseal sidecar |
| `authelia/configuration.yml` | Authelia config; OIDC clients defined here |
| `authelia/users.yml` | Local user database |
| `traefik/traefik.yml` | Traefik static config; plugin versions pinned here |
| `traefik/configs/` | File provider — routers, middlewares, site configs (hot-reload) |
| `prometheus/etc/prometheus.yml` | Scrape targets |
| `homelab-news/` | Homelab newspaper app |
| `bin/` | Host-level scripts (`cf-tunnel-sync`, `cf-fail2ban`) |

### Gitignored Runtime Files

| Path | Purpose |
|------|---------|
| `.env` | Core env vars (`DOCKERDIR`, `DOMAIN`, `LOCAL`, etc.) |
| `.env.openbao` | OpenBao AppRole credentials (`chmod 600`) |
| `.bao-unseal-key` | OpenBao unseal key |
| `traefik/configs/site-*.yml` | Per-service route configs (contain domain names) |
| `traefik/acme.json/` | TLS certificates |
| `authelia/secrets/` | Authelia file secrets (JWT, session, storage keys) |
| `homepage/services.yaml` | Homepage service list (contains internal URLs) |

---

## Rebuild From Scratch

1. Create Docker networks: `docker network create proxy && docker network create dmz`
2. Copy `~/docker`, `/var/lib/docker/volumes`, `~/.config/*`
3. Restore `.env` and `.env.openbao` (`chmod 600` on both)
4. Start OpenBao stack: `docker compose -f docker-compose.openbao.yml up -d`
5. Bootstrap OpenBao (init, unseal, configure) — see `docs/homelab-documentation.md`
6. Start everything: `./dc.sh up -d`
