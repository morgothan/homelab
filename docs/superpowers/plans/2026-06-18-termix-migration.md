# Termix Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the unused Guacamole container and the three-container ttyd stack with a single Termix instance, preserving the auto-tmux behavior on the traefik.hirschnet host terminal.

**Architecture:** Termix is a single Docker container that SSH-connects directly to managed hosts — no nsenter privilege escalation needed. It gets its own Authelia OIDC client and sits behind `chain-authelia-nowaf` in Traefik. The traefik.hirschnet SSH host entry in Termix is configured with `~/bin/start-tmux.sh` as the startup command, so the tmux layout fires only when connecting through the web UI.

**Tech Stack:** Termix (`ghcr.io/lukegus/termix:latest`), Authelia OIDC, OpenBao for secrets, Traefik for routing.

---

## File Map

| File | Action | What changes |
|------|--------|--------------|
| `docker-compose.yml` | Modify (lines ~534-535, 686-779) | Add `termix` service; remove `guacamole`, `ttyd-user`, `ttyd-router`; remove guacamole OIDC env vars from authelia block; add termix OIDC env vars |
| `authelia/configuration.yml` | Modify (lines ~271-292) | Remove guacamole OIDC client; add termix OIDC client |
| `ttyd/nginx.conf` | Delete | No longer needed |
| `bin/ttyd-shell` (at `~/bin/ttyd-shell` on host) | Delete | nsenter wrapper retired; SSH handles host shell directly |
| `guac/` (directory) | Delete | Guacamole config, fonts, database |

---

## Task 1: Provision OpenBao Secrets

> Writing new secrets to OpenBao requires a temporary root token. See the `openbao_admin_process.md` memory entry for the procedure to generate one on `traefik.hirschnet`.

**Files:** None (OpenBao only)

- [ ] **Step 1: Generate Termix OIDC credentials**

On `traefik.hirschnet`, run the following command **twice**. The first run produces the client_id values; the second run produces the client_secret values. Each invocation prints a random string and its pbkdf2 digest on two separate lines.

```bash
docker run authelia/authelia:latest authelia crypto hash generate pbkdf2 \
  --random --random.length 64 --random.charset alphanumeric
```

Record:
- **Run 1 random string** → `OIDC_TERMIX_CLIENT_ID` (used as client_id in Authelia config and passed to Termix)
- **Run 2 random string** → plaintext client_secret (stored in `kv/docker/termix` as `TERMIX_OIDC_CLIENT_SECRET`)
- **Run 2 pbkdf2 digest** (the `$pbkdf2-sha512$...` line) → `OIDC_TERMIX_CLIENT_SECRET` (stored in `kv/docker/authelia`, what Authelia verifies against)

- [ ] **Step 2: Write secrets to OpenBao**

Obtain a temporary root token (see openbao_admin_process memory), then write to two paths. Use the OpenBao UI at `https://openbao.${DOMAIN}` or the CLI:

**Path `kv/docker/termix`** — values Termix reads at startup:
```
TERMIX_OIDC_CLIENT_ID     = <Run 1 random string>
TERMIX_OIDC_CLIENT_SECRET = <Run 2 random string>
TERMIX_OIDC_SYSTEM_SECRET = <openssl rand -base64 32 output>
```

Generate the system secret first:
```bash
openssl rand -base64 32
```

**Path `kv/docker/authelia`** — values Authelia reads:
```
OIDC_TERMIX_CLIENT_ID     = <Run 1 random string>
OIDC_TERMIX_CLIENT_SECRET = <Run 2 pbkdf2 digest>
```

- [ ] **Step 4: Verify secrets are readable**

```bash
# From traefik.hirschnet, read back to confirm (requires read-capable token)
curl -s -H "X-Vault-Token: $VAULT_TOKEN" http://localhost:8200/v1/kv/data/docker/termix | python3 -m json.tool | grep -E "CLIENT_ID|CLIENT_SECRET"
```

Expected: both keys present under `data.data`.

---

## Task 2: Add Termix OIDC Client to Authelia, Remove Guacamole

**Files:**
- Modify: `authelia/configuration.yml:271-292`
- Modify: `docker-compose.yml:534-535`

- [ ] **Step 1: Remove guacamole OIDC client from authelia/configuration.yml**

Delete lines 271-292 (the entire `#GUACAMOLE` block):

```yaml
#GUACAMOLE
      - client_id: '{{ env "OIDC_GUACAMOLE_CLIENT_ID" }}'
        client_name: 'guacamole'
        client_secret: '{{ env "OIDC_GUACAMOLE_CLIENT_SECRET" }}'
        public: false
        authorization_policy: 'two_factor'
        require_pkce: false
        pkce_challenge_method: ''
        redirect_uris:
          - 'https://guac.{{ env "DOMAIN" }}'
        scopes:
          - 'openid'
          - 'profile'
          - 'groups'
          - 'email'
        response_types:
          - 'id_token'
        grant_types:
          - 'implicit'
        userinfo_signed_response_alg: 'none'
        claims_policy: 'default'
        token_endpoint_auth_method: 'client_secret_basic'
```

- [ ] **Step 2: Add Termix OIDC client in its place**

In `authelia/configuration.yml`, in the `clients:` list (where the guacamole block was), add:

```yaml
#TERMIX
      - client_id: '{{ env "OIDC_TERMIX_CLIENT_ID" }}'
        client_name: 'Termix'
        client_secret: '{{ env "OIDC_TERMIX_CLIENT_SECRET" }}'
        public: false
        authorization_policy: 'two_factor'
        pkce_challenge_method: 'S256'
        redirect_uris:
          - 'https://termix.{{ env "DOMAIN" }}/users/oidc/callback'
        scopes:
          - 'openid'
          - 'profile'
          - 'groups'
          - 'email'
        response_types:
          - 'code'
        grant_types:
          - 'authorization_code'
        token_endpoint_auth_method: 'client_secret_basic'
        userinfo_signed_response_alg: 'none'
```

- [ ] **Step 3: Update authelia environment block in docker-compose.yml**

At lines 534-535, replace the guacamole env var entries with termix ones:

Old:
```yaml
      - OIDC_GUACAMOLE_CLIENT_ID
      - OIDC_GUACAMOLE_CLIENT_SECRET
```

New:
```yaml
      - OIDC_TERMIX_CLIENT_ID
      - OIDC_TERMIX_CLIENT_SECRET
```

- [ ] **Step 4: Restart Authelia to pick up the new client**

```bash
./dc.sh restart authelia
```

- [ ] **Step 5: Verify Authelia started cleanly**

```bash
./dc.sh logs authelia --tail=30
```

Expected: no errors, no `OIDC_GUACAMOLE_*` references, no startup failures. If you see a missing env var error, check that the OpenBao secrets at `kv/docker/authelia` are set correctly and that `dc.sh` injected them.

---

## Task 3: Add Termix Service to docker-compose.yml

**Files:**
- Modify: `docker-compose.yml` (insert after the guacamole block, before ttyd section at line 730)

- [ ] **Step 1: Add the termix service block**

Insert the following block after the guacamole service (around line 728, before the `########## ttyd` comment):

```yaml
########## Termix
# Browser-based SSH management — replaces ttyd and guacamole
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

- [ ] **Step 2: Start Termix**

```bash
./dc.sh up -d termix
```

- [ ] **Step 3: Verify container started**

```bash
./dc.sh logs termix --tail=30
```

Expected: Termix prints startup messages, no crash, nginx starting, backend running. If you see an OIDC env var error, double-check that `TERMIX_OIDC_CLIENT_ID`, `TERMIX_OIDC_CLIENT_SECRET`, and `TERMIX_OIDC_SYSTEM_SECRET` are in `kv/docker/termix` and that `dc.sh` injected them.

---

## Task 4: Verify Termix OIDC Login

**Files:** None

- [ ] **Step 1: Navigate to Termix in browser**

Go to `https://termix.${DOMAIN}`. You should see either a Termix login page or be redirected to Authelia.

- [ ] **Step 2: Complete OIDC login**

Click "Sign in with SSO" (or similar). Authelia's login page appears. If already logged in to Authelia, the OIDC consent/callback happens automatically and you land on the Termix dashboard.

- [ ] **Step 3: Confirm dashboard loads**

Expected: Termix dashboard with empty host list. If you get a redirect loop or OIDC error, check:
- `./dc.sh logs termix --tail=50` for OIDC errors
- `./dc.sh logs authelia --tail=50` for callback/redirect_uri mismatches
- The redirect URI in `authelia/configuration.yml` must exactly match `https://termix.${DOMAIN}/users/oidc/callback`

---

## Task 5: Configure traefik.hirschnet SSH Host with Auto-Tmux

**Files:** None (Termix UI configuration)

- [ ] **Step 1: Verify start-tmux.sh works via direct SSH**

From another terminal, SSH into traefik.hirschnet and run the script directly (not via nsenter):

```bash
ssh nat@traefik.hirschnet
~/bin/start-tmux.sh
```

Expected: tmux session starts with your configured pane layout. If it errors, debug the script before proceeding — the nsenter wrapper is gone, so the script must work in a plain SSH session. If there are issues, they need fixing in `~/bin/start-tmux.sh` on the host.

Exit the tmux session (`Ctrl-b d` to detach, then `exit` the SSH session) before continuing.

- [ ] **Step 2: Generate SSH credential in Termix**

In the Termix UI → Settings → Credentials → Add Credential:
- Type: SSH Key
- Name: `termix-key`
- Click "Generate" to create a new keypair (or upload an existing one)
- Copy the public key that Termix displays

- [ ] **Step 3: Add Termix public key to authorized_keys on traefik.hirschnet**

On `traefik.hirschnet`:

```bash
echo "<paste public key here>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Verify the key was added:

```bash
tail -1 ~/.ssh/authorized_keys
```

Expected: the key you just pasted.

- [ ] **Step 4: Add traefik.hirschnet as a saved host in Termix**

In the Termix UI → Hosts → Add Host:
- Label: `traefik.hirschnet`
- Hostname: `traefik.hirschnet` (or its LAN IP if DNS isn't resolving inside the container)
- Port: `22`
- Username: `nat`
- Authentication: SSH Key → select `termix-key`
- Startup Command: `~/bin/start-tmux.sh`

Save the host.

- [ ] **Step 5: Test the connection**

Click the host to connect. Expected: terminal opens, `start-tmux.sh` runs, tmux pane layout appears. If the connection fails:
- Check that the public key is in `~/.ssh/authorized_keys` on the host
- Check that `traefik.hirschnet` resolves from inside the Termix container (`./dc.sh exec termix nslookup traefik.hirschnet`)
- Try using the host's LAN IP instead of hostname if DNS fails

---

## Task 6: Add Remaining Homelab Hosts

**Files:** None (Termix UI)

- [ ] **Step 1: Add spark.hirschnet**

In Termix → Hosts → Add Host:
- Label: `spark.hirschnet`
- Hostname: `spark.hirschnet`
- Port: `22`
- Username: `nat`
- Authentication: SSH Key → `termix-key` (same key — add it to spark's authorized_keys first)

On `spark.hirschnet`:
```bash
ssh nat@spark.hirschnet "echo '<paste termix-key public key>' >> ~/.ssh/authorized_keys"
```

Test the connection from Termix.

- [ ] **Step 2: Add other key hosts**

Repeat the authorized_keys + Termix host entry steps for each host you want accessible:
- Proxmox node (`root@<proxmox-ip>`, port 22)
- NAS (`<nas-user>@<nas-hostname>`, port 22 or custom SSH port)
- Any other hosts previously configured in Guacamole

For each, add the termix-key public key to that host's `~/.ssh/authorized_keys` and create the host entry in Termix.

---

## Task 7: Remove Guacamole and ttyd from docker-compose.yml

> Only proceed once Termix is working end-to-end (Tasks 4 and 5 complete).

**Files:**
- Modify: `docker-compose.yml` (remove lines ~686-779)

- [ ] **Step 1: Stop and remove the old containers**

```bash
./dc.sh stop guacamole ttyd-user ttyd-router
./dc.sh rm -f guacamole ttyd-user ttyd-router
```

- [ ] **Step 2: Remove the guacamole service block from docker-compose.yml**

Delete the entire `########## Guacamole` section (lines 686-727, from the comment through the last label). The block ends just before the blank lines at 728.

- [ ] **Step 3: Remove the ttyd service blocks from docker-compose.yml**

Delete the entire `########## ttyd` section (lines 730-779), which includes both `ttyd-user` and `ttyd-router`.

- [ ] **Step 4: Verify docker-compose.yml is valid**

```bash
./dc.sh config --quiet
```

Expected: no output (valid config). If there are YAML errors, fix the indentation or missing separators around the deleted blocks.

---

## Task 8: Clean Up Config Files and Commit

**Files:**
- Delete: `ttyd/nginx.conf`
- Delete: `~/bin/ttyd-shell` (on host)
- Delete: `guac/` directory (on host, at `${DOCKERDIR}/guac/`)

- [ ] **Step 1: Delete ttyd nginx config**

```bash
rm /home/nat/docker/ttyd/nginx.conf
rmdir /home/nat/docker/ttyd 2>/dev/null || true  # remove dir if now empty
```

- [ ] **Step 2: Delete ttyd-shell on the host**

```bash
rm ~/bin/ttyd-shell
```

- [ ] **Step 3: Remove guacamole data directory**

The guac directory contains the Guacamole SQLite database, font configs, and init scripts. It is safe to delete once the container is removed:

```bash
rm -rf ${DOCKERDIR}/guac
```

Substitute the actual value of `$DOCKERDIR` (typically `/home/nat/docker`):

```bash
rm -rf /home/nat/docker/guac
```

- [ ] **Step 4: Remove guacamole OIDC secrets from OpenBao**

In the OpenBao UI at `https://openbao.${DOMAIN}`, navigate to `kv/docker/authelia` and delete the `OIDC_GUACAMOLE_CLIENT_ID` and `OIDC_GUACAMOLE_CLIENT_SECRET` keys. (Requires write access / temporary root token.)

- [ ] **Step 5: Verify Termix still works after cleanup**

```bash
./dc.sh logs termix --tail=10
```

Navigate to `https://termix.${DOMAIN}` and confirm the dashboard loads and the traefik.hirschnet host is still present and connectable.

- [ ] **Step 6: Commit**

Check the diff before committing — confirm no domain names, IPs, tokens, or secrets are in staged files:

```bash
git diff HEAD
```

Then commit:

```bash
git add docker-compose.yml authelia/configuration.yml
git add -u  # stage any deletions (ttyd/nginx.conf)
git commit -m "feat: replace guacamole and ttyd with Termix

- Remove guacamole (unused Java-based remote desktop gateway)
- Remove ttyd-user, ttyd-router, and nsenter/nginx routing stack
- Add Termix: single SSH management container with OIDC via Authelia
- Auto-tmux behavior preserved via per-host SSH startup command"
```
