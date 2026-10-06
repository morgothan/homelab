# Cloudflare Rulesets API compatibility build

The official bouncer v0.3.0 uses the legacy Firewall Rules API. Cloudflare returns
`firewallrules.api.rulesets_only_rule` (10021) for zones with Rulesets API rules,
causing a restart loop. This local build pins upstream by commit and checksum
and adapts firewall operations to the Rulesets API. IP-list synchronization uses
the original upstream implementation.

Writes address individual rules, preserving unrelated rules and writable fields
of the updated rule. Disabled rules and rules with the wrong action are not
adopted as active enforcement. Upstream package tests and HTTP adapter tests run
during the image build.

## Credentials

`CF_CROWDSEC_TOKEN` retains account-list and zone-read operations.
`CF_CROWDSEC_WAF_TOKEN` handles Rulesets API operations and must have
**Zone → Zone WAF → Edit** for the affected zone. Compose supplies the existing
WAF-capable `CF_FAIL2BAN_TOKEN` for this purpose. If no separate WAF token is
provided, the adapter falls back to the list token. Credentials remain in OpenBao.

## Deploy and verify

After correcting permissions:

```sh
./dc.sh config --quiet
./dc.sh up -d --build --no-deps crowdsec-cloudflare-bouncer
docker logs --since 5m crowdsec-cloudflare-bouncer
docker inspect crowdsec-cloudflare-bouncer --format '{{.State.Status}} {{.RestartCount}}'
docker exec crowdsec cscli bouncers list
```

Verify an enabled block rule referencing `$crowdsec_block` with
`GET /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint`.
Review preceding skip rules for intended coverage. Container uptime and LAPI
pulls alone do not prove Cloudflare edge enforcement.

The existing 96-hour Cloudflare update interval is retained for list-write quota
compatibility. Upstream waits this interval before the first sync after startup.
Restoring the rule enforces the existing list immediately, but new decisions
will not synchronize until the next list update. The supported Worker bouncer
is the upstream migration path for faster synchronization and requires separate
Worker/KV resources and API permissions.

Sources:
- https://github.com/crowdsecurity/cs-cloudflare-bouncer
- https://developers.cloudflare.com/ruleset-engine/rulesets-api/update-rule/
- https://docs.crowdsec.net/u/bouncers/cloudflare/

## Recovery verified 2026-09-22

The WAF-capable token confirmed that the existing CrowdSec rule was enabled;
`num_referencing_filters: 0` in Lists API metadata did not mean it was unused by
the modern ruleset. The incident interrupted synchronization, not enforcement
of the previously uploaded list.

A temporary 60-second interval allowed one catch-up update at 13:11:59 UTC.
Cloudflare confirmed 10,000 entries and the new modification timestamp. The
normal 96-hour interval was restored and the container restarted at 13:12:26 UTC.
The existing rule was adopted, LAPI polling resumed, and Docker reported zero
automatic restarts. The list cap excluded 13,648 IPs during the catch-up update.
The upstream binary logs an intentional SIGTERM as fatal on manual restart;
that single shutdown message is not a renewed API failure.
