# Homelab News refactor and security review

## Remediation follow-up

The five numbered findings below describe the pre-fix baseline. The follow-up
restores Headroom result handling and policy, restores standalone media logging,
replaces direct local Docker socket access with an isolated read-endpoint proxy,
requires Seerr's configured Authorization header with a 16 KiB body limit, and
requires provisioned SSH host keys. The app no longer belongs to the Docker group.

The information-flow audit additionally added credential redaction before
operational persistence/inference and archive display, removed Hindsight's raw
failed-query/response logging, replaced a device-specific test fixture, disabled
unused API documentation routes, and excluded runtime data from the build context.
Both tokenizer encodings are cached in the image for offline operation.

Validation: 116 tests pass offline in the rebuilt image; 11 proxy allow/deny
checks pass against a fake Docker daemon; Compose and syntax checks pass.
The previous archive/calendar/shared-state findings remain separate follow-up work.

Reviewed: 2026-09-29. Scope: current working tree, including untracked extracted modules, compared with Git HEAD and the earlier review's known uncommitted SIP-phone changes. Application code was not modified or deployed.

## Assessment

The module extraction largely preserves behavior, but should not be accepted as fully equivalent yet. Two regressions were confirmed: Headroom compression output is discarded, and the standalone media worker no longer configures INFO logging. Existing tests pass because neither behavior is covered.

No newly introduced exploitable security vulnerability was identified in the extraction. Existing authentication and infrastructure trust risks remain; a passing test suite does not establish that the deployment is secure.

## Refactor regressions

### 1. Medium — Headroom compression silently becomes ineffective

Location: `homelab-news/llm.py:51–60`, `_compress_messages`.

Evidence: the new code calls `_headroom_compress(messages, config=_HeadroomConfig())`, then only uses the result if `isinstance(compressed, list)`. The installed API returns a `CompressResult` object containing `.messages`, not a list. A focused probe supplied a successful result containing different compressed messages; the helper returned the original messages.

The original implementation returned `result.messages` and explicitly selected `model="gpt-4o"`, `compress_user_messages=True`, `compress_system_messages=False`, `protect_recent=0`, `protect_analysis_context=False`, and `kompress_model="disabled"`. These settings were also lost. Installed defaults instead protect recent messages, disable user-message compression, and permit system-message compression.

Impact: larger inference requests, unnecessary compression work, and possible context-limit or memory failures under large inputs. Those downstream failures were not reproduced against live inference. The removal of system-message protection should be corrected when restoring result handling; currently the discarded output means that change is not evidence of modified instructions reaching the model.

Fix: restore the previous API contract and explicit configuration. Add tests for successful result extraction, unchanged system instructions/configuration, and exception fallback. Merely returning `.messages` leaves the configuration regression unresolved.

### 2. Low — Standalone media worker loses normal operational logs

Location: `homelab-news/media.py:522–544`; INFO messages at lines 511 and 526.

Evidence: the original worker called `logging.basicConfig(level=logging.INFO, ...)`; the extracted module does not configure logging before its entry point. A fresh-process check found root logging level 30 (WARNING) and zero handlers.

Impact: refresh-success and feature-disabled messages disappear under Supervisor's `python -u media.py`, making normal operation harder to distinguish from inactivity. Warning/error logs are not all lost.

Fix: configure logging in the worker entry point, avoiding logging side effects when the reusable module is imported. Verify in a fresh subprocess; importing `web` or another worker first can hide this issue by configuring global logging.

## Existing security risks, not introduced by the refactor

### 3. High — Docker socket grants much broader privileges than collectors require

Rule: least privilege / deployment isolation.

Location: `docker-compose.yml:1103`; `homelab-news/Dockerfile` appuser/docker group setup; `homelab-news/containers.py:35`.

Evidence: the app mounts `/var/run/docker.sock:/var/run/docker.sock:ro` and uses Docker SDK connections. A read-only filesystem mount of a Unix socket does not restrict the API methods sent through it.

Impact: if an attacker gains code execution as the socket-authorized application user, Docker API access can enable host-level compromise. This is a conditional escalation risk, not a demonstrated route to initial code execution.

Fix: put a tightly allowlisted Docker API proxy between the app and daemon, allowing only the required read endpoints, or move Docker collection into a separate process/service with narrow output. Preserve required log/inspection access while denying container creation, exec, and other mutations. Verify the actual daemon authorization policy before assuming unrestricted API access; runtime authorization was not tested with mutating requests.

### 4. Medium — Seerr webhook accepts unauthenticated writes on reachable internal paths

Rule: FASTAPI-AUTH-001.

Location: `homelab-news/web.py:153–187`; `docker-compose.yml:1165–1167`.

Evidence: `/api/events/seerr` parses and saves a request without verifying a token or signature. An isolated TestClient request with no credentials received HTTP 202 and wrote a temporary event. The local HTTP router has no authentication middleware attached in the inspected Compose configuration. The public HTTPS router does use the Authelia middleware chain (`docker-compose.yml:1158`); this is not a claim of unauthenticated public-internet access.

Impact: a caller able to reach the internal service/local route can forge media events and displace legitimate retained history. Those events can feed fallback media displays. Network reachability and live proxy enforcement were not probed.

Fix: verify a dedicated webhook secret/header or supported signature before accepting events. Keep public-route authentication, restrict the internal route to intended senders, and bound request bytes before JSON parsing. Field truncation after parsing is not a request-size limit.

### 5. Medium — SSH collector connections do not require verified host keys

Rule: transport peer authentication.

Location: `homelab-news/containers.py:283–303`; `homelab-news/updates.py:159–170`.

Evidence: subprocess arguments include `StrictHostKeyChecking=no`; the entry point provisions the private key but does not provision a reviewed known_hosts file.

Impact: on an untrusted/intercepted route, particularly first connection, collectors can accept an impersonated SSH server and ingest falsified operational data. This does not imply the SSH private key is transmitted to that server.

Fix: provision verified host keys and require strict checking, with an explicit key-rotation procedure. Confirm any externally provisioned known_hosts/host-certificate controls before changing deployment policy. This behavior was present before extraction.

## Validation and preserved behavior

- 107 existing unit tests passed against the current source mounted read-only in the existing `homelab-news-test` image, with temporary DATA_DIR.
- All 40 Python source/test files parsed successfully; scoped `git diff --check` passed.
- Fourteen fresh-process imports passed: web, today, rolling, daily, updates, periodic, trend_intelligence, media, security, llm, hindsight, containers, templates, and backfill.
- Seven additional routes returned HTTP 200 with isolated empty state: health, both favicons, blotter, entertainment, archive, and trends.
- Hostile article and media-title HTML was escaped in targeted rendering probes. The existing prompt-filter example still produced `[FILTERED]`; regex filtering is not a complete prompt-injection defense.
- AST comparisons of moved functions and top-level assignments found the rendering functions, media-domain functions, container functions, and most security/inference logic unchanged. Relevant differences were import relocation, the compression change, and the already-existing SIP-phone handling changes.
- Tests changed their patch targets to the new owning modules; the inspected changes did not remove their assertions. Compatibility re-exports preserve calls, but monkeypatching a re-export no longer changes the owning module's globals.

## Limits and remaining work

This was a source and isolated-test review, not a live deployment or penetration test. No production workers were started, no real webhook was sent, and no privileged Docker operation was attempted. Tests used existing image dependencies; the image was not rebuilt and dependencies were not checked against a current vulnerability database. The tokenizer's existing import-time encoding download remains.

The earlier archive-format mismatch, calendar-period selection problems, shared JSON update risks, and suppressed persistence errors remain outside this extraction. New reusable modules also remain at the top level rather than the `homelab_news/` location described in DEVELOPMENT.md, and media still combines a worker with reusable domain code. These are follow-up work, not new security regressions.

Recommended acceptance gate: fix findings 1 and 2 with regression tests, retain all 107 existing tests, and rebuild/smoke-test the resulting image before deployment. Treat findings 3–5 as a separate deployment-hardening effort with explicit compatibility checks.
