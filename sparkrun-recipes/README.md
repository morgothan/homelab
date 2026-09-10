# sparkrun-recipes

vLLM inference recipes for the `spark1` + `spark2` DGX Spark cluster. These are
`sparkrun` recipe-v2 files (`sparkrun recipe validate <file>`).

## Deployed

**`deepseek-v4-flash-vision-exp-dspark.yaml`** — the recipe the homelab's sole
inference backend runs, since **2026-09-10**. DeepSeek V4 Flash **Vision-Exp**
(native image input), DSpark spec-decode (k=5), 1M context, TP=2, B12X MoE,
`nvfp4_ds_mla` KV @ gmu 0.85. Served at `spark.hirschnet:8000/v1` as
`deepseek-v4-flash-vision-exp`. It replaced the 0731 text recipe (below, now the
rollback target). Full detail: the "Vision-Exp migration" section further down —
that is where the vendor provenance, the 3 local deltas, and the deploy /
rollback / consumer steps live.

It is **vendored** (not verbatim — 3 local deltas) from tonyd2wild's repo. The
live copy on spark1 at `~/.config/sparkrun/services/sparkrun-deepseek/recipe.yaml`
is what `sparkrun-deepseek.service` (systemd, system scope) actually loads; this
file is the version-controlled mirror. Keep them in sync by hand.

### Rollback target — `deepseek-v4-flash-0731-dspark-nvfp4kv.yaml`

The previous deployed recipe: DeepSeek V4 Flash 0731 (text only), DSpark k=5, 1M
context, `fp8` KV @ gmu 0.78, served as `deepseek-v4-flash-0731`. Still
**vendored verbatim** from the pre-migration live copy. To roll back: restore
this onto spark1's `recipe.yaml` (a `recipe.yaml.bak-*` from 2026-09-10 is the
same content), revert the `served_model_name` change across consumers (see the
migration section's consumer list), `systemctl restart sparkrun-deepseek`.

### Delta from the 2026-08-27 original export

- `num_speculative_tokens` 3 → 5 — upstream retracted all k=3 guidance.
- `pre_exec` step 3 applies tonyd2wild **Patch 5**
  (`0005-suppress-stops-in-reasoning.patch` @ `0fec8084`) via `git apply` inside
  the container, pinned to the container's vllm tree (0.21.1-dev). Idempotent;
  non-fatal if it fails to apply (server still serves, reasoning replies can be
  truncated when a client sends stop strings). Verified with `git apply --check`
  against the pinned image before shipping.

### Deploy / update

```bash
scp sparkrun-recipes/deepseek-v4-flash-0731-dspark-nvfp4kv.yaml \
    nat@spark.hirschnet:/tmp/recipe.new.yaml
ssh nat@spark.hirschnet '
  cd ~/.config/sparkrun/services/sparkrun-deepseek &&
  cp recipe.yaml recipe.yaml.bak-$(date +%Y%m%d-%H%M%S) &&
  cp /tmp/recipe.new.yaml recipe.yaml
'
ssh nat@spark.hirschnet 'sudo systemctl restart sparkrun-deepseek'
journalctl -u sparkrun-deepseek -f          # through "Step 7/7"
sparkrun logs <job-id> -f -a                 # job-id from: sparkrun status
curl -s http://spark.hirschnet:8000/v1/models
```

This restart **drops inference for the whole homelab** for the bring-up window
(~3-4 min): Open WebUI, Hermes, lab-monitor, Hindsight, Home Assistant all hit
`spark.hirschnet:8000`.

### Rollback

```bash
ssh nat@spark.hirschnet '
  cd ~/.config/sparkrun/services/sparkrun-deepseek &&
  cp recipe.yaml.bak-<stamp> recipe.yaml
'
ssh nat@spark.hirschnet 'sudo systemctl restart sparkrun-deepseek'
```

### Known lint (`sparkrun recipe validate`)

- `managed-cache-env` warning and two `inline-script` suggestions are inherited
  from the original export. The recipe patches its own container from inline
  `pre_exec` strings (dspark overlay + Patch 5) rather than a published image or
  a `mods:` dir. Left as-is to match the existing recipe; revisit if the
  pre_exec grows further.

## Vision-Exp migration (done 2026-09-10)

**`deepseek-v4-flash-vision-exp-dspark.yaml`** — now the deployed recipe (see
top). Serves `deepseek-ai/DeepSeek-V4-Flash-Vision-Exp`: native image input, plus
a few points on the text agent evals vs 0731 (DeepSWE +4.9, Toolathlon +5.6,
DSBench-Hard +4.0 — HF model card). Same digest-pinned base image as the 0731
recipe; the DSpark stage-c runtime and a ViT+aligner vision port are rebuilt
in-container by `pre_exec`, fetched pinned from tonyd2wild's repo. No image build.

Vendored from `tonyd2wild/DeepSeek-v4-Flash-Vision-Exp-DSpark-1M-NVFP4-KV-2x-DGX-Spark`,
file `sparkrun/deepseek-v4-flash-vision-exp-dspark-nvfp4-1m-vllm.yaml` @ `43201d1c`.
**Three local deltas** (see the file header): `port` 8888→8000; a homelab Patch 5
block (output-side-arming revision — Vision-Exp has no chat template so `<think>`
opens as an output token); JIT/compile cache env repointed from `/cache/runtime/*`
(not container-writable on spark1/spark2 — FlashInfer JIT logger got EPERM) to
`/cache/huggingface/sr-cache/*`, the set the 0731 recipe uses.

**Deltas from the previous 0731 recipe:** `served_model_name`
`deepseek-v4-flash-0731` → `deepseek-v4-flash-vision-exp` (all consumers moved —
see below); `kv_cache_dtype` fp8 → `nvfp4_ds_mla`; `gpu_memory_utilization`
0.78 → 0.85 (the profile tonyd2wild validates as a set for the vision port; its
README warns <0.85 "dies under traffic"). Known port deviations affect **image
quality only** — text requests are byte-identical to 0731.

**Bring-up notes from the actual 2026-09-10 deploy:** cold first boot ~8 min to
open `:8000` (in-container stage-c rebuild + vision-port inject + weight load +
CUDA-graph capture). Verified live: text + tool-call + 57K-ctx needle + native
image ("red left / blue right") all correct; Patches 3/4/5 present in-container;
`Using 'B12X' Mxfp4 MoE backend`; KV pool 2.72M tokens; ~34 tok/s prose (matches
upstream's vision numbers).

### Deploy

Pre-stage the weights on **both** nodes first (non-disruptive, ~167 GB, needs
~200 GB free — spark1/spark2 have ~2.5 TB):

```bash
for h in spark.hirschnet spark2.hirschnet; do
  ssh nat@$h 'docker run --rm -v ~/.cache/huggingface:/cache/huggingface \
    -e HF_HOME=/cache/huggingface -e HF_HUB_DISABLE_XET=1 \
    --entrypoint /opt/env/bin/python \
    ghcr.io/bjk110/vllm-spark@sha256:d8492e7677cf1b9aaa3344e0e6865efc468454013eee5ebabac85be90af027be \
    -c "from huggingface_hub import snapshot_download; print(snapshot_download(\"deepseek-ai/DeepSeek-V4-Flash-Vision-Exp\"))"'
done
```

Then swap in place (same mechanics as the 0731 recipe above):

```bash
scp sparkrun-recipes/deepseek-v4-flash-vision-exp-dspark.yaml \
    nat@spark.hirschnet:/tmp/recipe.new.yaml
ssh nat@spark.hirschnet '
  cd ~/.config/sparkrun/services/sparkrun-deepseek &&
  cp recipe.yaml recipe.yaml.bak-$(date +%Y%m%d-%H%M%S) &&
  cp /tmp/recipe.new.yaml recipe.yaml
'
# update the systemd unit description/served-model-name if it pins one:
ssh nat@spark.hirschnet 'systemctl cat sparkrun-deepseek | grep -n served-model-name || true'
ssh nat@spark.hirschnet 'sudo systemctl restart sparkrun-deepseek'
journalctl -u sparkrun-deepseek -f          # through "Step 7/7"; vision boot ~5-6 min
sparkrun logs <job-id> -f -a                # job-id from: sparkrun status
curl -s http://spark.hirschnet:8000/v1/models   # expect id deepseek-v4-flash-vision-exp
```

Smoke test before touching consumers: a text chat completion + a tool call, a
long-context prompt, and one `image_url` (base64) request.

### Consumers — `deepseek-v4-flash-0731` → `deepseek-v4-flash-vision-exp`

Done 2026-09-10 except Home Assistant (see below):

- ✅ OpenBao `kv/docker/misc:VLLM_MODEL` (via the admin root-token process —
  see the OpenBao Admin Process memory)
- ✅ OpenBao `kv/hermes/hindsight:REFLECT_VLLM_MODEL` + `CONSOLIDATION_VLLM_MODEL`
- ✅ Hermes `~/.hermes/config.yaml` (8 keys), `~/.hermes/profiles/fast/config.yaml`,
  `~/.hermes/hindsight/config.json` — `sed -i` + restart `hermes-gateway`.
  Backup: `~/.hermes/_model-swap-bak-20260910-180948/` on hermes.
- ✅ Recreated `lab-monitor` (traefik) + `hindsight` (hermes) with
  `./dc.sh up -d --force-recreate`. Hindsight log confirms
  `model=deepseek-v4-flash-vision-exp` for base/reflect/consolidation.
- ✅ Open WebUI auto-discovered via `/v1/models` — no change needed.
- ⏳ **Home Assistant** OpenAI-conversation integration — still on the old name.
  Change it in the HA UI: Settings → Devices & Services → the OpenAI conversation
  integration → Configure → model field → `deepseek-v4-flash-vision-exp`.

### Rollback

Restore a `recipe.yaml.bak-*` from 2026-09-10 (== `deepseek-v4-flash-0731-dspark-
nvfp4kv.yaml`) onto spark1's `recipe.yaml`, fix the unit `Description=` back,
`systemctl restart sparkrun-deepseek`. Port stayed 8000 throughout. Then revert
the consumers: OpenBao needs the admin root-token process again for the two
paths; Hermes `sed -i` the reverse (or restore the `_model-swap-bak-*` dir);
recreate `lab-monitor` + `hindsight`; restart `hermes-gateway`; HA UI. Deeper
fallback: the disabled single-node `vllm.service` (Qwen3.6) on spark1.

### Known lint (`sparkrun recipe validate`)

Same `managed-cache-env` warning + `inline-script` suggestions as the 0731
recipe, plus two more `inline-script` hits for the vision-port and torch-aotcache
`pre_exec` blocks. `VLLM_CACHE_ROOT` points at `/cache/runtime` by upstream's
choice (an NFS-race guard that doesn't bite us — our HF caches are node-local —
but harmless; costs a torch.compile rebuild per warm boot). Left as-is to stay
close to the upstream validated file.

## Not deployed

**`deepseek-v4-flash-0731-nvfp4-weights.experimental.yaml`** — seed for the
Option B experiment: NVFP4 **weights** checkpoint (`nvidia/DeepSeek-V4-Flash-
0731-NVFP4`) instead of fp8 weights + fp8/nvfp4 KV. Half the ~155 GB footprint,
but DSpark-on-NVFP4-weights is community-validated only and needs a different
vLLM base (`jasl/vllm` sm120 PR-41834) + its own draft-routing patch. Bring up
beside prod, benchmark acceptance + output quality, then decide on cutover
(which also means updating every consumer's model name). Not wired to anything.
