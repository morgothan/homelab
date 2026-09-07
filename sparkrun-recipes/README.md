# sparkrun-recipes

vLLM inference recipes for the `spark1` + `spark2` DGX Spark cluster. These are
`sparkrun` recipe-v2 files (`sparkrun recipe validate <file>`).

## Deployed

**`deepseek-v4-flash-0731-dspark-nvfp4kv.yaml`** — the recipe the homelab's sole
inference backend runs. DeepSeek V4 Flash 0731, DSpark spec-decode (k=5), 1M
context, TP=2, B12X MoE. Served at `spark.hirschnet:8000/v1` as
`deepseek-v4-flash-0731`.

It is **vendored verbatim** from the live copy on spark1 at
`~/.config/sparkrun/services/sparkrun-deepseek/recipe.yaml`, which is what
`sparkrun-deepseek.service` (systemd, system scope, on spark1) actually loads.
This file is the version-controlled mirror — spark1 is still the runtime source
of truth. Keep them in sync by hand.

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

## Not deployed

**`deepseek-v4-flash-0731-nvfp4-weights.experimental.yaml`** — seed for the
Option B experiment: NVFP4 **weights** checkpoint (`nvidia/DeepSeek-V4-Flash-
0731-NVFP4`) instead of fp8 weights + fp8/nvfp4 KV. Half the ~155 GB footprint,
but DSpark-on-NVFP4-weights is community-validated only and needs a different
vLLM base (`jasl/vllm` sm120 PR-41834) + its own draft-routing patch. Bring up
beside prod, benchmark acceptance + output quality, then decide on cutover
(which also means updating every consumer's model name). Not wired to anything.
