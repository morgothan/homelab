# RainSoft EC5 interceptor

This service emulates the HTTP endpoints used by a RainSoft EC5 controller, archives each
request as JSONL, and exports the reported values to Prometheus.

## Field interpretation

The names below are based on the EC5 owner's manual and on transitions observed in the
local request archive.

| Device field | Exported meaning |
| --- | --- |
| `daily_water` | Water used during the current day, gallons |
| `flow_since_regen` | Treated water since the last regeneration, gallons |
| `lifetime_flow` | Treated water since installation, gallons |
| `capacity_remaining` | Remaining treatment capacity, percent |
| `capacity_at_start` | Capacity remaining immediately before the last regeneration, percent |
| `water_28_day` | Total treated water during the rolling last 28 days, gallons |
| `salt_28_day` | Average salt used per week, calculated over four weeks, pounds |
| `regens_28_day` | Regeneration count during the rolling last 28 days |
| `salt_lbs` | Estimated salt remaining in the brine tank, pounds |
| `remain_interval` | Remaining auxiliary-system service interval; this device reports months |

The raw installer values `unit_size`, `resin_type`, `injector`, `psi`, `starting_cap`, and
`max_salt` are firmware codes/settings. They are deliberately exported with `_code` or
`_setting` names because their numeric encoding is not documented in the owner's manual.
Device event codes are likewise retained without speculative descriptions.

The observed auxiliary category order matches the EC5 manual's Drinking Water, Filter,
and Airmaster categories. The dashboard names systems 1–3 accordingly while retaining the
raw category/type codes in the definitions table.

## Persistence and logs

Metric state is saved atomically in `/data/last_state.json`. Rare event and auxiliary-system
metadata from older versions is recovered once from the JSONL archive. Raw requests rotate
at 50 MiB with five backups by default. Set `RAINSOFT_LOG_MAX_BYTES` or
`RAINSOFT_LOG_BACKUPS` to change those limits; set the maximum to `0` to disable rotation.
