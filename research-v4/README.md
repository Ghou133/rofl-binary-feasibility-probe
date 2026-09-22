# Protection Telemetry V4

This is an additive DuckDB layer over `research-v3/output/replay_research.duckdb`. It never alters, drops, or updates V3 tables. `backfill_protection` accepts decoded `0x009e` OnEvent and `0x0017` shield-damage JSONL streams and replaces only the target Replay's V4 rows transactionally.

The compact handoff carries this code and bounded, path-free publication summaries. It does not carry the database, raw Replay files, memory image or full decoded JSONL. A clean-machine full backfill therefore remains unverified until those authorised inputs are provided separately.

```powershell
python -B research-v4/protection_layer.py `
  --replay-sha256 <sha> `
  --decoded-jsonl <decoded-009e.jsonl> `
  --decoded-jsonl <decoded-0017.jsonl>

python -B -m unittest discover -s research-v4/tests -v
python -B research-v4/verify_v4.py `
  --db research-v3/output/replay_research.duckdb
```

`0x4b` heal rows are retained individually in `heal_events`; `protection_events` exposes one canonical first row per exact `(Replay, time, full params blob)` group and its group size. The reported amount is direct, but raw/effective/overheal semantics remain unresolved and therefore stay `NULL`.

`0xed` is the sole canonical shield-generation route. A preceding `0xee` is attached only if the identical Replay/time/blob has raw occurrence delta exactly one. Direct `0x0017` rows are emitted once as `SHIELD_ABSORBED`, with target and absorbed amount verified directly. They are target-total observations: source, spell, shield instance, and consumption order remain unavailable.

Current/max HP, shield remaining/unused, temporary HP, and temporary max-HP modification remain `NULL`. Normal Python batch ingest and the JavaScript semantic pipeline require both decoder routes; a verified zero-row `0x0017` scan is recorded as `NO_PROTECTION_EVENT`, not `DECODER_UNAVAILABLE`.
