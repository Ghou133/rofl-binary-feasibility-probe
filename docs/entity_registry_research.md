# Generic Entity Registry V1

Status: `PARTIAL` — a parser-only, deterministic registry foundation is now available. It records only supplied semantic/raw entity facts. It does not identify map regions, infer gameplay behavior, or elevate an unknown entity into a named game category.

## Contract

`src/generic_entity_registry.js` accepts supplied entity records and emits the canonical lifecycle vocabulary:

```text
ENTITY_SPAWN
ENTITY_UPDATE
ENTITY_DEATH
ENTITY_DESTROY
ENTITY_DESPAWN
```

Every stored entity preserves its primary ID plus all supplied network aliases, an explicitly supplied `entity_type`/`entity_subtype` (otherwise `UNKNOWN_ENTITY`), owner/team, lifecycle timestamps, position observations, names/template/archetype values, exact build metadata, and field/raw-packet evidence. The registry never derives a type from entity names, positions, owner, map fields, or timing.

`ingestLifecycle` converts an already-decoded lifecycle row to a spawn plus an observed end only when the source supplies an end timestamp. It does not decide whether that end was a death, structure destruction, or natural expiry.

## APIs

- `new GenericEntityRegistry()` / `ingest(record)` / `ingestMany(records)`
- `ingestLifecycle(record)` for a supplied lifecycle row
- `get(entityOrAlias)` and `query({ entity_id, event_type, from_ms, to_ms })`
- `toJSON()` and `writeEntityRegistry(path, registry)`
- `node scripts/build_entity_registry.js --input source.jsonl --output registry.json [--limit N]`

The builder accepts JSONL, a JSON array, a single record, or an existing semantic decode document with `events` arrays. `--lifecycle` is opt-in because no generic lifecycle source implicitly proves an event’s end semantics.

## Bounded saved-evidence exercise

`artifacts/semantic_coverage_v1/generic_entity_registry_16_16_vision_slice.json` is generated from the first 12 rows of the preserved `16_16_ward_semantic_recovery_v1/vision_entity_events_16_16.jsonl` corpus. Its source release manifest binds the source to build `16.16.805.0442`, 20 Replays, and 31,862 fully-consumed source rows. The bounded output intentionally retains those entities as `UNKNOWN_ENTITY` because that source does not supply a generic canonical entity type.

This is an integration artifact for schema/provenance preservation, not a claim that the Registry validates the upstream decoder or that every source entity is a ward.
