# ROFL capability manifest

The canonical machine-readable capability declaration is
`artifacts/semantic_coverage_v1/capability_manifest.json`. It is an additive
Parser-owned contract covering only protocol semantics and exact-build decoder
evidence. It does not define map locations, behavior, Replay acquisition, or
product UI.

The manifest contains every currently registered canonical capability for the
two exact profiles `16.15.801.3452` and `16.16.805.0442`. Every build/capability
record has these fields:

- `semantic_capability`, `build`, `protocol_route`,
  `packet_registration_route`, and `decoder_version`
- `field_mapping`, `evidence_grade`, `validation_status`, and `sample_count`
- `positive_examples`, `negative_examples`, `known_limits`, `introduced_at`,
  `last_verified_at`, and `canonical_schema_version`

`UNAVAILABLE` means the current exact-build semantic is not recovered; it never
claims that the data cannot exist in another build. `UNVERIFIED` means work has
not established the semantic. Both preserve missing values as null/unknown,
never zero.

## Programmatic interface

`src/capability_manifest.js` exposes:

- `createCapabilityManifest()` and `validateCapabilityManifest()` for the
  canonical in-memory contract.
- `queryCapability(manifest, { build, capability })` for an exact-build lookup.
  An unregistered build returns `UNSUPPORTED_BUILD` and no record.
- `writeCapabilityManifest(path)` and `readCapabilityManifest(path)` for
  validated artifact exchange.
- `createSemanticCompatibilityMatrix()`, `querySemanticCompatibility()`, and
  corresponding validation/write functions for cross-build consumption.

There is no wildcard, patch-family, or nearest-build lookup. Consumers must
pass the exact Replay header build and retain the emitted build/schema/evidence
metadata with their output.

## Evidence boundaries currently captured

`16.15.801.3452` records direct Hero Death (`0x0160`), Damage source/target/
amount and damage type (`0x028a`), the direct numeric/hex damage script key,
CastSpell, Buff, Protection V4 shield/heal fields, and the existing
Path/Level/Ward surfaces. `field_20 == 3` supports only a positive derived
critical flag. Human-readable spell/basic/item/rune/passive attribution and
pre/post-mitigation meaning remain unavailable.

`16.16.805.0442` records verified participant mapping, HeroPath (`0x00f6`),
LevelTransition (`0x0314`), WardSpawn (`0x049a`) and partial Ward lifecycle.
Hero Damage `0x017f` remains a disabled candidate; Hero Death, CastSpell, Buff,
Protection, combat state, inventory/economy and NPC semantics are not promoted.
Sweeper is explicitly `UNVERIFIED` for held state and does not establish
activation.
