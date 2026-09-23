# PROJECT CHARTER

## PROJECT ID

`ROFL_PARSER` (`rofl-binary-feasibility-probe`) owns replay protocol semantics.
The public repository is `SOURCE_FROZEN_DURING_MIGRATION`, with a semantic baseline
of 2026-08-21. Authorized maintenance does not reopen protocol research, promote
fields, delete research assets, or create a second active protocol authority.

For ordinary documentation, testing and fixes within the existing contract, read
`AGENTS.md`, this charter, `project_contract.json`, and the relevant local source.
No private sibling repository is required for that work. Cross-project ownership,
architecture, published capabilities and research-asset changes still require the
maintainer's V2 governance review described in `docs/PUBLIC_DEVELOPMENT.md`.
Do not treat archived stage reports as new tasks or run V1 governance.

## WHY THIS PROJECT EXISTS

To establish and validate replay protocol semantics that other layers can consume without duplicating binary decoding research.

## NORTH STAR ROLE

`.rofl -> version-specific protocol decode -> reliable semantic truth`.

## PRIMARY RESPONSIBILITIES

Own packet reverse engineering, decoder and payload layouts, semantic event extraction, exact-build version binding, evidence grades, the semantic API, and parser capability manifests.

## NON-GOALS

It does not own map truth, game-behavior inference, live runtime acquisition, application UI, or offline corpus collection.

## OWNED DATA

Protocol fixtures, packet inventories, payload layouts, decoder profiles, build registrations, replay parsing evidence, semantic event records, and capability manifests.

## OWNED LOGIC

Replay container decoding, packet decoding, event normalization, protocol semantics, compatibility gates, and parser validation.

## UPSTREAM

Offline replay/metadata pairs from `lol-data-collector`, canonical governance contracts, and lawful local replay fixtures.

## DOWNSTREAM

`lol-inference-lab` consumes semantic parser output; Akari may invoke only published parser/feature interfaces, never private decoder internals.

## FORBIDDEN RESPONSIBILITIES

Do not become the map/behavior authority, an Akari runtime, a collector, or an application UI. Do not own current-match state, enemy state, history acquisition, or progressive UI.

## FROZEN DECISIONS

Parser ownership is protocol semantics only. Map truth and behavior interpretation remain outside this project; runtime consumers use published contracts rather than copying decoder logic.

New-build semantic migration is permanently `AUTO_FIRST / MANUAL_LAST`.
Structural fingerprints, behavioral fingerprints, cross-field invariants,
ground-truth-derived regression oracles, negative controls, exact-build tests, and
registered exceptions must run before any manual request. Manual validation is
forbidden by default and may be requested only for the smallest failed capability
when automatic evidence cannot select one passing semantic candidate. A passing
capability is never revalidated manually merely because another capability failed.

## CURRENT MAJOR CAPABILITIES

Exact-build container/framing and semantic APIs; Hero Path, LevelTransition/LevelAfter, WardSpawn, HeroDamage, HeroDeath, HeroRespawn, inventory state, and bounded Cast/Buff/Protection surfaces for the registered builds; exact-build champion root-stat extraction, defense-field registry verification, fail-closed base-stat/dynamic-defense contracts, semantic acquisition routing, provenance/evidence grades, and an explicit 16.16 Sweeper capability boundary.

## KNOWN INCOMPLETE AREAS

The 16.16 build still lacks complete CastSpell/Buff/Protection and combat-state coverage; exact growth formulas, structured item/rune/buff mechanics, current Armor/MR and HP, reductions, attacker penetration, mitigation order, damage stage, shield instance/lifecycle, effective heal, and overheal remain unavailable. Sweeper held is `UNVERIFIED`, activation is `UNAVAILABLE`, ordinary-monster/camp clear is unavailable, and candidate scoreboard/item fields remain field-gated. Every promotion requires exact-build evidence and a capability-registry update.
