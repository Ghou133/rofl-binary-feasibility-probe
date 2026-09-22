# Sweeper capability V1

## Status

`SWEEPER_SEMANTIC_CAPABILITY_V1 = CAPABILITY_BOUNDARY_PUBLISHED` for exact
Replay build `16.16.805.0442`. This is an honest export boundary, not a claim
that a Sweeper event has been recovered. The contract is implemented by
`src/sweeper_capability.js`, registered through the exact-build registry, and
exposed by `src/semantic_api.js` as `sweeper_capability`.

Every capability record contains the exact Replay build, patch, evidence grade,
evidence source, route(s) considered, blocker, and event key. Empty arrays are
always exported but mean `EMPTY_EVENT_ARRAY_IS_NOT_A_ZERO_BEHAVIOR_CLAIM`.

## Exact-build boundary

This contract applies only to `16.16.805.0442` / patch `16.16`. A request for
`16.15.801.3452` or any other build returns `UNSUPPORTED_VERSION` and
`NO_CROSS_BUILD_INFERENCE`. The proven 16.15 item, CastSpell, or Buff surfaces
are not evidence for 16.16 and are not used to emit a 16.16 Sweeper signal.

| Capability | 16.16 status | Evidence grade | Exported event key |
| --- | --- | --- | --- |
| `TRINKET_STATE` | `UNVERIFIED` | `UNVERIFIED` | `trinket_state_events` |
| `TRINKET_SLOT_STATE` | `UNVERIFIED` | `UNVERIFIED` | `trinket_slot_state_events` |
| `TRINKET_SWAP` | `UNVERIFIED` | `UNVERIFIED` | `trinket_swap_events` |
| `TRINKET_PURCHASE_OR_SWAP` | `UNVERIFIED` | `UNVERIFIED` | `trinket_purchase_or_swap_events` |
| `SWEEPER_HELD` | `UNVERIFIED` | `UNVERIFIED` | `sweeper_held_events` |
| `SWEEPER_ACTIVATION` | `UNAVAILABLE` | `UNAVAILABLE` | `sweeper_activation_events` |
| `SWEEPER_ACTIVE_INTERVAL` | `UNAVAILABLE` | `UNAVAILABLE` | `sweeper_active_interval_events` |
| `SWEEPER_POSITION` | `UNAVAILABLE` | `UNAVAILABLE` | `sweeper_position_events` |
| `SWEEPER_OWNER` | `UNAVAILABLE` | `UNAVAILABLE` | `sweeper_owner_events` |

`SWEEPER_HELD != SWEEPER_ACTIVATION`. Holding Oracle Lens, changing from a
yellow trinket, pressing the active, an active interval, its owner, and its
position are distinct facts and must never be filled from one another.

## Probe routes and stop-loss

1. Item/trinket slot state has not established an exact 16.16 item ID, slot,
   participant, timestamp, initial state, or replacement route.
2. Swap/replacement has not established an exact 16.16 old-item/new-item,
   participant, timestamp route.
3. Cast/item-active has no verified 16.16 CastSpell Replay route or payload
   layout. It cannot establish activation.
4. Buff/state corroboration has no verified 16.16 Buff Replay route or payload
   layout. It cannot establish activation, owner, start/end, or duration.

The non-Holdout 16.16 Ward entity corpus supplies a bounded check of the
spawned-entity alternative: its 31,862 exact `0x049a` route rows across 20
replays contain zero `oracle`, `sweeper`, `lens`, or `scanner` name-token hits.
The same raw-name scan finds 797 `YellowTrinket` and 170 `BlueTrinket` token
occurrences (967 combined), not Oracle/Sweeper entity names. This is retained
as `BOUNDED_NEGATIVE_ENTITY_ROUTE_EVIDENCE_NOT_PROTOCOL_NONEXISTENCE_PROOF`:
it does not prove that an activation protocol cannot exist elsewhere.

Stop-loss: do not expand into general inventory or combat reverse engineering
for this V1 boundary. A future exact-build probe may independently promote
held, activation, or both only with a version-pinned route, payload evidence,
and a regenerated manifest. Until then no event is synthesized.

## Machine-readable export

Run `npm run build:sweeper-capability-manifest` to write the deterministic
default manifest at `artifacts/sweeper_capability_v1/manifest.json`, or call
`writeSweeperCapabilityManifest(path)` from `src/sweeper_capability.js`.
