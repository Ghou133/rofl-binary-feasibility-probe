# V3 Combat Research Status

Scope: replay version `16.15.801.3452`. Match Details was used only as a
post-decode oracle for the frozen holdout; it is not an input to any decoder or
enrichment rule.

## Damage type: VERIFIED_DIRECT

The exact `UnitApplyDamage` decoder already retained object byte `field_21` at
offset `+0x21`. Across all ten replays, the 27,625 champion-to-champion damage
rows use exactly three values:

| `field_21` | Meaning | Rows |
| ---: | --- | ---: |
| 0 | physical | 11,423 |
| 1 | magic | 12,799 |
| 2 | true | 3,403 |

The mapping is supported by three independent layers:

1. The exact current client handler decodes `+0x21` and routes its three values
   through damage-category triplets.
2. The public protocol contract has a `DamageType` byte, and the public enum is
   `0 physical / 1 magical / 2 true` ([LeaguePackets](https://github.com/LeagueSandbox/LeaguePackets/blob/207baab80dc4cd203dd2d41ce9d98f1aae7a1544/LeaguePackets/Game/101_UnitApplyDamage.cs), [GameServer](https://github.com/LeagueSandbox/GameServer/blob/b37c75483abf66048af7c914e7fab700efaa5e21/GameServerCore/Enums/DamageType.cs)).
3. On frozen holdout `HN1-11177593199`, summing replay damage by `field_21`
   reproduces every participant's physical/magic/true damage-to-champions
   totals within one point. The remaining difference is Details integer
   truncation of replay `f32` amounts.

Holdout totals:

| Source | Physical | Magic | True |
| --- | ---: | ---: | ---: |
| Replay decode | 60,622.5 | 89,145.6 | 3,685.2 |
| Details oracle | 60,617 | 89,141 | 3,683 |

`research-v3/combat_attribution.py` therefore emits `damage_type` as
`VERIFIED_DIRECT`. The mapping is patch-gated and is not applied to another
replay version.

## Per-hit spell attribution: VERIFIED_DERIVED_PARTIAL

`UnitApplyDamage.field_1c` is a direct spell/script key. Evidence includes:

- Ignite damage has key `0x06364f24`, exactly
  `ELFHash(lowercase("SummonerDot"))`.
- 156 damage rows have one and only one CastSpell with the exact same replay,
  millisecond, source, target, and spell key.
- 18,516 of 27,625 damage rows (67.03%) have one unique entry in the fixed
  16.15 CommunityDragon/ELF dictionary.

The research layer resolves only a unique dictionary identity. As a secondary
fallback, it accepts a CastSpell association only when replay, timestamp,
source, target, and key are all exact and the candidate is unique. It never
uses a nearest CastSpell rule. Unknown hashes and collisions remain `NULL`.

## Basic attack: VERIFIED_DERIVED_PARTIAL_TRUE_ONLY

For a unique 16.15 spell identity, an explicit `BasicAttack` or `CritAttack`
script name produces `is_basic_attack = true` only when the fixed dictionary
also classifies the object as `ENGINE_CAST`. This is an identity rule over the
direct damage `field_1c`, not a timing heuristic. No negative value is inferred
from the absence of such a name. This covers 3,798 rows. Seven
`FizzWBasicAttack` rows classified as `INTERNAL_CHILD` remain `NULL`: being
caused by an attack is not enough to prove that the child damage row is the
basic attack itself.

## Critical: VERIFIED_DERIVED_PARTIAL_TRUE_ONLY

The positive interpretation of `field_20 == 3` has independent semantic
support beyond replay correlation:

1. In the current 16.15 client, the UnitApplyDamage handler reads object
   `+0x20` at RVA `0x29F807` and passes it as the fifth argument to consumer
   RVA `0x267CB0`.
2. The consumer range-checks this argument as a result enum and dispatches it
   through a seven-entry jump table. Entry `3` targets RVA `0x267D9E`, whose
   branch maps damage type `0/1/2` to float-text IDs `6/7/8`.
3. The SHA-pinned public contract independently names result value `3` as
   `RESULT_CRITICAL` ([DamageResultType](https://github.com/LeagueSandbox/GameServer/blob/b37c75483abf66048af7c914e7fab700efaa5e21/GameServerCore/Enums/DamageResultType.cs#L3-L10))
   and float-text IDs `6/7/8` as physical/magical/true critical damage
   ([FloatTextType](https://github.com/LeagueSandbox/GameServer/blob/b37c75483abf66048af7c914e7fab700efaa5e21/GameServerCore/Enums/FloatTextType.cs#L3-L13)).

It is therefore valid to emit a positive `is_critical = true` for code `3`.
This flags 1,273 rows. As a replay-only secondary cross-check, 646 of 689 rows
whose unique script name explicitly contains `CritAttack` also have code `3`;
the remaining 43 reuse a crit-named script with another result code and are
not marked critical. The name correlation is not the semantic proof. Other
result codes are not mapped to `false` until the complete current-build result
enum is independently recovered.

## Protection value: UNAVAILABLE

CastSpell and Buff prove that protection-related actions and lifecycles exist,
but they do not prove numeric shield generated, shield absorbed, actual heal,
or temporary HP amounts. The ten current `shield_events.jsonl` and
`heal_events.jsonl` files contain zero rows, and the optional shield
registration probes do not establish a decoded amount field.

The V3 representation therefore keeps all observed protection amounts `NULL`
with status `UNAVAILABLE`. No theoretical amount model is emitted. If a future
formula model is added, it must be explicitly labeled `THEORETICAL` and kept
separate from replay-observed facts.

## Reproduction

```powershell
python -m unittest discover -s research-v3/tests -p "test_combat_attribution.py" -v
```

Machine-readable evidence is in
`.omo/evidence/v3_combat_research/summary.json`.
