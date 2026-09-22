# Semantic compatibility

The canonical matrix is
`artifacts/semantic_coverage_v1/semantic_compatibility_matrix.json`. It compares
the exact builds `16.15.801.3452` and `16.16.805.0442` using four independent
properties for each canonical capability:

| Property | Meaning |
| --- | --- |
| `binary_compatible` | The exact Replay route is the same. |
| `decoder_compatible` | The registered exact-build decoder profile is the same. |
| `semantic_compatible` | An explicit, evidence-cited pairwise declaration says the two exact-build records populate the same semantic meaning. |
| `schema_compatible` | Both records use the same canonical output-schema version. |

The status values are `YES`, `NO`, `NOT_COMPARABLE`, and `UNVERIFIED`.
`NOT_COMPARABLE` is used when one or both builds lack an evidence-backed
semantic; it is not a negative protocol claim. `UNVERIFIED` means both records
may be individually verified, but no explicit pairwise semantic-equivalence
declaration has been registered. Matching evidence grades, canonical field names,
or a shared schema version never infer semantic compatibility. Neither status
permits using another build's decoder.

## Current meaningful cross-build results

HeroPath, LevelTransition, WardSpawn, and WardLifecycle are semantically
compatible at their documented field grades, but their binary routes and exact
decoder profiles differ. For example, HeroPath moved `0x02d1 -> 0x00f6`,
LevelTransition moved `0x025a -> 0x0314`, and WardSpawn moved `0x0353 ->
0x049a`. A canonical schema does not erase field-level limitations: LevelAfter
remains build-bound derived, Ward participant/team/type remain derived, and
Ward lifecycle remains partial.

The 16.15 Damage semantic cannot be pooled as a verified 16.16 Damage semantic:
16.16 route `0x017f` is only a disabled candidate. The same rule applies to
Hero Death, CastSpell, Buff, Protection, combat state, item/economy and NPC
surfaces not independently recovered in both exact builds.

## New-build rule

For a new Replay header (for example `16.17.x`), first perform the L1/L2/L3
probe in `docs/ROFL_NEW_BUILD_PLAYBOOK.md`. Until a new exact profile and
evidence-backed semantic records are added, `queryCapability()` returns
`UNSUPPORTED_BUILD`; no 16.15 or 16.16 profile is selected as a fallback.
