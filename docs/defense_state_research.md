# Defense and hero-state research

Status: `PARTIAL`; release status for current HP, max HP, armor, and magic
resist remains `UNAVAILABLE`. This means no exact-build field is currently
publishable; it does not claim that the protocol lacks these values.

## First-round exact 16.15 probe

The reproducible probe walked four immutable exact-build Replays: 6,222,445
strictly framed packet rows, 296 packet IDs, and 120 keyframe/start-keyframe
chunks. It also scanned the pinned 35,205,120-byte runtime image with SHA-256
`7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb`.

The strongest *structural*, not semantic, candidates are:

| Route | Observations | Shape | Research use |
| --- | ---: | --- | --- |
| `0x03da` | 2,376 | All ten champion IDs; 2,320 keyframe and 56 game-chunk rows; payload 17–46 bytes | Strongest champion-bound bridge between snapshot and live traffic. |
| `0x0439` | 1,160 | One recurring 68–79 byte row per champion/keyframe observation | Wide hero snapshot candidate. |
| `0x003d` | 1,160 | One fixed 1,479 byte row per champion/keyframe observation | Large hero snapshot candidate. |
| `0x0298` | 432,680 | Champion-only keyframes; 7–9 byte components | Dense replicated-component candidate. |
| `0x00e7` | 2,139,531 | 98.8448% game-chunk, fixed two-byte payload, 42,083 raw entity params including all champions | Generic live entity-family candidate; far from a decoded HP field. |

For current HP, `0x03da` is the best hero-bound live/snapshot candidate and
`0x00e7` is the strongest high-frequency generic live family. For max HP,
armor, and MR, the wider keyframe families `0x0439` and `0x003d` are the most
promising snapshot targets. None of those associations is a field mapping.

The exact runtime image contains three string occurrences each for
`PKT_S2C_HeroStats_s`, `PKT_S2C_StatFormulaOutputs_s`,
`PKT_NPC_BuffUpdateStatAdjustments_s`, `PKT_CombatStateChanged_s`, and
`PKT_SetAbilityResourceState_s`. These are `NAME_ONLY_CANDIDATE` observations:
the registration route, packet ID, constructor, deserializer, and fields are not
yet connected.

## Negative evidence retained

- No decoded current-HP, max-HP, armor, or MR field was recovered.
- Packet frequency, champion-like raw parameters, keyframe cadence, and payload
  width do not identify a semantic.
- Keyframe-only data cannot supply a continuous 5/10/15-second combat state.
- Fixed-offset float scanning is not a valid replacement for the encoded packet
  deserializer.
- HP/damage/shield/heal residual analysis cannot begin until a direct HP field
  exists.
- Damage amount and protection events cannot be inverted into HP, armor, or MR.

## Existing defense values

Shield generation is direct from `0x009e/0x00ed`. Shield absorption is direct
target-total from `0x0017`, with no source/instance. Reported heal is direct from
`0x009e/0x004b`, but raw-versus-effective meaning is unresolved. Shield
remaining/unused, effective heal, overheal, temporary HP, and temporary max-HP
all remain `null`.

## Next promotion gate

Recover exact runtime registration → constructor → vtable → deserializer chains
for the HeroStats/StatFormulaOutputs name candidates, bind them to one of the
observed packet families, then validate decoded fields against Damage `0x028a`,
Death `0x0160`, Protection `0x009e`, LevelTransition `0x025a`, and keyframe
progression. No canonical field changes status before positive and negative
examples pass that exact-build gate.

Machine evidence: `artifacts/semantic_coverage_v1/combat_candidate_report.json`.
