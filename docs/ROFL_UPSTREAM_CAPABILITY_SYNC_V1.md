# ROFL upstream capability sync V1

Status: `ROFL_UPSTREAM_CAPABILITY_SYNC_V1_COMPLETE`

## Synchronized protocol facts

- `0x025a` exact-image profile: constructor RVA `0x00e82060`, deserializer RVA
  `0x00efaa50`, object size `0x18`, raw `field_10/+0x10` and
  `field_11/+0x11`.
- Hero LevelTransition occurrence, entity and timestamp:
  `VERIFIED_DIRECT`.
- `field_10 → level_after`: `VERIFIED_DERIVED`, strictly bound to
  `16.15.801.3452`.
- `SKILL_LEVEL_UP != HERO_LEVEL_UP_TIME`.
- Camp-clear direct result: `CAMP_CLEAR_DIRECT_UNAVAILABLE`.
- `0x0313`: `CANDIDATE`, `NOT_USABLE_FOR_CAMP_CLEAR`; 27,524 bounded
  decodes did not establish victim identity.
- `0x02eb`: `REJECTED_FOR_CAMP_CLEAR`; 477 bounded decodes did not match the
  verified death timing/identity anchors.
- `PKT_S2C_NeutralCampLeashStateChanged_s` remains a name-only candidate and
  `NeutralCampCleared`-family client strings remain script-string evidence,
  not verified Replay packet routes.
- XP, Jungle CS, current gold and total gold: `UNAVAILABLE` in the current
  verified parser/corpus, without claiming absolute protocol nonexistence.

## Fresh upstream validation

`npm run validate-level-transitions` was run against the 12 pinned Replay and
paired DETAILS files. The upstream decoder itself produced:

- 4,045/4,045 deserialize successes and full payload consumption in the
  evidence window (`0–360000 ms`);
- 494/494 paired hero LevelUp anchors, zero missing;
- delta distribution: 222 at 0 ms, 272 at 1 ms;
- 496 hero-param packets, with exactly two unmatched timestamp-zero
  initialization events;
- 120/120 monotonic participant sequences;
- mapped counts: Lv2 120, Lv3 120, Lv4 117, Lv5 93, Lv6 42, Lv7 2.

Promotion to `VERIFIED_DIRECT` is fail-closed. Every decoded row must match the
source row exported in the same process from the parsed Replay, including
Replay SHA-256, packet offsets, timestamp, raw parameter, payload length and
payload SHA-256. The row must also carry the pinned decoder profile and runtime
image identity. The runner verifies hashes of the decoder input JSONL, output
JSONL and decoder script before it constructs a public event.

The machine-local, path-complete result is
`artifacts/rofl_upstream_capability_sync_v1/level_transition_corpus_validation.json`.
The portable hash/count/corpus contract is
`test/fixtures/level-transition-evidence-v1.json`.

## Source artifact hashes

All paths below are relative to the sibling `lol-inference-lab` source root.
The machine-local validation result records their absolute paths.

| Source artifact | SHA-256 |
| --- | --- |
| `config/behavior_semantic_probe_v1.json` | `1e2dabdd107f17b77e771bc7d07037c0a3698e7a533aa991658cd661195d609e` |
| `tools/build_behavior_semantic_evidence.js` | `abd1b92aaf3de527f13c4d00b7f9750b5e9c6c83019368247dd4b7914971fc8d` |
| `tests-js/behavior_semantic_evidence.test.js` | `3402881b161c9506b82813ee0cf527c2525effce17c1689a99caf9520dd49cf9` |
| `artifacts/behavior_semantic_evidence_v1/packet_candidate_inventory.md` | `f652a45a5c51063e717fddab3ead215339d27706bea7b18e27f3156a3bf8848c` |
| `artifacts/behavior_semantic_evidence_v1/semantic_evidence_summary.md` | `6fb75c7662c569c3e9a0f523642a00f246ca6a96656baed60b098246247a8b22` |
| `artifacts/behavior_semantic_evidence_v1/semantic_signal_matrix.csv` | `49447cc8b5813f41435e6097bf7b00ddb552f23d40c4b98ac23d7518afa17025` |
| `artifacts/behavior_semantic_evidence_v1/level_signal_probe.csv` | `de672d19559cf5d09c056a21b0755893903b0627833c57755081b1500edc1a92` |
| `artifacts/behavior_semantic_evidence_v1/camp_clear_probe.csv` | `82342dc17ecb72f2ea15d2499ec2caa341a6601fe78b352cc7074aba5dc7d230` |
| `artifacts/behavior_semantic_evidence_v1/state_signal_probe.csv` | `527380913eaa0fa936d1ce24940cf8b9afe4e794285886c0298d9af11e448e7e` |
| `artifacts/behavior_semantic_evidence_v1/level_transition_validation.json` | `04f2ef841b9f2665ef04bd35b19c481b3b0418941a627ba105f39e9d4e5f25bb` |
| `artifacts/behavior_semantic_evidence_v1/packet_025a_decode_summary.json` | `473cd34e9d1c6e3a75d255980408eb0d942debf0bcb4c39d3c9323711b7660c3` |
| `artifacts/behavior_semantic_evidence_v1/packet_025a_decoded.jsonl` | `5ab5b6b408f4cca3969be0a01df1c15eb2c6ec0559d833b6dcef55c9f5f6b0eb` |
| `artifacts/behavior_semantic_evidence_v1/npc_death_candidate_validation.json` | `238ed9e2d88c28459af40f67965d043ca35f3342d91454d1571767a5991db83c` |
| `artifacts/akari_jungle_inference_audit_v1/paired_probe.csv` | `570314585654e8eb727078e6c3bf442f0a06f46bbcfcfc1377e9213a3dd81928` |
| `artifacts/akari_jungle_inference_audit_v1/paired_probe_summary.json` | `46f0243526d85eb2b0b841db5ac91af0c6c301cd7d1dc10516d1b80737c4ef51` |

The 12 Replay SHA-256 values and 12 paired DETAILS SHA-256 values are pinned in
the portable fixture and rechecked by the full-corpus validator before decode.

## Boundary

`ROFL binary feasibility probe` owns protocol reverse engineering, packet
registry, decoders, field semantics, evidence grades, version compatibility,
regression tests, and stable exported capabilities. `lol-inference-lab` owns
behavior interpretation and consumes those capabilities.
