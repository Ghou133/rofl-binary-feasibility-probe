# Downstream migration note

Target consumer: `lol-inference-lab`.

The upstream implementation and 12-Replay regression now pass. In the next
downstream change:

1. Replace production reads of the temporary
   `artifacts/behavior_semantic_evidence_v1/packet_025a_decoded.jsonl` stream
   with `runLevelTransitionDecoder(replay, options).events`, or consume
   `decodeSemanticReplay(...).events.level_transition_events`.
2. Replace local Lv2/Lv3/Lv4 filtering with
   `queryLevelTransitions(events, { participantId, levels: [2, 3, 4] })`.
3. After the consumer migration passes, disable/remove the temporary
   `vendor/rofl_adapter/scripts/emulate_exact_packet_decoder.py` profile named
   `npc_level_up_candidate`. Keep the frozen evidence artifacts as historical
   validation inputs; do not delete them as part of the API switch.
4. Stop treating `tools/build_behavior_semantic_evidence.js` as the owner of
   the protocol mapping. It may validate or consume upstream events, but packet
   layout, decoder RVAs, evidence grade, and version gate belong here.

The following remain downstream behavior/inference concerns and must not move
upstream: jungle timing norms, camp polygons/contact interpretation, Akari
logic, Jungle Timeline rules, invade/gank semantics, vision habits, player
recommendations, ML, and UI.

## Vision spawn handoff

Exact build `16.16.805.0442` now exposes Ward semantics through
`decodeSemanticReplay()` and the build-agnostic selectors `queryWardEvents()`,
`queryWardSpawns()` and `queryWardLifecycles()`. Downstream should request
`player_active_only: true` (or the confirmed event surface) for player vision
timelines. It must retain special/map/unknown rows when building future semantic
filters and must not interpret them as a player's first Ward.

Lifecycle is intentionally partial: an `OBSERVED_END` is a conservative match
to a direct corpse signal, while end reason remains `UNKNOWN`. No estimated game
rule duration is published. Strategic location names, Vision Habit statistics
and recommendations remain downstream responsibilities.
