# Packet coverage inventory

`PACKET_COVERAGE_INVENTORY_V1` is a deterministic, exact-build raw-packet
inventory. It extends the existing container/framing implementation in
`src/rofl.js` and uses `src/build_registry.js` only to label already-registered
exact-build routes. It is not a decoder, entity registry, map system, or
behavior classifier.

The architecture gate for this work is recorded at
`docs/ROFL_SEMANTIC_COVERAGE_COMBAT_STATE_V1_ARCHITECTURE_GATE.md` with
`ARCHITECTURE_GATE = PASS`. This capability is Parser-owned and
`OFFLINE_RESEARCH_ONLY`.

## Invocation

```powershell
node scripts/build_packet_coverage_inventory.js --output artifacts/semantic_coverage_v1/packet_coverage_inventory.json replay/example.rofl
node scripts/build_packet_coverage_inventory.js --records artifacts/exported_packets.jsonl
```

The second form accepts JSONL packet exports, a JSON array, or a JSON object
with `records` or `packet_records`. Each record requires an exact
`game_version`, `replay_version`, or `build`, plus `packet_id` and
`payload_length`. Replay inputs are walked with strict framing.

## Output contract

Rows are keyed by `(exact build, packet_id)` and sorted by build then numeric
packet id. Each row records packet count, payload-size distribution, registered
decoder status, raw-param entity candidate, observed temporal pattern, possible
category, confidence, research priority, and source provenance.

`decoded_as` means only “a route is registered in this exact build profile.” It
does not assert that a packet was semantic-decoded in this inventory run.
Registered candidate routes remain `CANDIDATE`; unavailable or unverified
routes are not promoted.

For unregistered packet identifiers, `possible_category = UNKNOWN` and
`confidence = CANDIDATE`. Raw parameter and time patterns use candidate labels
because neither proves entity identity nor game meaning. A missing value remains
`UNKNOWN`, never zero or a guessed semantic.

Unknown-route triage is frequency-only: `P0` at 10,000 observed packets, `P1`
at 100, and `P2` below that. It is a research queue, not a category or semantic
claim.

The output intentionally carries no wall-clock generation time, so the same
ordered-equivalent raw inputs produce byte-stable JSON. It never merges packet
observations across builds, including identical numeric packet identifiers.

## Saved first-round evidence

The exact 16.15 inventory covers four public local Replays, 6,222,445 packet
rows and 296 packet identifiers. Its deterministic SHA-256 is
`a1d8a2c5400177cde7fc39a3c623d36a3a33b0d6a40728061edb4681bd6a55da`.

The separately bounded 16.16 exported-Ward inventory covers 31,862 exact-build
rows and has SHA-256
`b76d9b16fc203070404c35f2dec5bb258b81899dd2d5483aab8cd77f910a1fbb`.
The two sources remain separate; an exported semantic-family slice is not a
claim of whole-Replay 16.16 packet coverage.
