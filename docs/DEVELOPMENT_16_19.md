# 16.19 development progress

Updated: 2026-09-25. Branch: `codex/16-19-development`.

- **New exact KR build:** The user supplied 11 `16.19.821.7343` Replays under
  `kr-rofl-batch-collector/data/KR/16.19/builds/16.19.821.7343/rofl/`.
  Their complete header build is distinct from the HN/KR `820.7193` inputs;
  an exact Riot client module was captured locally from a running 821 replay
  with 48,488,448/48,488,448 readable bytes (SHA-256
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`).
  The protected on-disk EXE is not a substitute for this mapped image. The
  image and replay data remain ignored under `artifacts/`. An independent 821 profile now
  offers CLI/API `--events hero_death` as `CANDIDATE` only. The game-stream
  `0x0259/0x0438/0x031b` co-timed core maps to all ten Replay-tail
  `NUM_DEATHS` counts in all 11 files (655 candidate rows). Two files each
  lack one auxiliary `0x03d4`; one file contains two isolated `0x0259` packets.
  These are retained as negative route evidence and excluded from candidate
  events. No 820 opcode transform or image is reused for 821. A separately
  gated `0x0438` killer-participant candidate is described below; assist
  attribution and confirmed death/respawn semantics remain open.
- **821 observed-return candidate:** `--events hero_respawn` pairs each matched
  death core with a subsequent same-participant `0x0048` and preceding co-timed
  `0x018d`, requiring the ten per-participant sums of elapsed milliseconds,
  floored to seconds, to equal Replay-tail `TOTAL_TIME_SPENT_DEAD`. All 11
  Replays pass: 607 observed return candidates, 48 unpaired final deaths, and
  64 extra `0x018d` packets retained as negative evidence. Return `0x0048`
  uses the observed `0x400000ae..b7` full raw-param family and payload lengths
  9 or 13; 33 matched deaths use a different full-param family, so identity is
  joined only through the validated participant candidate. The exact-image
  route and payload decode are described below; the death-to-return join and
  callback's gameplay effect remain candidates. This return route alone does
  not infer a timer for unpaired final deaths. Each paired event reports the
  observed death-to-return millisecond difference as a candidate arithmetic
  field, with no timer prediction.
- **821 return packet runtime fields and route boundary:** The exact image
  registers `0x0048` as `PKT_HeroReincarnateAlive_s` on `AIHeroClient`.
  Its constructor and deserializer fully consumed all 607 observed game
  packets (512 length 13, 95 length 9); all one-byte truncations failed and
  all appended bytes remained unread. A static wire inverse matched the
  runtime object's two `f32` values at `+0x10` and optional `f32` at `+0x18`
  for 607/607. The callback passes the pair as the first/third components of
  a three-component vector and the scalar to an actor virtual call; its
  concrete state effect is still unresolved. `hero_respawn` CLI/API output
  now exposes `decoded_0x0048_pair_f32`, `decoded_0x0048_scalar_f32`, and
  whether the optional wire field is present, without assigning a map or
  health meaning. The 11-Replay CLI batch returned 607 decoded candidates,
  11/11 `CANDIDATE`, zero errors, and exact numeric agreement with all 607
  native probe rows. The co-timed `0x018d` route is independently registered
  as `PKT_S2C_SetInventory_MapView_s` on `HeroInventoryClient`; it serves only
  as a structural fingerprint in the existing candidate gate. Its 64 extra
  packets remain explicit. The two early returns relative to death timers
  remain negative evidence against timer-based return prediction. Ignored
  runtime and CLI evidence is under
  `artifacts/16_19_development/kr_821_runtime_capture/` and
  `artifacts/16_19_development/kr_821_return_runtime_11/`.
- **821 death-timer candidate:** In the captured exact 821 image (SHA-256
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`),
  factory ID `0x0259` identifies `PKT_S2C_UpdateDeathTimer_s`, constructs at
  RVA `0xeca430`, and deserializes at RVA `0x10fa910`. Emulating its
  constructor and deserializer against all 657
  observed five-byte game packets fully consumed 657/657; truncating or
  appending one byte rejected full consumption in 657/657 controls each.
  The exact-image byte transform decodes bytes 1–4 into `f32` seconds,
  approximately 4.09–60.10 across all 657 packets. The two isolated
  `0x0259` packets are retained as negative evidence; the candidate is
  scoped to the 655 matched death cores. Among 607 independently observed
  `0x0048` returns, 605 death-to-return residuals have absolute magnitude
  at most 35 ms. Two returns in `KR_8394041123` occur 11.469 and 20.877
  seconds earlier than the respective timer values, so the timer is not a
  reliable return-time prediction. The other 48 matched deaths have no
  observed return before Replay end, and their timer endpoints lie beyond
  that end. This is a candidate decoded float and route correlation, not a
  published or callback-confirmed death-timer capability. The probe used a
  hooked base packet reader; original Replay bytes, runtime image, all
  exceptions, and negative controls remain local under
  `artifacts/16_19_development/kr_821_runtime_capture/`.
  The selected CLI's 11-Replay `hero_death_timer` batch returned 11/11
  `CANDIDATE` with no framing errors: 657 input packets, 655 candidate timer
  records, and two excluded isolated packet references. Its per-Replay
  provenance is under ignored
  `artifacts/16_19_development/kr_821_runtime_timer_11/`.
- **821 Hero_Die source candidate:** Exact image factory `0x0438` constructs
  `PKT_NPC_Hero_Die_s` and its deserializer fully consumed 655/655 real
  game packets across the 11 KR Replays. Last-byte truncation failed AL in
  655/655 controls; an appended zero left one byte unread in 655/655.
  Static decoding of each payload's final two bytes matched the runtime
  object's `+0x50` inverse in 655/655. The decoded source IDs include 653
  hero-family values (`0x400000ae..b7`) and two unmapped nonhero values
  (`0x400000a6`, `0x40000094`). Hero-source counts match all 110 numeric
  `CHAMPIONS_KILLED` Replay tails exactly; all 653 differ from the victim
  and fall in the opposing five-participant group. The `hero_death` CLI/API
  now reports `die_source_network_id_candidate` and its `0x0438` raw ref for
  each decoded event, plus `killer_participant_id_candidate` only when all
  ten kill tails align. A malformed source wire shape or absent/mismatched
  kill tail leaves the killer participant `null` without suppressing the
  independently validated victim candidate. The two nonhero source IDs stay
  unmapped. There is no confirmed callback field name for `+0x50` or assist
  list; this death route alone did not identify assists. The 11-Replay CLI batch yielded 655 decoded
  sources, 653 killer-participant candidates, 2 nonhero raw sources, and
  11/11 `CANDIDATE` with zero errors. Reproducible static/runtime checks and
  batch provenance remain under ignored
  `artifacts/16_19_development/hero_die_821_probe/` and
  `artifacts/16_19_development/kr_821_hero_die_source_11/`.
- **821 exact-image count-byte transform:** The captured 821 image's
  `0x0089` object deserializer contains a byte transform with a 256-byte
  lookup table at RVA `0x01ba1560` (SHA-256
  `328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b`).
  Its complete input-to-output mapping is bijective. It maps every byte in
  the earlier Replay-derived 0–17 codebook to the same value and decodes the
  former high-count unknowns: champion kills 18–20 and 24–26, assists 18–28
  and 30. An independent Replay-side probe of all 327 keyframes and 3,270
  exact-shape hero-family packets in the 11 KR Replays found zero count-order
  or tail-bound contradictions. This exact-build byte transform and the
  complete native carrier binding were subsequently verified; the count
  field labels remain Replay-correlated candidates (see the route boundary
  below).
- **821 death-count keyframe candidate:** `--events hero_deaths_snapshot`
  reads raw byte 1182 from exact KR `0x0089` keyframes of length 1263 and
  prefix `6700de`, using the pinned 821 count-byte transform. The Replay-side
  probe found 110/110 zero starts, monotone sequences, and values bounded by
  each participant's `NUM_DEATHS` tail. The last snapshot equals the tail for
  82 participants and trails by one for 28; the gap is retained. It remains
  a candidate snapshot, not a full HeroStats decode or individual death event.
- **821 champion-kill keyframe candidate:** `--events
  hero_champion_kills_snapshot` reads mirrored raw bytes 434 and 1186 in the
  same `0x0089` keyframe. The exact-image transform resolves the six higher
  codes formerly outside the 0–17 codebook in `KR_8394000013`. The probe
  found 110/110 zero starts, monotone sequences, and values bounded by
  `CHAMPIONS_KILLED` tails; 87 final snapshots equal their tails. Bytes 434
  and 1186 mirror within one packet, not independent semantic evidence. Tail
  gaps remain measured and uninterpolated; no kill event, time, or killer
  attribution follows from this candidate.
- **821 assist keyframe candidate:** `--events hero_assists_snapshot` reads
  raw byte 1178 in the same `0x0089` keyframe. The exact-image transform
  resolves the 49 packets in five Replays that exceeded the former 0–17
  codebook. The probe found 110/110 zero starts, monotone sequences, and
  values bounded by `ASSISTS` tails; 77 final snapshots equal their tails.
  Byte 1178 has no exact mirror in these payloads. This remains a candidate
  cumulative snapshot, without individual assist events or attribution.
- **Earlier finite-codebook run:** Before the exact image was captured, the
  finite codebook gave ten of eleven complete kill-snapshot Replays and six
  of eleven complete assist-snapshot Replays; unknown high bytes caused
  explicit `DECODE_FAILED` results with raw references. Those failures remain
  historical evidence under `artifacts/`, superseded for these bytes by the
  exact-image transform. No prior output is treated as proof of the runtime
  keyframe carrier or a published semantic capability.
- **821 six-capability CLI batch:** With the pinned 821 transforms, all 11
  exact-build KR Replays returned `CANDIDATE`, with no framing errors across
  18,235,209 scanned blocks. The run emitted 3,270 snapshots each for deaths,
  champion kills, and assists; 1,613 level observations, 655 death candidates,
  and 607 return candidates. Its two warnings state that game IDs could not
  be recovered from the containers (filename IDs remain inferred), and that
  this batch command did not itself run the Node test suite. The ignored
  `artifacts/16_19_development/kr_821_runtime_count_11/acceptance_summary.json`
  retains per-Replay status, input hashes, and output provenance. `CANDIDATE`
  is an experimental evidence grade, not semantic verification. This batch
  preceded the separate `Missions_MinionsKilled` batch below.
- **821 `Missions_MinionsKilled` keyframe candidate:** The pinned 821 runtime
  count-byte transform decodes byte 374 as the low byte and 373 as the high
  byte of a candidate cumulative value in exact-shape `0x0089` keyframes;
  decoded upper bytes 372 and 371 are zero across all 3,270 selected packets.
  In 11 KR Replays, all 110 participant sequences start at zero, remain
  monotone, and stay at or below the numeric Replay-tail
  `Missions_MinionsKilled` value. The final keyframe equals that tail for
  77/110 participants, with a maximum unobserved tail gap of 18; both games
  with a near-end keyframe match 20/20 final tails. Rotating participant
  assignments yields at most one exact final match, versus 77 for the aligned
  mapping. Alternative byte offsets reached only one match in the first two
  calibration Replays and zero in the other nine checked Replays; these nine
  were part of this exploratory corpus, not a protected holdout. Against the
  distinct standard `MINIONS_KILLED` tail,
  the same final values match 0/110 participants. This supports a bounded
  `hero_missions_minions_killed_snapshot` candidate, without relabeling it as
  standard minion kills or inferring individual last-hit events. The earlier
  finite-codebook scan of byte 374 alone fit only 30/110 final standard
  `MINIONS_KILLED` values and remains negative historical evidence for that
  label. A separate 11-Replay CLI batch returned 11/11 `CANDIDATE`, with
  3,270 input packets and 3,270 candidate snapshots, a total retained tail
  gap of 159, zero errors, and zero framing errors; it retained the same two
  game-ID and test-suite warnings described above. Its ignored per-Replay
  evidence is under
  `artifacts/16_19_development/kr_821_missions_minions_11/acceptance_summary.json`.
  A later native probe verified full runtime carrier consumption; this does
  not promote the proposed field label to a published semantic capability.
- **821 ward and cannon mission count candidates:** `hero_ward_stats_snapshot`
  reads transformed raw bytes 834/838/842 for `WARD_PLACED_DETECTOR`,
  `WARD_KILLED`, and `WARD_PLACED`; `hero_missions_cannon_minions_killed_snapshot`
  reads byte 450 for `Missions_CannonMinionsKilled`. All four decoded upper
  three bytes are zero across 3,270 selected hero packets in 327 keyframes.
  For each field, all 110 participant sequences start at zero, remain
  monotone, and do not exceed their own numeric Replay tail. Final snapshots
  equal the respective tail for 104, 106, 98, and 93 participants; aggregate
  retained gaps are 7, 5, 19, and 25. Rotated participant controls and an
  all-offset screen on two calibration Replays were much weaker; nine further
  checked Replays are part of the same exploratory corpus, not a protected
  holdout. The standard `NEUTRAL_MINIONS_KILLED` offset 1094 lead failed
  discrimination (45/110 final matches) and is not registered. The 11-Replay
  CLI batch selected both abilities, returned 11/11 `CANDIDATE`, emitted 3,270
  records for each, and had zero errors. Input hashes, per-field gaps, and
  raw refs remain under ignored
  `artifacts/16_19_development/kr_821_ward_cannon_11/`.
- **821 keyframe carrier structure:** A separate strict scan of those 327
  keyframes found 3,270/3,270 hero-family payloads with fixed `67 00 de`
  prefix and length 1,263. With the exact 821 constructor at RVA `0xeadf40`,
  deserializer at `0xf2f550`, and base-reader hook at `0x1269bb0`, the native
  route consumed all 1,263 bytes for every one of those 3,270 real packets,
  returned success, and preserved the Replay raw parameter. Its 1,260-byte
  vector matched the independently byte-transformed and reversed
  `payload[3:]` exactly. Per Replay, truncation failed at cursor 3; appending
  one trailing byte prevented full consumption; and a mutated length failed
  at cursor 3. The earlier five-byte result omitted the base-reader hook and
  accidentally consumed the Replay raw parameter as a payload field; it is
  retained as a failed probe, not a carrier boundary. Raw
  offsets 1186/1182/1178 map to object offsets `0x4c/0x50/0x54` for the
  existing KDA candidates; 842/838/834 map to `0x1a4/0x1a8/0x1ac` for the
  new ward candidates; 450 maps to `0x32c` for cannon mission count; and
  371..374 map to `0x378` for `Missions_MinionsKilled`. Raw 434 maps to
  `0x33c` and mirrors the `0x4c` kill candidate in all 3,270 packets. These
  byte offsets are native-vector facts; their semantic field names remain
  candidate correlations. The structural and corrected native audits are in
  ignored `artifacts/16_19_development/keyframe_carrier_821/carrier_scan.json`
  and `artifacts/16_19_development/keyframe_wrapper_821/probe_all_summary.json`.
- **821 experience, vision, and gold float snapshots:** In the 1,260-byte
  byte-transformed reversed `0x0089` blob, `f32LE` offsets `0x28`, `0x1b0`,
  `0x38`, and `0x34` correlate respectively with numeric Replay tails `EXP`,
  `VISION_SCORE`, `GOLD_EARNED`, and `GOLD_SPENT`. Across 11 KR Replays,
  327 keyframes, and 3,270 hero packets, each field has 110/110 finite,
  nonnegative, tail-bounded participant sequences. Initial values are zero
  except earned gold, which is 500 for all 110. Experience, vision, and
  earned gold never decrease; spent gold has one observed decrease and the
  CLI preserves it. Final floored snapshots equal their own tails for
  52/110, 84/110, 0/110, and 92/110 participants, with retained total gaps
  of 36,702, 45, 32,965, and 13,520. Earned gold's zero final equality is
  explicit; its aligned mean absolute gap is 300 versus at least 2,478 in
  nine rotated-participant controls. The other three fields also have much
  smaller aligned gaps than rotations. The four CLI/API abilities emit only
  cumulative `CANDIDATE` snapshots, without experience-source, vision-action,
  income, purchase, sale, or refund events. The 11-Replay CLI batch produced
  3,270 candidate rows per ability, 11/11 `CANDIDATE`, and zero errors.
  Reproducible exploratory checks and per-Replay CLI provenance remain under
  ignored `artifacts/16_19_development/kr_821_float_probe/` and
  `artifacts/16_19_development/kr_821_float_stats_11/`.
- **821 individual assist candidate:** Among 2,476 observed game-stream
  `0x040a` packets of length 44, 2,194 at the 655 validated death cores form
  1,097 exact two-shape pairs (identical bytes 5..42 and the same low-byte
  participant). The other 282 carry only the first shape and are excluded.
  Paired participants are on the 0x0438 killer side, excluding killer and
  victim; per-player pair totals match all 110 `ASSISTS` Replay tails.
  Pair counts match all 3,160 adjacent keyframe assist-snapshot increments;
  counts after the last keyframe match all 110 remaining tail gaps. The exact
  821 native deserializer fully consumed 2,476/2,476 observed 44-byte packets;
  truncate and append controls failed. The CLI/API output remains
  `CANDIDATE`, and nonhero-source deaths retain unknown assist lists. It does
  not promote a packet-specific callback field name. Reproducible evidence is
  ignored under `artifacts/16_19_development/assist_821_probe/`.
- **821 inventory MapView packet candidate:** Exact-image factory ID `0x018d`
  constructs a 0x30-byte object and native deserializer at RVA `0x1041220`.
  It fully consumed 671/671 observed game packets and produced 5,327 ordered
  slot/item records. All 671 truncations failed and all 671 appended-byte
  controls left trailing input. The per-packet record decoder uses the pinned
  821 lookup table; the 109/110 latest canonical participant packets are
  observations, not a continuous inventory state. The 64 additional packets,
  including two `0x400001b2/b5` raw-param variants, remain separate and unpaired.
  The CLI/API route requires the exact local image and emits packet records
  only; no purchase, sale, item-use, or final-state inference follows.
  Reproducible native and Replay checks are ignored under
  `artifacts/16_19_development/inventory_018d_821/`.
- **Earlier 821 gold raw-window negative lead:** Before the exact 821 byte
  transform and reversed blob were applied, direct raw integer/float windows
  did not yield a defensible `GOLD_EARNED` or `GOLD_SPENT` value. Survivors
  from two calibration Replays lost discrimination on nine further exploratory
  Replays; these were not a protected holdout. That failed search remains
  negative evidence for direct raw windows, and is superseded by the bounded
  transformed `f32` snapshot candidates above. It did not identify an income
  or transaction event.
- **Earlier 821 champion-damage raw-window negative lead:** The direct raw
  `f32`/`u32` windows and the earlier bounded byte search did not pass numeric,
  monotone, and tail checks for `TOTAL_DAMAGE_DEALT_TO_CHAMPIONS`. Byte 779
  had an ordered high-byte signal:
  a three-code mapping from the first two Replays matches 87/90 held-out
  final tail exponent bytes, against 52–65/90 rotated-participant controls.
  The six mismatches are one exponent behind the final tail, consistent with
  a last-keyframe lag. Lower bytes and the inverse numeric transform were
  unknown in that search; 776–779 remains raw structural evidence for that
  historical route, not a damage total. The later exact native-vector float
  candidates below use different offsets and do not retroactively validate
  the failed direct raw search.
- **821 native-vector damage float candidates:** The byte-transformed and
  reversed `0x0089` vector has `f32LE` candidates at `0x1e0` for
  `TOTAL_DAMAGE_DEALT_TO_CHAMPIONS`, `0x1d0` for `TOTAL_DAMAGE_DEALT`, `0x1f0`
  for `TOTAL_DAMAGE_TAKEN`, `0x200` for
  `TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS`, and `0x208` for
  `TOTAL_DAMAGE_SELF_MITIGATED`. Across 11 KR Replays and 110 participant
  sequences, each starts at zero, is finite, nonnegative, monotone, and
  bounded by its corresponding numeric Replay tail. Final floored snapshots
  equal those tails for 53, 40, 44, 55, and 45 participants respectively;
  every remaining gap is retained. Among 315 aligned float offsets screened,
  each selected offset ranked first by final-tail absolute error after the
  plausibility controls. All nine participant rotations yielded zero exact
  final matches for each field. Three CLI/API abilities expose the five
  cumulative `CANDIDATE` values; they imply no individual damage, target,
  source, or mitigation event. Reproducible controls and direct 11-Replay
  decoder smoke are ignored under
  `artifacts/16_19_development/damage_float_821/`.
  A combined five-capability CLI batch for assist, inventory, and these three
  damage snapshots returned 11/11 `CANDIDATE` with zero framing or capability
  errors: 655 death-linked assist rows with 1,097 pairs, 671 inventory packets
  with 5,327 records, and 3,270 rows for each damage ability. Input hashes
  and individual outcomes are ignored under
  `artifacts/16_19_development/kr_821_assist_inventory_damage_11/`.
- **821 further native-vector cumulative candidates:** The same 1,260-byte
  vector carries candidate `f32LE` values at `0x244`
  (`LONGEST_TIME_SPENT_LIVING`), `0x248` (`TOTAL_TIME_SPENT_DEAD`), `0x21c`
  (`TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS`), and `0x230`
  (`TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS`), plus candidate `u32LE`
  values at `0x234` (`TOTAL_HEAL`) and `0x23c` (`TOTAL_UNITS_HEALED`). Each
  passed zero-start, monotone, and Replay-tail bounds for all 110 participant
  sequences across 11 exact-build KR Replays. Final matches are respectively
  109, 94, 110, 59, 57, and 109 of 110; all gaps are retained. Rotated
  participant and nearby-offset controls were weaker. These are six separate
  `CANDIDATE` keyframe snapshots, without individual time, damage, control,
  healing, effective-heal, source, or target claims. Reproducible probes are
  ignored under `artifacts/16_19_development/time_stats_821_probe/`,
  `artifacts/16_19_development/kr_821_heal_probe/`, and
  `artifacts/16_19_development/epic_cc_821_probe/`.
  The combined six-capability CLI batch returned 11/11 `CANDIDATE`, zero
  errors, and 3,270 rows per ability; input hashes and individual results are
  ignored under `artifacts/16_19_development/kr_821_time_heal_epic_cc_11/`.
- **821 completed dead-time raw state:** Keyframe payload bytes 675–678 changed
  on exactly the 591/3,160 adjacent participant-frame transitions where
  cumulative completed death-to-return time advanced, and stayed fixed on
  2,569 others, including 318 with only an unfinished death interval growing.
  Rotating participant IDs leaves only 148–186 of those 591 transitions
  matched. The raw little-endian integer decreases on 302 true advances;
  per-byte substitution checks for direct float seconds/milliseconds or
  integer milliseconds/seconds already contradict the first two Replays.
  This is a strong raw structural clue, not a numeric dead-time snapshot.
- **821 level observation candidate:** The captured 821 factory, constructor,
  deserializer, and callback registration bind game route `0x0197` to
  `PKT_NPC_LevelUp_s`. Its `+0x11` object byte has an exact-image transform
  using the 256-byte table at RVA `0x01ba1560` (SHA-256
  `328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b`).
  That transform maps the observed byte codes to levels 1–20, including the
  former unknown `fa4d` as 20. The exact deserializer fully consumed all 76
  distinct selected-hero payload shapes across 1,613 game-stream packets in
  the 11 Replays; 74 two-byte shapes rejected a one-byte truncation and an
  appended byte at the full-consumption gate. CLI/API now emit 1,613 level
  candidates in 11/11 Replays with zero framing errors; one Replay retains a
  missing intermediate level observation. The runtime image is not required
  at CLI execution because the pinned transform table is embedded and checked.
  Participant assignment remains a Replay-tail candidate, and the one
  `0x400002ae` lead stays excluded despite structural full consumption.
- **821 scan reuse:** Selected 821 CLI capabilities now retain only their
  required route packets during the container analyzer's single full block
  walk. Standalone combined API calls share one strict walk. On the same
  11-Replay three-capability CLI batch, observed wall time fell from about
  6.9 s to 3.8 s; all 32 candidate JSONL files were byte-identical, with
  10 `CANDIDATE` and one `PARTIAL` Replay in both runs. Source-bound scan
  tokens reject another Replay or changed bytes; the API retains independent
  per-stream failures if a shared strict walk cannot complete.
  The return candidate now joins that same scan, retaining its death-core
  dependency even when selected alone. On the 11-Replay five-capability batch,
  observed wall time fell from about 7.2 s to 4.0 s; all five candidate JSONL
  families remained byte-identical, with nine `CANDIDATE` and two `PARTIAL`
  Replays in both runs. CLI preflight assesses dead-time totals separately
  from the required Replay-tail game length.

- **Done:** The HN `16.19.820.7193` replay's 107 chunks and 2,035,757 blocks
  pass strict container/framing inspection with zero errors. The main CLI/API now
  select `hero_death` explicitly and write separate candidate victim/time records,
  with 88 and 60 HN, 64 and 51 KR events on four exact-build replays. Each run
  requires a matching route triad and all ten final death-count invariants.
- **Second exact HN Replay:** A newly available `16.19.820.7193` input
  (SHA-256 `569ad4002bf16e64faef356e0ec139f2060df022f6f9b082f419293e14b6f81c`)
  framed 1,835,318 blocks with zero errors. A selected real CLI run emitted
  60 death, 60 timer, 57 respawn, 136 level, 12 SetItem, 2,757 Broadcast,
  26,150 BuffAdd2 and 10,548 BuffRemove2 candidate records. The first run
  reported `PARTIAL` because one MapView raw parameter lay outside the original
  ten canonical values. After the narrow MapView update, a combined real CLI
  rerun returned `CANDIDATE` with JSONL-only events and no embedded event array.
  All 16 previously exposed HeroStats candidates also returned `CANDIDATE`
  across its 270 participant keyframe snapshots; their field labels remain
  experimental.
- **Third exact HN Replay:** `HN1-11316024715.rofl` (SHA-256
  `a4b0f51c4e4b35434d159ac8482582327982110963a5ae0c71be6f7150579fdc`)
  framed 1,839,904 blocks with zero errors. The first all-capability CLI run
  returned `PARTIAL`: a repeated level 9, one 63-byte Broadcast packet plus
  five decoded flag-3 records, and three 41-byte BuffAdd keyframe packets
  exposed previously unseen shapes. The original failed result remains under
  `artifacts/16_19_development/third_hn_crosscheck_11316024715/`. The level
  decoder now retains the distinct repeated packet as an observation (135
  candidate rows, one repeat), and the exact image fully decodes all 297
  Broadcast packets into 2,950 candidate records. Selected real CLI reruns
  returned `CANDIDATE`; flag 3 and participant identity remain unclassified or
  candidate-only. The 41-byte BuffAdd shape passed the exact-image bounded
  vector and full-consumption checks described below.
- **Capability query:** `node src/cli.js capabilities <file.rofl> [--json]`
  reports the exact build's registered capabilities and checks required tail
  `NUM_DEATHS`/`LEVEL` fields without decompressing packet chunks or using a runtime
  image. It labels 16.19 `hero_death` and `hero_death_timer` as unpublished
  `CANDIDATE` and leaves route and death-count validation pending until decode.
- **Artifact event query:** `node src/cli.js query-events <replay-artifact-directory>
  --event <exact-event-key> [--from-ms n] [--to-ms n] [--participant 1..10]
  [--limit n] [--output path|-]` streams unchanged candidate JSONL rows from
  either default or `--event-jsonl-only` 16.19 CLI artifacts. It checks Replay
  identity and declared row counts, reports the original capability status and
  separate scanned/matched/emitted counts, and leaves unknown participants
  unselected by the participant filter. Real HN queries scanned 270 JSONL-only
  rows (27 participant-1 matches, two emitted by the limit) and 350 default
  rows (35 participant-2 matches, one emitted). This reads existing artifacts;
  it does not execute or promote the decoder.
- **Done:** The exact HN runtime identifies `0x04d9` as `PKT_NPC_Hero_Die_s`,
  `0x02d6` as `PKT_S2C_UpdateDeathTimer_s`, and `0x0357` as
  `PKT_HeroReincarnateAlive_s`. Its five-byte timer transform yields seconds;
  88 HN timer candidates pair with Hero_Die, 85 match reincarnation within
  0–33 ms, and the remaining 3 predict a time after the Replay ends. CLI/API
  select this capability independently and write `hero_death_timer_candidates`.
  The captured image SHA-256 is
  `7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d`;
  the decoder uses the recovered transform but does not read the image at run time.
- **Done:** `--events hero_respawn` projects only observed HN `0x0357`
  reincarnate-alive packets that uniquely match a validated death timer. It
  emits 85 candidate respawn times in the HN Replay and leaves three terminally
  censored timers without invented respawns. It can be selected independently
  or alongside the timer capability, sharing the Replay packet scan.
- **Done:** The same HN image identifies route `0x02b3` as a level-up packet and
  supplies the field transform. `--events hero_level_state` now emits only the
  159 observed HN hero-parameter packets as `hero_level_state_candidates`:
  one level-one observation and 158 higher-level packets. Their decoded values increase for
  each participant and never exceed the Replay tail `LEVEL`. Five participants
  have six missing update values in total, recorded as gaps rather than
  reconstructed events. KR has no corresponding `0x02b3` route in the two
  checked replays and reports `PROFILE_UNAVAILABLE`.
- **Done:** The exact HN runtime registers `PKT_S2C_HeroStats_s` at `0x0276`.
  Its keyframe payload inverse uses the captured image's 256-byte table
  (table SHA-256 `328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b`).
  `--events hero_minions_killed_snapshot` emits 350 candidate keyframe values,
  35 per hero, from one HN Replay. The offset `0x3c` f32 values are integral,
  nonnegative and monotonic; the last values are within 0–6 of each matching
  Replay-tail `MINIONS_KILLED`. The ten tail gaps total 12 and remain
  unobserved over the final 36,824 ms. This does not supply continuous CS events.
  The tail `NEUTRAL_MINIONS_KILLED` is a negative control and does not fit the
  field; a separate decoded kills field agrees with nine last snapshots and
  has one late tail increment.
- **Done:** The same exact HN HeroStats transform exposes an unpublished
  `hero_experience_snapshot` candidate at decoded f32LE offset `0x28`.
  All 350 observed keyframe values are finite, nonnegative, monotonic per
  participant, and their floors do not exceed Replay-tail `EXP`. Five final
  floors equal the matching tail; the other five final floor gaps are
  `551, 466, 511, 581, 104` (total 2213) in the unobserved last 36,824 ms.
  A four-byte-aligned scan found no second offset meeting the same tail and
  monotonic criteria; adjacent gold/CS offsets fail the EXP control. Separately,
  156 observed `0x02b3` level transitions fall between same-participant
  HeroStats keyframes. The XP `0x28` intervals have a common feasible threshold
  for each of the 18 observed target levels 2–19; CS `0x3c` does so for one
  level and gold earned `0x38` for two. Two transitions after the final keyframe
  were excluded. This cross-route check strengthens the one-Replay candidate,
  but does not establish a runtime semantic label or a confirmed XP field.
- **CLI/API efficiency:** Selecting the lane-CS, jungle-CS, EXP, GOLD_EARNED, GOLD_SPENT,
  CHAMPIONS_KILLED, NUM_DEATHS, ASSISTS, kill-stat and ward-stat HeroStats candidates shares one
  keyframe collection and retains separate field validation and results. The
  16.19 CLI reuses its raw-analysis walk for that collection; a compressed
  synthetic keyframe now decompresses once instead of twice. It also reuses
  that walk for selected game-route candidates, avoiding a second game-stream
  scan. A mixed compressed game/keyframe test decompresses each chunk once;
  malformed framing suppresses candidate output. A standalone API request
  selecting both game-route and HeroStats candidates now shares one walk too:
  a two-chunk compressed fixture decompresses twice instead of three times.
  A malformed stream affects only its dependent candidate family, which falls
  back to the established strict scan for its error result. Both collectors check the
  Replay source bytes and chunk layout before publishing copied packet refs.
  Selected BuffAdd2 and BuffRemove2 packet rows now use the same route token;
  ordinary route scans do not retain Buff rows. A synthetic two-chunk mixed
  API request decompresses twice instead of five times, and Buff-only CLI
  decoding reuses its analyzer walk. BuffRemove-only standalone API still scans
  stream 1 alone; malformed stream 2 does not suppress its independent result.
  On the exact HN Replay, the six earlier
  death/timer/respawn/level/CS/EXP candidate JSONL files remain byte-identical
  after game-scan reuse. The 820 KR Replay retains its death candidate and
  reports `PROFILE_UNAVAILABLE` for the HN-only selections.
- **Public test entry:** `npm run test:16-19` runs the portable 16.19 candidate
  decoder and CLI/API tests; `npm test` now includes it after maintenance.
  Real HN/KR Replay smoke remains separate evidence.
- **Done:** The same HN HeroStats blob has an unpublished
  `hero_gold_earned_snapshot` candidate at f32LE offset `0x38`. In one HN
  Replay, all 350 values are finite, nonnegative and per-hero monotonic; all
  ten first snapshots are 500, and all final snapshots remain below their
  matching Replay-tail `GOLD_EARNED`. The ten tail differences total about
  3217.741 over the unobserved final 36,824 ms. In the captured HN Replay
  (SHA-256 `50e781de65473f0b5e72cd67bdadbfdb4f30c98a9485c6098f22e2f1df38f846`),
  an aligned f32 scan of all 315 offsets in each 1,260-byte decoded blob
  compared the final ten values with tail `GOLD_EARNED`: `0x38` has total
  absolute difference 3217.741; the adjacent dynamic `0x34` field has
  15739. Rotating the ten tail participants by shifts 1–9 raises the minimum
  absolute difference to 29705. These are one-Replay correlation checks,
  not proof of a published gold field. No income event or intermediate value
  is inferred.
- **820 HN/KR boundary:** Candidate participant identity, timer and respawn
  meaning remain unpublished across the available HN Replays. The
  `16.19.820.7193` KR controls use different death/timer route IDs and report
  `PROFILE_UNAVAILABLE` for the HN timer profile. Eleven raw KR `0x0357`
  packets remain unclassified without that profile. No confirmed death, timer
  or respawn event is emitted.
- **820 KR lead:** In exact-build `KR_8391528229` and `KR_8391542020`, all 115
  `0x0259` death-triad packets reject the HN timer transform. All 104 packets
  on route `0x0048` pair with a pending candidate victim and a plausible
  death-to-reincarnation delay, but the 820 KR timer float transform and route
  name are unverified. The KR Replay SHA-256 values are
  `3f29ae2127ef75888baf1f4543d0790cc9c40d9df0197e73b2b16b3c799dd93c`
  and `2d7a53f76e11059ac00a45706d32ca19300d33dabca2d97bde99775c22062e1b`.
- **820 KR negative control:** A table learned from the first KR Replay covers only
  14/58 paired cases there and 22/46 in the second; all covered timing
  residuals are at most 35 ms. The other codewords are unaccounted for, so
  neither a general 820 KR timer transform nor route `0x0048` identity is claimed.
- **HeroStats 820 KR control:** One KR Replay has 19,698 keyframe `0x0276` packets
  of lengths 2–16 bytes and zero HN 1263-byte fingerprints. The HN HeroStats
  candidate reports `PROFILE_UNAVAILABLE`; these raw KR packets are unclassified.
- **Done:** `hero_gold_spent_snapshot` exposes candidate HN keyframe values
  from f32LE offset `0x34`. In the same exact HN Replay, all 350 values are
  nonnegative integers; the first ten are zero. Eight final values match
  tail `GOLD_SPENT`, and the other two are 500 lower (signed total difference
  1000 over the final 36,824 ms). One participant's observation declines
  from 9183 at 1,440,507 ms to 9083 at 1,500,533 ms; both raw packet refs
  remain in the output. The decoder does not require monotonicity or a
  nonnegative tail difference, and does not classify a sale, refund or
  transaction. In a 315-offset aligned f32 scan, only `0x34` met the observed
  integer/dynamic/initial-zero/final-tail criteria; circular tail shifts 1–9
  had zero exact matches and at least 30,670 absolute difference, versus
  eight exact and 1000 on the original participant alignment. This is one
  HN Replay correlation, not a confirmed gold-spent field.
- **Done:** `hero_champion_kills_snapshot` emits only observed HN HeroStats
  keyframe candidate values. Decoded u32LE offsets `0x4c` and `0x33c` match
  in all 350 packets; the decoder requires this mirror and does not claim a
  unique storage offset. Values are nondecreasing and never exceed their
  matching tail `CHAMPIONS_KILLED`: nine final values match, one has an
  unobserved gap of 1 over the last 36,824 ms. The `0x4c` neighbors `0x50`
  and `0x54` correlate with death and assist tails, while the `0x33c`
  neighbors are zero in this Replay; this helps locate a KDA cluster but
  remains one-Replay evidence. No individual kill event or time is inferred.
- **Done:** `hero_deaths_snapshot` emits observed HN HeroStats keyframe
  candidate counts from decoded u32LE offset `0x50`. Its 350 values equal the
  cumulative `hero_death` candidate victim count at each matching keyframe;
  among 315 aligned offsets, only `0x50` matches all 350. Nine final snapshots
  equal tail `NUM_DEATHS`. Participant 6 has one observed candidate death at
  2,058,225 ms after the final keyframe at 2,040,609 ms, explaining its final
  gap of one. The route, participant mapping and field meaning remain
  experimental and bounded to one HN Replay; this output creates no death
  events.
- **Done:** `hero_assists_snapshot` emits observed HN HeroStats keyframe
  candidate counts from decoded u32LE offset `0x54`. In one HN Replay all 350
  values are nonnegative, start at zero, are monotonic per participant, and do
  not exceed tail `ASSISTS`; eight final snapshots equal the tail, while
  participants 1 and 5 each have an unobserved gap of one. Among aligned
  offsets, only `0x54` meets the initial-zero, monotonic and close-tail
  criteria of at least eight exact final matches and total gap at most two.
  There is no independent assist-event anchor, so this field is a
  weaker one-Replay correlation and yields no assist event, time or attribution.
- **Done:** `hero_jungle_minions_killed_snapshot` emits the raw f32 values at
  HeroStats offsets `0x40/0x44/0x48` and their derived floors. Across 350
  HN participant snapshots from 35 keyframes, each sequence starts at zero,
  is nonnegative and nondecreasing,
  and stays within its own Replay-tail neutral-minion total, own-jungle and
  enemy-jungle fields. All three final floor arrays match 10/10 corresponding
  tail values; `0x40` is fractional in 85 snapshots. Among 315 aligned f32
  offsets, only `0x40` reaches at least nine total-neutral tail matches;
  circular participant shifts match at most two. This remains one-Replay
  field correlation, not a confirmed integer field or a neutral-minion event.
  The last keyframe precedes game end by 36,824 ms, so zero integer tail gaps
  do not exclude later fractional changes.
- **Done:** `hero_kill_stats_snapshot` emits six observed u32 HeroStats values
  at offsets `0x58` through `0x6c`: largest killing spree, killing sprees,
  largest multi-kill, and double/triple/quadra kills. In the same 35 HN
  keyframes (350 participant snapshots), all six start at zero, do not decline,
  and remain within their matching Replay-tail values. Five final vectors
  match their tails 10/10; killing sprees match 9/10 with one unobserved gap
  after the last keyframe. The full 350-value sequences for the five exact-tail
  fields are unique among 315 aligned u32 offsets in this Replay; the quadra
  final vector alone also occurs at `0x2bc`. Participant-shift and cross-field
  checks support the cluster but do not establish a published field or any
  individual kill event, time, or killer attribution. The local-only record is
  `artifacts/16_19_development/kill_stats_hn_cli_smoke/analysis.json`, generated
  by `analyze_kill_stats.js` in that directory from the pinned Replay SHA above;
  the CLI candidate output is retained beside it. Neither is packaged.
- **Done:** `hero_ward_stats_snapshot` emits three observed u32 HeroStats
  values at offsets `0x1a4/0x1a8/0x1ac`, correlated with Replay-tail
  `WARD_PLACED`, `WARD_KILLED` and `WARD_PLACED_DETECTOR`. All 350 values for
  each field start at zero per participant, do not decline, and remain within
  their own tail values. The final killed/detector vectors match 10/10; placed
  matches 9/10 with one unobserved gap. In the same HN Replay, each full
  sequence is unique among 315 aligned u32 offsets; only the killed and
  detector offsets also uniquely match their complete final tail vectors.
  This is one-Replay field correlation, not a ward spawn, position, lifecycle
  or removal event. Local-only probe output and script are retained under
  `artifacts/16_19_development/ward_stats_hn_probe/` and are not packaged.
- **Done:** `hero_damage_totals_snapshot` emits the observed HN HeroStats
  f32 values at decoded offsets `0x1e0` (candidate damage to champions),
  `0x1d0` (candidate total damage dealt), and `0x1f0` (candidate damage taken),
  with their derived floors and per-participant Replay-tail gaps. Across 35
  keyframes and 350 participant snapshots, all three start at zero, never
  decline, and their floors remain below their respective Replay tails. Their
  last floors match the tails for 7/10, 5/10, and 4/10 participants; the
  remaining differences after the last keyframe are retained. Each full
  sequence is unique among 315 aligned f32 offsets in this one HN Replay;
  participant-shift controls produce no final-tail matches. The CLI emitted
  350 candidate damage snapshots and 350 ward snapshots from the pinned HN
  Replay with 2,035,757 blocks and zero framing errors. Local-only scan and
  smoke outputs are under `artifacts/16_19_development/scoreboard_leads_probe/`
  and `artifacts/16_19_development/damage_totals_hn_cli_smoke/`. These
  correlations do not establish individual damage events, source, target,
  mitigation, or an exact published field meaning.
- **Done:** `hero_total_heal_snapshot` emits decoded HN
  HeroStats u32 offset `0x234`. In the same 35 keyframes, its 350 values
  start at zero per participant, rise 273 times, never decline, and stay
  within each participant's Replay-tail `TOTAL_HEAL`. The last values match
  5/10 tails, with five nonzero gaps totalling 6,335 after a 36,824 ms
  keyframe-to-tail interval. This sequence is unique among 315 aligned u32
  offsets; nine circular participant shifts match no final tails. The local
  probe is retained under `artifacts/16_19_development/heal_stats_probe/`.
  The real HN CLI smoke emitted 350 candidate snapshots, 35 keyframes,
  ten participants and a 6,335 unobserved tail gap with zero framing errors;
  its local output is `artifacts/16_19_development/total_heal_hn_cli_smoke/`.
  These one-Replay correlations support only a candidate accumulated value,
  not individual heal events, effective healing, or overheal.
- **Done:** `hero_vision_score_snapshot` and
  `hero_epic_monster_damage_snapshot` emit decoded HN
  HeroStats f32 offsets `0x1b0` and `0x21c`. Across the same 350 participant
  snapshots, the vision candidate changes 188 times, never declines, remains
  floor-bounded by each participant's `VISION_SCORE` tail, and its last floors
  match 8/10 tails (the other two are short by one). The epic-monster damage
  candidate changes 25 times, never declines, remains floor-bounded by each
  participant's `TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS` tail, and its last
  floors match 10/10. Each full f32 sequence is unique among 315 aligned
  offsets and nine circular participant shifts give no final-tail matches.
  Decoded `0x218` also approximately equals decoded `0x210 + 0x21c` across
  these snapshots (maximum f32 residual 0.01465); this is a structural
  cross-check, not a damage attribution. Local-only probe data is under
  `artifacts/16_19_development/scoreboard_next_probe/`. The real HN CLI
  emitted 350 candidates for each selected capability with 2,035,757 blocks,
  zero framing errors and tail-gap totals 2/0; local output is under
  `artifacts/16_19_development/vision_epic_hn_cli_smoke/`. Neither candidate
  establishes an individual vision or damage event.
- **Done:** `hero_crowd_control_time_snapshot` emits decoded HN HeroStats f32
  offset `0x230` and its derived floor. In the same 35 keyframes and ten
  participants, the value rises 177 times, never declines or exceeds the
  Replay-tail `TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS`; final floors
  match 5/10 tails and the remaining gaps total 12. Its complete sequence is
  unique among 315 aligned f32 offsets; nine participant shifts give at most
  one tail match. The exact HN CLI smoke emitted 350 candidate rows from
  2,035,757 blocks with zero framing errors under
  `artifacts/16_19_development/crowd_control_time_hn_cli_smoke/`. The offset
  interpretation and participant mapping remain one-Replay candidates; no
  individual crowd-control event, target or source is inferred.
- **Done:** `hero_structure_objective_damage_snapshot` emits decoded HN
  HeroStats f32 offsets `0x210/0x214` and `0x218` as one candidate snapshot.
  Across 350 observations, the first pair is equal, changes 41 times, never
  declines and stays floor-bounded by the Replay-tail BUILDINGS value. The
  `0x218` value changes 66 times, never declines and stays floor-bounded by
  OBJECTIVES. Last floors match 6/10 tails for each; both gap totals are
  8,678, with the final keyframe 36,824 ms before the tail. `0x218` is read
  directly but its floor equals the floor of `0x210 + 0x21c` in all 350
  observations. BUILDINGS and TURRETS tails are identical in this Replay,
  so neither turret identity nor independent objective attribution is
  established. The real HN CLI emitted 350 candidate rows with 2,035,757
  blocks and zero framing errors under
  `artifacts/16_19_development/structure_objective_hn_cli_smoke/`.
- **Done:** Opt-in `hero_damage_taken_from_champions_snapshot` emits the
  decoded HeroStats f32 at `0x200` and its derived floor. Two exact-build HN
  Replays provide 350 and 270 participant observations over 35 and 27
  keyframes. Values rise 234 and 180 times, never decline or floor above their
  participant's Replay-tail `TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS`; final floors
  match 6/10 and 3/10 tails, leaving unobserved tail gaps of 4,832 and 5,616.
  Among 315 aligned f32 offsets, `0x200` alone has final tail matches after
  the finite, nonnegative, monotone and tail-bound gates in both Replays;
  adjacent `0x1f0` and `0x208` fail those controls, and nine participant shifts
  give no final match. Real CLI smokes emitted 350 and 270 candidate JSONL
  rows with zero framing errors. The label remains an unpublished tail
  correlation; no individual damage event, source, target or mitigation is
  inferred.
- **Done:** Opt-in `hero_damage_self_mitigated_snapshot` emits the raw decoded
  HeroStats f32 at `0x208` and a separate derived floor. The two exact-build HN
  Replays contain 350 and 270 participant snapshots across 35 and 27 keyframes.
  The values rise 301 and 230 times, never decline or floor above their
  participant's `TOTAL_DAMAGE_SELF_MITIGATED` Replay tail. Last floors match
  4/10 and 2/10 tails; the remaining unobserved gap totals are 9,170 and
  4,455 over 36,824 and 26,577 ms. The aligned-offset and shifted-participant
  controls favor `0x208`; `0x20c` and `0x23c` remain research-only because their
  controls are weaker or ambiguous. A selected CLI run on both Replays returned
  `CANDIDATE` with zero framing errors. Its Buff decoders used image SHA-256
  `7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d`.
  This is an unpublished tail correlation, not an
  individual mitigation event or proof of the runtime field's meaning. Local
  evidence is under `artifacts/16_19_development/next_field_probe/` and
  `artifacts/16_19_development/self_mitigated_buff_pair_cli_smoke/`.
  On the third Replay, the `0x200` damage-taken and `0x208` mitigated snapshots
  both decoded as candidates, but neither had an exact final tail match across
  the ten participants; the last keyframe was 42,142 ms before game end.
  Their earlier two-Replay evidence grades are unchanged.
- **Done:** Opt-in `hero_longest_living_time_snapshot` emits the decoded
  HeroStats f32 at `0x244` and its separate floor with packet provenance.
  The offset was selected from the first two exact HN Replays before testing
  the third: final floors match `LONGEST_TIME_SPENT_LIVING` tails 10/10,
  10/10 and 9/10 across 350, 270 and 290 participant snapshots. The third
  Replay has one tail-value gap of 1,706 after the last keyframe; a candidate
  death packet also occurs after that keyframe, without proving an update
  rule. The selected real CLI run emitted 290 candidate rows with zero framing
  errors. No individual life span or death duration is inferred.
- **Done:** Opt-in `hero_total_time_spent_dead_snapshot` uses the independent
  `0x248` HeroStats f32 hypothesis for
  `TOTAL_TIME_SPENT_DEAD` was fixed using the first two HN Replays before
  opening the third. Its final floors matched 7/10, 7/10 and 10/10 tails;
  all snapshots remained finite, nonnegative, monotone and within tail
  bounds. Nine participant rotations matched at most one tail in the first
  two Replays and none in the third; adjacent `0x244` and `0x24c`, plus u32
  at `0x248`, failed the same bounds or final-value controls. This supports
  a candidate snapshot, not individual death duration. The selected CLI on
  the third Replay emitted 290 candidate rows over 29 keyframes with ten
  observed participants, zero tail-value gap and zero framing errors. A later
  JSONL-only combined run selected all 29 registered candidates on that
  Replay: every capability returned `CANDIDATE` over 1,839,904 framed blocks
  with zero framing errors; the BuffAdd exact image was `MATCHED_USED`.
- **Current:** A first-two-Replay hypothesis places `TOTAL_UNITS_HEALED` at
  decoded HeroStats u32 `0x23c`. Three strict exact-build scans contain
  350/270/290 snapshots with zero framing errors; this is the only one of 315
  aligned u32 offsets whose last snapshots equal all 30 participant tail
  values. Its observed sequences never decrease or exceed tail values, and
  change 11/13/15 times. The separate f32 `0x238` is positive exactly when
  this u32 exceeds one in all 910 snapshots. Most tails equal one, however,
  and the third Replay has a participant rotation with the same 10/10 final
  matches. The field and participant mapping remain candidates; no healing
  event or target is inferred. The selected real CLI returned `CANDIDATE` with
  290 rows, zero tail gap and zero framing errors on the third Replay.
- **Done:** `--events hero_inventory_mapview --runtime-image <exact-image>`
  runs the pinned HN `0x0420` MapView constructor/deserializer and emits only
  observed slot/item-definition-key records as candidates. All 94 game packets
  in the HN Replay returned success with full payload consumption, yielding
  732 records. The last MapView packets for three participants are within
  3.4–7.4 seconds of game end and their 21 slots 0–6 match Replay-tail
  `ITEM0`–`ITEM6` exactly. That tail correlation came from the original Replay;
  changing a valid raw param can decode the same payload, so participant mapping stays a
  candidate bound to the original packet ref. A second exact HN Replay has
  68 fully consumed MapView packets and 504 records. Its sole `0x400001ae`
  raw-param variant decodes five records, but those bytes do not establish
  participant identity; the CLI/API keep that participant null and retain its
  raw packet ref. Other unobserved raw params still fail closed. A truncated
  payload fails; KR has no HN `0x0420` game route. No full inventory state or
  item transaction is inferred. Missing or wrong images affect only this
  selected capability.
- **Done:** `--events hero_inventory_set_item --runtime-image <exact-image>`
  runs the pinned HN `0x03b7` SetItem constructor/deserializer. All 16
  seven-byte game packets returned success with full consumption, yielding
  slot 8, flag 1 and item keys 1200–1204. The ten initial hero-param packets
  match their first MapView slot-8 item keys 10/10. The six later packets
  repeat existing values; one has raw param `0x400001b7` and no participant
  candidate. A truncated packet fails, while changing only its raw param does
  not change decoded slot/item fields. This supplies observed packet fields,
  not a purchase, sale, transition, or general participant mapping.
- **Done:** `--events hero_inventory_broadcast --runtime-image <exact-image>`
  uses the pinned HN `0x03ef` Broadcast constructor/vector/record parsers and
  emits observed candidate slot/item-key records with raw packet references.
  The exact runtime fully consumed 356/356 HN packets (350 keyframe, six game)
  and returned 3,546 records; the tracked helper matched an independent
  packet probe on all 356. A truncated packet returned failure without full
  consumption. The real CLI emitted 3,546 candidate records with zero Replay
  framing errors and `MATCHED_USED` image status; local evidence is under
  `artifacts/16_19_development/broadcast_03ef_probe/` and
  `artifacts/16_19_development/inventory_broadcast_hn_cli_smoke/`. The
  emulated TLS epoch selects captured image static data; the live thread
  epoch was not captured. A bounded candidate mapping now assigns the ten
  canonical raw params to participants 1–10: last-keyframe slots 0–6 match
  the corresponding Replay tail items in 68/70 comparisons (the other two
  differences remain), uniquely best among all one-to-one assignments and
  ahead of nine shifted controls. The one observed `0x400001b1` Broadcast
  variant matches nearby canonical `0x400000b1` MapView slots 9/9 and maps
  candidate participant 4. A real HN CLI rerun emitted 3,546 candidate records, all
  retaining raw packet refs, with zero unmapped packets. Local negative
  controls and rerun details are under
  `artifacts/16_19_development/broadcast_identity_probe/`. The second exact HN
  Replay adds 278 fully consumed packets and 2,757 records. Its one
  `0x400001af` variant has seven records matching a nearby canonical
  `0x400000af` Broadcast array exactly; surrounding keyframes, a later
  MapView packet and final Replay-tail items favor participant candidate 2
  over the other nine. The CLI retains its original raw param and packet ref,
  emits these seven rows as candidate 2 and reports zero unmapped packets.
  The extra `0x100` bit is unclassified; no generic bitmask is applied. This
  third-Replay evidence adds one fully consumed 63-byte packet and five
  records with decoded flag 3. The exact image fully consumed 297 packets
  and emitted 2,950 records; last-keyframe slots 0–6 matched 56/70 tail
  values, ahead of nine shifted controls. The three-Replay evidence does not
  establish confirmed packet ownership, flag meaning,
  transactions or continuous inventory state.
- **Done:** `npc_buff_remove_packet` is wired as an unpublished exact-image
  candidate for HN game-stream `0x043c` BuffRemove2 packets. The exact callback,
  constructor and deserializer route was identified in the pinned image. A
  bounded probe fully consumed all 11,950 observed HN packets. Its decoded
  object contains a float at `0x10`, a byte used as a BuffManager slot index
  at `0x14`, and a u32 passed to a lookup at `0x18`. The float is zero in
  11,942 packets; the other eight track Replay time within 1 ms. Truncated
  payloads failed, and an appended byte and foreign route failed the
  full-consumption check. Local probe evidence is under
  `artifacts/16_19_development/cast_buff_probe/`. The real HN CLI emitted
  11,950/11,950 candidates from 2,035,757 framed Replay blocks with zero
  errors and `MATCHED_USED` image status; local output is under
  `artifacts/16_19_development/buff_remove_hn_cli_smoke/`. Owner, buff identity
  and successful removal are not established.
- **Done:** `npc_buff_add_packet` is wired as an unpublished exact-image
  candidate for HN game/keyframe `0x03ed` BuffAdd2 packets. The pinned image
  links the callback, constructor and deserializer; all 32,434 observed route
  packets decoded with full consumption, across 24 stream/length shapes.
  Each shape's one-byte truncation failed; an appended byte remained
  unconsumed. The callback reads six selected transformed scalars, including
  f32 offsets `0x14` and `0x1c`. For 6,481 same-opaque-tuple keyframe rows
  with an observed game counterpart, `0x14 + 0x1c` matched a game `0x14`
  within 0.05 in 6,223 cases; a 137-row circular shift matched only 563.
  Restricting the game comparison to values at most 1,000 and tolerance 0.01
  gives 1,321/1,444 matches versus zero shifted controls. The real HN CLI
  emitted 32,434 candidate records from 2,035,757 framed blocks with zero
  errors and `MATCHED_USED` image status; local output is under
  `artifacts/16_19_development/buff_add_hn_cli_smoke/`.
  This is a one-Replay correlation between anonymous fields, not proof of
  duration, elapsed time, owner, buff identity or successful application.
  Local probe evidence is under `artifacts/16_19_development/buff_add_probe/`.
  For the high-volume BuffAdd2 and BuffRemove2 outputs, repeated field grades
  and limits are stored once per capability in `semantic_run.json`; each JSONL
  row retains its candidate status, build profile and raw packet provenance.
- **Third-Replay BuffAdd shape:** Three keyframe `0x03ed` packets of length 41
  and raw param `0x400000b3` contain one 40-byte polymorphic element in the
  first runtime object vector. The exact `820.7193` image returned AL=1 and
  consumed all 41 bytes for each; truncation returned AL=0 and an appended
  byte remained unconsumed. The decoder checks an allocated emulator-heap
  pointer, count/capacity 1, pinned vtable, and empty second vector. The
  element stays opaque, and game-stream or foreign-parameter 41-byte packets
  remain unsupported. Profile v2 emitted all 27,208 BuffAdd packets as
  candidates in the third Replay, including these three marked rows; the
  full 28-capability CLI rerun returned `CANDIDATE` with zero framing errors
  and exact-image status `MATCHED_USED`. The initial `PARTIAL` artifact is
  retained. This adds a packet shape, not a buff identity or lifecycle.
- **Done:** Selecting both Buff packet candidates now adds an unpublished
  `candidate_associations.npc_buff_add_remove_opaque_key` summary in
  `semantic_run.json` and the exact-build API. It compares only the anonymous
  `(u32 token, u8 slot)` fields from the two decoded routes. All 3,217 distinct
  Remove keys in the first Replay and all 2,730 in the second appear among Add
  keys; 3,212 and 2,726 also appear in game-stream Adds. The corresponding
  packet counts are 32,434 Add / 11,950 Remove and 26,150 Add / 10,548 Remove.
  Missing exact-image dependencies produce an `UNAVAILABLE` association while
  preserving each capability's own status. In the second Replay, a preceding
  same-key Add within 30 seconds is absent for 614 Remove rows and non-unique
  for 4,518; a rotated-key control leaves 6,932 unmatched. Repeated keys and
  ambiguous timing prevent a deterministic packet join. The summary claims no
  buff identity, owner, application, removal, duration or lifecycle. The
  second-Replay ordering and shuffled controls are retained under
  `artifacts/16_19_development/buff_link_probe_second/`.
  In the third Replay all 3,030 distinct Remove keys appear in Add rows, while
  3,023 appear in game-stream Adds; row identity remains unresolved.
- **Next:** Continue bounded KR route research beyond the assist and damage
  candidates above; test additional independent combat-field anchors.
  Further independent HN Replays
  can test HeroStats and inventory candidates. The HN
  Broadcast participant mapping remains candidate-only after three Replays, and
  inventory-state inference needs independent anchors. Movement-route
  research still needs a position-field link.
- **Path negative control:** The exact HN image identifies `0x03ee` as
  DirectInputMovementDriverServerTurnData (84 HN packets in one short interval),
  `0x0160` as SetMovementDriver (4), `0x04dd` as AddFollowTargetPosition (0),
  and `0x00d2` as SyncCircularMovementRestriction (7,023; 7,013 one-byte).
  None establishes an ordinary hero-coordinate stream. The old 16.16 path
  opcode `0x00f6` has a 16.19 factory object size `0x18`, not the old `0x2c`
  layout. A path candidate still needs an exact observed receive/field-write
  link and independent position anchors; no old profile is reused.
- **821 path negative control:** A strict scan of all 11 KR Replays found no
  defensible ordinary hero coordinate or path field. `0x038e` had 69/607
  same-participant packets near matched returns versus 39/607 rotated-ID
  controls, a weak lead. `0x023c` co-times with other routes, `0x0113` forms
  short repeated trains, and `0x0194` appears during observed death intervals.
  None is emitted as a path candidate.
- **821 HeroStats route correction:** The exact image registers
  `PKT_S2C_HeroStats_s` and its factory constructor at numeric ID `0x0089`.
  An earlier probe on two real 1,263-byte KR keyframe payloads consumed only
  five bytes because it omitted the native base-reader hook. The corrected
  native probe consumed 1,263/1,263 bytes and produced the exact independent
  1,260-byte vector for all 3,270 target packets. The object's
  internal byte path implements `a = ROR8((raw + 0x11) & 255, 2)`,
  `index = (((a & 0xd5) << 1) | ((a >> 1) & 0x55)) & 255`, and
  `decoded = (table[index] + 0x39) & 255`. The keyframe raw-byte candidates
  match this transform and remain independently gated Replay correlations.
  Native carrier binding confirms the bytes, not the proposed semantic names
  or published capability. The failed and corrected probe evidence is retained
  under `artifacts/16_19_development/path_probe_agent/` and
  `artifacts/16_19_development/keyframe_wrapper_821/`.
- **Ward negative control:** Old 16.16 WardSpawn opcode `0x049a` is not an HN
  16.19 factory case and has no packets in this Replay. The HN `0x0400` case
  has 6,627 packets and a distinct exact-image runtime deserializer. Its
  object contains a dynamic byte field and two three-float regions, but no
  observed receive or independent link to ward identity, owner or coordinates;
  no ward candidate is emitted. Of 6,627 packets, 3,478 are game packets and
  3,149 are keyframe packets; no game raw param equals a HeroStats hero param.
  An interval with zero ward-count increments still has 104 game `0x0400`
  packets, and count correlations resemble other frequent routes. Bounded
  runtime and Replay-side evidence is retained under
  `artifacts/16_19_development/ward_route_0400_probe/`.
- **CLI batch:** A two-Replay HN/KR run with death, respawn and level selection
  yielded HN `CANDIDATE`, KR `PARTIAL`, and aggregate `PARTIAL`, retaining the
  KR death candidate while reporting the HN-only capabilities unavailable.
- **Blocked proof:** Confirmed timer and candidate victim mapping need broader
  independent anchors beyond the three HN Replays. The separate Riot client is `16.19.821.7343`
  and cannot supply a `16.19.820.7193` decoder image.

Research outputs, original replay data, and client binaries remain local and
outside Git. The 2026-08-21 published semantic baseline remains historical.
