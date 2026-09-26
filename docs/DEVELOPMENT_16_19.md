# 16.19 development progress

Updated: 2026-09-26. Branch: `codex/16-19-development`.

Current progress (older notes below retain their original research context):

- **Healing counter snapshot source query:** Saved exact-821
  `hero_total_heal_snapshot_candidates` and
  `hero_total_units_healed_snapshot_candidates` can now use `--verify-source`.
  The query re-decodes the same physical ROFL through the existing candidate
  decoder, checks all keyframe rows and tail-gap metadata even after
  `--limit`, and accepts a same-byte relocated ROFL via `--source-replay`.
  One original Replay verified 330/330 rows for each event. The values
  remain cumulative reported candidates; effective healing, individual
  recipient and source remain `UNKNOWN`.

- **TargetHero callback key to roster (opt-in candidate):** On exact
  `16.19.821.7343`, select `--events target_hero_roster_key_pair
  --runtime-image IMAGE --event-jsonl-only` or API capability
  `target_hero_roster_key_pair`. The pair reuses the complete native
  `target_hero_packet` and ten-key `hero_roster_metadata_bridge` outcomes;
  both source JSONL streams are saved with a CLI pair-only request. The
  11-Replay `--jobs 2` CLI pair batch returned 11/11 `CANDIDATE` and zero
  framing errors, with 62,219 native game `0x0265` rows:
  30,874 zero callback keys and 31,345 nonzero keys. Every nonzero full u32
  equals one of the ten canonical `0x0089` HeroStats raw keys in its Replay;
  zero is counted but never labeled; all 31,345 nonzero rows paired and no
  unexpected key appeared. Each Replay saved the target, roster and pair
  JSONL streams. The pair preserves the original
  `0x0265` and latest `0x0089` packet refs, plus direct metadata champion,
  team and role labels. The roster-to-metadata link remains `CANDIDATE`;
  live receiver lookup, source actor, resolved target, target state and
  gameplay effect remain `UNKNOWN`. Unexpected nonzero keys or incomplete
  source outcomes fail the entire pair with no partial rows.

- **Anonymous `0x029c` packet-local u32 (explicit opt-in candidate):** The
  pinned `16.19.821.7343` image maps game packet `0x029c` to factory case
  `0xf06643`, constructor `0xe9abf0`, object vtable `0x1ba3c88`, and
  deserializer `0xf88030`. Eleven original KR Replays supplied 457,095
  packets in 13 observed shapes, including 43,038 with nonzero raw parameters.
  Every packet passed native full consumption, object identity including its
  original parameter, and ordered input/output hash checks; the object
  selector at `+0x10` was the same protected byte on all packets. The
  protected `+0x14` word decodes to an anonymous u32 on 453,545 packets and
  to the `0xffffffff` sentinel on 3,550 one-byte packets. Every shape's
  truncated and appended controls failed the full packet gate. No exact
  packet class or callback name has been established for this route.
  Select `--events anonymous_029c_packet --runtime-image IMAGE
  --event-jsonl-only`, or API capability `anonymous_029c_packet`; the parser
  accepts at most 50,000 route packets per Replay. A real 32,336-packet
  Replay produced candidate JSONL with four native batches and passed a
  saved query with `--verify-source --limit 1`, which checked all 32,336
  physical packets before emitting one row. The first CLI attempt failed
  because it incorrectly required zero raw parameters; the corrected gate
  accepts the original u32 and checks its native object identity. The failed
  artifact remains in the ignored worktree evidence. Actor, target, object
  role, receiver state, behavior and effect remain `UNKNOWN`.
  [The native gate](ANONYMOUS_029C_821_NATIVE_GATE.json) records source
  hashes, packet counts, nonzero raw parameter counts, ordered digests,
  negative controls and the real Replay smoke without raw payloads.

- **HeroStats roster to Replay metadata (opt-in candidate):** Select
  `--events hero_roster_metadata_bridge --event-jsonl-only` on exact
  `16.19.821.7343`, or request API capability
  `hero_roster_metadata_bridge`. The bridge requires complete ten-player
  HeroStats K/D/A snapshot references, death/source-kill/assist candidate
  counts, canonical raw `TEAM` values, nonblank `SKIN`, and a unique ten-way
  match to Replay tail K/D/A. All 11 pinned KR Replays yielded 110 candidate
  rows; a saved batch query with `--event
  hero_roster_metadata_bridge_candidates --verify-source --limit 1` checked
  all 110 physical rows and emitted one. Without `--verify-source`, saved
  queries validate the manifest-hashed `rofl_inventory.json` and all ten
  candidate rows without opening the original ROFL. Explicit source
  verification additionally re-decodes the physical tail `statsJson` and
  HeroStats packet references. Hero, team, and role labels come directly
  from metadata; the raw roster key association remains `CANDIDATE` and
  per-packet actor identity remains `UNKNOWN`. The upstream event counters
  already use tail gates, so their unique match is internal consistency,
  not independent player identity proof. Only 49/110 latest K/D/A snapshots
  equal tail values; no missing tail interval is filled. The new bridge
  JSONL rows omit PUUID, Riot ID, player name, and metadata player ID;
  existing Replay inventory artifacts retain their established fields.

- **ChangeMissileTarget V2 anonymous native f32 triplet (explicit opt-in):**
  The exact KR `16.19.821.7343` deserializer `0x10e8e30` writes protected
  object bytes `+0x10..+0x1b` through helper `0x10a5b00`. Its native
  inverse yields three finite f32 components at `+0x10/+0x14/+0x18`.
  In the 11 original Replays, all 12,869 length-13 packets carry twelve
  packet bytes in component order `payload[9:13], [5:9], [1:5]`; the 256
  length-3/4 packets carry no vector bytes and retain the native default
  zero triplet. All 13,125 packets passed full exact-image deserialization.
  One-byte changes at each of the twelve long-form data positions changed
  exactly one protected vector byte without changing the callback key;
  truncation, append, and wrong-image controls failed closed. The V2 CLI
  flag `--change-missile-target-v2` and API
  `changeMissileTargetProfile: 'v2'` add the protected bytes, inverse raw
  f32 bytes, three values, and packet/default source. V1 remains the default
  and its saved artifacts retain their original format and digest. V2
  native output digests and saved-query validation bind all vector bytes
  and values; two original Replays (one long-form and one short-form) passed
  complete `--verify-source --limit 1` queries over 3,620 and 176 rows.
  [The V2 native gate](CHANGE_MISSILE_TARGET_821_NATIVE_VECTOR_V2_GATE.json)
  records the form counts and per-Replay hashes. These are anonymous
  packet-local values; target position, identity, receiver match, change,
  effect and causality remain `UNKNOWN`.

- **ChangeMissileTarget 0x040c packet-local comparison key (opt-in candidate):**
  The pinned KR `16.19.821.7343` image registers
  `PKT_S2C_ChangeMissileTarget_s` on `MissileClient` through factory case
  `0xf0b2cf`, constructor `0xea4f10`, deserializer `0x10e8e30`, and callback
  `0x997c80`. Strict framing of the 11 original KR Replays found 13,125
  game packets in seven Replays, with four route-absent Replays. All 13,125
  packets passed exact native deserialization, full consumption, and object
  identity checks across 13 observed length/prefix shapes. The callback
  transforms packet object `+0x1c` into a u32 key before comparing it with
  live receiver state. Each shape reached that pre-comparison point with a
  synthetic receiver; one-byte truncations and appends failed the full route
  gate. [The native gate](CHANGE_MISSILE_TARGET_821_NATIVE_GATE.json) records
  the exact image and callback hashes, source hashes, shape counts, and
  negative controls. CLI `--events change_missile_target_packet
  --runtime-image IMAGE --event-jsonl-only` and API
  `capabilities: ['change_missile_target_packet']` are explicit opt-ins.
  One original Replay emitted 176/176 candidate rows with zero framing
  errors; saved `query-events --event change_missile_target_packet_candidates
  --verify-source --limit 1` checked all 176 rows against that original ROFL
  and emitted one unchanged row. A route-absent original Replay returned
  `PROFILE_UNAVAILABLE`. Query rows remain `CANDIDATE`; live receiver match,
  missile identity, owner, target, actual target change, effect, and
  causality remain `UNKNOWN`. Original ROFLs, image, and complete CLI output
  remain local and ignored.
- **ShowHealthBar saved-source verification (2026-09-26):** The opt-in
  `query-events --event show_health_bar_packet_candidates --verify-source`
  now binds exact-821 saved rows to original ROFL packets and runs the
  existing per-row callback transform, metadata, count, and ordered native
  input checks even without `--show-health-zero-flag`. A real selected CLI
  run on `KR_8393821675.rofl` emitted 5,452/5,452 candidate rows. The saved
  query physically verified all 5,452 packets and emitted one unchanged row
  with `--limit 1`. Synthetic late time/offset, top-level time/parameter,
  and packet-ID metadata forgeries fail with zero stdout. This does not rerun
  the native callback or establish a health or visibility effect.
- **Opt-in exact-821 batch concurrency (2026-09-26):** `batch --events ...
  --event-jsonl-only --jobs 2` uses at most two isolated Replay workers. Each
  worker writes its own candidate JSONL and returns only its saved analysis
  without event arrays; the parent retains input order, per-Replay failures,
  and the ordinary batch manifest. The default batch path is unchanged.
  On two original KR `16.19.821.7343` Replays with the same
  `unit_apply_damage_packet` selection and exact runtime image, one Windows
  host measured 20.542 s with `--jobs 1` and 12.965 s with `--jobs 2`.
  Both runs returned `CANDIDATE`, 3,481,428 framed blocks, zero framing
  errors, and identical candidate JSONL SHA-256 for the 64,824 and 57,939
  rows. A single 11-Replay `--jobs 2` confirmation took 61.732 s, returned
  `CANDIDATE` with 18,235,209 framed blocks, zero errors, and all 628,909
  candidate rows byte-identical to the earlier saved serial V5 artifact;
  per-Replay order, counts, and actual file hashes matched. That older
  artifact was generated at commit `d911f819`, so it is a parity reference,
  not a same-commit timing baseline. These timings are one-host observations,
  not cross-platform speed claims. Inputs, outputs, and logs stay ignored under
  `artifacts/16_19_development/batch_jobs_821_benchmark_20260926/`.
- **UnitApplyDamage saved-source verification (2026-09-26):** The opt-in
  `query-events --verify-source` now covers exact-821 0x005f
  `unit_apply_damage_packet_candidates` V1-V6. It checks the original ROFL
  identity, every physical packet position/time/parameter/payload and the
  existing per-row field, transform, count, and ordered native-input witness
  even without a damage filter. One original KR Replay verified 64,824/64,824
  V6 rows and emitted one unchanged row with `--limit 1`. A copy with only
  the last saved row's time and offsets changed failed
  `SOURCE_PROVENANCE_MISMATCH` with zero stdout bytes. Eleven original KR
  Replays contain 628,909 strict-framed 0x005f packets, all in game chunks;
  this count is a source inventory, not a new native V6 gate. The original
  Replay, image, and full saved rows remain local and ignored. This source
  check does not rerun native callback code or establish actual damage
  effects.
- **SetDimensionMissile 0x008a packet-local callback byte (opt-in candidate):**
  The pinned KR `16.19.821.7343` image registers
  `PKT_SetDimensionMissile_s` on `MissileClient` through factory case
  `0xeffc77`, constructor `0xeccbe0`, deserializer `0x111f960`, and
  callback `0x998520`. Strict framing of all 11 original KR Replays found
  218,764 game `0x008a` packets in 60 observed length/prefix shapes. Every
  packet natively returned success with full consumption and matching object
  identity; the callback transformed object byte `+0x14` to a packet-local
  u8 before the receiver method. The two observed protected-byte/argument
  pairs were `d5/0` and `a7/6`. The exact image, callback code and table,
  per-Replay source/input/output hashes, counts, and negative controls are
  recorded in [the native gate](SET_DIMENSION_MISSILE_821_NATIVE_GATE.json).
  All 60 representative truncations and appends failed the full route gate.
  Six of 11 sampled `0x0087` payloads also passed this deserializer, so
  the decoder requires the `0x008a` framing ID; payload shape alone is
  insufficient. `decode --events set_dimension_missile_packet
  --runtime-image IMAGE --event-jsonl-only` and API
  `capabilities: ['set_dimension_missile_packet']` are explicit opt-ins.
  One original Replay emitted 14,572/14,572 candidate rows in two native
  batches with both ordered digests matching the independent native gate.
  Saved `query-events --event set_dimension_missile_packet_candidates
  --verify-source --limit 1` validated all 14,572 rows against the original
  ROFL and emitted one unchanged row. A later saved-row time/offset forgery
  failed source verification with zero output; ordered native digests are
  still checked after `--limit`. Live receiver state, missile identity,
  owner, target, actual dimension change, gameplay effect and causality
  remain `UNKNOWN`. Original ROFLs, runtime image, and complete JSONL output
  remain local and ignored.
- **Integrated 821 provenance and 0x0087 validation (2026-09-26):** After
  merging the opt-in ForceCreateMissile candidate with saved-query source
  verification, `npm test` passed 1,166 of 1,288 Node tests across 42 groups,
  with zero failures and 122 declared skips; 19 Python unittests passed.
  Seven focused query files passed 122/122 without skips. The pinned exact
  image passed the four focused 0x0087 candidate tests without skips. A saved
  query over original `KR_8393821675.rofl` checked all 14,353 candidate rows
  against the source ROFL, returned `SOURCE_REPLAY_VERIFIED`, and emitted one
  unchanged row. A later time/offset-only forgery after `--limit 1` failed
  `SOURCE_PROVENANCE_MISMATCH` with zero stdout bytes. `npm run test:all`
  and other operating systems were not tested in this integration run.
- **Optional saved-row source verification (2026-09-26):** `query-events
  --verify-source` now reopens the original exact-821 ROFL for the packet-local
  NotifyContextualSituation, item-group V1/V2, cooldown broadcast, item-charges,
  target-hero, ForceCreateMissile, SetDimensionMissile, UnitApplyDamage,
  ShowHealthBar, and CastSpellAns candidate streams. It checks the full
  Replay build/SHA-256,
  strict packet framing, ordered stream/chunk IDs and offsets, timestamp,
  parameter, payload, and total count before publishing stdout. A single
  Replay may use `--source-replay PATH` when the same bytes were moved; batch
  queries use each saved source path. Other event shapes reject this option.
  Ordinary offline queries remain available and report
  `SAVED_ONLY_UNVERIFIED`; checked rows report `SOURCE_REPLAY_VERIFIED`
  (a partial batch reports `PARTIAL_SOURCE_REPLAY_VERIFIED`). This verifies
  packet provenance against supplied source bytes, without rerunning native
  callback decoding or promoting candidate effects. Focused query tests passed
  116/116 with zero skips. The original KR_8392938200 artifact/source passed
  for 4,600 item-charges and 6,703 target-hero rows; a copy with only saved
  time/offset edits failed `SOURCE_PROVENANCE_MISMATCH` after `--limit 1` with
  zero stdout bytes.
- **ForceCreateMissile 0x0087 packet-local comparison key (opt-in candidate):**
  The pinned KR `16.19.821.7343` image registers `PKT_S2C_ForceCreateMissile_s`
  on `AIBaseClient` through factory `0xeffb9f`, constructor `0xeac850`,
  deserializer `0x10f0690`, and callback `0x2bf6d0`. Strict framing of the
  11 original KR Replays found 206,957 game packets in 12 observed shapes
  (3/4 bytes with selectors `f0/f1/f2/f4/f6/f7`). All 206,957 natively
  returned success, consumed the full payload, and matched the registered
  object identity. The callback's exact byte transform yielded 61,952
  distinct anonymous comparison keys. A synthetic receiver caused all
  12 representative shapes to reach the pre-comparison key; hit, mismatch,
  and null-receiver controls behaved as expected. Twelve truncated,
  twelve appended, and eleven foreign `0x008a` samples were rejected as
  full route packets. [The sanitized native gate](FORCE_CREATE_MISSILE_821_NATIVE_GATE.json)
  records per-Replay ordered input/output SHA-256 values. The hashes cover
  raw parameter/payload and native callback bytes; full source provenance
  still requires the original ROFL. `--events force_create_missile_packet
  --runtime-image IMAGE --event-jsonl-only` and API
  `capabilities: ['force_create_missile_packet']` are explicit opt-ins.
  A real CLI run on one original Replay emitted 14,353/14,353 candidate rows,
  used two native batches and the matched image, and had zero framing errors;
  its ordered input/output digests matched the independent gate. Saved
  `query-events --event force_create_missile_packet_candidates --limit 1`
  validated all 14,353 rows and emitted one unchanged row. Live receiver
  lookup and match, missile identity, owner, target, actual creation, effect,
  and causality remain `UNKNOWN`. Original Replays, image, and full raw
  packet/CLI artifacts remain local and ignored.

- **Combined 821 CLI/API validation (2026-09-26):** After registering both
  new opt-in candidates, `npm test` passed 1,150 Node tests across 41 groups
  with zero failures and 120 declared skips, plus 19 Python unittests. Exact
  image focused tests passed 10/10 for `0x0437` and 9/9 for `0x0265`. One
  combined CLI run on `KR_8392938200.rofl` emitted 4,600 item-charges and
  6,703 target-hero candidate rows with zero framing errors; each route's
  ordered native input/output digests matched its independent full gate.
  Saved queries scanned all 4,600 and 6,703 rows respectively and emitted
  one unchanged match each. The first combined public run exposed an
  outdated capability-list expectation; that failure was corrected before
  this passing rerun. The Replay, image, and generated outputs remain local.
- **SetItemCharges packet callback arguments (opt-in candidate):** The exact
  KR `16.19.821.7343` route `0x0437` is registered as
  `PKT_S2C_SetItemCharges_s` for `HeroInventoryClient` in the pinned runtime
  image. Factory case `0xf0bb2a`, constructor `0xebda80`, deserializer
  `0x1041380`, and callback `0x350250` are bound to image SHA-256
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`.
  Strict framing of 11 original KR Replays found 40,439 game-chunk packets
  with payload lengths 1, 2, 3, or 4 and zero framing errors. All 40,439
  packets natively returned AL=1 with full consumption and matching object
  identity. The native callback's `0x2af490` selector range check executed;
  the witness captured a u8 selector and u16 value at `0x350310` before
  the receiver method. Eight cross-Replay representative truncations and
  eight appends were rejected by the full-consumption gate. The bounded
  CLI/API decoder and saved query verify separate ordered input/output
  hashes; per-Replay hashes and shape counts are in
  [the sanitized native gate summary](ITEM_CHARGES_821_NATIVE_GATE.json).
  The hashes cover raw parameter/payload and native callback bytes, not
  saved timestamps or file offsets; full provenance requires the original
  ROFL.
  One real CLI run emitted 4,600/4,600 candidate rows in one native batch,
  matched both independent hashes, and had zero framing errors. A saved
  selector-zero query validated all 4,600 rows after `--limit 1`, matched
  631, and emitted one unchanged row; valid unobserved selector `6` matched
  zero. Selector values observed were `0`, `1`, `2`, `3`, `4`, `5`, and `8`;
  a separate synthetic packet natively passed the range check with selector
  `7`, which the saved query accepts. The u16 argument ranged from 0 to
  1,111 in the original Replays. The receiver method was not
  executed: actual item identity, charges, slot, owner, receiver state and
  gameplay effect remain `UNKNOWN`. Original Replays, image, and full JSONL
  stay ignored outside Git. Focused exact-image Node tests passed 9/9.
- **TargetHero 0x0265 callback u32 (opt-in candidate):** The pinned exact KR
  `16.19.821.7343` runtime registers route `0x0265` as
  `PKT_AI_TargetHeroS2C_s` on `AIBaseClient`, through factory case
  `0xf05c17`, constructor `0xe99060`, deserializer `0xf19ec0`, and callback
  `0x2bb950`. This differs from the historical build's use of route `0x0265`.
  Strict framing of 11 original KR Replays found 62,219 game-stream packets:
  30,874 one-byte and 31,345 three-byte payloads. All 62,219 natively
  deserialized with full consumption and reached the callback callsite with
  one packet-local u32; the decoder stops before the receiver-dependent
  function. Independent per-Replay ordered raw-input hashes and native-output
  hashes matched the CLI decoder; the sanitized per-Replay hashes are in
  [the exact native gate summary](TARGET_HERO_821_NATIVE_GATE.json). Eight
  truncate/append controls were not
  accepted as full packets. `--events target_hero_packet --runtime-image IMAGE
  --event-jsonl-only` is an explicit CLI opt-in; the API uses
  `capabilities: ['target_hero_packet']`. A real CLI run emitted 6,703/6,703
  candidate rows with `MATCHED_USED`, one native batch, and zero framing
  errors. Saved `query-events --event target_hero_packet_candidates
  --opaque-u32 0 --limit 1` validated all 6,703 rows, matched 3,335 and
  emitted one unchanged row. The saved query validates each row and both
  ordered digests even after the output limit; focused exact-image tests
  passed 9/9 with zero skips. The callback u32 is zero for every observed
  one-byte packet and takes ten `0x400000ae..0x400000b7` values for the
  three-byte packets. A resolved target object, source actor, receiver state,
  and actual effect remain `UNKNOWN`. Original Replays, image, complete
  native gate and CLI artifacts remain local and ignored.
- **SetItemGroupData_Broadcast conditional callback byte (opt-in V2 candidate):**
  `--item-group-packet-v2` or API `itemGroupPacketProfile: 'v2'` retains the
  exact `0x013f` V1 packet route and lookup key, then adds the native object's
  protected `+0x1c` byte and the callback's transformed u8 value if its
  receiver lookup hits. The pinned nested reader writes `+0x1c`; callback
  RVA `0x35055e..0x350578` transforms it and `0x3505c9` writes it to a
  receiver entry only on the lookup-hit branch. The native witness supplies
  a synthetic lookup hit and checks that write for every selected packet;
  its callback transform, code region and nested reader region are pinned to
  the exact KR `16.19.821.7343` image. A read-only census of all 11 original
  KR Replays found 1,604 distinct `0x013f` payloads, all native fully
  consumed, and six transformed byte values: `0`, `1`, `2`, `3`, `99`, `255`.
  Two original packets with the same raw parameter `0x400000ae` and lookup
  key `90922051` produced `1` and `0`; they show this byte varies
  independently of the lookup key. Native truncate and append controls fail
  full consumption. A real CLI V2 run on `KR_8393821675.rofl` emitted
  90,240/90,240 `CANDIDATE` rows in 10 native batches with `MATCHED_USED`
  and zero framing errors; direct API decoding of that Replay returned the
  same count. Saved `query-events --event
  item_group_data_broadcast_packet_candidates --opaque-u32 90922051
  --item-group-callback-u8 0 --limit 1` validated all 90,240 rows, matched
  33 and emitted one unchanged row. The valid but unobserved byte `4`
  completed the same full-row validation with zero matches. V2 saved queries
  check separate ordered
  raw-input and native-output digests including the new protected and
  transformed byte, even after the output limit. V1 remains the default
  profile, row shape and digest. The captured image lacks live receiver
  state: actual lookup success, group/item/owner/slot, purchase, inventory
  state change and gameplay effect remain `UNKNOWN`. The private image,
  Replays and generated JSONL stay ignored outside Git. Focused exact-image
  Node and Python tests passed 11/11 and 5/5 without skips.
- **SetCooldown_Broadcast callback lookup key (opt-in candidate):** The exact
  KR `16.19.821.7343` route `0x039d` maps through factory case `0xf09d3f`,
  constructor `0xe99ba0`, deserializer `0xf1a4e0`, and callback `0x2bbc90`
  in the pinned runtime image (SHA-256
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`).
  The callback reads packet object `+0x10` and forms a lookup key before
  calling `0x98a840`. Strict framing of 11 original exact-build KR Replays
  found 182,482 route packets across game and keyframe streams and eight
  observed payload lengths, with zero framing errors. An independent native
  pass fully consumed all 182,482 packets and captured one lookup key per
  packet; ordered raw-input and native-output SHA-256 values are retained
  for each Replay in
  [the source-bound evidence summary](COOLDOWN_BROADCAST_821_NATIVE_GATE.json).
  The bounded CLI/API decoder verifies the exact image,
  native full consumption, object identity, callback key, and both digests
  before emitting `cooldown_broadcast_packet_candidates`. One real CLI
  smoke emitted 19,714/19,714 rows in two native batches; its input/output
  hashes matched the independent full gate. A saved query validated all
  19,714 rows after `--limit 1`, matched 2,507 keys equal to zero, and
  emitted one unchanged row. Truncated and appended packet controls failed
  full native consumption. The key remains packet-local: actual cooldown,
  slot, actor, target, receiver lookup result and effect are `UNKNOWN`.
  This route is opt-in and does not enter default semantic output. The image,
  original Replays, full-gate record and CLI output remain ignored outside Git.
- **SetItemGroupData_Broadcast packet lookup key (opt-in candidate):** Exact
  KR `16.19.821.7343` keyframe route `0x013f` is a packet factory route,
  separate from `0x040a` OnEvent child IDs. The pinned runtime image SHA-256
  is `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`;
  factory/constructor/deserializer/callback RVAs are
  `0xf0214f`/`0xebdd70`/`0x10425b0`/`0x350440`. The callback transforms the
  packet object's protected `+0x20` word and forwards a u32 lookup key to
  `0x5d3bd0`. The native helper forces that lookup to miss; the captured
  module has no live receiver map. In 11 original exact-build KR Replays,
  strict framing found 1,229,520 `0x013f` packets, all keyframe, across 15
  observed length/selector shapes and zero framing errors. The largest
  single Replay had 124,080 packets, below the explicit 150,000 cap;
  overflow is reported as `UNSUPPORTED`. For each selected Replay, the
  decoder uses bounded native batches and requires full consumption plus
  separate ordered raw-input and native-output SHA-256 digests before
  emitting candidate rows. Representative truncate/append controls failed
  native full consumption as expected. Real CLI `--events
  item_group_data_broadcast_packet --runtime-image IMAGE --event-jsonl-only`
  produced 124,080/124,080 and 90,240/90,240 candidate rows on two original
  Replays, each with `MATCHED_USED`, zero framing errors, and respectively 13
  and 10 native batches. The saved `query-events --event
  item_group_data_broadcast_packet_candidates --opaque-u32 5247418 --limit 1`
  validated all 124,080 first-Replay rows, matched 330 and emitted one
  unchanged row; it checks all rows after the limit, verifies those separate
  ordered digests, and gates per-row provenance fields.
  `native_callback_lookup_key_u32` is
  packet-local only. Lookup success, group/item/slot/owner/participant,
  purchase/state change and gameplay effect remain `UNKNOWN`; this candidate
  does not enter default semantic output. The image, Replays and output
  JSONL stay ignored outside Git. Focused Node and exact-image native tests
  passed 7/7 and 3/3 without skips; the two real CLI runs took about 10.2
  and 7.3 seconds, writing about 177 and 129 MB of JSONL. An initial public
  test run found one stale capability-list assertion, which was corrected;
  the final `npm test` passed with 1,127 Node passes, 110 declared skips
  (private inputs were not set), zero failures, and 19 Python unittest passes.
  Both run logs are retained under ignored
  `artifacts/16_19_development/item_group_821_integration/`.
- **NotifyContextualSituation packet string (opt-in candidate):** Exact
  `16.19.821.7343` route `0x0113` is distinct from the `0x040a` OnEvent
  child `0x0113`. The pinned image factory/constructor/deserializer are at
  RVAs `0xf01897`/`0xeb3b50`/`0x102d520`; the callback at `0x2c9820`
  passes the object's string pointer to `0x228610`. The exact-image native
  witness checks full packet consumption, heap pointer/length/capacity/NUL
  bounds and strict UTF-8 for each packet. CLI `--events
  notify_contextual_situation_packet` and API output remain `CANDIDATE`.
  On 11 original KR 821 Replays, 37,229/37,229 packet-local strings were
  emitted with exact image `MATCHED_USED`, zero framing errors and seven
  observed string values. Saved `query-events --event
  notify_contextual_situation_packet_candidates --contextual-situation
  RecallCancel --limit 1` validated all 37,229 rows, matched 522 and
  emitted one original row. Saved queries check ordered native string
  length, capacity and UTF-8 bytes against the native output digest, as
  well as the separate ordered raw-input digest, even after `--limit`.
  These names do not establish a Recall action,
  actor, team or gameplay effect. The six observed packet lengths and
  seven observed strings are fail-closed scope gates, not a substitute for
  native per-packet decoding. Image, Replays and outputs remain outside Git.
  Focused decoder and query tests passed 12/12 with the exact local inputs.
  After the output-digest change, `npm test` passed with 1,122 Node passes,
  108 declared skips (private inputs were not set for that run), zero failures,
  and 19 Python unittest passes. The focused exact-input suite passed 12/12.
- **Saved event discovery:** `query-events DIR --list-events` lists actual
  saved candidate keys and per-Replay exact build, capability status and
  declared count. It distinguishes saved zero rows, unavailable and
  unrequested capabilities; batch mode checks manifest hashes. Real V7
  CastSpellAns and multi-event V5 damage batches each listed 11 KR 821
  Replays. The listing does not scan JSONL rows and says so in its output.
- **Saved query stdout integrity:** `query-events` now stages selected stdout
  lines in a temporary file and releases them only after every source row and
  digest validates, including rows after `--limit` and later batch Replays.
  Before the fix, corrupting only line 124,080 of a copied original 821
  item-group JSONL produced `INVALID_EVENT_ROW` but had already sent the
  first 1,407-byte row to stdout. The same real negative control now exits 2
  with zero stdout bytes; the valid query still scans all 124,080 rows,
  matches 330 and emits one unchanged row. The copied negative artifact and
  both command outcomes remain under ignored
  `artifacts/16_19_development/item_group_stdout_probe_20260926/`.
- **CastSpellAns nested anonymous f32 at packet +0xa0 (opt-in V7):** The
  exact 821 deserializer at RVA `0x10bd7d4..0x10bd991` writes protected
  nested `+0x90` bytes; the callback at RVA `0x8d76da..0x8d7710` converts
  them directly to temporary `+0x9c`. The 256-byte transforms are pinned by
  SHA-256 and inverse controls. V7 keeps V5/V6 fields and V4 remains the
  default. The real CLI batch on all 11 original KR 821 Replays wrote
  63,496/63,496 candidate rows, 11/11 `CANDIDATE`, exact image
  `MATCHED_USED`, and zero framing errors to ignored
  `artifacts/16_19_development/cast_v7_11_replay_20260926/`.
  Saved `--cast-nested-f32-0xa0 1.1395 --limit 1` validated all 63,496
  rows, matched one, and emitted that original row. A separate query found
  63,452 values equal to `1.0`; the other 44 remain anonymous. Native
  truncate/append and exact-image controls passed. The adjacent nested
  `+0x8c` word passes through a runtime-tree helper at RVA `0x57cc00`;
  the captured module has no receiver heap, so it was not emitted.
  Focused decoder/native tests passed 21/21, saved-query tests 17/17, and
  CLI option tests 30/30 with the supplied exact inputs.
- **CastSpellAns packet-local callback lookup key at packet +0x28 (opt-in V8):**
  The exact 821 nested deserializer at RVA `0x10babce..0x10bae7b` writes the
  protected word at nested `+0x18`; callback RVA `0x8d75b3..0x8d75f5`
  decodes its four bytes, and RVA `0x8d86c2..0x8d875a` uses the resulting
  word as a conditional runtime-tree lookup key. The pinned image is SHA-256
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`.
  The byte transform and its inverse pass all 256 inputs, with SHA-256
  `8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5`
  and `442516bee22a1147d65334928ed5300c815deeab1ac6c92002960045590a4e71`.
  A native audit fully consumed 63,496/63,496 packets across the 11
  original KR 821 Replays; the real V8 CLI batch wrote 11/11 `CANDIDATE`,
  exact image `MATCHED_USED`, zero framing errors, and all 63,496 rows to
  ignored `artifacts/16_19_development/cast_v8_11_replay_20260926/`.
  The new field has 424 distinct values; every prior V7 row field and raw
  packet reference was preserved. Native truncate/append controls fail full
  consumption as expected, and 448 saved native object bytes match the
  route-specific witness. V4 remains default, V8 is opt-in, and the tree
  lookup result, object identity, actor, spell and effect remain `UNKNOWN`:
  the captured module does not contain the live receiver heap. The native
  packet witness includes the raw and decoded `+0x28` values per packet;
  there is no ordered native-output digest for these rows.
  Opt-in saved-query `--verify-source` binds every CastSpellAns packet ref
  to the independently hashed original ROFL by exact build, Replay SHA,
  packet order/count, stream, offsets, time, parameter and payload SHA-256.
  It validates all saved rows after `--limit` before emitting stdout. This
  physical provenance check does not rerun the native decoder or bind the
  saved V8 key to an ordered native-output digest. A real 11-Replay V8
  `--cast-nested-u32-0x28 190941627 --limit 1 --verify-source` query
  verified all 63,496 original packets, matched 4,136 rows, and emitted
  one original row. A synthetic physical-ROFL test forged a later packet's
  time and offsets; query exited `SOURCE_PROVENANCE_MISMATCH` with zero
  stdout. Source verification now also checks CastSpellAns profile metadata,
  the pinned packet ID, and every row's top-level time/parameter against its
  packet reference even when no nested-field filter is supplied. Later
  top-level time or parameter forgeries fail with `INVALID_EVENT_ROW` and
  zero stdout under `--from-ms --to-ms --limit 1`; a profile packet-ID forgery fails
  `CAPABILITY_METADATA_MISMATCH`. Historical V3 source verification and its
  nested-field unavailability remain distinct. The real no-nested-filter
  `--verify-source --from-ms 1000 --limit 1` query validated all 63,496
  packets across the 11 original Replays and emitted one original row.
  Focused saved-query tests passed 24/24 after this correction, including
  unfiltered physical-source checks for each V3 through V8 profile.
- **CastSpellAns ordered native-output witness (opt-in V9):** V9 keeps every
  V8 candidate field and remains separate from V4 default and all saved V3–V8
  artifacts. For each native batch of at most 8,192 exact-821 packets, Python
  SHA-256 hashes the ASCII domain `CAST_SPELL_ANS_821_V9_NATIVE_OUTPUT_V1` plus
  a zero byte, then each row's local u32 index, raw u32 parameter, u32 consumed
  payload length, 32-byte payload SHA-256, decoded flag byte and signed i32,
  protected float bytes at `+0xe0`, protected and decoded byte at `+0x140`,
  protected and decoded bits at `+0x24`, protected and decoded u32 at `+0x1c`
  and `+0x4c`, protected float bytes at `+0xa0`, and protected and decoded
  lookup-key u32 at `+0x28`. Integers are little endian. The protected float
  bytes are hashed while decoded float values are checked against the pinned
  transforms; this avoids JSON float formatting differences. Only fields
  retained in candidate JSONL enter the digest. JavaScript verifies each
  native batch digest before accepting the batch. It then hashes the ASCII
  domain `CAST_SPELL_ANS_821_V9_REPLAY_V1` plus a zero byte, the 32-byte
  Replay SHA-256, and each ordered batch's u32 start, u32 count, and 32-byte
  native digest into replay-level `native_output_sha256`.
  The original exact `16.19.821.7343` image SHA-256
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`
  decoded 63,496/63,496 CastSpellAns packets across 11/11 original KR
  Replays to ignored
  `artifacts/16_19_development/cast_v9_11_replay_20260926/` with zero
  framing errors. A saved V9 query with `--cast-nested-u32-0x28 190941627
  --limit 1 --verify-source` checked all 63,496 ordered digest rows and
  physical source packets, matched 4,136 rows, and emitted one unchanged row.
  A portable Python/JavaScript digest agreement test, later-batch failure,
  late forged-row, and V9 metadata downgrade controls passed in the focused
  suite: 78 passed, 0 failed, 6 private-fixture tests skipped. The source
  check proves physical Replay provenance separately; the output digest binds
  persisted candidate fields to the native run. Neither proves a runtime-tree
  lookup hit, receiver, actor, spell, target, successful cast, or effect.
- **Damage identity stop-loss:** In saved V5 output for the 11 KR Replays,
  anonymous `+0x18` `RAW_READER` occurred in 11/1,035 death-coincident
  victim-key packets and 823/62,860 first-lookup roster pairs. Conditional
  callback lookup/cast results and a packet-linked state change remain
  unobserved; this branch cannot identify a fatal packet, target or effect.
  Source artifacts are the ignored `combat_v5_associations_11_821` batch.
- **Cast/Timer identity stop-loss:** The pinned image registers the
  `SetSpellTimer` callback through `AIBaseClient`, but the captured module
  has no replay-session receiver heap or observed per-packet map hit. Among
  5,481 Timer V2 rows, 303 rows carry raw parameters outside the common
  `0x400000ae..b7` family. No independent participant or spell-slot binding
  was established; Cast and Timer identities remain `UNKNOWN`.
- **CastSpellAns nested anonymous u32 at packet +0x4c (opt-in packet V6):**
  The pinned `16.19.821.7343` image callback RVA `0x8d7860..0x8d78cb`
  reads nested `+0x3c` (packet object `+0x4c`), converts four protected
  bytes with the table at RVA `0x1b41db0`, and writes the word to temporary
  `+0xac`. The nested deserializer writes the inverse protected bytes at
  RVA `0x10bb405..0x10bb744` with table RVA `0x1badb60` (SHA-256
  `ae15d606869d66dc47309b26cb489e01bf841e9dd57d540683e2dc7f5e394588`);
  both transforms invert each other for all 256 byte values. The callback
  transform SHA-256 is
  `ad5ff48a6d097a43b6880bcafd30d0f8ef7f30f3988c049e1add1261f626eb4c`.
  CLI `--cast-packet-v6` or API `castPacketProfile: 'v6'` retains every V5 field and adds
  `raw_u32_0x4c_hex` and `opaque_u32_0x4c`. V4 remains the default; V5
  retains its historical profile identity. Three original KR Replays
  produced 5,980/5,980, 5,713/5,713 and 5,561/5,561 V6 candidates,
  17,254/17,254 combined, with exact image `MATCHED_USED` and zero decode
  failures. Four fixed game/keyframe packet anchors match protected bytes
  and decoded words; one-byte truncate and append controls fail full native
  consumption. The word is anonymous: no caster, spell, target, action or
  gameplay effect is inferred.
  The integrated selected CLI batch on all 11 exact-build KR Replays then
  returned `CANDIDATE` in 11/11, zero framing errors, and 63,496/63,496
  V6 rows. Saved batch `--cast-nested-u32-0x4c 1073742460 --limit 1`
  completed 11/11, checked every 63,496 row, matched one and emitted its
  original JSONL line. V3/V4/V5 saved artifacts report the second u32
  unavailable; V6 queries also validate the historical V5 field. Private
  Replay, image and output files remain outside Git.
  Focused direct/native tests with those private inputs passed 18/18 with
  zero skips; saved-query tests passed 14/14. The public `npm test` run
  exited 0 with 1,092 Node passes, 100 declared skips, and
  19 Python unittest passes.
- **CastSpellAns nested anonymous u32 at +0x1c (opt-in packet V5):** The
  pinned `16.19.821.7343` image callback RVA `0x8d77ed..0x8d785a` reads
  nested `+0x0c` (packet object `+0x1c`), converts its protected bytes with
  the exact table at RVA `0x1b41db0`, and writes the word to temporary
  `+0xa8`. The derived 256-byte transform SHA-256 is
  `5b858c9ef8d1393d05d867112316c3344ff777044719d839ad8cd64867d7f537`.
  V5 adds `raw_u32_0x1c_hex` and `opaque_u32_0x1c` behind CLI
  `--cast-packet-v5` or API `castPacketProfile: 'v5'`; V4 remains the
  default and saved V4 output retains its historical profile identity.
  Original KR Replays `KR_8392938200` and `KR_8393456728` produced
  5,980/5,980 and 5,713/5,713 V5 packet candidates respectively,
  11,693/11,693 combined, with exact image `MATCHED_USED`, full native
  payload consumption and zero decode errors. Three fixed original
  packet anchors cross-check game/keyframe protected bytes and converted
  values; one-byte truncate and append controls both fail full consumption.
  Focused tests with local inputs: 14 passed, 0 failed, 0 skipped. Saved
  V5 `cast_spell_ans_packet_candidates` rows can be filtered with
  `query-events --cast-nested-u32` (decimal or hexadecimal uint32); the
  query validates the full exact-build metadata, raw packet reference,
  protected four bytes and transform before filtering. V3/V4 artifacts
  report this field unavailable. The callback's temporary transfer does
  not prove caster, spell, target, cast success or gameplay effect.
  A subsequent selected CLI batch across all 11 exact-build KR Replays
  returned `CANDIDATE` in 11/11 with zero framing errors and
  63,496/63,496 V5 rows. A saved batch `--cast-nested-u32 1531465011
  --limit 1` query completed 11/11, checked every 63,496 row, matched
  511 (all in `KR_8392938200`), and emitted one original JSONL row.
  These private Replay and image inputs and local outputs remain outside Git.
- **UnitApplyDamage anonymous callback u32 at +0x1c (opt-in V6):** On the
  pinned `16.19.821.7343` mapped image (SHA-256
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`),
  the callback reads object `+0x1c` at RVA `0x2ce2f8`, decodes its four
  bytes with helper `0x251df0` (complete table SHA-256
  `5acd891ce46e85484de06fa22f6cece25e6bfcc4c258094863c98d225ea3dc18`),
  and forwards the word to `0x2827c0`. The exact deserializer selects
  its write branch using header bits 12..14. The opt-in V6 packet decoder
  checks every final four-byte write, callback transform, native raw-reader
  call and exact variable-length raw span. The exact `0xe81ec0` reader
  rederives the value from the protected two- or three-byte raw span;
  V5 remains the default CLI/API profile and historical saved-query identity.
  Original KR Replays `KR_8392938200` and
  `KR_8393872512` yielded 125,182/125,182 fully consumed packets and
  +0x1c full writes. The first had 61,535 constant-zero and 3,289
  raw-reader rows (472 two-byte, 2,817 three-byte spans); the second had
  60,358 constant-zero rows. Selectors 1/2/3/4/5/7 took their respective
  native raw reader branches in the first Replay; selector 0 wrote zero.
  Selector 6 has a static constant-`0xffffffff` branch in the image but
  occurred in none of the 11 supplied KR Replays and is rejected by V6.
  V6 is selected through CLI `--damage-packet-v6` or API
  `damagePacketProfile: 'v6'`. One original Replay produced 64,824 packet
  candidates and four V4 association candidate counts of 5,254, 6,888,
  19,142 and 71 through the CLI, with zero framing errors. Saved V6 packet
  queries validate the anonymous `+0x1c` u32 and its raw provenance;
  all four saved V4 association queries completed full scans of those
  original-Replay outputs. Historical V5/V3 identities remain available.
  The u32 has no proven actor, type,
  amount, source, target, or gameplay-effect meaning.
- **Objective-steal OnEvent packet markers (isolated development branch):**
  The exact 821 image names `0x040a` child `0x00be`
  `OnKillDragonSteal` and child `0x00d6` `OnKillWormSteal` at
  name-table entry RVAs `0x1ef90e0` and `0x1ef94a0`. The selected
  `objective_steal_event_packet` CLI/API route requires the pinned image,
  game-stream 133-byte parent, native full consumption, exact child and
  encoded IDs, and the observed 124-byte native child blob. It preserves
  the opaque blob/hash and original packet reference. Real selected CLI
  runs on `KR_8393872512` and `KR_8394041123` each emitted one
  `CANDIDATE` row with zero framing errors (children `0x00d6` and
  `0x00be`, respectively). `KR_8392938200` had no 133-byte parent and
  returned `PROFILE_UNAVAILABLE` with zero framing errors; its CLI exit
  code was 1 for that unavailable status. Focused synthetic route/API/CLI
  tests passed 4/4. With the pinned image and two original Replays, three
  native tests passed for both positive packets, a same-length foreign
  child, truncated input, and a wrong image. Without private inputs,
  these three native tests explicitly skip. The earlier exact-image census
  found only these two 133-byte parents among 11 supplied KR Replays; the new CLI route was
  run on the two positive Replays and one absent control, not all 11.
  The image labels and packet presence do not prove an actual steal,
  objective state change, actor, target, or gameplay effect. Local outputs
  remain ignored under `artifacts/16_19_development/objective_steal_real_821/`.
  A bounded child-field check found that both IDs register the same callback
  RVA `0x2ce720`, but its typed argument cannot be equated with the native
  124-byte child buffer: treating that buffer as the argument would make its
  `+0x08` word a noncanonical pointer on both original packets. The two
  positive parents still fully consume 133 bytes, and the exact-image native
  tests pass 3/3 (0 skipped), including foreign-child, truncation and wrong
  image controls. No additional child field was promoted; the blob remains
  opaque pending an exact-build child conversion or callback-argument trace.
  A further bounded trace found only the first dispatch hop: receive RVA
  `0x4ce432` places the blob pointer in a wrapper, then `0x4ccf10` passes
  it through listener dispatch RVA `0x4ccc80`. The listener calls are
  indirect, and no observed path converts this blob into callback
  `0x2ce720`'s typed argument. Its helper checks type tags `0x35/0x3b/0x3d`,
  whereas both native blobs start with `0x1d5`. This is additional negative
  evidence, not a child-field decode.
- **UnitApplyDamage anonymous callback f32 v5:** The pinned 821 native
  deserializer writes callback object `+0x18` from a protected raw f32 reader
  for header selector 0/2/3/6, or constant zero for selector 5. The output
  retains the native final-write witness, protected bytes, decoded finite
  value, raw offset/bytes where applicable, source branch, and table hash.
  A fresh packet-only batch on all 11 supplied KR Replays was `CANDIDATE`
  in 11/11 with zero framing errors: 628,909/628,909 full writes, 828
  `RAW_READER`, and 628,081 `CONSTANT_0`. A saved v5 `query-events
  --damage-callback-f32-0x18-raw --limit 1` completed 11/11, checked all
  628,909 rows, matched 828, and emitted one. Four dependent association
  profiles were versioned to V3 for v5, with historical V1/V2 kept for
  older packet outputs. A fresh selected-only association batch was
  `CANDIDATE` in 11/11 for each route: 49,473 raw roster, 62,860 first
  lookup roster, 173,125 second lookup roster, and 655 death anchors.
  These are exact packet/key observations; the float does not establish
  actual damage, a source, target, or health effect. The first local v5
  saved batch omitted a required table-hash metadata field and was rejected;
  the corrected batch above is a separate run. Both local artifacts remain
  ignored, preserving that failed validation.
- **Damage association source scan reuse:** In a selected exact-821 API/CLI
  run, the four damage/roster/death associations now use the same private,
  Replay-bound strict route scan to verify their complete `0x005f` and
  `0x0089` source rows. Standalone association calls still walk the Replay;
  foreign or changed scan tokens fail. On one supplied KR Replay, all four
  association results and JSONL outputs matched the preceding batch exactly
  (5,254 / 6,888 / 19,142 / 71 rows). Direct three-association work took
  2,280 ms with repeated walks versus 1,882 ms with the shared token; the
  API already collects the token, whose standalone creation took 154 ms in
  that measurement. This changes validation work, not candidate semantics.
- **OnFirstBloodAssist packet marker:** The exact 821 image names OnEvent
  child `0x0017` at name-table entry RVA `0x1ef76c8`. The new selected
  `first_blood_assist_event_packet` CLI/API route requires the pinned image,
  fully consumes each game-stream `0x040a` length-16 parent, and retains the
  anonymous eight-byte child blob, its digest, and the original packet ref.
  A real 11-Replay selected-only batch had zero framing errors: eight
  `CANDIDATE` Replays with nine target packets, three
  `PROFILE_UNAVAILABLE` Replays, and three same-length native child
  `0x002c` exclusions. CLI batch status was `PARTIAL` because those three
  Replays have no target child. The image label and packet-local bytes do not
  prove an effective first blood, an assist, a participant role, or a game
  effect. Raw inputs and local batch output remain outside Git.
- **UnitApplyDamage anonymous callback u32 v4:** The exact-821 native
  deserializer writes an anonymous u32 to callback object offset `+0x10`.
  The first header selector determines whether its four payload bytes pass
  through the pinned native reader or whether the callback writes constant
  zero. The decoder preserves the encoded bytes, decoded u32, write source,
  exact runtime/table hashes, and a full-consumption witness per packet.
  A fresh packet-only CLI batch on all 11 supplied KR Replays returned
  `CANDIDATE` in 11/11 with zero framing errors. All 628,909 selected packets
  had the `+0x10` native write: 464,779 `RAW_READER`, 164,130 `CONSTANT_0`.
  A separate selected-only batch of the four dependent raw/lookup/death
  associations was `CANDIDATE` in 11/11 for each, with 49,473, 62,860,
  173,125, and 655 rows respectively. Their v2 profiles bind the v4 packet
  input; these counts describe packet/key proximity rather than combat effects.
  A saved `query-events --damage-callback-u32-0x10 0 --limit 1` run on the
  11-Replay v4 packet batch completed 11/11, checked all 628,909 rows,
  matched 164,130 constant-zero packets, and emitted one row. The filter is
  limited to v4 artifacts and validates all saved rows despite an output
  limit. Historical
  v1/v2/v3 packet profiles remain readable under their original contracts;
  dependent roster/death associations use new profiles for v4 inputs and
  retain their historical profile identities for older saved results. The
  integer has no established damage type, amount, actor, target, or effect.
- **Death/damage native lookup-key co-occurrence candidate:** The independent
  `hero_death_damage_lookup_key_cooccurrence` capability links each exact-821
  `hero_death` candidate anchor to every `0x005f` native-witnessed packet in
  the same chunk and millisecond whose `+0x24` full key equals the candidate
  victim's canonical ten-person HeroStats roster key. It reports each packet's
  separate `+0x2c` numeric equality with the death route's decoded die-source
  ID, including nonroster keys and equality failures. The decoder freshly
  verifies the death route, the complete damage/roster source set, the pinned
  runtime image, original packet references, and Replay-tail counts. It emits
  one row per death anchor, preserving zero or multiple candidate packets,
  their order relative to the primary death route, and all original source
  references. A fresh selected-only CLI batch on all 11 supplied KR Replays
  returned `CANDIDATE` in 11/11 with zero framing errors: 655 death-anchor
  rows, 628,909 native-witnessed damage packets, and 1,035 same-time victim
  `+0x24` packets. There were 227 anchors with multiple such packets; 987 of
  the 1,035 packets also had `+0x2c` equal to the die-source ID. At least one
  such packet occurred at 633 anchors, while 22 had none. Of the 1,035
  victim-key packets, 933 preceded the primary `0x0259` packet and 102
  followed it within the same Replay millisecond. A saved `query-events`
  run completed 11/11, checking all 655 rows despite `--limit 1`; a victim
  filter selected 70 rows for participant 1 and a nested original damage
  `raw_param` filter selected 34 rows for `0x400001ae`. Saved queries validate
  artifacts, not original ROFL bytes. Neither a matching pair nor temporal
  proximity selects a fatal packet or establishes an actor, source, target,
  object-lookup success, or health effect. The preceding saved-data controls
  and their 22 hero-source exceptions are recorded below as independent
  research context; they did not physically reopen original ROFL bytes.
- **UnitApplyDamage second native lookup-key roster pair:** The independent
  `unit_apply_damage_lookup2c_roster_key_pair` capability now uses the exact
  821 native `+0x2c` full key and the complete ten-key HeroStats roster. It
  retains both native lookup keys, their protected bytes, the original
  `raw_param` relation, and both source references. The decoder physically
  rechecks the raw-key pair against the Replay and validates the prior
  `+0x24` pair before output. A fresh selected-only CLI batch on all 11
  supplied KR Replays returned `CANDIDATE` in 11/11, zero framing errors,
  and the one pinned runtime-image SHA
  `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`.
  Of 628,909 native-witnessed damage packets, 173,125 matched `+0x2c` to
  the canonical roster and 455,784 did not; 632,179 damage and HeroStats
  source references were physically checked. Among matches, `+0x24` was the
  same roster key in 15, a different roster key in 34,697, and outside the
  roster in 138,413. The new saved `query-events --raw-param 0x400000ae
  --limit 1` then checked all 173,125 association rows across all 11 Replay
  artifacts, matched 2,387 original damage raw parameters, and emitted one
  unchanged row. Saved queries validate their stored metadata, rows, hashes
  and references; they do not reopen original ROFL bytes. Lookup success,
  actor, source, target, killer, fatal packet, actual amount and health effect
  remain `UNKNOWN`. Local batch inputs/results remain ignored under
  `artifacts/16_19_development/combat_lookup2c_roster_pair_11_821/`.
- **Saved v3 native lookup-key query:** `query-events` now filters the
  separate exact `+0x24` and `+0x2c` u32 keys, individually or conjunctively,
  without assigning either a combat role. It requires the exact-821 v3
  artifact and checks every saved packet's native witness metadata, raw bytes,
  key transforms, source reference and ordered input digest, even after the
  output limit. On the 11-Replay v3 batch, each of four saved queries checked
  all 628,909 rows: key `0x400000ae` selected 9,481 at `+0x24`, 16,253 at
  `+0x2c`, and zero where both fields equaled that key. A two-key query
  (`+0x24 = 0x400000ae`, `+0x2c = 0x400000b3`) selected 2,147. These counts describe
  independent fields, not a source or target assignment.
- **Second native lookup key research controls:** The 11 exact-build saved
  damage artifacts have complete ten-key HeroStats rosters and full native
  consumption. `+0x2c` matched a canonical roster key in 173,125/628,909
  packets; `+0x24` matched in 62,860. Both matched in 34,712, only `+0x2c`
  in 138,413, only `+0x24` in 28,148, and neither in 427,636. Of the
  both-matched packets, only 15 had the same key in both fields. A preceding
  ten-key control matched `+0x2c` in 1,957 packets; the corresponding
  `+0x100` alias matched zero. There were 9,802 replay times with multiple
  distinct roster-matched `+0x2c` keys, so a timestamp is not a unique
  pairing. This is a research observation, not a default roster association
  or an actor, source, target, killer, or damage inference. The saved audit
  checked artifact SHA identities and roster completeness; a future decoder
  must still physically verify original packet references.
- **Death-time lookup-key control:** All 655 candidate death times in the 11
  Replays had at least one same-time damage packet whose `+0x24` key equaled
  the candidate victim roster key; 227 times had multiple such packets. Of
  653 deaths with a candidate killer, 631 had a same-packet `+0x2c` key equal
  to that killer's roster key. At the 22 exceptions, the same-time victim-key
  packets all had nonroster `+0x2c` keys; 12 of those anchors had a hero-key
  pair only at an earlier nonidentical time within one second. Two deaths
  without a killer participant had a same-time `+0x2c` key equal to the
  decoded nonhero die-source key. Participant-ID +1 controls produced only
  24/655 victim-key matches and 2/653 joint key matches. This establishes a
  bounded co-occurrence candidate for later source-referenced work, not a
  unique fatal packet or confirmed combat role/effect.
- **UnitApplyDamage native lookup keys v3:** Exact-image native audit
  explicitly observed writes to object `+0x24` and `+0x2c` in all
  628,909/628,909 `0x005f` packets. The callback decodes these as two
  separate object lookup keys; the first lookup result receives a virtual
  `+0x720` call with the anonymous `+0x20` float. Production now retains
  both decoded u32 keys, their protected object bytes and the relation
  between `raw_param` and the first key, with full native witness and pinned
  lookup transforms. All 10,284 hero-key `+0x100` aliases decode their
  first key to the canonical HeroStats key. At 655 candidate death anchors,
  a same-time packet had first key equal to the candidate victim in 655
  cases (rotated-key control 24); among 653 anchors with a candidate killer,
  631 same packets also had second key equal to that killer (rotated control
  2). These are bounded role clues; lookup and type-cast success, actual
  health change and effective damage remain `UNKNOWN`. Eleven observed
  `+0x20` floats were `2e9`, so that field is not an effective-damage amount.
  The new 11-Replay CLI batch returned `CANDIDATE` in 11/11 with
  628,909/628,909 full native lookup-write witnesses. First-key relation to
  `raw_param` was `EQUAL` in 568,329 rows, `raw_param = key + 0x100` in
  49,239, and `OTHER` in 11,341. Saved v1, v2 and v3 damage queries each
  checked 628,909 rows and selected the original 6,501 narrow-shape rows.
- **UnitApplyDamage native callback float v2:** The same exact 821 image
  writes object `+0x20` for every one of the 628,909 observed `0x005f`
  packets. Native and raw-byte checks distinguish 622,951 raw-reader writes
  from 5,958 constant writes (`0`, `1`, or `2`). The new
  `native_callback_f32_*` row fields retain the finite anonymous value,
  source class and, for raw reads, the packet-local byte offset and bytes.
  Old `callback_f32_*` fields and the saved v1 query contract remain limited
  to the original 6,501 calibrated rows. Neither field proves applied damage
  or actor roles; `+0x100` raw-key aliases remain unassigned. Saved v2
  queries check each new field and source counts before selection.
  A fresh 11-Replay CLI batch returned `CANDIDATE` in 11/11 with
  628,909/628,909 native full-consumption witnesses; the saved v2 query
  scanned all rows and selected the original 6,501 narrow-shape values.
  Its local JSONL stays ignored under
  `artifacts/16_19_development/combat_packet_batch_v2_11_821/`.
- **UnitApplyDamage raw-key identity control:** Full `raw_param` matched one
  of the ten unique HeroStats hero keys in 49,473/628,909 `0x005f` packets;
  another 10,284 used the corresponding `+0x100` alias. At 655 candidate
  death anchors, 442 same-time packets matched the full victim key; a
  rotated-key control matched 11. Low-byte matching would add 24,473 other
  packets, so no loose key merge is used. The direct key relation is a
  bounded participant-label candidate only; the `+0x100` alias and any
  source/target or applied-damage role remain unresolved.
- **UnitApplyDamage full-key roster pair:** Selecting
  `unit_apply_damage_roster_key_pair` now runs the native-gated `0x005f`
  decoder and complete ten-key HeroStats keyframe decoder once, then emits
  only exact full-key pairs with both source references. The new 11-Replay
  CLI batch returned `CANDIDATE` in 11/11: 49,473 of 628,909 damage packets
  matched a canonical roster key, 10,284 `+0x100` hero-key aliases were
  separately excluded, and 579,436 packets remained unmatched. All 632,179
  source packet references (damage and roster) and ordered native input
  digests were physically checked. The roster label is a co-key candidate
  and does not establish a damage actor, source, target or health effect.
- **UnitApplyDamage native lookup-key roster pair:** Selecting
  `unit_apply_damage_lookup_roster_key_pair` independently checks the native
  callback's decoded object `+0x24` full key against the complete ten-key
  `0x0089` HeroStats roster. It requires the native-witnessed v3 damage
  outcome, the complete roster and the validated raw-key pair, and preserves
  both original packet references plus each `raw_param`/lookup-key relation.
  A fresh 11-Replay CLI batch returned `CANDIDATE` in 11/11 with zero framing
  errors: 62,860/628,909 damage packets matched a roster key, including
  49,473 `EQUAL`, 10,284 `raw_param = key + 0x100`, and 3,103 `OTHER`
  relations (`+0x200..+0xA00` observed); 566,049 packets were unmatched.
  The prerequisite pair physically checked 632,179 damage and roster source
  references. The original raw-parameter pair remains separate at 49,473;
  no blanket alias normalization is applied. The roster participant label
  records lookup-key co-occurrence only. Object lookup/type conversion,
  actor, source, target, actual amount and health effect remain `UNKNOWN`.
  Saved `query-events --raw-param 0x400001ae --limit 1` then checked all
  62,860 rows in the new batch and selected 2,075 by the damage packet's
  original parameter; it does not substitute the decoded lookup or roster key.
- **ShowHealthBar packet candidate:** The image registers `0x0165` as
  `PKT_S2C_ShowHealthBar_s`. All 89,515 observed packets in 11 exact-build
  KR Replays were fully consumed by the native deserializer: 61,813 had
  one-byte payload `4a` and 27,702 had `4b`. The separate CLI/API capability
  emits raw source references, a callback byte and a zero-flag candidate,
  with `UNKNOWN` effect. Native code also accepts foreign one-byte values,
  so the decoder limits output to the two observed bytes. These fields do
  not establish health, damage, actor identity or actual display state. The
  same 11-Replay CLI batch returned `CANDIDATE` in 11/11, zero framing
  errors and 89,515/89,515 native full-consumption witnesses. Saved
  `query-events --show-health-zero-flag 1` checked all 89,515 rows and
  selected 27,702 while preserving original JSONL.
- **Exact-821 UnitApplyDamage packet candidate:** The pinned mapped image
  registers game-stream route `0x005f` as `PKT_UnitApplyDamage_s`. Native
  deserialization fully consumed all 628,909 observed packets in the 11
  supplied KR Replays, covering 728 observed selector/length tuples with no
  failed packet. A same-length, same-selector bit-flip control was only
  partially consumed by native code; packet shape alone is insufficient.
  The production decoder therefore requires the exact image, Python and
  Unicorn, runs a bounded native full-consumption witness over every selected
  packet before emitting any events, and retains each original packet and
  source reference. One 15-byte shape yielded 6,501 anonymous callback
  `+0x20` f32 values, each matching the pinned native transform; the other
  622,408 rows carry `null` with `UNAVAILABLE_SHAPE`, never a numeric zero.
  The new real CLI batch returned `CANDIDATE` in 11/11 Replays with zero
  framing errors and `native_full_success_count = event_count` for each.
  Saved `query-events --damage-callback-f32-available` verified all 628,909
  rows, their ordered raw-input SHA and persisted native-witness metadata,
  then selected the 6,501 native-matched rows; output remains byte-for-byte
  original JSONL. Saved queries do not rerun native deserialization or reopen
  original ROFL files. This route name and float do not establish
  applied damage, health loss, attacker, victim, object lookup, or effect.
  Local original inputs and batch evidence remain ignored under
  `artifacts/16_19_development/unit_apply_damage_packet_native_batch_11_821/`.
- **Exact-821 level packet / EXP keyframe time brackets:** Selecting both
  `hero_level_state,hero_experience_snapshot` emits
  `level_experience_keyframe_bracket_candidates` when a higher-level packet
  falls strictly between two complete adjacent EXP keyframes for the same
  candidate participant. All 11 supplied KR Replays produced 1,564 rows in
  1,495 distinct participant intervals, with three original packet references
  per row. The source has 1,613 level packets; 2 level-one and 22 repeated
  observations are excluded, as are 25 higher-level packets after the last
  keyframe. One level sequence gap remains explicit. All 1,564 row endpoint
  differences are positive, but a rotated-participant negative control also
  finds positive intervals at similar rates. The relation therefore reports
  sampled time and candidate participant alignment only; it does not locate
  an EXP gain, assign an interval delta to a level packet, or establish an
  upgrade threshold. The fresh CLI batch is ignored under
  `artifacts/16_19_development/level_experience_keyframe_bracket_batch_11_821/`.
  Saved `query-events --level-after` validated all 1,564 bracket rows and
  their LevelUp/EXP source JSONL rows across the same 11 Replays: level 2
  and 3 each matched 110 rows; level 1 matched zero after complete checks.
- **Exact-821 circular movement restriction packet candidate:** The pinned
  image registers route `0x0464` as
  `PKT_S2C_SyncCircularMovementRestriction_s`. All 11 KR Replays yielded
  68,242 packet candidates: 68,113 one-byte zero-record packets and 129
  24-byte one-record packets. A separate exact-image native probe fully
  consumed all 129 record-bearing packets; the production decoder checks
  the image and byte-transform hashes and accepts only the observed shapes.
  It preserves raw packet refs and anonymous scalar/vector values. Neither
  route name nor these values prove an actor, world position, hero path,
  receiver, or effective movement restriction.
  Follow-up negative control: 110/129 record-bearing packets are time-zero
  keyframes with five canonical raw keys sharing each of two vectors per
  Replay. Of the 19 later packets, 18 have no DirectInput `0x00ba` row with
  the same full raw parameter; the sole match is over 510 seconds apart.
  The `0x00ba` callback also gates its write on an unobserved live receiver
  mode. No actor or path relation is promoted from these packet fields.
  A future actor/path claim needs a same-build receiver dispatch trace,
  independent receiver-to-roster identity and coordinate observation, plus
  rotated-key controls; named path-adjacent registrations alone supply no
  such evidence in these Replays.
  Saved `query-events --packet-record-count 1` verifies the pinned table,
  every raw payload/reference and the derived anonymous fields before
  selecting rows. The 11-Replay batch checked 68,242 rows: 129 had one
  record and 68,113 had zero, with no unavailable Replays.
- **Saved CastSpellAns nested-byte query:** `query-events --cast-nested-bits`
  checks the exact-821 profile, callback transform and original packet refs
  before filtering saved `cast_spell_ans_packet_candidates` rows. The
  11-Replay batch checked 63,496 rows, with six matches for value 8, five
  for 100, and zero for 2; older v3 rows report the field unavailable.
- **Shield-damage route stop-loss:** The pinned 821 image registers
  `PKT_UnitApplyShieldDamage_s` at `0x043e`, but a fresh strict scan of all
  streams in the 11 supplied KR Replays found zero such packets and zero
  framing errors. There is no Replay payload or native-consumption sample
  for this route. Existing ShieldingParams `0x040a` pairs are distinct and
  do not establish absorbed damage, so no `0x043e` event is selected.
- **Completed exact-821 experience endpoint intervals:** Selecting
  `hero_experience_snapshot` also emits
  `experience_keyframe_interval_difference_candidates` for positive
  differences between two adjacent complete keyframe samples for the same
  candidate participant. The fresh 11-KR-Replay CLI batch returned 11/11
  `CANDIDATE` with no framing errors: 327 keyframes and 3,270 physically
  verified source packets form 3,160 participant intervals, with 2,931
  positive endpoint differences and 229 equal endpoints. Rows preserve both
  original packet references, sampled times, f32 values, floors and deltas.
  Equal endpoints produce no row but remain in the association counts. This
  does not locate a gain inside the interval, identify its source, count XP
  events, infer a level threshold, or fill the final Replay-tail gap. Saved
  `query-events` checks the source JSONL and association before time,
  participant and latest-per-participant filters. The 11-Replay query emitted
  all 2,931 original rows byte-for-byte (SHA-256
  `447eb591e4da62096ca48f84003bbb3a479788aada3c14160c4ed04fdc2a2754`);
  participant 1 with latest-per-participant selected 11 rows after scanning
  the same 2,931 rows. The local batch is ignored under
  `artifacts/16_19_development/experience_keyframe_interval_batch_11_821/`.
- **Completed exact-821 CastSpellAns opaque nested byte:** The pinned runtime
  native packet object at `+0x24` (nested object `+0x14`) is now retained as
  protected raw byte `raw_nested_bits_0x24_hex` and callback-transformed
  `opaque_nested_bits_0x24` in the existing `cast_spell_ans_packet` output.
  The fresh 11-Replay CLI batch fully decoded 63,496/63,496 route packets
  with no framing or native failures; observed transformed byte values were
  `0` (49,152), `1` (106), `3` (52), `4` (13,704), `8` (6), `12` (471), and
  `100` (5). The image callback copies some bits to temporary flags, but
  these values do not establish a cast, actor, slot, spell, target or effect.
  Local output is ignored under
  `artifacts/16_19_development/cast_spell_ans_bits_batch_11_821/`.
- **Ward route stop-loss:** Rechecking the exact 821 image and 11 Replays
  found neither registered `OnPlaceWard` nor `OnKillWard` child in 86,604
  fully decoded OnEvent packets. Aggregate ward counter increases lack a
  packet-local object/time/owner/position; other probed routes failed their
  positive/zero controls or full native consumption. No new ward event is
  selected. Negative evidence remains under
  `artifacts/16_19_development/ward_anchor_followup_821/` and
  `artifacts/16_19_development/ward821_next/`.
- **Completed exact-821 OnObjectiveBountyClaimed packet candidate and query:**
  Selected `objective_bounty_claimed_packet` uses the pinned local mapped
  821 image to fully deserialize game-stream `0x040a` child `0x0113`, retaining
  its image name, anonymous eight-byte child blob, `blob_u32_0x04`, original
  packet reference, and same-length foreign-child exclusions. The supplied
  11 KR Replays produced 11 target rows in seven Replays and 5,610 excluded
  child references; four target-free Replays report `PROFILE_UNAVAILABLE`.
  Saved `query-events` reads all 11 original rows and lists those four
  sources as unavailable (`PARTIAL`), with time, raw-param, child-ID and
  anonymous-u32 filters. The exact image and observed packet do not prove
  a bounty payment, actor, team, object, or state change.
- **Completed conditional plate/die/claim packet association:** Selecting
  `objective_bounty_claimed_packet,turret_plate_event_packet,turret_die_event_packet`
  also emits `objective_bounty_turret_pair_candidates` when all three
  exact-image routes are available. Same Replay/chunk/millisecond, strict
  `plate < die < claim` order and equality of three anonymous native u32
  words are required; full original packet references are physically checked.
  The 11-Replay CLI batch yielded 10 triples and one unmatched claim
  (`NO_SAME_KEY_PLATE_OR_DIE`), preserving that claim in its packet stream.
  Four claim-free Replays retain `MISSING_INPUT` for the association and make
  the batch `PARTIAL`. Saved-artifact query checked 10 triple rows against all
  three source JSONLs and, for batch roots, their manifest hashes. Seven
  Replays were queryable and four unavailable; searching the unmatched claim
  word returned zero triples. A changed triple word that disagrees with its
  source packet is rejected before output. The public suite after this fix
  passed 956 Node tests and 16 Python tests, with one existing portability
  skip and zero failures. This is a packet relation, not a gameplay effect.
  Ignored evidence is under
  `artifacts/16_19_development/objective_bounty_scout_20260925/`,
  `artifacts/16_19_development/objective_bounty_claimed_cli_batch_11_821/`,
  and `artifacts/16_19_development/objective_bounty_turret_pair_cli_batch_11_821/`.
- **Next sibling route stop-loss:** The exact-image `OnObjectiveBountySoon`
  child `0x0114` and `OnObjectiveBountyEnded` child `0x0115` were rechecked
  with native full consumption on 12 and six original packets. Their 18
  child blobs and outer parameters are identical, with no same-ms or
  adjacent-ms claim/plate/die match and no stable ordering around claim.
  No separate selectable lifecycle capability is added from these names
  alone; roles and effects remain `UNKNOWN`. Ignored negative evidence is
  under `artifacts/16_19_development/objective_bounty_phase_scout_20260925/`.
- **Completed saved decode-root query:** `query-events` now accepts a valid
  single- or multi-Replay `decode` output root as well as `batch`, retaining
  manifest, Replay identity, directory and requested-event hash checks.
  The saved exact-821 OnHQKill decode roots queried 1/1 and 11/11 Replays
  with the same original JSONL SHA-256 as the corresponding true batch
  outputs. Unknown commands and malformed roots remain rejected.
- **Completed 821 OnHQKill packet candidate:** The exact-image `0x040a`
  child `0x0046` now has a selected `hq_kill_event_packet` API/CLI output.
  The 11 supplied KR Replays produced one candidate row each and retained
  820 same-length foreign-child packet references, with zero framing errors.
  An independent scout matched all 11 original packet references and native
  blob hashes. `OnHQKill` is the image name; actual HQ destruction, winner,
  actor and state change remain `UNKNOWN`. A true saved `batch` query checked
  and emitted all 11 original lines (SHA-256
  `022c71699616e1113c68171a823e73bce3c80c3b49430b35387cb1a42c50c430`);
  query validation uses saved artifacts and does not reparse the ROFL bytes.
  Evidence is ignored under
  `artifacts/16_19_development/on_hq_kill_scout_20260925/` and
  `artifacts/16_19_development/hq_kill_query_batch_11_821/`.
- **Completed opcode label cache check:** A bounded cache for repeated u16
  packet labels preserved three inventory JSONLs and the packet inventory
  byte-for-byte. An isolated before/after test on one exact-821 Replay
  measured 795.58 ms versus 749.52 ms mean wall time (eight runs each);
  this is a single-host observation, not a general speed claim. The ignored
  measurements are in `artifacts/16_19_development/opcode_cache_benchmark_821/`.
- **Completed 821 game Broadcast comparison query:** Saved
  `inventory_game_broadcast_keyframe_bracket_candidates` now accepts one of
  five exact endpoint-comparison labels, with optional slot and game item
  key required on the same explicit record. The 11-Replay batch was
  `COMPLETE`: 55 rows checked, 25 unmodified rows contained one of the 31
  `DIFFERS_FROM_EQUAL_ENDPOINTS` records (SHA-256
  `97bb23d56a2d8b603571e22b33c9f2febc97d91c517df1328445ad1a043cc198`).
  The label describes three packet observations, not an action or a
  continuous inventory state.
- **Completed 821 game Broadcast/keyframe bracket candidate:** Selecting
  `hero_inventory_broadcast_packet` now also emits
  `inventory_game_broadcast_keyframe_bracket_candidates` through the API/CLI.
  A fresh exact-image 11-Replay batch returned 11/11 `CANDIDATE` with zero
  framing errors: 55/61 game-stream Broadcast packets lay strictly between
  adjacent complete keyframes for the same canonical raw parameter, yielding
  421 explicit slot comparisons across 42 participant intervals. Four
  noncanonical and two after-last packets retain exclusion references; all
  3,331 source Broadcast references were verified by the prerequisite.
  The five comparison labels counted 355 same as both endpoints, 31 different
  despite equal endpoints, 3 previous only, 27 next only, and 5 neither.
  The saved-artifact query validated and emitted all 55 original rows (SHA-256
  `96e7c50fa77aa8bc90411fe61047e104037c55b839d9337b181382d825abe046`).
  These are three packet observations, not continuous inventory or actions.
  Local output is ignored under
  `artifacts/16_19_development/inventory_game_broadcast_bracket_batch_11_821/`.
- **Completed 821 inventory endpoint reversal query:**
  `query-events --event inventory_keyframe_interval_difference_candidates
  --endpoint-reversed-pair` checks both saved complete 10-slot Broadcast
  keyframe endpoints and their raw packet references, then selects rows with
  exactly two changed slots and two distinct nonzero item keys reversed and
  unique in both endpoints. The real 11-Replay batch was `COMPLETE` for all
  Replays, inspected 1,759 interval rows, and emitted 15 unmodified rows
  (SHA-256 `beaeac6bef5ae26cf6e13ef80b2c6460fc595832bc63e3508b9298d815dc3b30`).
  Joining by Replay, full raw parameter and adjacent keyframe indexes found
  no overlap between these 15 rows and the 55 game-stream Broadcast bracket
  rows; the same join matched 24 bracket rows to ordinary differing-endpoint
  intervals. This is an endpoint pattern, not an observed swap action or
  change time.
- **Completed previous-endpoint inventory query:** The exact-821
  `inventory_keyframe_interval_difference_candidates` query accepts
  `--previous-item-id` and matches it with optional current `--item-id` and
  `--slot` on one changed slot. Both endpoint keys may be zero. In the saved
  11-Replay batch, slot 7 `2001 -> 2002` matched 62 original rows (SHA-256
  `20f7c1f78fae662fba31e5a35710c4afbd60b8dc5661021d4250e90a1cbb6036`),
  slot 6 `0 -> 3340` matched 97
  (`caf74ff8a81e6c69ca9421c2ec4838bd16e7c2fc5fef21206507d97e8509921f`),
  and `0 -> 0` matched none; a loose cross-slot conjunction would have falsely
  matched 119 rows. These are sampled endpoint differences, not transactions.
- **Completed candidate bracket query:** Saved
  `increment_minion_keyframe_bracket_candidates` supports candidate
  participant, raw-parameter and time filters after exact-build/image,
  dependency, full keyframe roster, source JSONL and row checks. All 11 saved
  Replays were `COMPLETE`, scanning 278 strict bracket rows. Participant 4 / raw
  parameter `0x400000b1` matched 119 original JSONL lines; the output SHA-256
  matched an independent source-line filter:
  `da52d239f95c7d304b329c9bb6f25481eca9733b063219bfd72676726fcbeb2e`.
  The one boundary packet remains in unbracketed metadata.
- **Completed candidate packet/keyframe bracket output:** Selecting both
  exact-821 `increment_minion_kills_packet` and
  `hero_minions_killed_snapshot` now emits
  `increment_minion_keyframe_bracket_candidates`. A fresh 11-Replay CLI batch
  returned 11/11 `CANDIDATE`, zero framing errors, 279 route packets, 3,270
  standard minions keyframe snapshots over 327 complete frames, 278 strict
  same-key packet brackets in 148 distinct participant intervals, and one
  `ON_KEYFRAME_BOUNDARY` packet at 360,065 ms in `KR_8393456728` retained
  separately. All 3,549 source packet references were physically checked.
  The 278 strict rows have positive sampled endpoint differences, but the
  difference is not assigned to any individual packet; the conditional live
  object lookup/write and effective CS remain `UNKNOWN`. Ignored output is
  under `artifacts/16_19_development/increment_minion_keyframe_bracket_batch_11_821/`.
- **Completed candidate query:** Saved exact-821
  `inventory_keyframe_interval_difference_candidates` can be filtered by
  candidate participant, current endpoint time, raw parameter, differing
  slot, and the current item key on that same slot (including zero).
  `--latest-per-participant` selects the last matching sampled difference,
  never a sustained inventory state. The query validates exact build/image,
  source association, row references and counts; missing-image batch entries
  remain unavailable. In the saved 11-Replay batch, all 1,759 rows scanned:
  participant 1 / slot 7 / current item 2001 matched 6 (output SHA-256
  `80be3c89d3903e6316e50056c9d3d82a83c4af981d7081ad75b781e26afb3074`),
  participant 1 / slot 0 / current item 0 matched 2
  (`89e12e0779f6417081386ce46c70ee183601b8b6d63790913418c449b50ccf6c`),
  and `--latest-per-participant --to-ms 600000` matched 543 and selected 110
  (`434ed1bcaa67d85af4720f11c6c4f441818b0f6526c1a5a84c55a32b518d4e56`).
- **Completed candidate interval output:** Selecting exact-821
  `hero_inventory_broadcast_packet` now also emits
  `inventory_keyframe_interval_difference_candidates` for slots whose values
  differ at two adjacent complete keyframe endpoints for the same candidate
  participant. A fresh selected 11-Replay CLI batch returned 11/11
  `CANDIDATE`, zero framing errors, 327 complete keyframes, 3,160 participant
  intervals: 1,759 with differing endpoints, 1,401 with identical endpoints,
  and 3,949 differing slot positions. All 3,331 source Broadcast references
  were physically checked against Replay packet bytes; 61 partial game-stream
  packets were excluded from the complete keyframe sequence. The independent
  saved-artifact scan matched the interval counts. Endpoint difference does
  not identify change time, transaction, swap, or state between observations;
  identical endpoints do not exclude intervening changes. Ignored output is
  under `artifacts/16_19_development/inventory_keyframe_interval_batch_11_821/`.
- **Completed query:** Saved `increment_minion_kills_packet_candidates` now
  receives exact-build profile/image/transform, original packet reference,
  payload/key, and `UNKNOWN` effect-field checks before time/raw-param
  filtering. Missing image remains unavailable in batch results. The real
  11-Replay batch query validated 279 rows, matched 119 for raw parameter
  `0x400000b1`, and emitted the same 119 original JSONL lines byte-for-byte.
  No participant or latest-per-participant interpretation is supplied.
- **Completed protocol candidate:** Exact-821 game route `0x03a7` is registered as
  `PKT_S2C_IncrementMinionKills_s`. Its three-byte payload is consumed by the
  pinned native constructor/deserializer; the callback-derived object lookup
  key agrees with Replay `raw_param` for all 279 observed packets in the 11 KR
  Replays. The candidate decoder emits selector, key, and raw packet ref with
  conditional counter write and semantic CS effect `UNKNOWN`. Across these
  Replays only seven of the ten canonical hero-family keys appeared, and 279
  packets do not explain the 16,567 standard lane-CS tail total. In 70 of 110
  participant sequences the lane-CS tail was positive without any `0x03a7`
  packet; 2,127 keyframe intervals gained lane-CS with no such packet. The
  148 route-bearing intervals with lane-CS gains leave individual effects
  unresolved. The next decisive gate is an exact-build live receiver/heap
  trace of lookup branches and the resolved object's counter before/after a
  Replay-anchored packet; the mapped image does not contain that live state.
  The selected
  CLI batch returned 11/11 `CANDIDATE`, zero framing errors, 279 JSONL rows,
  and `MATCHED_USED` for the pinned image in every Replay; all 279 rows had
  matching callback key/raw parameter and explicit `UNKNOWN` effect status.
  Ignored output is under
  `artifacts/16_19_development/increment_minion_kills_cli_batch_11_821/`.
- **Completed query increment:** `query-events` reads saved exact-821
  `ward_inventory_keyframe_pair_candidates` with participant, time, raw-param,
  same-record item/slot and latest-observed filters. The saved association is
  checked against both source capabilities and its two packet references;
  missing image remains unavailable. A real 11-Replay query validated all
  3,270 rows and returned `COMPLETE` for all 11. At 600,000 ms, 1,100 rows
  matched and the last-observed query selected 110 original lines; their
  sorted line-set SHA-256 matched an independent source JSONL scan. A
  single-Replay participant/time/raw-param/item/slot filter returned one
  byte-identical source line. This is a saved-artifact check, not a replay
  byte re-decode at query time.
- **Completed candidate association:** Jointly selecting exact KR 821
  `hero_ward_stats_snapshot,hero_inventory_broadcast_packet` with the pinned
  image adds `ward_inventory_keyframe_pair_candidates` and an association
  summary. A fresh 11-Replay CLI batch returned 11/11 `CANDIDATE`, zero
  framing errors, 3,270 unique same-keyframe pairs, 61 excluded game-stream
  Broadcast rows, and 6,601 physically checked source packet references.
  Missing image leaves the independent ward stream available and the pair
  `MISSING_INPUT`. This is synchronized candidate observation only; no ward
  placement, coordinate, item transaction, or persistent inventory follows.
  Ignored output is under
  `artifacts/16_19_development/ward_inventory_keyframe_joint_batch_11/`.
- **Completed efficiency increment:** The exact-821 death-episode association
  reuses the source-bound route scan's retained packet copies to verify all
  original references; standalone calls still reframe Replay chunks. A warmed
  one-Replay comparison measured 174.765 ms for reframe verification versus
  5.728 ms for scan reuse (six calls each), with identical association JSON.
  A fresh 11-Replay CLI batch remained 11/11 `CANDIDATE`, zero framing errors;
  all 44 source/association JSONL files and 11 association summaries matched
  the previous batch exactly. This is a local measurement, not a throughput
  guarantee for other selections or machines.
- **Completed query:** `query-events --latest-per-participant [--to-ms T]`
  selects the last original matching exact-821 candidate row for each mapped
  participant within each Replay. It validates the full artifact before output,
  chooses the later source line on a timestamp tie, and reports matching,
  selected, emitted, and unavailable-participant counts separately. The saved
  11-Replay Broadcast artifact at 600,000 ms scanned 3,331 rows, matched 1,115,
  counted one unmapped row, and emitted 110 rows; the selected raw-line set hash
  matched an independent source JSONL scan. A level candidate batch at the same
  cutoff selected 110 rows from 703 matches. This reports latest observations,
  not carried-forward inventory, experience, level, or damage state.
- **Completed query:** `query-events --event hero_death_episode_candidates`
  validates the exact 821 association, all three source capability results,
  count partition, and stored packet references before filtering unchanged
  JSONL rows by victim, candidate killer or assistant, time, or recorded raw
  parameter. The saved 11-Replay CLI batch query completed 11/11 and scanned
  all 655 rows. A combined real filter matched one source row byte-for-byte;
  an unavailable source remains unavailable rather than a zero match. Query
  checks artifact provenance and structure; raw Replay bytes were checked at
  decode time.
- **Completed candidate association:** Selecting `hero_assist,hero_death_timer,hero_respawn`
  for exact KR 821 also writes `hero_death_episode_candidates` and
  `candidate_associations.hero_death_episode`. Each row joins the three
  independently decoded outcomes by its original `0x0259` death packet and
  physically verifies all source packet references. The real 11-Replay CLI
  batch scanned 18,235,209 blocks with zero framing errors: all 11 were
  `CANDIDATE`, yielding 655 episode rows, 607 observed `0x0048` returns, and
  48 deaths with no observed return before Replay end. Missing or conflicting
  sources fail the association while independent successful outputs remain.
  Timer values do not predict return. Ignored local output is under
  `artifacts/16_19_development/hero_death_episode_cli_batch_11/`.
- **Completed query:** `query-events --event dampener_die_event_packet_candidates`
  checks the exact build, pinned image, native child identity, counts, blob
  hash and raw packet references before filtering unchanged rows by time or
  recorded raw parameter. The real 11-Replay batch query emitted all 18
  candidates from 10 Replays and reported the remaining Replay as
  `PROFILE_UNAVAILABLE` (`PARTIAL` batch summary).
- **Completed packet candidate:** Exact KR 821 `0x040a/116` child `0x0035`,
  named `OnDampenerDie` in the SHA-256-pinned runtime image, is selectable
  through CLI/API. The exact-image native census fully consumed all 831
  same-length parents from the 11 supplied Replays: 18 target packets in
  10 Replays, with 813 foreign-child controls. One Replay has no target and
  reports `PROFILE_UNAVAILABLE`. Candidate rows retain the anonymous
  108-byte child blob and raw packet provenance. The image name and packet
  occurrence do not establish actual structure destruction, structure or actor
  identity, or a game-state transition.
- **Completed query:** `query-events --event turret_first_blood_die_pair_candidates`
  reads exact 821 single-Replay or batch artifacts and filters by time or either
  recorded raw packet parameter. The query checks the pair and both source
  capability identities, pinned image, counts and row packet references before
  returning unchanged candidate rows. The real 11-Replay batch query matched
  11/11 rows with no unavailable Replay; no structure or actor identity follows.
- **Completed candidate association:** Selecting both exact KR 821
  `turret_die_event_packet,turret_first_blood_event_packet` capabilities also
  emits `turret_first_blood_die_pair_candidates` and
  `candidate_associations.turret_first_blood_die_pair`. In the 11 supplied
  Replays, each of 11 native `OnTurretFirstBlood` child packets uniquely
  follows one of 136 native `OnTurretDie` child packets in the same chunk and
  millisecond, with no intervening `0x040a` OnEvent packet; 125 Die packets
  remain unpaired. The association rechecks exact-image outcomes and raw
  Replay packet references, and fails the whole Replay association on
  ambiguous or conflicting pairs. Raw outer parameters and anonymous child
  `+0x04` values are not equality gates. This is packet order evidence only,
  not an actual first turret death, structure or actor identity, or game
  state transition.
- **Completed packet candidate:** Exact KR 821 `0x040a/116` child `0x003d`,
  named `OnTurretFirstBlood` in the pinned runtime image, is selectable through
  CLI/API with the exact image SHA-256 gate. All 11 supplied Replays returned
  `CANDIDATE`: one target packet per Replay passed native full consumption and
  child identity checks (11 total); 820 same-length foreign children were
  excluded by their observed raw fingerprints and retained as raw source
  references. The batch scanned 18,235,209 blocks with zero framing errors.
  Rows preserve the anonymous 108-byte child blob, its SHA-256, and packet
  provenance. The image label does not establish an actual first turret death,
  structure or actor identity, or state transition. Selecting this packet
  capability alone does not output a Die association. Ignored real CLI output
  is under
  `artifacts/16_19_development/turret_first_blood_cli_batch_11/`.
- **Completed query:** `query-events --opaque-u32 VALUE` for
  `revive_ally_event_packet_candidates` filters the exact 821 anonymous native child `+0x04`
  integer without changing JSONL or assigning an actor/recipient role. A real
  11-Replay artifact query for `0x400000b6` scanned three candidate rows,
  emitted one original line, and reported one complete Replay plus ten
  unavailable Replays (`PARTIAL`). Missing and null values stay unavailable;
  checked nonmatches are zero, not missing input.
- **Completed packet candidate:** Exact KR 821 `0x040a/116` child `0x003b`,
  named `OnTurretDie` in the pinned runtime image, is selectable through
  CLI/API with the exact image SHA-256 gate. All 11 supplied Replays returned
  `CANDIDATE`: 136 target packets passed native full consumption and child
  identity checks, while 695 same-length foreign children were excluded by
  their observed raw fingerprints and retained as raw source references.
  The batch scanned 18,235,209 blocks with zero framing errors. Rows preserve
  the anonymous 108-byte child blob, its SHA-256, and packet provenance. The
  image label does not establish an actual turret death, structure or actor
  identity, or state transition. Ignored real CLI output is under
  `artifacts/16_19_development/turret_die_cli_batch_11/`.
- **Completed packet candidate:** Exact KR 821 `0x040a/16` child `0x002c`,
  named `OnReviveAlly` in the pinned runtime image, is selectable through
  CLI/API with the exact image SHA-256 gate. One of the 11 supplied Replays
  yielded three packets that passed native full consumption and child identity
  checks; nine same-length foreign children were retained as exclusions.
  The other ten Replays reported `PROFILE_UNAVAILABLE`, so the 11-Replay batch
  is `PARTIAL`, with zero framing errors. Rows preserve the anonymous native
  child `+0x04` u32, raw bytes, and packet provenance. No actual revive,
  actor/recipient role, or state change is established. Ignored real CLI
  output is under `artifacts/16_19_development/revive_ally_cli_batch_11/`.
- **Completed:** `query-events --killer-participant 1..10` filters exact 821
  death and assist candidate rows by the independently decoded killer
  participant candidate. A real KR Replay had 71 death rows, three matches
  for participant 6, and preserved the original JSONL line. Another Replay
  had one unavailable nonhero source among 41 rows. Missing or nonhero IDs
  stay unavailable, while a checked zero match remains complete.
- **Completed:** `query-events --assisting-participant 1..10` filters exact
  821 `hero_assist_candidates` without altering JSONL rows. A real 11-Replay
  batch scanned 655 death rows and found 85 participant-2 matches; all 11
  Replays remained queryable. Two nonhero rows had unavailable (`null`)
  assist lists; 101 had available empty lists. The query reports these
  separately from zero matches and fails on malformed candidate lists.
- **Completed candidate:** Optional exact-image `hero_assist` validation now
  checks native `0x040a/44` child IDs `0x0056/0x0057` and two anonymous field
  equalities against the independently matched Hero_Die packet. All 11 KR 821
  Replays returned `CANDIDATE`: 1,379 first children, 1,097 second children,
  1,097 aligned pairs, 282 excluded first-only packets, and 655 death rows.
  Of the paired child `+0x04` values, 1,047 equal the death raw parameter and
  50 equal it after clearing `0x100`; second child `+0x20` equals the decoded
  death source candidate in all 1,097. Candidate event times, participant
  lists, pair counts, and exclusions remained unchanged. Image-free candidates
  remain available with identity marked `NOT_CHECKED`; an image mismatch fails
  only this capability. The fields and assist attribution remain candidates.
  Ignored outputs are under
  `artifacts/16_19_development/assist_native_field_join_cli_batch_11/`.
- **Research boundary:** In the pinned 821 image, BuffUpdateCount `+0x14` and
  BuffReplace `+0x18` feed a runtime object-table lookup; their decoded byte
  fields, and BuffUpdateNumCounter `+0x18`, index a BuffManager vector. This
  establishes packet-processing use, not the looked-up object's identity.
  Of 151,495 UpdateCount rows, 114,340 lookup values match one of the ten
  independent HeroStats hero raw parameters per Replay, but a `value+1`
  control still matches 105,760. Replace matches 23,189/23,351 versus 20,914
  for the same control. The module-only capture lacks the Replay-time manager
  heap, vector, object table, virtual receiver, and labeled identity anchor;
  no Buff/owner/target role is promoted. UpdateNumCounter `+0x14` is
  overwritten on receiver entry, so its Add-pair equality cannot establish a
  consumed Buff identity.
- **Excluded from current KR work:** Exact-image AddBuffModifier `0x02c0` and
  RemoveBuffModifier `0x0026` are registered, but strict scans found zero
  target packets in all 11 supplied KR 821 Replays (18,235,209 framed blocks,
  zero framing errors). Real native packet validation lacks inputs for them.
- **Completed candidate:** Exact KR 821 `0x025d` SetSpellLevel is selectable
  through CLI/API with two callback-transformed anonymous `u32` fields, raw
  object bytes, and Replay packet provenance. All 342/342 game-stream packets
  across 11 supplied Replays passed exact-image native return and full
  consumption; real CLI batch wrote 342 JSONL rows, 11/11 `CANDIDATE`, matched
  image, and zero framing errors. The observed wire lengths are 1/2/3 bytes;
  truncated, appended, and foreign-route controls did not satisfy the full
  target gate. No spell identity, actual level, owner, or effect is inferred.
  Ignored output is in `artifacts/16_19_development/set_spell_level_cli_batch_11/`.
- **Completed opt-in SetSpellLevel callback witness V2:** The exact 821 callback
  at RVA `0x998630` selects a synthetic receiver table slot from decoded
  object `+0x10` (0..63, otherwise slot 0); exact callee RVA `0x947f20`
  caps nonnegative `+0x14` at 6, writes the selected receiver's `+0x28`,
  and writes its `+0x2c` positive flag only for a positive value. V2 runs
  both native routines for each source-bound packet, keeps V1 as the default,
  and exposes only candidate receiver-slot, selection-source, capped-scalar,
  and flag-write fields. All 342/342 packets across the 11 supplied exact
  Replays completed V2 native witness with matched image and zero framing
  errors. Native fallback/9-to-6/zero controls passed; a signed-negative
  control wrote -1 natively and was rejected from bounded V2 output. The
  synthetic table does not identify a live receiver, spell, level change, or
  effect. An integrated V2 `batch` run over the same 11 original Replays
  returned 11/11 `CANDIDATE`, 342 JSONL rows, and zero framing errors.
  Saved `query-events` then checked all 342 rows in 11/11 Replays despite
  `--limit 1`: receiver index 12 matched 278 rows and clamped scalar 6
  matched 22. The query checks both saved capability metadata copies,
  exact V2 row shape, and protected raw words before filtering; V1 artifacts
  report these callback fields unavailable. The private Replay/image inputs
  and generated batch artifacts remain outside Git. Image-backed SetSpellLevel
  Node tests passed 16/16, native Python controls passed 4/4. The public
  `npm test` run passed 1,129 Node tests, skipped 73 declared cases, failed 0,
  and passed 19 public Python unittests.
- **Completed candidate:** Exact KR 821 `0x00fd` SetSpellTimerFromBuff is
  selectable through CLI/API with six anonymous callback fields, raw object
  bytes, and Replay packet provenance. All 5,481/5,481 target packets across
  11 supplied Replays passed native full consumption and object identity; the
  real CLI batch wrote 5,481 JSONL rows, 11/11 `CANDIDATE`, matched image,
  and zero framing errors. Truncation, appended-byte, and sampled foreign
  routes failed full target consumption. No spell or Buff identity, owner,
  timer effect, or lifecycle claim is made. Ignored output is in
  `artifacts/16_19_development/set_spell_timer_cli_batch_11/`.
- **Completed opt-in SetSpellTimerFromBuff callback witness V2:** The pinned
  821 callback at RVA `0x2c2760` accepts decoded object `+0x20` values
  0..5 and 63, selects that slot through receiver lookup RVA `0x98a840`,
  and forwards the five other decoded fields to call entry RVA `0x946cf0`.
  A synthetic receiver table witnesses the exact callback route and all
  forwarded arguments for each source-bound packet; the receiver function
  is stopped at entry because the live receiver heap and clock are absent.
  All 5,481/5,481 target packets across 11 original KR Replays completed
  V2 witness after scanning 18,235,209 blocks with zero framing errors.
  Selector counts were 0:1,601; 1:1,728; 2:1,299; 3:324; 4:12; 5:2;
  63:515. Native controls for 6, 62 and 64 reached no receiver call and
  fail closed in V2. V1 remains the default; no Buff or spell identity,
  owner, timer effect or lifecycle is inferred.
- **Completed V2 CLI/API and saved query:** `--spell-timer-packet-v2` and
  `setSpellTimerProfile: 'v2'` select the native witness; V1 remains the
  default. The real CLI batch on the 11 original KR 821 Replays wrote 5,481
  candidate JSONL rows, with 11/11 `CANDIDATE` and zero framing errors, to
  ignored `artifacts/16_19_development/spell_timer_v2_11_replay_20260926/`.
  `query-events --spell-timer-receiver-slot 63 --limit 1` validated all
  5,481 saved rows and matched 515; the limit emitted one row. V1 artifacts
  explicitly report receiver unavailable. Focused Node tests passed 16/16.

- **Completed candidate:** Exact KR 821 `0x0194` BuffUpdateNumCounter and
  `0x02d9` BuffUpdateCount are selectable CLI/API packet candidates with
  pinned-image native full consumption, anonymous callback fields, raw bytes,
  and packet provenance. The 11 supplied Replays produced 132,851 and
  151,495 rows respectively; all capability results were `CANDIDATE` with
  zero framing errors. No buff identity, owner, effect, or count meaning is
  inferred. Ignored outputs are in
  `artifacts/16_19_development/buff_update_num_counter_cli_batch_11/` and
  `artifacts/16_19_development/buff_update_count_cli_batch_11/`.
- **Completed candidate association:** Selecting KR 821 BuffAdd2 and
  BuffUpdateNumCounter together exposes Replay-scoped equality and packet-order
  counts for anonymous `(u32,u8)` fields and recorded raw parameters. All
  132,851 Update rows have a pair present in game-stream Add rows; 125,362
  have a preceding Add with the same pair and raw parameter, but 42,506 have
  multiple such predecessors. This does not identify or pair Buff instances.
  Ignored output is in
  `artifacts/16_19_development/buff_add_update_num_counter_cli_batch_11/`.
- **Completed:** `query-events --opaque-u32` now filters the decoded 821
  BuffUpdateCount `+0x14` field. A real KR Replay query scanned 7,629 rows,
  matched 1,750, and emitted three unmodified rows with `--limit 3`.
- **Completed candidate:** Exact-image KR 821 `0x01ad` BuffReplace is selectable
  through CLI/API with four anonymous callback fields, raw object bytes, and
  packet provenance. Independent native checks fully consumed 23,351/23,351
  packets across 11 supplied Replays; the real CLI batch also produced 23,351
  JSONL rows with 11/11 `CANDIDATE`, matched image, and zero framing errors.
  Truncation, appended-byte, and four foreign-route controls did not pass as
  full target packets. No buff replacement, owner, slot, or lifecycle claim is
  made. Ignored output is in
  `artifacts/16_19_development/buff_replace_cli_batch_11/`.
- **Completed:** A real four-capability Buff Add/UpdateNum/UpdateCount/Replace
  CLI run on `KR_8393821675` returned 24,296/8,189/13,518/770 candidate
  rows and a `CANDIDATE` Add/UpdateNum aggregate, with zero framing errors.
  `query-events --opaque-u32` now filters BuffReplace's anonymous `+0x18`;
  a real query scanned 770 rows and matched 12.
- **Completed:** `query-events --opaque-pair U32:U8` selects the exact
  anonymous field pair in 821 BuffAdd2, BuffRemove2, or BuffUpdateNumCounter
  rows. On `KR_8393821675`, pair `95298804:13` matched 712 UpdateNum and
  12 Add rows; an 11-Replay UpdateNum batch query scanned all 132,851 rows,
  matched 4,920, and kept every Replay queryable. These are field matches,
  not packet or buff-instance joins.
- **Current:** Continue exact-build field research where an independent
  receiver or raw anchor can resolve the remaining anonymous roles.
  Unavailable virtual callback receivers still block owner/target/effect
  promotion for several existing event candidates.
- **821 healing/shielding cross-route stop-loss:** In the 11 KR Replays,
  `ParamsHeal` has 70,698 reported-amount candidates and
  `ShieldingParams` has 2,778 packet pairs. The two anonymous Heal keys
  differ in 612 packets. With key `+0x04`, 2,196 sampled participant
  intervals have summed reports greater than the observed `TOTAL_HEAL`
  endpoint difference; 370 individual reports exceed their interval
  difference. Among positive self-mitigated intervals, 1,717 have no
  matching ShieldingParams key, while 74 zero-difference intervals do.
  These routes do not establish effective healing, shield absorption,
  source, or target. Input hashes, exact counts, and method are retained
  under ignored `artifacts/16_19_development/heal_shield_negative_scout_20260925/`.
- **Completed 821 FaceDirection packet candidate:** The exact 821 `0x038e`
  route is selectable as `face_direction_packet` in the CLI/API. The pinned
  image and callback transform yield a packet-local unit-vector candidate;
  observed 17-byte game packets also carry an optional scalar candidate.
  The 11 supplied KR Replays produced 262,393/262,393 candidate rows
  (67,999 keyframe/13, 2,504 game/13, 191,890 game/17), 11/11
  `CANDIDATE`, and zero framing errors in a real JSONL-only CLI batch.
  The raw marker, parameter, payload, and packet reference remain in each
  row. A `query-events --raw-param 0x400000b7` check scanned all 262,393
  rows and matched 1,548. Native representatives and controls support the
  observed lengths; rare marker branches are not all natively sampled.
  This batch used the exact-image-derived transform;
  it did not execute the native callback per packet. That callback compares
  against a live receiver absent from the capture. Actor, coordinates,
  path, and direction effect remain `UNKNOWN`. Local output is ignored at
  `artifacts/16_19_development/face_direction_batch_11_821/`.
- **Completed 821 FaceDirection keyframe roster pair:** The independently
  selectable `face_direction_keyframe_roster_pair` decodes its exact-image
  FaceDirection and `0x0089` minions-snapshot sources, then matches only
  canonical full raw parameters in the same keyframe and timestamp with
  HeroStats preceding FaceDirection. Across the same 11 Replays, 327
  keyframes yielded 3,270/3,270 candidate pairs and 265,663 physically
  checked source packet references; 194,394 game packets and 64,729
  noncanonical keyframe FaceDirection packets were excluded. A rotated-key
  control preserved chunk, time and order but produced zero full-key matches.
  The real pair-only CLI batch returned 11/11 `CANDIDATE` with zero framing
  errors. `query-events --participant 4` scanned 3,270 rows and matched
  327 roster-participant candidates; `--latest-per-participant` selected
  110 last-observed keyframe rows, ten per Replay. The participant label belongs to the
  HeroStats roster, not a proven FaceDirection actor; receiver, position,
  path and direction effect remain `UNKNOWN`. The initial one-Replay CLI
  failure caused by a missing `input_count` contract field and the corrected
  rerun are both retained locally. Batch output is ignored at
  `artifacts/16_19_development/face_direction_roster_pair_batch_11_821/`.
- **821 FaceDirection actor-binding stop-loss:** The exact-image callback
  receives a live `AIBaseClient` and does not use the packet's `+0x0c` field
  as an actor key. In the saved 11-Replay game stream, 151,492/194,394
  FaceDirection rows share a millisecond with different full parameters.
  None of 8,463 independently selected movement rows has a same-key
  FaceDirection packet at the same millisecond; a 100 ms window finds the
  actual canonical key for 102 movement rows versus 117 for a rotated
  wrong-key control. These observations do not bind packets to actors.
  Receiver identity, position, path, and effective direction remain
  `UNKNOWN`. The ignored evidence and next gate are in
  `artifacts/16_19_development/face_actor_scout_20260925/RESULT.md`.

- **Completed candidate marker:** Exact KR 821 CLI/API now selects native
  `0x040a` child `0x000b`, named `OnChampionDoubleKill` in the pinned image.
  Across the 11 supplied Replays, 63/654 length-104 packets are targets;
  591 same-length children are excluded controls. Every target uniquely
  shares Replay/chunk/ms with a prior Multi/Die/Hero packet group, but the
  callback accesses a live virtual receiver absent from the mapped image.
  The output retains child identity, blob digest, and raw provenance only;
  no effective double kill, actor, or callback field is inferred. The real
  11-Replay CLI batch returned 63 target JSONL rows from 654 same-length
  packets, excluded 591 controls, and had zero framing errors. Ignored
  CLI output is under `artifacts/16_19_development/on_event_000b_cli_batch_821/`;
  underlying evidence is under
  `artifacts/16_19_development/on_event_000b_followup_821/` and
  `artifacts/16_19_development/on_event_000b_group_join_821/`.
- **Completed:** `query-events` accepts a batch artifact root, keeps the
  manifest's Replay order, validates its exact Replay directory inventory,
  metadata and queried JSONL hashes, then scans each full JSONL and reports
  per-Replay unavailable states. The existing 11-Replay OnResurrect batch
  produced 29 rows from seven queryable Replays; four remained
  `PROFILE_UNAVAILABLE` and the query reported `PARTIAL`.
- **Completed candidate integration:** Selecting the 821 inventory packet,
  deaths snapshot, and a movement route now exposes the Replay-scoped
  full-parameter participant association in CLI/API summaries. It does not
  add an actor to movement rows; details and negative keys are below.
- **Completed:** The shared 821 scan now resolves selected route flags once
  per scan instead of checking the selected set for every packet block. A
  same-process alternating 12-scan comparison on three KR Replays measured
  2449 to 1778 ms for the collector; the 11-Replay candidate JSONLs were
  byte-identical in the focused comparison. Evidence is under
  `artifacts/16_19_development/performance_followup_821/`.
- **Completed:** `query-events` now reads the four exact-821 derived packet
  group JSONLs using their `candidate_associations` summaries and selected
  upstream capability results. It checks profile/build, Replay identity,
  dependency statuses and counts, row/ref integrity, and refuses missing or
  inconsistent associations. Time, any recorded raw parameter, and directly
  decoded child `+0x04` u32 filters return unmodified candidate rows. Real
  queries succeeded for the first three groups in both an ordinary KR Replay and
  a Replay containing an optional death-route omission. These checks do
  not promote the underlying candidate fields to confirmed semantics. The
  OnShutdown group has also passed selected KR CLI query smoke with its
  anonymous `+0x04/+0x58/+0x5c` fields.
- **Completed:** KR 821 `hero_death,champion_die_event_packet,
  champion_multiple_kill_event_packet` now emits a third selected CLI/API
  candidate packet group. All 653 OnChampionMultipleKill children in 11 KR
  Replays uniquely share Replay SHA/chunk/ms with an OnChampionDie/Hero_Die
  pair; two Die/Hero pairs have no MultipleKill child. Multi outer
  `raw_param` equals Die child `+0x04` and the Hero_Die source candidate in
  653/653; Multi child `+0x04` equals the Hero_Die victim raw parameter
  after clearing bit `0x100` in 653/653 (620 exact). Packet order is
  Die child, Multi child, Hero_Die primary. Shifted-time controls matched
  none; rotated intact fields reached at most seven dual matches versus
  41–93 true rows per Replay. The final four-capability CLI batch wrote
  655 Die/Hero pairs, 581 Kill groups, and 653 Multi groups with zero
  framing or association failures. Without the image, each derived group
  reports `MISSING_INPUT` and writes no group JSONL. Static exact-image
  tracing confirms Multi child `+0x04` is an object lookup key and `+0x0c`
  bounds the `+0x10` u32 lookup-key list; `+0x08` is passed unchanged to a
  virtual call. No callback lookup result, actual multikill, numeric streak,
  actor, or victim is confirmed. Ignored evidence is under
  `artifacts/16_19_development/multiplekill_death_link_821/`,
  `artifacts/16_19_development/multiplekill_native_fields_821/`, and
  `artifacts/16_19_development/onchampion_three_groups_cli_batch_821/`.
- **Completed:** The selected KR 821 `hero_death,champion_die_event_packet,
  champion_kill_event_packet` route now exposes a second candidate packet
  association. All 581 OnChampionKill children in 11 Replays have a unique
  same-Replay/chunk/ms OnChampionDie and Hero_Die group with packet order
  Die child, Kill child, Hero_Die primary; 74 Die/Hero groups have no Kill
  child. Kill outer `raw_param` equals Die child `+0x04` and the Hero_Die
  source candidate in 581/581. Kill child `+0x04` equals the Hero_Die victim
  raw parameter after clearing bit `0x100` in 581/581 (551/581 exact).
  Shifted-time controls gave no exact matches; rotated intact field pairs
  reached at most ten dual matches versus 34–86 per observed Replay. The
  association preserves all packet refs and fails locally on ambiguity or
  conflict, without asserting actual kill, actor, or victim semantics.
  The final three-capability CLI batch wrote 581 candidate JSONL rows and
  reported 11/11 `CANDIDATE`; without the image, the downstream group is
  `MISSING_INPUT` and no group JSONL is written. Ignored evidence is under
  `artifacts/16_19_development/champion_kill_death_link_821/` and
  `artifacts/16_19_development/champion_kill_die_hero_cli_batch_821/`.
- **Completed:** Selecting KR 821 `hero_death,champion_die_event_packet`
  together now emits `champion_die_hero_death_pair_candidates.jsonl` through
  the shared CLI/API. The exact-build association requires a unique same
  Replay, chunk, and millisecond join, equality between OnChampionDie child
  `+0x04` and the independently decoded Hero_Die source candidate, and
  equality of outer raw-parameter low bytes. The real 11-Replay CLI batch
  produced 655/655 candidate pairs with no framing or association failures;
  only 333/655 full raw parameters matched. Shifted-time controls produced
  no dual-field exact-time match; rotated-ID controls yielded at most seven
  such matches per Replay, rather than a complete association. Any conflicting
  row fails the association locally and leaves the independent event candidates
  intact. Exact-image static tracing shows child `+0x04` is used as a 32-bit
  object-tree lookup key in both OnChampionDie and OnChampionKill callbacks,
  but lookup success, object type, effective death, and actor roles remain
  unverified. Ignored raw/negative evidence is under
  `artifacts/16_19_development/champion_die_hero_death_link_821/`,
  `artifacts/16_19_development/champion_die_field_identity_821/`, and
  `artifacts/16_19_development/death_die_pair_jsonl_batch_821/`.
- **Completed:** A real four-capability CLI batch over the same 11 KR 821
  Replays emitted 4,913 stealth, 655 OnChampionDie, 581 OnChampionKill, and
  653 OnChampionMultipleKill packet candidates. All 44 capability results
  remained `CANDIDATE`, with zero framing errors and a matched exact image.
  This verifies the selected CLI/API path for these packet candidates, not
  their gameplay effects. Ignored output is under
  `artifacts/16_19_development/onevent_four_batch_821/`.
- **Completed:** KR 821 `champion_multiple_kill_event_packet` is an
  unpublished selected CLI/API candidate for exact-image OnEvent child
  `0x0009`, named OnChampionMultipleKill in the image table. The registered
  callback directly reads anonymous child `+0x04/+0x08/+0x0c` u32 values
  and passes the `+0x10` address with the bounded `+0x0c` value to a helper.
  Native decoding fully consumed all 653 observed 88-byte packets in 11 KR
  Replays; all had child `0x0009`, with no real same-length foreign-child
  controls. A changed child ID on one packet still fully decoded but was
  rejected by the explicit ID gate. The candidate exposes a bounded opaque
  u32 list, source ref and blob hash without assigning an actor, multikill
  level or gameplay effect. A seven-capability CLI smoke on `KR_8392938200`
  emitted 71 such packets with zero framing errors. Ignored independent
  evidence is under `artifacts/16_19_development/on_champion_multiple_kill_821/`.
- **Completed:** KR 821 `on_shutdown_event_packet` is a selected exact-image
  CLI/API candidate for OnEvent child `0x00e8`, labeled OnShutdown by the
  image name table. All 72 observed 105-byte packets in 11 KR Replays were
  natively fully consumed and emitted as candidates with anonymous child
  `+0x04/+0x58/+0x5c` u32 and raw refs. The selected
  `hero_death,champion_die_event_packet,on_shutdown_event_packet` route
  also emitted 72 three-route candidate groups with zero framing or
  association errors. All 72 Shutdown packets join unique same-Replay,
  chunk, and millisecond Die/Hero_Die groups, and no observed Kill group;
  581 other observed Multi groups join Kill groups. Without the exact image,
  the Shutdown packet and derived group report `MISSING_INPUT` and write no
  JSONL. Same-length foreign-child controls were absent, and the registered
  closure invokes an unresolved indirect callback. No gameplay shutdown
  effect, actor, or state transition is established. Ignored evidence is
  under `artifacts/16_19_development/on_shutdown_821/`,
  `artifacts/16_19_development/on_shutdown_death_link_821/`, and
  `artifacts/16_19_development/on_shutdown_group_cli_batch_821/`.
- **Completed:** KR 821 OnEvent child `0x002d` has a dedicated exact-image
  packet candidate decoder. The image name table labels it OnResurrect;
  native code fully consumed all 29 observed 20-byte parents in seven of
  the 11 KR Replays. The other four lack this packet shape and report
  `PROFILE_UNAVAILABLE`, rather than a zero observation. The output keeps
  anonymous native child `+0x04/+0x08` u32 values and raw refs. None of the
  29 packets is co-timed with any of 607 existing `hero_respawn` candidates,
  so the two routes remain separate. The selected 11-Replay CLI batch emitted
  29 JSONL rows from seven Replays; the four absent-shape Replays wrote no
  event JSONL, and the batch reported `PARTIAL` with zero framing errors.
  `query-events --opaque-u32` matched an anonymous native field in the real
  JSONL. Real same-length foreign-child controls
  are absent; wrong child, image, build, stream and payload-length controls
  fail closed. No actual resurrection, actor, or state transition is
  established. Ignored evidence is under
  `artifacts/16_19_development/on_event_next_followup_821/` and
  `artifacts/16_19_development/on_resurrect_cli_batch_821/`.
- **Completed:** KR 821 `turret_plate_event_packet` is a selected exact-image
  CLI/API packet candidate for OnEvent child `0x0107`. The image name table
  labels it OnTurretPlateDestroyed. Native parent decoding fully consumed
  5,621 observed 17-byte game packets in 11 KR Replays: 657 targets and
  4,964 same-length foreign children. The 11-Replay CLI batch emitted 657
  candidate JSONL rows, excluded the controls, and reported zero framing
  errors. `query-events --opaque-u32` matched the anonymous native child
  `+0x04` field while retaining the distinct outer `raw_param`. No
  child-specific callback, object role, plate destruction, or state change
  is confirmed. Ignored evidence is under
  `artifacts/16_19_development/on_turret_plate_followup_821/` and
  `artifacts/16_19_development/on_turret_plate_cli_batch_821/`.
- **Investigated:** Exact 821 child `0x000b` is named OnChampionDoubleKill
  by the image table; 63 target packets and 591 same-length controls were
  natively fully consumed. Its callback obtains a value through a virtual
  accessor on an unavailable live object, so no direct child field or
  gameplay effect is established. Packet marker only; no field decoder was
  added. Ignored evidence is under
  `artifacts/16_19_development/on_event_000b_followup_821/`.
- **Completed:** KR 821 `champion_kill_event_packet` is an unpublished
  selected CLI/API candidate for exact-image OnEvent child `0x0007`. The
  exact name table labels it OnChampionKill, and the registered callback
  directly reads anonymous child `+0x04/+0x58/+0x5c` u32 values. Native
  decoding fully consumed all 654 observed 104-byte OnEvent packets in 11
  KR Replays, yielding 581 target packets and 73 same-length controls.
  The latter two u32 fields were constant `0xffffffff` and zero in these
  samples. No effective kill, killer, victim, or transition is inferred.
  A combined CLI smoke on `KR_8392938200` emitted 63 candidates and
  excluded four controls without framing errors. Ignored evidence is
  under `artifacts/16_19_development/champion_kill_event_validation_821/`.
- **Completed:** KR 821 `champion_die_event_packet` is an unpublished
  selected CLI/API candidate for exact-image OnEvent child `0x0004`. The
  exact name table labels it OnChampionDie, and the ParamsDie callback
  directly reads anonymous child `+0x04` u32. Native decoding fully consumed
  all 831 observed 116-byte OnEvent packets in 11 KR Replays, yielding
  655 target packets and 176 same-length controls. The packet marker and
  field do not prove an effective death, a victim, or a killer. A combined
  CLI smoke on `KR_8392938200` emitted 71 candidates and excluded 24
  controls without framing errors. Ignored independent evidence is under
  `artifacts/16_19_development/on_event_remaining_821/`.
- **Completed:** KR 821 `stealth_event_packet` is an unpublished selected
  CLI/API candidate for exact-image OnEvent children `0x0101/0x0102`.
  The exact 821 event-name table labels them OnEnterStealth and OnExitStealth.
  Native decoding fully consumed 5,621 observed 17-byte packets in 11
  Replays, yielding 4,913 target packets and excluding 708 known same-length
  child controls. Each candidate keeps its raw reference and callback-read
  anonymous `+0x04` u32. The event names do not prove a participant, a
  visibility effect, or a persistent stealth interval. Ignored cross-checks
  are under `artifacts/16_19_development/on_event_remaining_821/` and
  `artifacts/16_19_development/ward_route_probe_821/`. A four-capability
  CLI smoke on `KR_8392938200` scanned 2,048,130 framed blocks without
  errors and reported `decoded_packet_count=7337`; stealth produced 691
  candidates while excluding 77 same-length controls. Its exact-u32 query
  matched two rows, one of which had a different outer `raw_param`.
- **Completed:** `query-events --opaque-u32` searches either decoded
  anonymous u32 in exact 821 `params_heal_packet_candidates` or
  `shielding_params_packet_pair_candidates`, or `event_u32_0x04` in
  `stealth_event_packet_candidates`. It also matches callback-read anonymous
  u32 fields in `champion_die_event_packet_candidates` and
  `champion_kill_event_packet_candidates`, and scalar `+0x04/+0x08/+0x0c`
  fields in `champion_multiple_kill_event_packet_candidates`. It preserves JSONL rows,
  reports missing fields separately from zero matches, and never substitutes
  outer `raw_param` or assigns entity roles. A real KR Replay query scanned
  6,059 heal rows and 164 shield pairs, matching 321 and 100 respectively
  for two selected exact u32 values. Ignored query output is under
  `artifacts/16_19_development/opaque_u32_query_821/`.
- **Completed:** KR 821 `shielding_params_packet_pair` is an unpublished
  selected CLI/API candidate for exact-image OnEvent children `0x00f0`
  and `0x00ef`, both registered as `ShieldingParams`. Native decoding fully
  consumed all 5,556 observed 29-byte packets in 11 Replays; their 20-byte
  child blobs form 2,778 unique ordered pairs within replay, chunk and time.
  The two packet refs and callback-read anonymous `+0x08/+0x0c` u32 fields
  are retained. The raw `+0x10` f32 is opaque: zero and negative values
  occur, and neither callback reads it directly. No shield amount, actor,
  target, generation or absorption is inferred. Ignored cross-checks are
  under `artifacts/16_19_development/shielding_pair_validation_821/`.
- **Completed:** KR 821 `params_heal_packet` is an unpublished selected
  CLI/API candidate for exact-image OnEvent child `0x004b` (`ParamsHeal`).
  Independent native validation accepted and fully consumed all 86,604
  outer `0x040a` packets in 11 Replays: 70,698 are the 60-byte child
  `0x004b` packets, while 15,906 other child packets remain excluded. The
  registered handler reads the child blob's `+0x18` f32, exposed as a
  reported-amount candidate; `+0x04` and `+0x14` u32 values stay anonymous.
  Twenty truncated/appended controls failed the full-consumption gate.
  No effective-heal amount, caster or target is inferred. Ignored cross-checks
  are under `artifacts/16_19_development/heal_event_validation_821/`.
- **Completed:** KR 821 `hero_inventory_set_item_packet` is an unpublished
  selected CLI/API candidate for the exact-image `0x002d` SetItem route.
  The factory, constructor, nested reader and HeroInventoryClient class
  registration were independently bound to this full build. All 177/177
  seven-byte game packets in 11 Replays were fully consumed natively; their
  decoded slot candidate was 8 and the item key had six observed values.
  Each packet keeps its raw reference. A noncanonical raw-param variant in
  two packets remains participant-unmapped. `query-events --item-id` can
  filter the scalar packet item key. No purchase, sale, replacement or
  between-packet inventory state is inferred. Ignored controls are under
  `artifacts/16_19_development/set_item_821_next/`.
- **Completed:** KR 821 `hero_inventory_broadcast_packet` is an unpublished
  selected CLI/API candidate for the exact-image `0x0357` Broadcast route.
  The independent factory, constructor, class descriptor and registration
  distinguish it from `0x018d` MapView; both registrations use the same
  inventory receive callback. Native decoding fully consumed 3,331/3,331
  packets from 11 exact-build Replays. It retains every packet record,
  including decoded item key `0`, and a callback-based packet-local slots
  0–9 candidate snapshot; absent records remain `null`. One real selected
  CLI run emitted 341 packet rows and 3,388 records with zero framing errors.
  `query-events --item-id` can filter Broadcast records, including zero.
  Latest-keyframe ITEM0–ITEM6 candidates matched 651/770 Replay-tail values;
  119 differences and the 604–59,926 ms tail gaps remain in ignored evidence.
  No purchase, sale, between-packet state or participant identity for four
  noncanonical raw-param variants is inferred. Ignored proof and native
  summaries are under `artifacts/16_19_development/inventory_routes_821/`.
- **821 inventory cross-route NO-GO:** A combined exact-image CLI run on all
  11 KR Replays emitted 671 MapView, 3,331 Broadcast and 177 SetItem packet
  candidates without framing errors. No MapView packet shared both raw param
  and replay time with a Broadcast or SetItem packet. The 110 SetItem rows at
  time zero shared actor and time with Broadcast rows but came from different
  chunks and had different observed slot-8 item keys (positive versus zero).
  Among 174 SetItem rows with a later same-param MapView row, only 95 first
  later rows had the same observed slot/item key. These routes are not joined
  into inventory changes or transactions. The comparisons and original JSONL
  are retained under ignored
  `artifacts/16_19_development/inventory_three_routes_cli_batch_821/`.
- **Completed:** KR 821 `cast_spell_ans_packet` profile v3 also retains the
  protected native byte and decoded anonymous u8 at packet object `+0x140`.
  An exact-image inverse table is SHA-pinned and recomputed at the JS
  boundary. All 63,496 route packets in 11 Replays were fully consumed by
  the native helper; a selected CLI smoke emitted 5,980 v3 candidate rows
  from one Replay with zero framing errors. The 29 observed byte values do
  not identify a spell, owner, target or cast action. Ignored evidence is
  under `artifacts/16_19_development/cast821_next/`.
- **Completed candidate integration:** The selected KR 821 CLI/API now emits
  `candidate_associations.movement_full_param_participant_candidate` only when
  inventory, deaths snapshot, and at least one movement route are selected
  with complete exact-build decoder outcomes. The utility checks a complete
  candidate `0x0089` roster, latest `0x018d`
  packet-local inventory, and a unique 7/7 Replay-tail item match for each
  shared full `raw_param`. A run over all 11 Replays found five replay/key
  candidates; 6,160 `0x00ba` and 98 `0x0335` rows share those keys. Those
  row counts do not establish an actor for each packet. Another 1,648 direct
  and 14 Set rows use noncanonical parameter variants and remain unbound.
  The utility accepts trusted complete decoder arrays; it does not rewalk
  each referenced payload. The API records Replay-scoped candidate coverage
  but leaves every movement packet row unchanged and its actor unverified.
  A per-packet callback/receiver identity anchor remains missing. A fresh
  real CLI run reproduced the one-key Direct/Set association on
  `KR_8392938200`, and `KR_8394000013` retained a Set-only association with
  Direct `PROFILE_UNAVAILABLE`. Ignored positive and negative evidence is under
  `artifacts/16_19_development/movement821_identity/`.
- **Completed:** KR 821 `cast_spell_ans_packet` profile v2 retains protected
  native bytes and the decoded anonymous f32 at packet object `+0xe0`.
  The exact-image inverse table is pinned by SHA-256 and checked again at
  the JS boundary; malformed or mismatched helper rows fail closed. Native
  full decode covered all 63,496 route packets in 11 Replays; a v2 CLI batch
  emitted 63,496 candidate rows with 0 errors. Among the native rows, 512
  nonzero values occurred only in keyframe packets. The field has no established
  spell, position, time or action meaning. Ignored controls are under
  `artifacts/16_19_development/cast821_next/`.
- **Completed:** KR 821 `hero_inventory_packet` now emits a packet-local
  candidate snapshot for slots 0–9 alongside its original decoded records.
  The exact-image callback clears those slots and applies each packet's
  records; absent records yield `null` with explicit reset provenance. All
  671 packets and 5,327 records from 11 Replays retained exact native decode.
  All 6,710 slot entries follow the record/reset rule; 146 adjacent
  same-participant packet pairs demonstrate that absent slots are not carried
  forward. Near-end slots 0–6 matched Replay tails in 345/364 comparisons;
  19 gaps remain. This is not a between-packet inventory or transaction.
- **Completed:** KR 821 `set_movement_driver_packet` is wired as an
  unpublished selected CLI/API candidate for exact-image route `0x0335`.
  Native decoding fully consumed all 131 packets in nine of 11 Replays; the
  other two have no route. The selected CLI batch scanned 18,235,209 blocks
  with zero framing errors and emitted 131 rows. Aggregate `PARTIAL`/exit 1
  reflects the two absent routes. It emits only an anonymous callback-transformed
  dispatch byte at object `+0x2a`, the observed selector and raw packet ref.
  The emulated base-parameter hook injects Replay framing `raw_param`, so
  object agreement is only stub consistency. No driver-state transition,
  path, position or participant is inferred. Ignored evidence is under
  `artifacts/16_19_development/set_movement_driver_821/`. A combined selected
  CLI run on `KR_8392938200.rofl` returned 121 direct-input-turn and four
  SetMovementDriver rows, 125 unique decoded packets, zero framing errors.
- **Completed:** KR 821 `direct_input_movement_turn_packet` is wired to the
  selected CLI/API using the independently registered `0x00ba` route and
  exact-image native constructor/deserializer. Eight of 11 Replays contain
  8,463 packets in total; three have no route. The selected batch scanned
  18,235,209 blocks with zero framing errors and emitted 8,463 events; its
  aggregate `PARTIAL`/exit 1 reflects the three absent routes. The candidate
  emits only three anonymous callback-transformed f32 packet fields and raw
  provenance. The emulated base-parameter stub receives `raw_param` from
  Replay framing; object agreement is a stub-consistency check. The
  callback's driver-state write is conditional, so no world position, hero
  path or participant binding is claimed. Ignored probe evidence is under
  `artifacts/16_19_development/path821_route/`.
- **Completed:** KR 821 structure/objective damage keyframe candidates and
  exact-image CastSpellAns packet fields are available through selected CLI/API
  output. All 11 supplied KR Replays returned `CANDIDATE`: 3,270 damage
  snapshots and 63,496 CastSpellAns packet rows. A source-check cache reduced
  the same 19-snapshot batch from 4.94 to 3.63 seconds with identical event JSON.
- **Completed:** KR 821 `npc_buff_remove_packet` now selects the independently
  registered game-stream `0x047c` BuffRemove2 route. All 11 KR Replays returned
  `CANDIDATE`, with 139,457/139,457 exact-image native packets fully consumed,
  zero framing errors, and three callback-transformed anonymous fields in
  CLI/API JSONL. The 820 HN route and decoder remain separate.
- **Completed:** KR 821 `npc_buff_add_packet` now selects the independently
  registered game/keyframe `0x00ae` BuffAdd2 route. It emits only the
  callback-transformed anonymous u32 at object `0x10` and u8 at `0x14`,
  with exact image and per-packet native full-consumption gates. The 820 HN
  route and decoder remain separate. All 11 supplied KR Replays returned
  `CANDIDATE`: 346,098/346,098 native packets fully consumed, with zero
  framing errors and exact agreement with independently counted raw routes.
- **821 BuffAdd2 batch sizing:** The original `KR_8392938200` Replay has
  34,527 selected packets. A bounded 40,000-packet/8 MB native request now
  handles them in one launch; the 50,000-packet Replay limit and per-packet
  native checks remain. Before/after CLI JSONL files both contain 34,527 rows
  and have identical SHA-256
  `5ee4516fe702196a0e262053e93bd663eab85f10b905c7eccebae3d75ece4f50`.
  A local same-input native A/B measured 2,016 ms for two launches versus
  1,885 ms for one; this is a bounded single-Replay measurement.
- **Current:** Building versus turret labels, CastSpellAns field meanings, and
  all per-action interpretations remain candidate or unknown; no public
  capability was promoted.
- **Next:** Seek independent owner/spell or ward-identity anchors before
  interpreting packet fields as actions or placing wards on a map.
- **Blocked:** KR 821 ward spawn/position/owner remains unavailable. Surveyed
  routes occur in zero-increment ward windows. The exact HN 820 image remains
  absent. The exact 821 image's `OnPlaceWard`/`OnKillWard` child registrations
  (`0x00dd`/`0x00de`)
  have zero observed children among 86,604 fully consumed `0x040a` packets in
  the 11 supplied Replays, despite candidate HeroStats ward-counter increments.
  The static callbacks do not bind a Replay packet to a typed ward object;
  owner and coordinates remain `UNKNOWN`. The image/Replay hash recheck and
  negative controls are retained under ignored
  `artifacts/16_19_development/ward_anchor_followup_821/`.

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
- **821 BuffRemove2 packet candidate:** The exact image independently links
  `PKT_NPC_BuffRemove2_s` to callback RVA `0x008f2930`, factory route
  `0x047c`, constructor `0x00e9d240`, and deserializer `0x010dbc20`.
  The callback transforms object offsets `0x10` (u32), `0x14` (u8), and
  `0x18` (f32) through exact-image byte helpers. The selected CLI/API
  capability emits these as opaque packet fields with source references and
  requires the captured 821 image SHA-256. A strict 11-Replay batch emitted
  exactly 139,457 candidate rows, matching the independent raw route counts,
  with `MATCHED_USED` image status for every Replay. Across 41 observed
  stream/length shapes, one-byte truncation failed and an appended byte was
  not fully consumed. In one full Replay, every one of 3,833 distinct Remove
  `(u32, u8)` tuples occurred among independently decoded Add tuples, versus
  13 overlapping after an Add-token +1 control. That is only an opaque packet
  compatibility finding; no owner, buff identity, successful removal, duration,
  or lifecycle is inferred. Ignored evidence is under
  `artifacts/16_19_development/kr_821_buff_route_probe/` and the real CLI
  batch under `artifacts/16_19_development/kr_821_buff_remove_cli_11/`.
  Run the selected capability with `node src/cli.js batch <821-rofl-directory>
  --events npc_buff_remove_packet --runtime-image <captured-821-image>
  --event-jsonl-only --out-dir <output-directory>`.
- **821 BuffAdd2 packet candidate:** The exact image independently links
  `PKT_NPC_BuffAdd2_s` to callback RVA `0x008f2620`, factory route `0x00ae`,
  constructor `0x00e9cbd0`, and deserializer `0x010d88d0`. Callback byte
  transforms at `0x00873b80` and `0x00873df0` supply anonymous object
  offsets `0x10` (u32) and `0x14` (u8). The selected CLI/API capability
  requires the captured 821 image SHA-256, observed game/keyframe stream and
  length shapes, a matching native object and raw param, and full native
  consumption for every packet. A complete KR Replay gave 34,527/34,527
  fully consumed packets, and 584/584 first/last route-shape samples from
  all 11 Replays did likewise. All eight rare keyframe packets (seven length
  41, one length 42) fully consumed and matched their distinct one-element
  vector structures; each one-byte truncation failed and each appended byte
  remained unread. The selected 11-Replay CLI batch emitted 346,098 candidate
  rows (144,163 game, 201,935 keyframe), matching the independent raw route
  counts and Replay hashes, with `MATCHED_USED` image status for every Replay.
  Its local output is under
  `artifacts/16_19_development/kr_821_buff_add_cli_11/`. Vector elements
  stay opaque and are not emitted. The
  output assigns no owner, buff identity, application, duration or lifecycle.
  Ignored evidence is under
  `artifacts/16_19_development/kr_821_buff_route_probe/`.
  Run `node src/cli.js batch <821-rofl-directory> --events npc_buff_add_packet
  --runtime-image <captured-821-image> --event-jsonl-only
  --out-dir <output-directory>`.
- **821 opaque Buff key compatibility:** When both exact-image packet decoders
  succeed, CLI/API now emits a per-Replay
  `candidate_associations.npc_buff_add_remove_opaque_key` summary. In the
  independently decoded 11-Replay corpus, all 37,417 per-Replay distinct
  Remove `(opaque_u32_0x10, opaque_u8_0x14)` keys appear among Add rows;
  37,373 appear among game-stream Add rows and the remaining 44 only in keyframe Add
  snapshots. A shifted-u32 control overlaps only 162 distinct Remove keys.
  But 77 Remove rows have no preceding same-key game Add, 103,072 have
  multiple preceding game Adds, and 17,399 follow another same-key Remove
  without an intervening game Add. The summary makes no packet-row join and
  does not infer Buff identity, owner, target, successful application or
  removal, duration, or lifecycle. Missing/failed decoders yield
  `UNAVAILABLE`; keyframe Add snapshots are counted separately. The 11-Replay
  independent analysis and per-Replay JS/Python agreement are retained under
  ignored `artifacts/16_19_development/kr_821_buff_pair_evidence/`. The
  combined exact-image CLI batch also returned 11/11 `CANDIDATE` associations,
  11/11 `MATCHED_USED` image outcomes, and zero framing errors; its ignored
  output is `artifacts/16_19_development/kr_821_buff_pair_cli_11/`.
- **821 CastSpellAns dispatch key boundary:** In the pinned 821 mapped image,
  receive-side RVA `0x6ff3e0` reads native packet `+0x0c` (Replay `raw_param`)
  as an outer callback-registry lookup key, then uses packet `+0x08` for the
  inner route lookup. This is the same outer map populated by the `0x01da`
  `AIBaseClient` registration through RVA `0x711e90`; the registered key is
  read from the bound object's `this+0xbc`. The trace establishes the
  conditional registry lookup, not an observed hit for each Replay packet.
  The captured image contains the client module but not the heap registry,
  and capture metadata does not name the playing Replay. Registered keys,
  per-packet bound receivers, caster and participant identity remain
  `UNKNOWN`; no CastSpellAns actor field was added. Exact-image assembly,
  scripts, Replay controls, and the negative boundary are retained under
  ignored `artifacts/16_19_development/kr_821_cast_identity_probe/`.
- **821 CastSpellAns callback field boundary:** The exact-image callback
  transforms packet `+0x14c` into the existing opaque i32 and passes it to a
  conditional receiver-state comparison at RVA `0x32db20`. Exact-image Unicorn
  positive and negative controls verified its compare/write behavior. The
  callback also converts nested `+0xe0` and `+0x140` into a temporary object;
  this does not identify their gameplay meanings. Current source hashes and
  63,496 existing CLI rows were rechecked across all 11 KR Replays. The i32
  is nonzero in 435 rows, all keyframe; it is zero in all 62,968 game rows.
  The i32 and nested float are not a one-to-one presence pair. The captured
  image lacks the receiver heap, so per-packet gate outcomes, actor, spell and
  action remain `UNKNOWN`. Scripts, callback bytes and controls are retained
  under ignored `artifacts/16_19_development/castspellans_followup_821/`.
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
- **821 standard `MINIONS_KILLED` keyframe candidate:** The exact 821 native
  `0x0089` vector has an integral `f32LE` field at offset `0x3c` across all
  3,270 hero packets from 327 keyframes in 11 KR Replays. All 110 participant
  sequences start at zero, are nonnegative and monotone, and stay at or below
  their own numeric Replay-tail `MINIONS_KILLED`. Last snapshots equal 73/110
  matching tails; the retained aggregate gap is 164 and the largest gap is 18.
  An aligned scan of 1,260 `u32LE`/`u16LE`/`f32LE` offset-type combinations
  places this field first among zero-start, monotone, tail-bounded nonconstant
  candidates (mean final gap 1.49 versus 11.5 for the next candidate). Nine
  participant rotations yield at most 4 exact matches. As a negative control,
  the same `0x3c` value matches the distinct `Missions_MinionsKilled` tail for
  only 2/110 and exceeds it for 104/110; conversely the mission field at
  `0x378` matches standard `MINIONS_KILLED` for 0/110. This is an exploratory
  corpus, not a protected holdout. `--events hero_minions_killed_snapshot`
  now emits cumulative `CANDIDATE` snapshots and retains final tail gaps,
  without inferring individual last hits. The combined standard/mission
  11-Replay CLI batch returned 11/11 `CANDIDATE`, 3,270 events for each,
  zero errors and zero framing errors. Reproducible ignored evidence is under
  `artifacts/16_19_development/minions821_tail_field/`.
- **821 three neutral-minion keyframe candidates:** Independent exact-821
  transformed-vector scans identify f32LE offsets `0x40/0x44/0x48` against
  `NEUTRAL_MINIONS_KILLED`, `NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE`, and
  `NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE`. All three have 110/110 finite,
  zero-start, monotone, tail-bounded participant series across 3,270 packets.
  Last floored snapshots equal 102/110, 103/110, and 108/110 numeric tails;
  aggregate retained gaps are 31, 27, and 2. Fractional raw f32 values are
  preserved. The selected CLI/API capability emits only `CANDIDATE`
  snapshots; it does not infer individual kills, monster identity, or location.
  The exact-build 11-Replay CLI batch returned 11/11 `CANDIDATE`, 3,270
  records, and zero framing errors. Scans, controls, and local output remain
  ignored under `artifacts/16_19_development/jungle821_field/`.
- **821 six kill-stat keyframe candidates:** An independent exact-821
  transformed-vector scan identifies aligned slots `0x58..0x6c` against
  `LARGEST_KILLING_SPREE`, `KILLING_SPREES`, `LARGEST_MULTI_KILL`,
  `DOUBLE_KILLS`, `TRIPLE_KILLS`, and `QUADRA_KILLS`. All 110 participant
  sequences per field start at zero, remain monotone, and stay within their
  numeric Replay tails. Final matches are 102/106/108/107/110/110 of 110;
  retained aggregate gaps are 10/4/2/3/0/0. `QUADRA_KILLS` has only one
  positive participant, so its field label is especially sparse; PENTA and
  UNREAL are not exposed because this corpus has no positive tails. The
  selected CLI/API emits only cumulative `CANDIDATE` snapshots, with no
  individual kill or attribution inference. The 11-Replay CLI batch returned
  11/11 `CANDIDATE`, 3,270 records, and zero framing errors. Reproducible
  scan, controls, and local output are ignored under
  `artifacts/16_19_development/killstats821_field/`.
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
  observations, not a continuous inventory state. The exact-image callback
  (`0x350240` trampoline to `0x354c60`) first clears client slots 0–9 through
  `0x2925f0`/`0x5e5400`, then applies the packet records. The CLI/API now
  reports `snapshot_application: RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS` as a
  candidate callback action. Among 560 consecutive canonical participant packet
  pairs, 146 omit a slot present in the preceding packet; this is a difference
  between sparse observations, not evidence of a particular item action. For
  52 last packets within 120 seconds of game end, slots 0–6 including omitted
  slots as empty match the independent Replay tail 345/364 times; participant
  rotation controls match 21–56/364, and all 19 mismatches remain negative
  evidence. Of the 671 packets, 607 are co-timed with a `0x0048` return and
  64 are not; 669 use the ten canonical raw params, while the two
  `0x400001b2/b5` variants remain unmapped. These counts describe different
  partitions of the same packets.
  The CLI/API route requires the exact local image and emits packet records and
  callback application only; no purchase, sale, item-use, between-packet state,
  or final-state inference follows.
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
  For `TOTAL_UNITS_HEALED`, the sole final mismatch is participant 1 in
  `KR_8392938200`: all 33 snapshots have `0x23c = 1`, and the last is
  57,919 ms before the Replay tail value of 5. Other participant-1 counters
  agree with the tail, so changing the participant assignment does not
  resolve this gap; no late healing event is directly observed.
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
- **Artifact event query:** `node src/cli.js query-events <replay-or-batch-artifact-directory>
  --event <exact-event-key> [--from-ms n] [--to-ms n] [--participant 1..10]
  [--raw-param uint32|0xhex] [--limit n] [--output path|-]` streams unchanged
  candidate JSONL rows from
  either default or `--event-jsonl-only` 16.19 CLI artifacts. A batch root with
  `manifest.json` streams its Replay artifacts in manifest order with a global
  output limit, per-Replay availability, and `PARTIAL` status when some Replay
  capability streams are unavailable. No queryable Replay is an error, not zero.
  It checks Replay
  identity and declared row counts, reports the original capability status and
  separate scanned/matched/emitted counts, and leaves unknown participants
  unselected by the participant filter. The raw-parameter filter matches an
  exact recorded packet parameter without treating it as an actor identity;
  streams without recorded parameters report `RAW_PARAM_UNAVAILABLE`. Real HN
  queries scanned 270 JSONL-only
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
- **821 team-visibility route stop-loss:** The pinned image registers numeric
  route `0x021b` with `PKT_S2C_OnEnterTeamVisibility_s` and a callback that
  reads object `+0x10`. Across all 11 exact-build KR Replays, 6,192,525
  packets have two-byte payloads: 3,104,065 `1b03` and 3,088,460 `1b50`,
  with zero framing errors. Native deserialization of both original payload
  shapes reaches a pointer to process heap omitted from the captured module
  image, so neither has a full-consumption or decoded-field witness. A wrong
  selector returns success after consuming only one of two bytes. No field or
  event is emitted. A same-build heap capture or live packet callback trace,
  including both payloads and truncation/append controls, is needed to reopen
  this route. Actual visibility, actor, ward and map meaning remain unknown.
  Counts, packet references and the failed native probe are retained under
  ignored `artifacts/16_19_development/visibility_021b_821/`.
- **821 ChangeSlotSpellData route stop-loss:** Strict framing across the 11
  exact-build KR Replays found 107,059 packets at numeric route `0x049c` over
  38 observed payload lengths. In a read-only pinned-image survey, two
  representatives per length yielded full native consumption for 62/76;
  representatives from seven lengths reached an emulator invalid-instruction
  error. This is an incomplete native witness, not proof that those Replay
  packets are invalid. No field or event is emitted. The unsupported native
  path and all observed lengths need a full-consumption witness before this
  route can be added.
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
