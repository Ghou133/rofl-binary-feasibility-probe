# 16.19 development progress

Updated: 2026-09-24. Branch: `codex/16-19-development`.

- **Done:** The HN `16.19.820.7193` replay's 107 chunks and 2,035,757 blocks
  pass strict container/framing inspection with zero errors. The main CLI/API now
  select `hero_death` explicitly and write separate candidate victim/time records,
  with 88 HN, 64 KR and 51 KR events on three exact-build replays. Each run
  requires a matching route triad and all ten final death-count invariants.
- **Capability query:** `node src/cli.js capabilities <file.rofl> [--json]`
  reports the exact build's registered capabilities and checks required tail
  `NUM_DEATHS`/`LEVEL` fields without decompressing packet chunks or using a runtime
  image. It labels 16.19 `hero_death` and `hero_death_timer` as unpublished
  `CANDIDATE` and leaves route and death-count validation pending until decode.
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
  CHAMPIONS_KILLED, NUM_DEATHS and ASSISTS HeroStats candidates together shares one
  keyframe collection and retains separate field validation and results. The
  16.19 CLI reuses its raw-analysis walk for that collection; a compressed
  synthetic keyframe now decompresses once instead of twice. It also reuses
  that walk for selected game-route candidates, avoiding a second game-stream
  scan. A mixed compressed game/keyframe test decompresses each chunk once;
  malformed framing suppresses candidate output. Standalone API calls still
  perform their own strict walk. Both candidate route collectors check the
  Replay source bytes and chunk layout before publishing copied packet refs.
  On the exact HN Replay, the six earlier
  death/timer/respawn/level/CS/EXP candidate JSONL files remain byte-identical
  after game-scan reuse. The KR Replay retains its death candidate and reports
  `PROFILE_UNAVAILABLE` for the HN-only selections.
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
- **Current:** Candidate participant identity, timer and respawn meaning are bounded to
  one HN Replay; KR uses different death/timer route IDs and reports
  `PROFILE_UNAVAILABLE` for the HN timer profile. Eleven raw KR `0x0357`
  packets remain unclassified without that profile. No confirmed death, timer
  or respawn event is emitted.
- **KR lead:** In exact-build `KR_8391528229` and `KR_8391542020`, all 115
  `0x0259` death-triad packets reject the HN timer transform. All 104 packets
  on route `0x0048` pair with a pending candidate victim and a plausible
  death-to-reincarnation delay, but the KR timer float transform and route name
  are unverified. The KR Replay SHA-256 values are
  `3f29ae2127ef75888baf1f4543d0790cc9c40d9df0197e73b2b16b3c799dd93c`
  and `2d7a53f76e11059ac00a45706d32ca19300d33dabca2d97bde99775c22062e1b`.
- **KR negative control:** A table learned from the first KR Replay covers only
  14/58 paired cases there and 22/46 in the second; all covered timing
  residuals are at most 35 ms. The other codewords are unaccounted for, so
  neither a general KR timer transform nor route `0x0048` identity is claimed.
- **HeroStats KR control:** One KR Replay has 19,698 keyframe `0x0276` packets
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
- **Done:** `--events hero_inventory_mapview --runtime-image <exact-image>`
  runs the pinned HN `0x0420` MapView constructor/deserializer and emits only
  observed slot/item-definition-key records as candidates. All 94 game packets
  in the HN Replay returned success with full payload consumption, yielding
  732 records. The last MapView packets for three participants are within
  3.4–7.4 seconds of game end and their 21 slots 0–6 match Replay-tail
  `ITEM0`–`ITEM6` exactly. This remains one-Replay evidence; a changed valid
  raw param can decode the same payload, so participant mapping stays a
  candidate bound to the original packet ref. A truncated payload fails; KR
  has no HN `0x0420` game route. No full inventory state or item transaction
  is inferred. Missing or wrong images affect only this selected capability.
- **Done:** `--events hero_inventory_set_item --runtime-image <exact-image>`
  runs the pinned HN `0x03b7` SetItem constructor/deserializer. All 16
  seven-byte game packets returned success with full consumption, yielding
  slot 8, flag 1 and item keys 1200–1204. The ten initial hero-param packets
  match their first MapView slot-8 item keys 10/10. The six later packets
  repeat existing values; one has raw param `0x400001b7` and no participant
  candidate. A truncated packet fails, while changing only its raw param does
  not change decoded slot/item fields. This supplies observed packet fields,
  not a purchase, sale, transition, or general participant mapping.
- **Next:** Seek a matching KR runtime to resolve its timer field, and independent
  HN Replays to test level, HeroStats and inventory candidates. The HN
  Broadcast `0x03ef` vector reaches ten records but its record parser still
  depends on runtime TLS state; no record decoder is published for it.
  Movement-route research still needs a position-field link.
- **Path negative control:** The exact HN image identifies `0x03ee` as
  DirectInputMovementDriverServerTurnData (84 HN packets in one short interval),
  `0x0160` as SetMovementDriver (4), `0x04dd` as AddFollowTargetPosition (0),
  and `0x00d2` as SyncCircularMovementRestriction (7,023; 7,013 one-byte).
  None establishes an ordinary hero-coordinate stream. The old 16.16 path
  opcode `0x00f6` has a 16.19 factory object size `0x18`, not the old `0x2c`
  layout. A path candidate still needs an exact observed receive/field-write
  link and independent position anchors; no old profile is reused.
- **Ward negative control:** Old 16.16 WardSpawn opcode `0x049a` is not an HN
  16.19 factory case and has no packets in this Replay. The HN `0x0400` case
  has 6,627 packets and a distinct runtime deserializer, but no observed link
  to ward identity, owner or coordinates; no ward candidate is emitted.
- **CLI batch:** A two-Replay HN/KR run with death, respawn and level selection
  yielded HN `CANDIDATE`, KR `PARTIAL`, and aggregate `PARTIAL`, retaining the
  KR death candidate while reporting the HN-only capabilities unavailable.
- **Blocked proof:** Broader timer validation and candidate victim mapping need
  independent replay evidence. The separate Riot client is `16.19.821.7343`
  and cannot supply a `16.19.820.7193` decoder image.

Research outputs, original replay data, and client binaries remain local and
outside Git. The 2026-08-21 published semantic baseline remains historical.
