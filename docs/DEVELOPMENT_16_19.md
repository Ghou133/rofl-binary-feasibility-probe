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
- **Next:** Seek a matching KR runtime to resolve its timer field, or independent
  HN Replays to test the candidate level field and participant mapping.
- **Blocked proof:** Broader timer validation and candidate victim mapping need
  independent replay evidence. The separate Riot client is `16.19.821.7343`
  and cannot supply a `16.19.820.7193` decoder image.

Research outputs, original replay data, and client binaries remain local and
outside Git. The 2026-08-21 published semantic baseline remains historical.
