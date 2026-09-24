# 16.19 development progress

Updated: 2026-09-24. Branch: `codex/16-19-development`.

- **Done:** The HN `16.19.820.7193` replay's 107 chunks and 2,035,757 blocks
  pass strict container/framing inspection with zero errors. The main CLI/API now
  select `hero_death` explicitly and write separate candidate victim/time records,
  with 88 HN, 64 KR and 51 KR events on three exact-build replays. Each run
  requires a matching route triad and all ten final death-count invariants.
- **Capability query:** `node src/cli.js capabilities <file.rofl> [--json]`
  reports the exact build's registered capabilities and known missing inputs
  from container metadata without decompressing packet chunks or using a runtime
  image. It labels 16.19 `hero_death` as unpublished `CANDIDATE` and leaves
  route and death-count validation pending until decode.
- **Current:** The captured exact HN runtime identifies candidate route `0x04d9`
  as `PKT_NPC_Hero_Die_s` and `0x02d6` as `PKT_S2C_UpdateDeathTimer_s`.
  Trace the latter's decoded fields against raw replay bytes before using them
  as a death-timer capability; keep victim mapping experimental. The local,
  unpacked runtime image SHA-256 is
  `7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d`;
  the image is not an input to the current candidate decoder.
- **Next:** Recover a bounded death-timer field or choose another viable 16.19
  field, then connect it to the same selected-capability CLI/API path.
- **Blocked proof:** Timer units and the victim identifier in the death-timer
  packet are unverified. The separate Riot client is `16.19.821.7343` and
  cannot supply the `16.19.820.7193` decoder image.

Research outputs, original replay data, and client binaries remain local and
outside Git. The 2026-08-21 published semantic baseline remains historical.
