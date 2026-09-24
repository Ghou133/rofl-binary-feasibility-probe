'use strict';

const crypto = require('node:crypto');

const { analyzeReplay } = require('../analysis');
const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');

const REPLAY_VERSION = '16.19.820.7193';
const PACKET_ID = 0x0276;
const HERO_PARAM_FIRST = 0x400000ae;
const HERO_PARAM_LAST = 0x400000b7;
const BLOB_LENGTH = 1260;
const PAYLOAD_LENGTH = BLOB_LENGTH + 3;
const EXPERIENCE_OFFSET = 0x28;
const GOLD_SPENT_OFFSET = 0x34;
const GOLD_EARNED_OFFSET = 0x38;
const MINIONS_KILLED_OFFSET = 0x3c;
const JUNGLE_MINIONS_KILLED_OFFSET = 0x40;
const YOUR_JUNGLE_MINIONS_KILLED_OFFSET = 0x44;
const ENEMY_JUNGLE_MINIONS_KILLED_OFFSET = 0x48;
const CHAMPION_KILLS_OFFSET = 0x4c;
const DEATHS_OFFSET = 0x50;
const ASSISTS_OFFSET = 0x54;
const CHAMPION_KILLS_MIRROR_OFFSET = 0x33c;
const RUNTIME_IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const LOOKUP_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const HERO_STATS_SNAPSHOT_CAPABILITIES = Object.freeze([
  'hero_minions_killed_snapshot',
  'hero_jungle_minions_killed_snapshot',
  'hero_experience_snapshot',
  'hero_gold_earned_snapshot',
  'hero_gold_spent_snapshot',
  'hero_champion_kills_snapshot',
  'hero_deaths_snapshot',
  'hero_assists_snapshot',
]);
const HERO_STATS_SNAPSHOT_CAPABILITY_SET = new Set(HERO_STATS_SNAPSHOT_CAPABILITIES);
const PRECOLLECTED_SCAN_SOURCE = new WeakMap();

// Exact 256-byte table at RVA 0x1ba7600 of the captured 16.19.820.7193 image.
// The deserializer at RVA 0xf33290 uses this table before reversing the blob.
const LOOKUP_TABLE = Buffer.from([
  'd75682dc83028f2935042171799e927fcb976a5105c76fe640637e345b470778',
  '5a96b8b92c995e6ed1754161245f4aaa4bcf0ed4865dba1d3f2bdf62f0330055',
  'cafc19acf3662369bceb46f89c50874d6d108e88be1bb5da4e1a13cc2209ada4',
  '9d30a6e57dfac91712c2fde1bbe70b98bfbd1137c07cf795b6dd49f4812a9f1c',
  'fb8d9a727b577a43b3a953e459202fa8f67436a085f1a7147031840cb2a5dbe8',
  '16ae3d25b1cd9b0367155cea1f39a1440a8b76de606593f264d5c1c84c064fb7',
  'edfee0f9a2184891ce1e3cb46c425494e328e90127ec0d45ff26efe28aabd9f5',
  '08c4af32c56b80c6c358eea33e2d0f893ab0d2d33873d8d08c7790523bd62e68',
].join(''), 'hex');

if (LOOKUP_TABLE.length !== 256
  || crypto.createHash('sha256').update(LOOKUP_TABLE).digest('hex') !== LOOKUP_TABLE_SHA256) {
  throw new Error('exact-build HeroStats lookup table identity mismatch');
}

const HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-minions-killed-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_minions_killed_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  minions_killed_f32le_offset: MINIONS_KILLED_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN runtime HeroStats deserializer and one HN Replay with 350 keyframe snapshots',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no minion kill event or intervening value is inferred.',
    'The offset 0x3c interpretation and hero participant mapping remain candidates from one HN Replay.',
    'The Replay tail can exceed the last observed snapshot; tail gaps are reported without interpolation.',
  ]),
});

const HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-jungle-minions-killed-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_jungle_minions_killed_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  jungle_minions_killed_f32le_offset_candidate: JUNGLE_MINIONS_KILLED_OFFSET,
  your_jungle_minions_killed_f32le_offset_candidate: YOUR_JUNGLE_MINIONS_KILLED_OFFSET,
  enemy_jungle_minions_killed_f32le_offset_candidate: ENEMY_JUNGLE_MINIONS_KILLED_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN HeroStats route and transform; offsets 0x40/0x44/0x48 correlate after flooring with three neutral-minion Replay tails in one HN Replay with 350 keyframe snapshots',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no neutral-minion kill event, type, location, or intervening value is inferred.',
    'The three decoded f32 fields are fractional in this Replay; their integer floors are derived candidates, not stored integer fields.',
    'The offset interpretations and hero participant mapping remain candidates from one HN Replay, not exact-runtime field semantics.',
    'Zero integer tail gaps do not exclude unobserved fractional changes after the last keyframe.',
  ]),
});

const HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-experience-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_experience_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  experience_f32le_offset_candidate: EXPERIENCE_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN runtime HeroStats deserializer; offset 0x28 correlates with EXP in one HN Replay with 350 keyframe snapshots',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no experience-gain event or intervening value is inferred.',
    'The offset 0x28 experience interpretation and hero participant mapping remain candidates from one HN Replay, not exact-runtime field semantics.',
    'The Replay tail can exceed the last observed floor(snapshot); tail gaps are reported without interpolation.',
  ]),
});

const HERO_GOLD_EARNED_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-gold-earned-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_gold_earned_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  gold_earned_f32le_offset_candidate: GOLD_EARNED_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN runtime HeroStats deserializer; offset 0x38 correlates with GOLD_EARNED in one HN Replay with 350 keyframe snapshots',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no income event or intervening value is inferred.',
    'The offset 0x38 gold-earned interpretation and hero participant mapping remain candidates from one HN Replay, not exact-runtime field semantics.',
    'The Replay tail can exceed the last observed snapshot; the float difference is reported without interpolation.',
  ]),
});

const HERO_GOLD_SPENT_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-gold-spent-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_gold_spent_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  gold_spent_f32le_offset_candidate: GOLD_SPENT_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN runtime HeroStats deserializer; offset 0x34 correlates with GOLD_SPENT in one HN Replay with 350 keyframe snapshots',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no purchase, refund, sale, or other transaction is inferred.',
    'The offset 0x34 gold-spent interpretation and hero participant mapping remain candidates from one HN Replay, not exact-runtime field semantics.',
    'Observed declines and signed tail-minus-last differences are retained without behavioral explanation or interpolation.',
  ]),
});

const HERO_CHAMPION_KILLS_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-champion-kills-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_champion_kills_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  champion_kills_u32le_offset_candidate: CHAMPION_KILLS_OFFSET,
  champion_kills_mirror_u32le_offset_candidate: CHAMPION_KILLS_MIRROR_OFFSET,
  storage_offset_status: 'AMBIGUOUS_MIRRORED_COPIES_ONE_REPLAY',
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN HeroStats route and transform; two equal offsets in all 350 snapshots of one HN Replay, with final CHAMPIONS_KILLED tail comparison',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no champion kill event or intervening value is inferred.',
    'Decoded offsets 0x4c and 0x33c mirror in one HN Replay; the unique storage offset and participant mapping remain candidates.',
    'The Replay tail can exceed the last observed snapshot; tail gaps are reported without interpolation.',
  ]),
});

const HERO_DEATHS_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-deaths-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_deaths_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  deaths_u32le_offset_candidate: DEATHS_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN HeroStats route and transform; offset 0x50 matches 350 observed keyframe death-candidate cumulative counts in one HN Replay',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no death event or intervening count is inferred.',
    'The one-Replay death-candidate timing match shares the candidate participant mapping and is not independent validation or exact-runtime field semantics.',
    'The Replay tail can exceed the last observed snapshot; tail gaps are reported without interpolation.',
  ]),
});

const HERO_ASSISTS_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-assists-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_assists_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  assists_u32le_offset_candidate: ASSISTS_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN HeroStats route and transform; offset 0x54 has 350 nonnegative, initially zero, monotonic snapshots bounded by ASSISTS tail in one HN Replay; 8 of 10 last snapshots equal tail and two have gap 1',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no assist event, time, attribution, or intervening count is inferred.',
    'The offset 0x54 interpretation and hero participant mapping remain candidates from one HN Replay; there is no independent assist event anchor or exact-runtime field semantics.',
    'The Replay tail can exceed the last observed snapshot; tail gaps are reported without interpolation.',
  ]),
});

function decodeHeroStatsByte(encoded) {
  const x = LOOKUP_TABLE[encoded];
  let y = (((x & 0xd5) << 1) | ((x >>> 1) & 0x55)) & 0xff;
  y = ((y >>> 5) | (y << 3)) & 0xff;
  y = (y + 0x7e) & 0xff;
  return ((~y) - 0x5a) & 0xff;
}

function decodeHeroStatsBlob(payload) {
  if (!Buffer.isBuffer(payload) || payload.length !== PAYLOAD_LENGTH) {
    return { status: 'DECODE_FAILED', error: `HeroStats payload must contain exactly ${PAYLOAD_LENGTH} bytes` };
  }
  if (payload[0] !== 0x1c || payload[1] !== 0xa6 || payload[2] !== 0xe8) {
    return { status: 'DECODE_FAILED', error: 'HeroStats selector or encoded varint prefix differs from the exact HN profile' };
  }
  const firstVarintByte = decodeHeroStatsByte(payload[1]);
  const secondVarintByte = decodeHeroStatsByte(payload[2]);
  if ((firstVarintByte & 0x80) === 0 || (secondVarintByte & 0x80) !== 0
    || ((firstVarintByte & 0x7f) | (secondVarintByte << 7)) !== BLOB_LENGTH) {
    return { status: 'DECODE_FAILED', error: 'HeroStats decoded varint length differs from the exact HN profile' };
  }
  const blob = Buffer.allocUnsafe(BLOB_LENGTH);
  for (let index = 0; index < BLOB_LENGTH; index += 1) {
    blob[BLOB_LENGTH - 1 - index] = decodeHeroStatsByte(payload[index + 3]);
  }
  return { status: 'PASS', blob };
}

function decodeHeroMinionsKilledPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const value = decoded.blob.readFloatLE(MINIONS_KILLED_OFFSET);
  if (!Number.isSafeInteger(value) || value < 0) {
    return { status: 'DECODE_FAILED', error: 'HeroStats offset 0x3c is not a finite nonnegative integer f32' };
  }
  return { status: 'PASS', minions_killed_candidate: value };
}

function decodeHeroJungleMinionsKilledPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const values = [
    decoded.blob.readFloatLE(JUNGLE_MINIONS_KILLED_OFFSET),
    decoded.blob.readFloatLE(YOUR_JUNGLE_MINIONS_KILLED_OFFSET),
    decoded.blob.readFloatLE(ENEMY_JUNGLE_MINIONS_KILLED_OFFSET),
  ];
  if (values.some((value) => !Number.isFinite(value) || value < 0
    || !Number.isSafeInteger(Math.floor(value)))) {
    return { status: 'DECODE_FAILED',
      error: 'HeroStats jungle offsets 0x40/0x44/0x48 must be finite nonnegative safe-range f32 values' };
  }
  return {
    status: 'PASS',
    jungle_minions_killed_raw_f32_candidate: values[0],
    jungle_minions_killed_floor_candidate: Math.floor(values[0]),
    your_jungle_minions_killed_raw_f32_candidate: values[1],
    your_jungle_minions_killed_floor_candidate: Math.floor(values[1]),
    enemy_jungle_minions_killed_raw_f32_candidate: values[2],
    enemy_jungle_minions_killed_floor_candidate: Math.floor(values[2]),
  };
}

function decodeHeroExperiencePayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const value = decoded.blob.readFloatLE(EXPERIENCE_OFFSET);
  if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(Math.floor(value))) {
    return { status: 'DECODE_FAILED', error: 'HeroStats offset 0x28 is not a finite nonnegative safe-range f32 experience candidate' };
  }
  return { status: 'PASS', experience_points_candidate: value,
    experience_floor_candidate: Math.floor(value) };
}

function decodeHeroGoldEarnedPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const value = decoded.blob.readFloatLE(GOLD_EARNED_OFFSET);
  if (!Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    return { status: 'DECODE_FAILED', error: 'HeroStats offset 0x38 is not a finite nonnegative safe-range f32 gold-earned candidate' };
  }
  return { status: 'PASS', gold_earned_candidate: value };
}

function decodeHeroGoldSpentPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const value = decoded.blob.readFloatLE(GOLD_SPENT_OFFSET);
  if (!Number.isSafeInteger(value) || value < 0) {
    return { status: 'DECODE_FAILED', error: 'HeroStats offset 0x34 is not a finite nonnegative safe integer f32 gold-spent candidate' };
  }
  return { status: 'PASS', gold_spent_candidate: value };
}

function decodeHeroChampionKillsPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const value = decoded.blob.readUInt32LE(CHAMPION_KILLS_OFFSET);
  const mirror = decoded.blob.readUInt32LE(CHAMPION_KILLS_MIRROR_OFFSET);
  if (value !== mirror) {
    return { status: 'DECODE_FAILED',
      error: 'HeroStats champion-kills candidate offsets 0x4c and 0x33c disagree' };
  }
  return { status: 'PASS', champion_kills_candidate: value };
}

function decodeHeroDeathsPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  return { status: 'PASS', deaths_candidate: decoded.blob.readUInt32LE(DEATHS_OFFSET) };
}

function decodeHeroAssistsPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  return { status: 'PASS', assists_candidate: decoded.blob.readUInt32LE(ASSISTS_OFFSET) };
}

function assessHeroStatsTail(replay, field) {
  const stats = replay?.tail?.stats;
  if (!Array.isArray(stats)) {
    return { field, status: 'MISSING_INPUT',
      error: 'Replay tail statsJson participant rows are missing' };
  }
  if (stats.length !== 10) {
    return { field, status: 'UNSUPPORTED',
      error: `candidate scope requires 10 participants; got ${stats.length}` };
  }
  const rawValues = stats.map((row) => row?.[field]);
  if (rawValues.some((value) => value === undefined || value === null || value === '')) {
    return { field, status: 'MISSING_INPUT',
      error: `Replay tail ${field} is missing for one or more participants` };
  }
  if (rawValues.some((value) =>
    !(typeof value === 'string' && /^\d+$/.test(value))
    && !(Number.isSafeInteger(value) && value >= 0))) {
    return { field, status: 'UNSUPPORTED',
      error: `Replay tail ${field} must be nonnegative integers` };
  }
  const values = rawValues.map(Number);
  if (values.some((value) => !Number.isSafeInteger(value))) {
    return { field, status: 'UNSUPPORTED',
      error: `Replay tail ${field} must be safe integers` };
  }
  return { field, status: 'PASS', values };
}

function assessHeroMinionsKilledSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'MINIONS_KILLED');
}

function assessHeroJungleMinionsKilledSnapshotTail(replay) {
  const assessments = [
    assessHeroStatsTail(replay, 'NEUTRAL_MINIONS_KILLED'),
    assessHeroStatsTail(replay, 'NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE'),
    assessHeroStatsTail(replay, 'NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE'),
  ];
  const failure = assessments.find((row) => row.status !== 'PASS');
  if (failure) return { ...failure, required_fields: assessments };
  return { ...assessments[0], required_fields: assessments,
    yourJungleValues: assessments[1].values,
    enemyJungleValues: assessments[2].values };
}

function assessHeroExperienceSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'EXP');
}

function assessHeroGoldEarnedSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'GOLD_EARNED');
}

function assessHeroGoldSpentSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'GOLD_SPENT');
}

function assessHeroChampionKillsSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'CHAMPIONS_KILLED');
}

function assessHeroDeathsSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'NUM_DEATHS');
}

function assessHeroAssistsSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'ASSISTS');
}

function packetRef(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function finalizeHeroStatsRows(replay, rows, scannedBlockCount) {
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { status: 'UNSUPPORTED', scanned_block_count: null };
  }
  if (rows.length === 0) {
    return { status: 'PROFILE_UNAVAILABLE', scanned_block_count: scannedBlockCount,
      error: 'HN HeroStats 0x0276 keyframe route is absent from this Replay' };
  }
  const hasHnFingerprint = rows.some(({ block }) => block.payload_length === PAYLOAD_LENGTH
    && block.payload[0] === 0x1c && block.payload[1] === 0xa6 && block.payload[2] === 0xe8);
  if (!hasHnFingerprint) {
    return { status: 'PROFILE_UNAVAILABLE', scanned_block_count: scannedBlockCount,
      observed_raw_route_count: rows.length,
      error: '0x0276 keyframe route is present, but no packet matches the exact HN HeroStats payload fingerprint' };
  }
  rows.sort((left, right) => left.block.timestamp_ms - right.block.timestamp_ms
    || (left.block.param >>> 0) - (right.block.param >>> 0)
    || left.chunk.index - right.chunk.index || left.block.offset - right.block.offset);
  return { status: 'PASS', scanned_block_count: scannedBlockCount, rows };
}

function replayWithStableChunks(replay) {
  // Capture the parsed chunk list once. The strict walk and source check use
  // the same list, including when a caller exposes chunks through a getter.
  const scanReplay = Object.create(replay);
  Object.defineProperty(scanReplay, 'chunks', { value: replay.chunks });
  return scanReplay;
}

function scanHeroStatsRows(replay) {
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { status: 'UNSUPPORTED', scanned_block_count: null };
  }
  const scanReplay = replayWithStableChunks(replay);
  const sourceError = replaySourceError(scanReplay);
  if (sourceError) {
    return { status: 'DECODE_FAILED', scanned_block_count: null,
      error: `Replay source failed: ${sourceError}` };
  }
  const rows = [];
  let walk;
  try {
    walk = walkBlocks(scanReplay, (block, chunk) => {
      if (block.packet_id === PACKET_ID) rows.push({ block, chunk });
    }, { includeStreams: [2, 3], strict: true });
  } catch (error) {
    return { status: 'DECODE_FAILED', scanned_block_count: null,
      error: `Replay keyframe framing failed: ${error.message}` };
  }
  return finalizeHeroStatsRows(replay, rows, walk.block_count);
}

function createHeroStatsScanCollector(replay, scanReplay = replay) {
  if (!replay || typeof replay !== 'object') {
    throw new TypeError('HeroStats scan collector requires a Replay object');
  }
  const source = {
    replay,
    source_path: replay.source_path ?? null,
    source_sha256: replay.source_sha256 ?? null,
    version: replay.header?.version ?? null,
  };
  const rows = [];
  let keyframeBlockCount = 0;
  let finished = false;
  return Object.freeze({
    observe(block, chunk) {
      if (finished) throw new Error('HeroStats scan collector is already finished');
      if (chunk?.stream_tag !== 2 && chunk?.stream_tag !== 3) return;
      keyframeBlockCount += 1;
      if (block?.packet_id !== PACKET_ID) return;
      if (!Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length) {
        throw new TypeError('HeroStats observed block payload is invalid');
      }
      // Copy only selected keyframe payloads so later reuse does not retain
      // whole decompressed chunks or depend on caller mutation.
      rows.push({
        block: {
          offset: block.offset,
          payload_offset: block.payload_offset,
          payload_length: block.payload_length,
          payload: Buffer.from(block.payload),
          timestamp_ms: block.timestamp_ms,
          packet_id: block.packet_id,
          param: block.param,
        },
        chunk: {
          index: chunk.index,
          chunk_id: chunk.chunk_id,
          stream: chunk.stream,
          offset: chunk.offset,
        },
      });
    },
    finish(expectedKeyframeBlockCount) {
      if (finished) throw new Error('HeroStats scan collector is already finished');
      if (expectedKeyframeBlockCount !== undefined
        && (!Number.isSafeInteger(expectedKeyframeBlockCount)
          || expectedKeyframeBlockCount !== keyframeBlockCount)) {
        throw new RangeError('HeroStats expected keyframe block count differs from observed framing');
      }
      finished = true;
      const sourceError = replaySourceError(scanReplay);
      const scan = sourceError
        ? { status: 'DECODE_FAILED', scanned_block_count: keyframeBlockCount,
          error: `Replay source failed: ${sourceError}` }
        : finalizeHeroStatsRows(replay, rows, keyframeBlockCount);
      const token = Object.freeze({
        status: scan.status,
        scanned_block_count: scan.scanned_block_count,
        ...(scan.observed_raw_route_count === undefined ? {}
          : { observed_raw_route_count: scan.observed_raw_route_count }),
      });
      PRECOLLECTED_SCAN_SOURCE.set(token, { ...source, scan });
      return token;
    },
  });
}

function analyzeReplayWithHeroStats(replay, options = {}, afterBlock = null) {
  if (afterBlock !== null && typeof afterBlock !== 'function') {
    throw new TypeError('HeroStats additional block observer must be a function');
  }
  const scanReplay = replayWithStableChunks(replay);
  const collector = createHeroStatsScanCollector(replay, scanReplay);
  // The observer is owned by this function and only receives blocks from the
  // full analyzer walk. Copy the HeroStats bytes before another observer sees
  // them; neither collector exposes a source of forgeable packet refs.
  const analysis = analyzeReplay(scanReplay, {
    ...options,
    includeStreams: [1, 2, 3],
    onBlock(block, chunk) {
      collector.observe(block, chunk);
      if (afterBlock !== null) afterBlock(block, chunk);
    },
  });
  return {
    analysis,
    heroStatsScan: analysis.block_errors.length === 0 ? collector.finish() : null,
  };
}

function replayBoundHeroStatsScan(replay, token) {
  const source = token && typeof token === 'object'
    ? PRECOLLECTED_SCAN_SOURCE.get(token) : null;
  if (source?.replay === replay
    && source.source_path === (replay?.source_path ?? null)
    && source.source_sha256 === (replay?.source_sha256 ?? null)
    && source.version === (replay?.header?.version ?? null)) {
    return source.scan;
  }
  return { status: 'DECODE_FAILED', scanned_block_count: null,
    error: 'HeroStats precollected scan belongs to a different Replay or is unbound' };
}

function collectHeroStatsSnapshotCandidates(replay, spec, scan) {
  const { profile } = spec;
  const base = { profile_id: profile.id, input_packet_id: PACKET_ID };
  if (scan.status !== 'PASS') {
    return { ...base, status: scan.status, event_count: null, input_count: null,
      scanned_block_count: scan.scanned_block_count,
      ...(scan.observed_raw_route_count === undefined ? {}
        : { observed_raw_route_count: scan.observed_raw_route_count }),
      events: null,
      error: scan.status === 'UNSUPPORTED'
        ? `${profile.capability} candidate supports only ${REPLAY_VERSION}` : scan.error };
  }
  const { rows } = scan;
  const inputCount = rows.length;
  const fail = (error) => ({ ...base, status: 'DECODE_FAILED', event_count: null,
    input_count: inputCount, scanned_block_count: scan.scanned_block_count, events: null, error });
  const tail = spec.assessTail(replay);
  if (tail.status !== 'PASS') {
    return { ...base, status: tail.status, event_count: null, input_count: inputCount,
      scanned_block_count: scan.scanned_block_count, events: null, error: tail.error };
  }
  const previous = Array(10).fill(null);
  const lastTimes = Array(10).fill(null);
  const previousRefs = Array(10).fill(null);
  const observations = [];
  const observedDeclines = [];
  let timestamp = null;
  let currentGroup = new Set();
  let keyframeTimestampCount = 0;
  for (const { block, chunk } of rows) {
    const rawParam = block.param >>> 0;
    if (rawParam < HERO_PARAM_FIRST || rawParam > HERO_PARAM_LAST) {
      return fail(`HN HeroStats route has unsupported raw param 0x${rawParam.toString(16)}`);
    }
    if (!Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0) {
      return fail('HN HeroStats route has invalid Replay timestamp');
    }
    if (block.timestamp_ms !== timestamp) {
      if (timestamp !== null && currentGroup.size !== 10) {
        return fail(`HN HeroStats keyframe at ${timestamp} ms lacks one or more hero params`);
      }
      timestamp = block.timestamp_ms;
      currentGroup = new Set();
      keyframeTimestampCount += 1;
    }
    const participantId = rawParam - HERO_PARAM_FIRST + 1;
    if (currentGroup.has(participantId)) {
      return fail(`HN HeroStats keyframe duplicates participant ${participantId} at ${timestamp} ms`);
    }
    currentGroup.add(participantId);
    const decoded = spec.decodePayload(block.payload);
    if (decoded.status !== 'PASS') {
      return fail(`${decoded.error} at ${block.timestamp_ms} ms, participant ${participantId}`);
    }
    const value = decoded[spec.valueKey];
    if (previous[participantId - 1] !== null && value < previous[participantId - 1]) {
      if (spec.allowDeclines !== true) {
        return fail(`HN participant ${participantId} has a decreasing observed ${tail.field} snapshot`);
      }
    }
    if (spec.enforceTailBound !== false && spec.tailProjection(value) > tail.values[participantId - 1]) {
      return fail(`HN participant ${participantId} exceeds Replay tail ${tail.field}`);
    }
    const rawPacketRef = packetRef(replay, block, chunk);
    if (previous[participantId - 1] !== null && value < previous[participantId - 1]) {
      observedDeclines.push({
        participant_id_candidate: participantId,
        from_replay_time_ms: lastTimes[participantId - 1],
        to_replay_time_ms: block.timestamp_ms,
        from_value_candidate: previous[participantId - 1],
        to_value_candidate: value,
        observed_delta_candidate: value - previous[participantId - 1],
        from_raw_packet_ref: previousRefs[participantId - 1],
        to_raw_packet_ref: rawPacketRef,
      });
    }
    previous[participantId - 1] = value;
    lastTimes[participantId - 1] = block.timestamp_ms;
    previousRefs[participantId - 1] = rawPacketRef;
    observations.push({ block, chunk, rawParam, participantId, value, decoded,
      rawPacketRef });
  }
  if (currentGroup.size !== 10) {
    return fail(`HN HeroStats keyframe at ${timestamp} ms lacks one or more hero params`);
  }
  const gameLength = replay?.tail?.metadata?.gameLength;
  const gameLengthMs = Number.isSafeInteger(gameLength) && gameLength >= 0 ? gameLength : null;
  if (gameLengthMs !== null && lastTimes.some((time) => gameLengthMs - time < 0)) {
    return fail('HN HeroStats keyframe timestamp exceeds Replay tail gameLength');
  }
  return {
    ...base,
    status: 'CANDIDATE',
    event_count: observations.length,
    input_count: inputCount,
    scanned_block_count: scan.scanned_block_count,
    keyframe_timestamp_count: keyframeTimestampCount,
    observed_participant_count: previous.filter((value) => value !== null).length,
    observations,
    observedDeclines,
    previous,
    lastTimes,
    tailValues: tail.values,
    gameLengthMs,
  };
}

function snapshotEvent(replay, profile, observation, eventType,
  semanticStatus, valueFields, fieldConfidence) {
  return {
    event_type: eventType,
    game_version: REPLAY_VERSION,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256 ?? null,
    replay_time_ms: observation.block.timestamp_ms,
    hero_raw_param: observation.rawParam,
    participant_id_candidate: observation.participantId,
    ...valueFields,
    observation_kind: 'KEYFRAME_SNAPSHOT',
    confidence: 'CANDIDATE',
    semantic_status: semanticStatus,
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      hero_raw_param: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE',
      ...fieldConfidence,
    },
    raw_packet_ref: observation.rawPacketRef,
    known_limits: [...profile.known_limits],
  };
}

function decodeHeroMinionsKilledFromScan(replay, scan) {
  const profile = HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroMinionsKilledSnapshotTail,
    decodePayload: decodeHeroMinionsKilledPayload,
    valueKey: 'minions_killed_candidate',
    tailProjection: (value) => value,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_minions_killed_candidate: previous[index],
    final_minions_killed_tail: finalValue,
    unobserved_tail_gap: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_KEYFRAME_FIELD_AND_TAIL_BOUND',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_minions_killed: tailValues,
    observed_max_minions_killed: previous,
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_gap, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_RUNTIME_KEYFRAME_FIELD_AND_TAIL_BOUND',
      { minions_killed_candidate: observation.value },
      { minions_killed_candidate: 'CANDIDATE_EXACT_RUNTIME_FIELD' })),
  };
}

function decodeHeroJungleMinionsKilledFromScan(replay, scan) {
  const profile = HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroJungleMinionsKilledSnapshotTail,
    decodePayload: decodeHeroJungleMinionsKilledPayload,
    valueKey: 'jungle_minions_killed_raw_f32_candidate',
    tailProjection: Math.floor,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tail = assessHeroJungleMinionsKilledSnapshotTail(replay);
  const yourPrevious = Array(10).fill(null);
  const enemyPrevious = Array(10).fill(null);
  const events = [];
  const fail = (error) => ({ profile_id: profile.id, input_packet_id: PACKET_ID,
    status: 'DECODE_FAILED', event_count: null, input_count: base.input_count,
    scanned_block_count: base.scanned_block_count, events: null, error });
  for (const observation of observations) {
    const { decoded } = observation;
    const index = observation.participantId - 1;
    const yourValue = decoded.your_jungle_minions_killed_raw_f32_candidate;
    const enemyValue = decoded.enemy_jungle_minions_killed_raw_f32_candidate;
    if (yourPrevious[index] !== null && yourValue < yourPrevious[index]) {
      return fail(`HN participant ${observation.participantId} has a decreasing observed own-jungle snapshot`);
    }
    if (enemyPrevious[index] !== null && enemyValue < enemyPrevious[index]) {
      return fail(`HN participant ${observation.participantId} has a decreasing observed enemy-jungle snapshot`);
    }
    if (Math.floor(yourValue) > tail.yourJungleValues[index]) {
      return fail(`HN participant ${observation.participantId} exceeds Replay tail NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE`);
    }
    if (Math.floor(enemyValue) > tail.enemyJungleValues[index]) {
      return fail(`HN participant ${observation.participantId} exceeds Replay tail NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE`);
    }
    yourPrevious[index] = yourValue;
    enemyPrevious[index] = enemyValue;
    events.push(snapshotEvent(replay, profile, observation,
      'HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_THREE_TAIL_CORRELATION',
      {
        jungle_minions_killed_raw_f32_candidate: observation.value,
        jungle_minions_killed_floor_candidate: Math.floor(observation.value),
        your_jungle_minions_killed_raw_f32_candidate: yourValue,
        your_jungle_minions_killed_floor_candidate: Math.floor(yourValue),
        enemy_jungle_minions_killed_raw_f32_candidate: enemyValue,
        enemy_jungle_minions_killed_floor_candidate: Math.floor(enemyValue),
      },
      {
        jungle_minions_killed_raw_f32_candidate: 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION',
        jungle_minions_killed_floor_candidate: 'DERIVED_FROM_CANDIDATE',
        your_jungle_minions_killed_raw_f32_candidate: 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION',
        your_jungle_minions_killed_floor_candidate: 'DERIVED_FROM_CANDIDATE',
        enemy_jungle_minions_killed_raw_f32_candidate: 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION',
        enemy_jungle_minions_killed_floor_candidate: 'DERIVED_FROM_CANDIDATE',
      }));
  }
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_jungle_minions_killed_raw_f32_candidate: previous[index],
    last_snapshot_jungle_minions_killed_floor_candidate: Math.floor(previous[index]),
    final_neutral_minions_killed_tail: finalValue,
    unobserved_tail_floor_gap: finalValue - Math.floor(previous[index]),
    last_snapshot_your_jungle_minions_killed_raw_f32_candidate: yourPrevious[index],
    last_snapshot_your_jungle_minions_killed_floor_candidate: Math.floor(yourPrevious[index]),
    final_neutral_minions_killed_your_jungle_tail: tail.yourJungleValues[index],
    unobserved_your_jungle_tail_floor_gap:
      tail.yourJungleValues[index] - Math.floor(yourPrevious[index]),
    last_snapshot_enemy_jungle_minions_killed_raw_f32_candidate: enemyPrevious[index],
    last_snapshot_enemy_jungle_minions_killed_floor_candidate: Math.floor(enemyPrevious[index]),
    final_neutral_minions_killed_enemy_jungle_tail: tail.enemyJungleValues[index],
    unobserved_enemy_jungle_tail_floor_gap:
      tail.enemyJungleValues[index] - Math.floor(enemyPrevious[index]),
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_THREE_TAIL_CORRELATION',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_neutral_minions_killed: tailValues,
    final_neutral_minions_killed_your_jungle: tail.yourJungleValues,
    final_neutral_minions_killed_enemy_jungle: tail.enemyJungleValues,
    observed_max_jungle_minions_killed_raw_f32: previous,
    observed_max_jungle_minions_killed_floor: previous.map(Math.floor),
    observed_max_your_jungle_minions_killed_raw_f32: yourPrevious,
    observed_max_your_jungle_minions_killed_floor: yourPrevious.map(Math.floor),
    observed_max_enemy_jungle_minions_killed_raw_f32: enemyPrevious,
    observed_max_enemy_jungle_minions_killed_floor: enemyPrevious.map(Math.floor),
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_floor_gap, 0),
    events,
  };
}

function decodeHeroExperienceFromScan(replay, scan) {
  const profile = HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroExperienceSnapshotTail,
    decodePayload: decodeHeroExperiencePayload,
    valueKey: 'experience_points_candidate',
    tailProjection: Math.floor,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_experience_points_candidate: previous[index],
    last_snapshot_experience_floor_candidate: Math.floor(previous[index]),
    final_experience_tail: finalValue,
    unobserved_tail_floor_gap: finalValue - Math.floor(previous[index]),
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_experience: tailValues,
    observed_max_experience_points: previous,
    observed_max_experience_floor: previous.map(Math.floor),
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_floor_gap, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'HERO_EXPERIENCE_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
      { experience_points_candidate: observation.value,
        experience_floor_candidate: Math.floor(observation.value) },
      { experience_points_candidate: 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION',
        experience_floor_candidate: 'DERIVED_FROM_CANDIDATE' })),
  };
}

function decodeHeroGoldEarnedFromScan(replay, scan) {
  const profile = HERO_GOLD_EARNED_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroGoldEarnedSnapshotTail,
    decodePayload: decodeHeroGoldEarnedPayload,
    valueKey: 'gold_earned_candidate',
    tailProjection: (value) => value,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_gold_earned_candidate: previous[index],
    final_gold_earned_tail: finalValue,
    unobserved_tail_difference_candidate: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_gold_earned: tailValues,
    observed_max_gold_earned: previous,
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_difference_candidate, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'HERO_GOLD_EARNED_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
      { gold_earned_candidate: observation.value },
      { gold_earned_candidate: 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION' })),
  };
}

function decodeHeroGoldSpentFromScan(replay, scan) {
  const profile = HERO_GOLD_SPENT_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroGoldSpentSnapshotTail,
    decodePayload: decodeHeroGoldSpentPayload,
    valueKey: 'gold_spent_candidate',
    tailProjection: (value) => value,
    allowDeclines: true,
    enforceTailBound: false,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailDifferences = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_gold_spent_candidate: previous[index],
    final_gold_spent_tail: finalValue,
    tail_minus_last_snapshot_candidate: finalValue - previous[index],
    time_between_snapshot_and_tail_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  const tailDifferenceTotal = tailDifferences.reduce((sum, row) =>
    sum + row.tail_minus_last_snapshot_candidate, 0);
  if (!Number.isSafeInteger(tailDifferenceTotal)) {
    return { profile_id: profile.id, input_packet_id: PACKET_ID, status: 'DECODE_FAILED',
      event_count: null, input_count: base.input_count,
      scanned_block_count: base.scanned_block_count, events: null,
      error: 'signed GOLD_SPENT tail difference total exceeds safe integer range' };
  }
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_gold_spent: tailValues,
    last_observed_gold_spent: previous,
    tail_differences: tailDifferences,
    tail_difference_total: tailDifferenceTotal,
    observed_decline_count: observedDeclines.length,
    observed_declines: observedDeclines.map((row) => ({
      participant_id_candidate: row.participant_id_candidate,
      from_replay_time_ms: row.from_replay_time_ms,
      to_replay_time_ms: row.to_replay_time_ms,
      from_gold_spent_candidate: row.from_value_candidate,
      to_gold_spent_candidate: row.to_value_candidate,
      observed_delta_candidate: row.observed_delta_candidate,
      from_raw_packet_ref: row.from_raw_packet_ref,
      to_raw_packet_ref: row.to_raw_packet_ref,
    })),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'HERO_GOLD_SPENT_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
      { gold_spent_candidate: observation.value },
      { gold_spent_candidate: 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION' })),
  };
}

function decodeHeroChampionKillsFromScan(replay, scan) {
  const profile = HERO_CHAMPION_KILLS_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroChampionKillsSnapshotTail,
    decodePayload: decodeHeroChampionKillsPayload,
    valueKey: 'champion_kills_candidate',
    tailProjection: (value) => value,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_champion_kills_candidate: previous[index],
    final_champions_killed_tail: finalValue,
    unobserved_tail_gap: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_MIRRORED_FIELD_AND_TAIL_BOUND',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_champions_killed: tailValues,
    observed_max_champion_kills: previous,
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_gap, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'HERO_CHAMPION_KILLS_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_MIRRORED_FIELD_AND_TAIL_BOUND',
      { champion_kills_candidate: observation.value },
      { champion_kills_candidate: 'CANDIDATE_ONE_REPLAY_MIRRORED_FIELD_AND_TAIL_CORRELATION' })),
  };
}

function decodeHeroDeathsFromScan(replay, scan) {
  const profile = HERO_DEATHS_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroDeathsSnapshotTail,
    decodePayload: decodeHeroDeathsPayload,
    valueKey: 'deaths_candidate',
    tailProjection: (value) => value,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_deaths_candidate: previous[index],
    final_num_deaths_tail: finalValue,
    unobserved_tail_gap: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_DEATH_COUNT_CORRELATION',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_num_deaths: tailValues,
    observed_max_deaths: previous,
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_gap, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'HERO_DEATHS_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_DEATH_COUNT_CORRELATION',
      { deaths_candidate: observation.value },
      { deaths_candidate: 'CANDIDATE_ONE_REPLAY_DEATH_COUNT_CORRELATION' })),
  };
}

function decodeHeroAssistsFromScan(replay, scan) {
  const profile = HERO_ASSISTS_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroAssistsSnapshotTail,
    decodePayload: decodeHeroAssistsPayload,
    valueKey: 'assists_candidate',
    tailProjection: (value) => value,
  }, scan);
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, observedDeclines, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_assists_candidate: previous[index],
    final_assists_tail: finalValue,
    unobserved_tail_gap: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_ASSISTS_TAIL_CORRELATION',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_assists: tailValues,
    observed_max_assists: previous,
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_gap, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'HERO_ASSISTS_SNAPSHOT_CANDIDATE',
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_ASSISTS_TAIL_CORRELATION',
      { assists_candidate: observation.value },
      { assists_candidate: 'CANDIDATE_ONE_REPLAY_ASSISTS_TAIL_CORRELATION' })),
  };
}

function decodeHeroStatsSnapshotCandidateSet(replay, capabilities, precollectedScan) {
  if (!Array.isArray(capabilities) && !(capabilities instanceof Set)) {
    throw new TypeError('HeroStats candidate capabilities must be an array or Set');
  }
  const selected = new Set(capabilities);
  for (const capability of selected) {
    if (!HERO_STATS_SNAPSHOT_CAPABILITY_SET.has(capability)) {
      throw new RangeError(`unsupported HeroStats candidate capability: ${String(capability)}`);
    }
  }
  if (selected.size === 0) return {};
  const scan = precollectedScan === undefined
    ? scanHeroStatsRows(replay) : replayBoundHeroStatsScan(replay, precollectedScan);
  const outcomes = {};
  if (selected.has('hero_minions_killed_snapshot')) {
    outcomes.hero_minions_killed_snapshot = decodeHeroMinionsKilledFromScan(replay, scan);
  }
  if (selected.has('hero_jungle_minions_killed_snapshot')) {
    outcomes.hero_jungle_minions_killed_snapshot = decodeHeroJungleMinionsKilledFromScan(replay, scan);
  }
  if (selected.has('hero_experience_snapshot')) {
    outcomes.hero_experience_snapshot = decodeHeroExperienceFromScan(replay, scan);
  }
  if (selected.has('hero_gold_earned_snapshot')) {
    outcomes.hero_gold_earned_snapshot = decodeHeroGoldEarnedFromScan(replay, scan);
  }
  if (selected.has('hero_gold_spent_snapshot')) {
    outcomes.hero_gold_spent_snapshot = decodeHeroGoldSpentFromScan(replay, scan);
  }
  if (selected.has('hero_champion_kills_snapshot')) {
    outcomes.hero_champion_kills_snapshot = decodeHeroChampionKillsFromScan(replay, scan);
  }
  if (selected.has('hero_deaths_snapshot')) {
    outcomes.hero_deaths_snapshot = decodeHeroDeathsFromScan(replay, scan);
  }
  if (selected.has('hero_assists_snapshot')) {
    outcomes.hero_assists_snapshot = decodeHeroAssistsFromScan(replay, scan);
  }
  return outcomes;
}

function decodeHeroMinionsKilledSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_minions_killed_snapshot']).hero_minions_killed_snapshot;
}

function decodeHeroJungleMinionsKilledSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_jungle_minions_killed_snapshot']).hero_jungle_minions_killed_snapshot;
}

function decodeHeroExperienceSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_experience_snapshot']).hero_experience_snapshot;
}

function decodeHeroGoldEarnedSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_gold_earned_snapshot']).hero_gold_earned_snapshot;
}

function decodeHeroGoldSpentSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_gold_spent_snapshot']).hero_gold_spent_snapshot;
}

function decodeHeroChampionKillsSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_champion_kills_snapshot']).hero_champion_kills_snapshot;
}

function decodeHeroDeathsSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_deaths_snapshot']).hero_deaths_snapshot;
}

function decodeHeroAssistsSnapshotCandidates(replay) {
  return decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_assists_snapshot']).hero_assists_snapshot;
}

module.exports = {
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  HERO_ASSISTS_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_CHAMPION_KILLS_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_DEATHS_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_GOLD_EARNED_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_GOLD_SPENT_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE,
  assessHeroAssistsSnapshotTail,
  assessHeroChampionKillsSnapshotTail,
  assessHeroDeathsSnapshotTail,
  assessHeroExperienceSnapshotTail,
  assessHeroGoldEarnedSnapshotTail,
  assessHeroGoldSpentSnapshotTail,
  assessHeroJungleMinionsKilledSnapshotTail,
  assessHeroMinionsKilledSnapshotTail,
  analyzeReplayWithHeroStats,
  decodeHeroStatsByte,
  decodeHeroAssistsPayload,
  decodeHeroAssistsSnapshotCandidates,
  decodeHeroChampionKillsPayload,
  decodeHeroChampionKillsSnapshotCandidates,
  decodeHeroDeathsPayload,
  decodeHeroDeathsSnapshotCandidates,
  decodeHeroExperiencePayload,
  decodeHeroExperienceSnapshotCandidates,
  decodeHeroGoldEarnedPayload,
  decodeHeroGoldEarnedSnapshotCandidates,
  decodeHeroGoldSpentPayload,
  decodeHeroGoldSpentSnapshotCandidates,
  decodeHeroJungleMinionsKilledPayload,
  decodeHeroJungleMinionsKilledSnapshotCandidates,
  decodeHeroStatsSnapshotCandidateSet,
  decodeHeroMinionsKilledPayload,
  decodeHeroMinionsKilledSnapshotCandidates,
};
