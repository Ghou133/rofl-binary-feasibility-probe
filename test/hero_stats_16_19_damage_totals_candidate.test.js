'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_DAMAGE_TOTALS_SNAPSHOT_CANDIDATE_PROFILE: profile,
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  analyzeReplayWithHeroStats,
  assessHeroDamageTotalsSnapshotTail,
  decodeHeroDamageTotalsPayload,
  decodeHeroDamageTotalsSnapshotCandidates,
  decodeHeroStatsByte,
  decodeHeroStatsSnapshotCandidateSet,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_damage_totals_snapshot';
const OUTPUT = 'hero_damage_totals_snapshot_candidates';
const IMAGE_SHA = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const FIELDS = [
  ['TOTAL_DAMAGE_DEALT_TO_CHAMPIONS', 'damage_to_champions_raw_f32_candidate',
    'damage_to_champions_floor_candidate', 0x1e0],
  ['TOTAL_DAMAGE_DEALT', 'total_damage_dealt_raw_f32_candidate',
    'total_damage_dealt_floor_candidate', 0x1d0],
  ['TOTAL_DAMAGE_TAKEN', 'total_damage_taken_raw_f32_candidate',
    'total_damage_taken_floor_candidate', 0x1f0],
];

// Synthetic inverse for test packets; the production byte transform remains in the decoder.
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function valuesFor(participantId, timeIndex) {
  if (timeIndex === 0) return Object.fromEntries(FIELDS.map(([, key]) => [key, 0]));
  return {
    damage_to_champions_raw_f32_candidate: participantId + 0.5,
    total_damage_dealt_raw_f32_candidate: participantId * 4 + 0.25,
    total_damage_taken_raw_f32_candidate: participantId * 2 + 0.75,
  };
}

function payloadFor(values = valuesFor(1, 0)) {
  const blob = Buffer.alloc(1260);
  for (const [, key, , offset] of FIELDS) blob.writeFloatLE(values[key] ?? 0, offset);
  const payload = Buffer.alloc(1263);
  payload.set([0x1c, 0xa6, 0xe8]);
  for (let index = 0; index < blob.length; index += 1) {
    payload[index + 3] = ENCODE_BYTE[blob[blob.length - 1 - index]];
  }
  return payload;
}

function blockFor(participantId, timeMs, payload, packetId = 0x0276) {
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ times = [0, 1000], values, tails, version = BUILD, stream = 2,
  extraBlocks = [], omitParticipant = null } = {}) {
  const rows = values ?? times.map((_, timeIndex) => Array.from({ length: 10 },
    (__, index) => valuesFor(index + 1, timeIndex)));
  const body = Buffer.concat([
    ...times.flatMap((timeMs, timeIndex) => rows[timeIndex].flatMap((row, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(row))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = (tails ?? rows.at(-1).map((row, index) =>
    Object.fromEntries(FIELDS.map(([field, key]) =>
      [field, Math.floor(row[key]) + (field === 'TOTAL_DAMAGE_TAKEN' && index === 1 ? 1 : 0)]))))
    .map((row) => ({ ...Object.fromEntries(Object.entries(row).map(([key, value]) =>
      [key, String(value)])), ASSISTS: '0' }));
  replay.tail.metadata.gameLength = times.at(-1) + 1000;
  return replay;
}

function writeReplayWithTailStats(replay, outputPath) {
  const original = replay.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({ ...replay.tail.metadata,
    statsJson: JSON.stringify(replay.tail.stats) }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(outputPath, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
}

test('exact HN profile pins three f32 offsets and payload decoding retains raw and floor', () => {
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.replay_block_packet_id, 0x0276);
  assert.equal(profile.payload_length, 1263);
  assert.equal(profile.status, 'CANDIDATE');
  assert.equal(profile.evidence_runtime_image_sha256, IMAGE_SHA);
  assert.match(profile.evidence_scope, /one HN Replay/);
  assert.ok(profile.known_limits.some((limit) => /no damage event/.test(limit)));
  for (const [, key, , offset] of FIELDS) {
    assert.equal(profile[`${key.replace(/_raw_f32_candidate$/, '')}_f32le_offset_candidate`],
      offset);
  }
  const values = valuesFor(3, 1);
  const decoded = decodeHeroDamageTotalsPayload(payloadFor(values));
  assert.equal(decoded.status, 'PASS');
  for (const [, rawKey, floorKey] of FIELDS) {
    assert.equal(decoded[rawKey], values[rawKey]);
    assert.equal(decoded[floorKey], Math.floor(values[rawKey]));
  }
  const malformed = payloadFor(values);
  malformed[0] = 0x1d;
  assert.equal(decodeHeroDamageTotalsPayload(malformed).status, 'DECODE_FAILED');
  assert.equal(decodeHeroDamageTotalsPayload(malformed.subarray(1)).status, 'DECODE_FAILED');
  for (const invalid of [-1, Infinity, NaN, 2 ** 53]) {
    const row = { ...values, total_damage_taken_raw_f32_candidate: invalid };
    assert.equal(decodeHeroDamageTotalsPayload(payloadFor(row)).status, 'DECODE_FAILED',
      String(invalid));
  }
});

test('observed keyframes preserve three raw f32 values, derived floors, provenance and tail gap', () => {
  const replay = fixture();
  const result = decodeHeroDamageTotalsSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.equal(result.evidence_runtime_image_sha256, IMAGE_SHA);
  assert.equal(result.evidence_status,
    'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_THREE_DAMAGE_TAIL_CORRELATIONS');
  assert.deepEqual(result.tail_gaps[1].field_gaps.TOTAL_DAMAGE_TAKEN, {
    last_snapshot_raw_f32_candidate: 4.75,
    last_snapshot_floor_candidate: 4,
    final_tail: 5,
    unobserved_tail_floor_gap: 1,
  });
  assert.equal(result.tail_gaps[1].unobserved_tail_time_ms, 1000);
  const last = result.events.at(-1);
  assert.equal(last.event_type, 'HERO_DAMAGE_TOTALS_SNAPSHOT_CANDIDATE');
  assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(last.confidence, 'CANDIDATE');
  assert.equal(last.participant_id_candidate, 10);
  assert.equal(last.raw_packet_ref.packet_id, 0x0276);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(valuesFor(10, 1))).digest('hex'));
  for (const [, rawKey, floorKey] of FIELDS) {
    assert.equal(last[rawKey], valuesFor(10, 1)[rawKey]);
    assert.equal(last[floorKey], Math.floor(last[rawKey]));
    assert.equal(last.field_confidence[rawKey], 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
    assert.equal(last.field_confidence[floorKey], 'DERIVED_FROM_CANDIDATE');
  }
  for (const key of ['damage_event_time_ms', 'source', 'target', 'mitigation']) {
    assert.equal(Object.hasOwn(last, key), false);
  }
});

test('each damage tail is required, and missing values fail only this selected capability', () => {
  const replay = fixture();
  assert.deepEqual(assessHeroDamageTotalsSnapshotTail(replay).required_fields
    .map((row) => row.field), FIELDS.map(([field]) => field));
  for (const [field] of FIELDS) {
    const missing = fixture();
    delete missing.tail.stats[0][field];
    const outcomes = decodeHeroStatsSnapshotCandidateSet(missing,
      [CAPABILITY, 'hero_assists_snapshot']);
    assert.equal(outcomes[CAPABILITY].status, 'MISSING_INPUT', field);
    assert.equal(outcomes.hero_assists_snapshot.status, 'CANDIDATE', field);
    const invalid = fixture();
    invalid.tail.stats[0][field] = '-1';
    assert.equal(decodeHeroDamageTotalsSnapshotCandidates(invalid).status, 'UNSUPPORTED', field);
  }
  const noTail = fixture();
  noTail.tail.stats = null;
  assert.equal(decodeHeroDamageTotalsSnapshotCandidates(noTail).status, 'MISSING_INPUT');
});

test('each raw damage field rejects an observed decrease and a floor above its own tail', () => {
  for (const [field, key] of FIELDS) {
    const first = Array.from({ length: 10 }, () =>
      Object.fromEntries(FIELDS.map(([, rawKey]) => [rawKey, 3.5])));
    const second = first.map((row) => ({ ...row }));
    second[0][key] = 2.5;
    const tails = Array.from({ length: 10 }, () =>
      Object.fromEntries(FIELDS.map(([tailField]) => [tailField, 10])));
    const decreasing = decodeHeroDamageTotalsSnapshotCandidates(fixture({
      values: [first, second], tails,
    }));
    assert.equal(decreasing.status, 'DECODE_FAILED', field);
    assert.match(decreasing.error, new RegExp(`decreasing observed ${field}`));
    const aboveTail = fixture();
    aboveTail.tail.stats[0][field] = '0';
    const overrun = decodeHeroDamageTotalsSnapshotCandidates(aboveTail);
    assert.equal(overrun.status, 'DECODE_FAILED', field);
    assert.match(overrun.error, new RegExp(`exceeds Replay tail ${field}`));
    assert.equal(overrun.events, null);
  }
});

test('wrong build, foreign stream/shape, malformed packet, source mutation and incomplete roster fail closed', () => {
  assert.equal(decodeHeroDamageTotalsSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  assert.equal(decodeHeroDamageTotalsSnapshotCandidates(fixture({ stream: 1 })).status,
    'PROFILE_UNAVAILABLE');
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) =>
      blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], BUILD);
  assert.equal(decodeHeroDamageTotalsSnapshotCandidates(foreign).status,
    'PROFILE_UNAVAILABLE');
  const mixed = fixture({ times: [0], extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  assert.equal(decodeHeroDamageTotalsSnapshotCandidates(mixed).status, 'DECODE_FAILED');
  const tampered = fixture();
  tampered.buffer[0] = 0;
  assert.match(decodeHeroDamageTotalsSnapshotCandidates(tampered).error,
    /Replay source failed/);
  const missingHero = fixture({ times: [0], omitParticipant: 3 });
  assert.match(decodeHeroDamageTotalsSnapshotCandidates(missingHero).error,
    /lacks one or more hero params/);
});

test('bound precollected scan gives the same candidate without a second Replay walk', () => {
  const replay = fixture();
  const standalone = decodeHeroDamageTotalsSnapshotCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not rescan Replay chunks');
  } });
  assert.deepEqual(decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY], heroStatsScan)[CAPABILITY],
    standalone);
});

test('selected API and capability query expose candidate snapshots and all three tail dependencies', () => {
  const { decodeSemanticReplay, getHeroDamageTotalsSnapshotCandidates } = require('../src/semantic_api');
  const { capabilityQuery } = require('../src/cli');
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  assert.equal(getHeroDamageTotalsSnapshotCandidates(decoded).length, 20);
  assert.equal(decoded.events.damage_events, undefined);
  const row = capabilityQuery(replay).capabilities.find((item) => item.capability === CAPABILITY);
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, OUTPUT);
  assert.deepEqual(row.required_inputs.map((input) => input.name), [
    'replay', 'replay_tail_statsJson', ...FIELDS.map(([field]) => `replay_tail_${field}`),
  ]);
  assert.deepEqual(row.missing_inputs, []);
  delete replay.tail.stats[2].TOTAL_DAMAGE_DEALT;
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((item) => item.capability === CAPABILITY).missing_inputs,
  ['replay_tail_TOTAL_DAMAGE_DEALT']);
});

test('selected CLI writes damage snapshot candidates and source provenance as JSONL', async (t) => {
  const { main } = require('../src/cli');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-damage-totals-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CAPABILITY, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].tail_gaps[1]
    .field_gaps.TOTAL_DAMAGE_TAKEN.unobserved_tail_floor_gap, 1);
  const events = JSON.parse(fs.readFileSync(path.join(replayDir, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), [OUTPUT]);
  const rows = fs.readFileSync(path.join(replayDir, `${OUTPUT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 20);
  assert.equal(rows.at(-1).total_damage_dealt_raw_f32_candidate, 40.25);
  assert.equal(rows.at(-1).total_damage_dealt_floor_candidate, 40);
  assert.equal(rows.at(-1).raw_packet_ref.packet_id, 0x0276);
  assert.equal(rows.at(-1).raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
  assert.equal(rows.at(-1).raw_packet_ref.source_path, input);
});
