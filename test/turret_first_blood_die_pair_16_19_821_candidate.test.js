'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseReplayFile, walkBlocks } = require('../src/rofl');
const { TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_turret_first_blood_event_packet_candidate');
const { TURRET_DIE_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_turret_die_event_packet_candidate');
const { TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE,
  associateTurretFirstBloodDieCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_turret_first_blood_die_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function sha(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(packetId, rawParam, length, timeMs, fill) {
  const payload = Buffer.alloc(length, fill);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function ref(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256,
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
    raw_payload_sha256: sha(block.payload),
  };
}

function candidateRow(replay, block, chunk, kind, fill) {
  const first = kind === 'first';
  const blob = Buffer.alloc(108, fill);
  return {
    event_type: first ? 'TURRET_FIRST_BLOOD_EVENT_PACKET_CANDIDATE'
      : 'TURRET_DIE_EVENT_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19',
    build_profile: first ? TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE.id
      : TURRET_DIE_EVENT_PACKET_821_PROFILE.id,
    replay_sha256: replay.source_sha256,
    replay_time_ms: block.timestamp_ms,
    raw_param: block.param >>> 0,
    event_id: first ? 0x003d : 0x003b,
    event_name: first ? 'OnTurretFirstBlood' : 'OnTurretDie',
    raw_event_id_hex: first ? '0x4986' : '0x4966',
    event_blob_hex: blob.toString('hex'), event_blob_sha256: sha(blob),
    confidence: 'CANDIDATE',
    semantic_status: first
      ? 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_FIRST_BLOOD_PACKET'
      : 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_DIE_PACKET',
    raw_packet_ref: ref(replay, block, chunk),
  };
}

function outcome(kind, events) {
  const first = kind === 'first';
  return {
    status: 'CANDIDATE',
    profile_id: first ? TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE.id
      : TURRET_DIE_EVENT_PACKET_821_PROFILE.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    runtime_image_sha256: IMAGE_SHA256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    input_packet_id: 0x040a, child_event_id: first ? 0x003d : 0x003b,
    input_count: events.length, event_count: events.length,
    observed_same_length_packet_count: events.length,
    excluded_same_length_foreign_count: 0, events,
  };
}

function fixture({ interveningOnEvent = false, extraDieAtSameTime = false,
  firstTimeMs = 1000, firstBeforeDie = false } = {}) {
  const unpaired = packet(0x040a, 0x400000b1, 116, 500, 0x11);
  const die = packet(0x040a, 0x400000b3, 116, 1000, 0x3b);
  const first = packet(0x040a, 0x400001bc, 116, firstTimeMs, 0x3d);
  const ordinary = packet(0x0259, 0x400000b2, 7, 1000, 0x59);
  const intervening = packet(0x040a, 0x400000b4, 20, 1000, 0x04);
  const duplicateDie = packet(0x040a, 0x400000b5, 116, 1000, 0x5b);
  const body = Buffer.concat([
    unpaired,
    ...(firstBeforeDie ? [first, die] : [die, ordinary,
      ...(interveningOnEvent ? [intervening] : []),
      ...(extraDieAtSameTime ? [duplicateDie] : []), first]),
  ]);
  const replay = replayFromChunks([{ stream: 1, body }], BUILD);
  const found = [];
  const scan = walkBlocks(replay, (block, chunk) => found.push({ block, chunk }),
    { strict: true });
  assert.equal(scan.errors.length, 0);
  const select = (rawParam) => found.find(({ block }) => block.param === rawParam);
  const dieEvents = [
    candidateRow(replay, ...Object.values(select(0x400000b1)), 'die', 0x11),
    candidateRow(replay, ...Object.values(select(0x400000b3)), 'die', 0x3b),
    ...(extraDieAtSameTime
      ? [candidateRow(replay, ...Object.values(select(0x400000b5)), 'die', 0x5b)]
      : []),
  ];
  const firstEvents = [candidateRow(replay,
    ...Object.values(select(0x400001bc)), 'first', 0x3d)];
  return {
    replay,
    turretFirstBloodEventPacketOutcome: outcome('first', firstEvents),
    turretDieEventPacketOutcome: outcome('die', dieEvents),
  };
}

test('821 turret packet pair retains both source refs and permits differing anonymous values', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE.capability,
    'turret_first_blood_die_pair');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 1);
  assert.equal(result.pair_count, 1);
  assert.equal(result.turret_die_count, 2);
  assert.equal(result.unpaired_turret_die_count, 1);
  assert.equal(result.events[0].turret_die_raw_param, 0x400000b3);
  assert.equal(result.events[0].turret_first_blood_raw_param, 0x400001bc);
  assert.ok(result.events[0].source_order_block_offset_gap > 116);
  assert.equal(result.events[0].intervening_on_event_count, 0);
  assert.deepEqual(result.events[0].raw_packet_refs,
    [result.events[0].turret_die_raw_packet_ref,
      result.events[0].turret_first_blood_raw_packet_ref]);
  for (const field of ['actor', 'target', 'turret', 'structure',
    'actual_first_blood', 'effective_turret_death']) {
    assert.equal(field in result.events[0], false);
  }
});

test('821 turret packet pair rejects intervening OnEvent even when time and chunk match', () => {
  const values = fixture({ interveningOnEvent: true });
  const result = associate(values.replay, values);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  assert.equal(result.pair_count, null);
  assert.equal(result.diagnostics.intervening_on_event_count, 1);
});

test('821 turret packet pair rejects ambiguous, mismatched-time, and reversed-order matches', () => {
  const ambiguous = fixture({ extraDieAtSameTime: true });
  assert.equal(associate(ambiguous.replay, ambiguous).status, 'INCONSISTENT');
  const mismatched = fixture({ firstTimeMs: 2000 });
  assert.equal(associate(mismatched.replay, mismatched).status, 'INCONSISTENT');
  const reversed = fixture({ firstBeforeDie: true });
  assert.equal(associate(reversed.replay, reversed).status, 'INCONSISTENT');
});

test('821 turret packet pair fails closed on altered source or unverified raw reference', () => {
  const wrongSha = fixture();
  wrongSha.turretDieEventPacketOutcome.events[1].replay_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongSha.replay, wrongSha).status, 'INCONSISTENT');
  const wrongPacket = fixture();
  wrongPacket.turretDieEventPacketOutcome.events[1].raw_packet_ref.raw_payload_sha256 =
    'f'.repeat(64);
  assert.equal(associate(wrongPacket.replay, wrongPacket).status, 'INCONSISTENT');
  const changedSource = fixture();
  changedSource.replay.buffer[0] ^= 1;
  assert.equal(associate(changedSource.replay, changedSource).status, 'DECODE_FAILED');
});

test('821 turret packet pair requires independently matched exact-image outcomes', () => {
  const values = fixture();
  assert.equal(associate(values.replay, {
    turretDieEventPacketOutcome: values.turretDieEventPacketOutcome,
  }).status, 'MISSING_INPUT');
  const unavailable = structuredClone(values.turretFirstBloodEventPacketOutcome);
  unavailable.status = 'PROFILE_UNAVAILABLE';
  assert.equal(associate(values.replay, {
    turretFirstBloodEventPacketOutcome: unavailable,
    turretDieEventPacketOutcome: values.turretDieEventPacketOutcome,
  }).status, 'MISSING_INPUT');
  const wrongImage = structuredClone(values.turretDieEventPacketOutcome);
  wrongImage.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(values.replay, {
    turretFirstBloodEventPacketOutcome: values.turretFirstBloodEventPacketOutcome,
    turretDieEventPacketOutcome: wrongImage,
  }).status, 'INCONSISTENT');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
});

test('one supplied KR Replay pairs independently decoded exact-image turret packets', (t) => {
  const replayPath = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
    'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');
  const artifactRoot = path.resolve(__dirname, '..', 'artifacts', '16_19_development');
  const source = (directory, capability, output) => ({
    run: path.join(artifactRoot, directory, 'replays', 'KR_8392938200', 'semantic_run.json'),
    rows: path.join(artifactRoot, directory, 'replays', 'KR_8392938200', `${output}.jsonl`),
    capability,
  });
  const first = source('turret_first_blood_cli_batch_11',
    'turret_first_blood_event_packet', 'turret_first_blood_event_packet_candidates');
  const die = source('turret_die_cli_batch_11',
    'turret_die_event_packet', 'turret_die_event_packet_candidates');
  if (![replayPath, first.run, first.rows, die.run, die.rows].every(fs.existsSync)) {
    t.skip('supplied private Replay or independently decoded local candidate outputs absent');
    return;
  }
  const outcomeFromFiles = ({ run, rows, capability }) => ({
    ...JSON.parse(fs.readFileSync(run, 'utf8')).capability_results[capability],
    events: fs.readFileSync(rows, 'utf8').trim().split(/\r?\n/).map(JSON.parse),
  });
  const replay = parseReplayFile(replayPath);
  const turretFirstBloodEventPacketOutcome = outcomeFromFiles(first);
  const turretDieEventPacketOutcome = outcomeFromFiles(die);
  const result = associate(replay, {
    turretFirstBloodEventPacketOutcome, turretDieEventPacketOutcome,
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.pair_count, 1);
  assert.equal(result.turret_die_count, 18);
  assert.equal(result.unpaired_turret_die_count, 17);
  assert.equal(result.events[0].source_order_block_offset_gap, 159);
  assert.notEqual(result.events[0].turret_die_raw_param,
    result.events[0].turret_first_blood_raw_param);
  const pairedDie = turretDieEventPacketOutcome.events.find((row) =>
    row.raw_packet_ref.decompressed_block_offset
      === result.events[0].turret_die_raw_packet_ref.decompressed_block_offset);
  assert.ok(pairedDie);
  assert.notEqual(pairedDie.event_blob_sha256,
    turretFirstBloodEventPacketOutcome.events[0].event_blob_sha256);
});
