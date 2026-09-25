'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { CHAMPION_DIE_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_die_event_packet_candidate');
const { HERO_DEATH_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_7343');
const { CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE,
  associateChampionDieHeroDeathCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_champion_die_hero_death_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId, rawParam, length, timeMs) {
  const payload = Buffer.alloc(length, packetId & 0xff);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function ref(replay, block, chunk, role) {
  return {
    ...(role ? { role } : {}),
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
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function fixture(specs = [
  { timeMs: 1000, dieRaw: 0x400001ae, victimRaw: 0x400000ae,
    sourceId: 0x400000b0 },
  { timeMs: 2000, dieRaw: 0x400000af, victimRaw: 0x400000af,
    sourceId: 0x400000b1 },
]) {
  const body = Buffer.concat(specs.flatMap((spec) => [
    packet(0x040a, spec.dieRaw, 116, spec.timeMs),
    packet(0x031b, 0, 40, spec.heroTimeMs ?? spec.timeMs),
    packet(0x0259, spec.victimRaw, 5, spec.heroTimeMs ?? spec.timeMs),
    packet(0x0438, spec.victimRaw, 37, spec.heroTimeMs ?? spec.timeMs),
  ]));
  const replay = replayFromChunks([{ stream: 1, body }], BUILD);
  const groups = new Map();
  walkBlocks(replay, (block, chunk) => {
    const key = `${block.timestamp_ms}/${block.packet_id}`;
    groups.set(key, { block, chunk });
  }, { strict: true });
  const dieEvents = [];
  const heroEvents = [];
  for (const spec of specs) {
    const heroTime = spec.heroTimeMs ?? spec.timeMs;
    const dieSource = groups.get(`${spec.timeMs}/1034`);
    const primarySource = groups.get(`${heroTime}/601`);
    const pairedSource = groups.get(`${heroTime}/1080`);
    const longSource = groups.get(`${heroTime}/795`);
    const dieRef = ref(replay, dieSource.block, dieSource.chunk);
    const primary = ref(replay, primarySource.block, primarySource.chunk, 'candidate_primary');
    const paired = ref(replay, pairedSource.block, pairedSource.chunk, 'candidate_paired');
    const long = ref(replay, longSource.block, longSource.chunk,
      'corroborating_core_co_timed');
    dieEvents.push({
      event_type: 'CHAMPION_DIE_EVENT_PACKET_CANDIDATE',
      game_version: BUILD, build_profile: CHAMPION_DIE_EVENT_PACKET_821_PROFILE.id,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_ON_CHAMPION_DIE_PACKET',
      replay_sha256: replay.source_sha256,
      replay_time_ms: dieRef.replay_time_ms, raw_param: spec.dieRaw,
      event_id: 0x0004, event_name: 'OnChampionDie', raw_event_id_hex: '0x4948',
      event_u32_0x04: spec.sourceId,
      event_blob_sha256: 'a'.repeat(64), raw_packet_ref: dieRef,
    });
    heroEvents.push({
      event_type: 'death', game_version: BUILD,
      build_profile: HERO_DEATH_CANDIDATE_PROFILE_821.id,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT',
      replay_sha256: replay.source_sha256,
      replay_time_ms: primary.replay_time_ms,
      victim_raw_param: spec.victimRaw,
      die_source_network_id_candidate: spec.sourceId,
      die_source_decode_status: 'EXACT_821_RUNTIME_WIRE_TRANSFORM',
      raw_packet_ref: primary, die_source_raw_packet_ref: paired,
      raw_packet_refs: [primary, paired, long],
    });
  }
  const championDieEventPacketOutcome = {
    status: 'CANDIDATE', profile_id: CHAMPION_DIE_EVENT_PACKET_821_PROFILE.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    runtime_image_sha256: IMAGE_SHA256, runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true, input_packet_id: 0x040a, child_event_id: 0x0004,
    input_count: dieEvents.length, event_count: dieEvents.length,
    observed_same_length_control_count: 0, events: dieEvents,
  };
  const heroDeathOutcome = {
    status: 'CANDIDATE', profile_id: HERO_DEATH_CANDIDATE_PROFILE_821.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    source_id_lookup_table_sha256:
      HERO_DEATH_CANDIDATE_PROFILE_821.source_id_lookup_table_sha256,
    runtime_image_status: 'STATIC_821_HERO_DIE_SOURCE_TRANSFORM_EMBEDDED',
    runtime_image_used: false,
    input_packet_id: 0x0259, input_count: heroEvents.length,
    event_count: heroEvents.length, matched_core_count: heroEvents.length,
    unmatched_primary_count: 0, hero_die_source_decoded_count: heroEvents.length,
    events: heroEvents,
  };
  return { replay, championDieEventPacketOutcome, heroDeathOutcome };
}

test('821 packet pair retains both raw routes and anonymous equality only', () => {
  const { replay, championDieEventPacketOutcome, heroDeathOutcome } = fixture();
  const result = associate(replay, { championDieEventPacketOutcome, heroDeathOutcome });
  assert.equal(CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE.capability,
    'champion_die_hero_death_pair');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 2);
  assert.equal(result.pair_count, 2);
  assert.equal(result.exact_raw_param_equal_count, 1);
  assert.deepEqual(result.raw_param_xor_delta_counts,
    { '0x00000000': 1, '0x00000100': 1 });
  assert.equal(result.events[0].on_champion_die_event_u32_0x04,
    result.events[0].hero_death_die_source_network_id_candidate);
  assert.deepEqual(result.events[0].raw_packet_refs.map((ref) => ref.packet_id),
    [0x040a, 0x0259, 0x0438, 0x031b]);
  for (const role of ['killer_participant_id', 'victim_participant_id',
    'effective_death']) {
    assert.equal(role in result.events[0], false);
  }
});

test('821 packet pair rejects duplicate same-chunk, same-ms rows atomically', () => {
  const values = fixture();
  values.championDieEventPacketOutcome.events.push(
    structuredClone(values.championDieEventPacketOutcome.events[0]));
  values.championDieEventPacketOutcome.event_count += 1;
  values.championDieEventPacketOutcome.input_count += 1;
  const result = associate(values.replay, values);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  assert.equal(result.pair_count, null);
  assert.match(result.error, /duplicated|duplicate/);
});

test('821 packet pair rejects foreign Replay SHA and changed source bytes', () => {
  const values = fixture();
  values.heroDeathOutcome.events[0].replay_sha256 = 'f'.repeat(64);
  const foreign = associate(values.replay, values);
  assert.equal(foreign.status, 'INCONSISTENT');
  assert.equal(foreign.events, null);
  const source = fixture();
  source.replay.buffer[0] ^= 1;
  assert.equal(associate(source.replay, source).status, 'DECODE_FAILED');
});

test('821 packet pair rejects time and anonymous field mismatches', () => {
  const time = fixture([{ timeMs: 1000, heroTimeMs: 2000,
    dieRaw: 0x400001ae, victimRaw: 0x400000ae,
    sourceId: 0x400000b0 }]);
  const unmatched = associate(time.replay, time);
  assert.equal(unmatched.status, 'INCONSISTENT');
  assert.equal(unmatched.events, null);
  assert.equal(unmatched.diagnostics.unmatched_on_champion_die_count, 1);
  assert.equal(unmatched.diagnostics.unmatched_hero_death_count, 1);
  const field = fixture();
  field.championDieEventPacketOutcome.events[0].event_u32_0x04 += 1;
  const conflicted = associate(field.replay, field);
  assert.equal(conflicted.status, 'INCONSISTENT');
  assert.equal(conflicted.events, null);
  assert.match(conflicted.error, /fields disagree/);
  const lowByte = fixture();
  const die = lowByte.championDieEventPacketOutcome.events[0];
  die.raw_param = 0x400001af;
  die.raw_packet_ref.raw_param = die.raw_param;
  assert.equal(associate(lowByte.replay, lowByte).status, 'INCONSISTENT');
});

test('821 packet pair requires exact successful decoder outcomes', () => {
  const values = fixture();
  assert.equal(associate(values.replay, {
    championDieEventPacketOutcome: values.championDieEventPacketOutcome,
  }).status, 'MISSING_INPUT');
  const wrongImage = structuredClone(values.championDieEventPacketOutcome);
  wrongImage.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(values.replay, { championDieEventPacketOutcome: wrongImage,
    heroDeathOutcome: values.heroDeathOutcome }).status, 'INCONSISTENT');
  const unavailable = structuredClone(values.heroDeathOutcome);
  unavailable.status = 'DECODE_FAILED';
  assert.equal(associate(values.replay, {
    championDieEventPacketOutcome: values.championDieEventPacketOutcome,
    heroDeathOutcome: unavailable,
  }).status, 'MISSING_INPUT');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
});
