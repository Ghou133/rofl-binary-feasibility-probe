'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { ON_SHUTDOWN_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_on_shutdown_event_packet_candidate');
const { CHAMPION_DIE_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_die_event_packet_candidate');
const { HERO_DEATH_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_7343');
const { ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE,
  associateOnShutdownDieHeroDeathCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_on_shutdown_die_hero_death_pair_candidate');

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
    chunk_index: chunk.index, chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length, raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function fixture(specs = [
  { timeMs: 1000, dieRaw: 0x400001ae, victimRaw: 0x400001ae,
    sourceId: 0x400000b0, shutdownKey: 0x400000ae, hasShutdown: true },
  { timeMs: 2000, dieRaw: 0x400000af, victimRaw: 0x400000af,
    sourceId: 0x400000b1, shutdownKey: 0x400000af, hasShutdown: true },
  { timeMs: 3000, dieRaw: 0x400000b2, victimRaw: 0x400000b2,
    sourceId: 0x400000b3, hasShutdown: false },
]) {
  const body = Buffer.concat([
    packet(0x0999, 0, 10, 0),
    ...specs.flatMap((spec) => [
      packet(0x040a, spec.dieRaw, 116, spec.timeMs),
      packet(0x031b, 0, 40, spec.timeMs),
      ...(spec.hasShutdown ? [packet(0x040a, spec.sourceId, 105,
        spec.shutdownTimeMs ?? spec.timeMs)] : []),
      packet(0x0259, spec.victimRaw, 5, spec.timeMs),
      packet(0x0438, spec.victimRaw, 37, spec.timeMs),
    ]),
  ]);
  const replay = replayFromChunks([{ stream: 1, body }], BUILD);
  const groups = new Map();
  walkBlocks(replay, (block, chunk) => {
    groups.set(`${block.timestamp_ms}/${block.packet_id}/${block.payload_length}`,
      { block, chunk });
  }, { strict: true });
  const dieEvents = [];
  const shutdownEvents = [];
  const heroEvents = [];
  for (const spec of specs) {
    const get = (packetId, length, time = spec.timeMs, role) => {
      const source = groups.get(`${time}/${packetId}/${length}`);
      return ref(replay, source.block, source.chunk, role);
    };
    const dieRef = get(0x040a, 116);
    const primary = get(0x0259, 5, spec.timeMs, 'candidate_primary');
    const paired = get(0x0438, 37, spec.timeMs, 'candidate_paired');
    const long = get(0x031b, 40, spec.timeMs, 'corroborating_core_co_timed');
    dieEvents.push({
      event_type: 'CHAMPION_DIE_EVENT_PACKET_CANDIDATE',
      game_version: BUILD, build_profile: CHAMPION_DIE_EVENT_PACKET_821_PROFILE.id,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_ON_CHAMPION_DIE_PACKET',
      replay_sha256: replay.source_sha256, replay_time_ms: spec.timeMs,
      raw_param: spec.dieRaw, event_id: 0x0004, event_name: 'OnChampionDie',
      raw_event_id_hex: '0x4948', event_u32_0x04: spec.sourceId,
      event_blob_sha256: 'a'.repeat(64), raw_packet_ref: dieRef,
    });
    heroEvents.push({
      event_type: 'death', game_version: BUILD,
      build_profile: HERO_DEATH_CANDIDATE_PROFILE_821.id,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT',
      replay_sha256: replay.source_sha256, replay_time_ms: spec.timeMs,
      victim_raw_param: spec.victimRaw,
      die_source_network_id_candidate: spec.sourceId,
      die_source_decode_status: 'EXACT_821_RUNTIME_WIRE_TRANSFORM',
      raw_packet_ref: primary, die_source_raw_packet_ref: paired,
      raw_packet_refs: [primary, paired, long],
    });
    if (spec.hasShutdown) {
      const shutdownRef = get(0x040a, 105, spec.shutdownTimeMs ?? spec.timeMs);
      shutdownEvents.push({
        event_type: 'ON_SHUTDOWN_EVENT_PACKET_CANDIDATE',
        game_version: BUILD, build_profile: ON_SHUTDOWN_EVENT_PACKET_821_PROFILE.id,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
        replay_sha256: replay.source_sha256,
        replay_time_ms: shutdownRef.replay_time_ms,
        raw_param: spec.sourceId,
        child_event_id: 0x00e8, registered_event_name: 'OnShutdown',
        raw_event_id_hex: '0x49af', event_u32_0x04: spec.shutdownKey,
        event_u32_0x58: 17, event_u32_0x5c: 19,
        event_blob_sha256: 'b'.repeat(64), raw_packet_ref: shutdownRef,
      });
    }
  }
  return {
    replay,
    onShutdownEventPacketOutcome: {
      status: 'CANDIDATE', profile_id: ON_SHUTDOWN_EVENT_PACKET_821_PROFILE.id,
      evidence_runtime_image_sha256: IMAGE_SHA256,
      runtime_image_sha256: IMAGE_SHA256, runtime_image_status: 'MATCHED_USED',
      runtime_image_used: true, input_packet_id: 0x040a, child_event_id: 0x00e8,
      input_count: shutdownEvents.length, event_count: shutdownEvents.length,
      events: shutdownEvents,
    },
    championDieEventPacketOutcome: {
      status: 'CANDIDATE', profile_id: CHAMPION_DIE_EVENT_PACKET_821_PROFILE.id,
      evidence_runtime_image_sha256: IMAGE_SHA256,
      runtime_image_sha256: IMAGE_SHA256, runtime_image_status: 'MATCHED_USED',
      runtime_image_used: true, input_packet_id: 0x040a, child_event_id: 0x0004,
      input_count: dieEvents.length, event_count: dieEvents.length,
      observed_same_length_control_count: 0, events: dieEvents,
    },
    heroDeathOutcome: {
      status: 'CANDIDATE', profile_id: HERO_DEATH_CANDIDATE_PROFILE_821.id,
      evidence_runtime_image_sha256: IMAGE_SHA256,
      source_id_lookup_table_sha256:
        HERO_DEATH_CANDIDATE_PROFILE_821.source_id_lookup_table_sha256,
      runtime_image_status: 'STATIC_821_HERO_DIE_SOURCE_TRANSFORM_EMBEDDED',
      runtime_image_used: false, input_packet_id: 0x0259,
      input_count: heroEvents.length, event_count: heroEvents.length,
      matched_core_count: heroEvents.length, unmatched_primary_count: 0,
      hero_die_source_decoded_count: heroEvents.length, events: heroEvents,
    },
  };
}

test('821 Shutdown packet group preserves anonymous fields and distinct raw references', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE.capability,
    'on_shutdown_die_hero_death_pair');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.pair_count, 2);
  assert.equal(result.unmatched_on_shutdown_count, 0);
  assert.equal(result.unpaired_on_champion_die_count, 1);
  assert.deepEqual(result.shutdown_0x04_xor_hero_raw_delta_counts,
    { '0x00000000': 1, '0x00000100': 1 });
  assert.deepEqual(result.events[0].raw_packet_refs.map((item) => item.packet_id),
    [0x040a, 0x031b, 0x040a, 0x0259, 0x0438]);
  assert.equal(result.events[0].on_shutdown_raw_param,
    result.events[0].hero_death_die_source_network_id_candidate);
  assert.equal(result.events[0].on_shutdown_event_u32_0x58, 17);
  for (const field of ['killer_participant_id', 'victim_participant_id',
    'effective_shutdown', 'effective_kill', 'shutdown_streak']) {
    assert.equal(field in result.events[0], false);
  }
});

test('821 Shutdown packet group fails atomically on wrong identity, duplicate or field conflict', () => {
  const duplicate = fixture();
  const extra = structuredClone(duplicate.onShutdownEventPacketOutcome.events[0]);
  extra.raw_packet_ref.decompressed_block_offset += 1;
  extra.raw_packet_ref.decompressed_payload_offset += 1;
  duplicate.onShutdownEventPacketOutcome.events.push(extra);
  duplicate.onShutdownEventPacketOutcome.event_count += 1;
  duplicate.onShutdownEventPacketOutcome.input_count += 1;
  assert.equal(associate(duplicate.replay, duplicate).status, 'INCONSISTENT');

  const changedField = fixture();
  changedField.onShutdownEventPacketOutcome.events[0].event_u32_0x04 ^= 1;
  const fieldResult = associate(changedField.replay, changedField);
  assert.equal(fieldResult.status, 'INCONSISTENT');
  assert.equal(fieldResult.events, null);
  assert.equal(fieldResult.pair_count, null);

  const wrongImage = fixture();
  wrongImage.onShutdownEventPacketOutcome.runtime_image_sha256 = '0'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
});

test('821 Shutdown packet group requires same chunk/time and exact upstream outcomes', () => {
  const shifted = fixture([{ timeMs: 1000, shutdownTimeMs: 2000,
    dieRaw: 0x400001ae, victimRaw: 0x400001ae,
    sourceId: 0x400000b0, shutdownKey: 0x400000ae, hasShutdown: true }]);
  const shiftedResult = associate(shifted.replay, shifted);
  assert.equal(shiftedResult.status, 'INCONSISTENT');
  assert.match(shiftedResult.error, /counterpart/);

  const missing = fixture();
  delete missing.onShutdownEventPacketOutcome;
  assert.equal(associate(missing.replay, missing).status, 'MISSING_INPUT');

  const unavailable = fixture();
  unavailable.onShutdownEventPacketOutcome.status = 'MISSING_INPUT';
  assert.equal(associate(unavailable.replay, unavailable).status, 'MISSING_INPUT');

  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
});
