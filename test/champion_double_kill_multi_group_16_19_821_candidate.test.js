'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_double_kill_event_packet_candidate');
const { CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_multiple_kill_die_hero_death_pair_candidate');
const { CHAMPION_DOUBLE_KILL_MULTI_GROUP_821_PROFILE: profile,
  associateChampionDoubleKillMultiGroupCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_champion_double_kill_multi_group_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MULTI_GROUP_STATUS = 'CANDIDATE_821_ON_CHAMPION_MULTIPLE_KILL_DIE_HERO_DIE_PACKET_GROUP';

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
  { timeMs: 1000, sourceParam: 0x400000b0, victimParam: 0x400001ae,
    multiOpaque08: 2, hasDouble: true },
  { timeMs: 2000, sourceParam: 0x400000b1, victimParam: 0x400000af,
    multiOpaque08: 1, hasDouble: false },
  { timeMs: 3000, sourceParam: 0x400000b2, victimParam: 0x400000b3,
    multiOpaque08: 2, hasDouble: true },
]) {
  const body = Buffer.concat([
    packet(0x0999, 0, 10, 0),
    ...specs.flatMap((spec) => {
      const die = packet(0x040a, spec.victimParam, 116, spec.timeMs);
      const double = spec.hasDouble
        ? packet(0x040a, spec.doubleParam ?? spec.sourceParam, 104,
          spec.doubleTimeMs ?? spec.timeMs) : null;
      const multi = packet(0x040a, spec.sourceParam, 88, spec.timeMs);
      const heroPrimary = packet(0x0259, spec.victimParam, 5, spec.timeMs);
      const heroPaired = packet(0x0438, spec.victimParam, 37, spec.timeMs);
      if (spec.doubleBeforeDie) {
        return [double, die, multi, heroPrimary, heroPaired];
      }
      if (spec.doubleAfterMulti) {
        return [die, multi, double, heroPrimary, heroPaired];
      }
      return [die, ...(double ? [double] : []), multi, heroPrimary, heroPaired];
    }),
  ]);
  const replay = replayFromChunks([{ stream: 1, body }], BUILD);
  const rows = [];
  walkBlocks(replay, (block, chunk) => rows.push({ block, chunk }), { strict: true });
  const find = (timeMs, packetId, length) => {
    const source = rows.find(({ block }) => block.timestamp_ms === timeMs
      && block.packet_id === packetId && block.payload_length === length);
    assert.ok(source, `${timeMs}/${packetId}/${length}`);
    return ref(replay, source.block, source.chunk);
  };
  const doubleEvents = [];
  const groupEvents = [];
  for (const spec of specs) {
    const die = find(spec.timeMs, 0x040a, 116);
    const multi = find(spec.timeMs, 0x040a, 88);
    const heroPrimary = find(spec.timeMs, 0x0259, 5);
    const heroPaired = find(spec.timeMs, 0x0438, 37);
    if (spec.hasDouble) {
      const target = find(spec.doubleTimeMs ?? spec.timeMs, 0x040a, 104);
      doubleEvents.push({
        event_type: 'CHAMPION_DOUBLE_KILL_EVENT_PACKET_CANDIDATE',
        game_version: BUILD,
        build_profile: CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE.id,
        replay_sha256: replay.source_sha256, replay_time_ms: target.replay_time_ms,
        raw_param: target.raw_param, child_event_id: 0x000b,
        registered_event_name: 'OnChampionDoubleKill', raw_event_id_hex: '0x4968',
        event_blob_sha256: 'a'.repeat(64), confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
        raw_packet_ref: target,
      });
    }
    groupEvents.push({
      event_type: 'CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
      game_version: BUILD,
      build_profile: CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE.id,
      replay_sha256: replay.source_sha256, replay_time_ms: spec.timeMs,
      on_champion_multiple_kill_child_event_id: 0x0009,
      on_champion_multiple_kill_raw_param: spec.sourceParam,
      on_champion_multiple_kill_event_u32_0x08: spec.multiOpaque08,
      on_champion_die_event_u32_0x04: spec.sourceParam,
      hero_death_die_source_network_id_candidate: spec.sourceParam,
      raw_packet_ref: structuredClone(multi),
      on_champion_multiple_kill_raw_packet_ref: multi,
      on_champion_die_raw_packet_ref: die,
      hero_death_raw_packet_refs: [
        { ...heroPrimary, role: 'candidate_primary' },
        { ...heroPaired, role: 'candidate_paired' },
      ],
      raw_packet_refs: [die, multi, heroPrimary, heroPaired]
        .map((item) => structuredClone(item)),
      confidence: 'CANDIDATE', semantic_status: MULTI_GROUP_STATUS,
    });
  }
  return {
    replay,
    championDoubleKillEventPacketOutcome: {
      status: 'CANDIDATE',
      profile_id: CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE.id,
      evidence_runtime_image_sha256: IMAGE_SHA256,
      runtime_image_sha256: IMAGE_SHA256,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      input_packet_id: 0x040a, child_event_id: 0x000b,
      input_count: doubleEvents.length, event_count: doubleEvents.length,
      events: doubleEvents,
    },
    championMultipleKillDieHeroDeathPairOutcome: {
      status: 'CANDIDATE',
      profile_id: CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE.id,
      evidence_runtime_image_sha256: IMAGE_SHA256,
      evidence_status: MULTI_GROUP_STATUS,
      replay_sha256: replay.source_sha256,
      pair_count: groupEvents.length, event_count: groupEvents.length,
      events: groupEvents,
    },
  };
}

test('821 double-kill-named packet group joins exact keys and preserves raw refs', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(profile.capability, 'champion_double_kill_multi_group');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.pair_count, 2);
  assert.equal(result.on_champion_double_kill_count, 2);
  assert.equal(result.on_champion_multiple_kill_group_count, 3);
  assert.equal(result.matched_multi_u32_0x08_2_count, 2);
  assert.equal(result.excluded_other_multi_u32_0x08_count, 1);
  assert.equal(result.unmatched_on_champion_double_kill_count, 0);
  assert.equal(result.unpaired_multi_u32_0x08_2_count, 0);
  assert.deepEqual(result.events.map((row) => row.replay_time_ms), [1000, 3000]);
  const row = result.events[0];
  assert.deepEqual(row.raw_packet_refs.map((item) => item.payload_length),
    [116, 104, 88, 5, 37]);
  assert.equal(row.on_champion_double_kill_raw_param,
    row.on_champion_multiple_kill_raw_param);
  assert.equal(row.on_champion_multiple_kill_opaque_u32_0x08, 2);
  assert.equal(row.on_champion_double_kill_raw_packet_ref.raw_payload_sha256,
    values.championDoubleKillEventPacketOutcome.events[0]
      .raw_packet_ref.raw_payload_sha256);
  assert.equal(row.on_champion_multiple_kill_raw_packet_ref.raw_payload_sha256,
    values.championMultipleKillDieHeroDeathPairOutcome.events[0]
      .on_champion_multiple_kill_raw_packet_ref.raw_payload_sha256);
  for (const field of ['killer', 'victim', 'actor', 'effective_double_kill',
    'double_kill_count', 'on_champion_double_kill_event_u32_0x04']) {
    assert.equal(field in row, false);
  }
});

test('821 double-kill-named packet group fails on missing, unavailable and wrong-build inputs', () => {
  const values = fixture();
  assert.equal(associate(values.replay, {}).status, 'MISSING_INPUT');
  const unavailable = fixture();
  unavailable.championDoubleKillEventPacketOutcome.status = 'PROFILE_UNAVAILABLE';
  assert.equal(associate(unavailable.replay, unavailable).status, 'MISSING_INPUT');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
  const corrupt = fixture();
  corrupt.replay.buffer[0] ^= 1;
  assert.equal(associate(corrupt.replay, corrupt).status, 'DECODE_FAILED');
});

test('821 double-kill-named packet group fails on unmatched and missing selected Multi keys', () => {
  const shifted = fixture([{ timeMs: 1000, doubleTimeMs: 1001,
    sourceParam: 0x400000b0, victimParam: 0x400001ae,
    multiOpaque08: 2, hasDouble: true }]);
  const shiftedResult = associate(shifted.replay, shifted);
  assert.equal(shiftedResult.status, 'INCONSISTENT');
  assert.equal(shiftedResult.events, null);
  assert.equal(shiftedResult.diagnostics.unmatched_on_champion_double_kill_count, 1);
  assert.equal(shiftedResult.diagnostics.unpaired_multi_u32_0x08_2_count, 1);

  const missing = fixture([
    { timeMs: 1000, sourceParam: 0x400000b0, victimParam: 0x400001ae,
      multiOpaque08: 2, hasDouble: true },
    { timeMs: 2000, sourceParam: 0x400000b1, victimParam: 0x400000af,
      multiOpaque08: 2, hasDouble: false },
  ]);
  const missingResult = associate(missing.replay, missing);
  assert.equal(missingResult.status, 'INCONSISTENT');
  assert.equal(missingResult.events, null);
  assert.equal(missingResult.diagnostics.unpaired_multi_u32_0x08_2_count, 1);
});

test('821 double-kill-named packet group rejects duplicate keys and positions', () => {
  const duplicate = fixture();
  const extra = structuredClone(duplicate.championDoubleKillEventPacketOutcome.events[0]);
  extra.raw_packet_ref.decompressed_block_offset += 1;
  extra.raw_packet_ref.decompressed_payload_offset += 1;
  duplicate.championDoubleKillEventPacketOutcome.events.push(extra);
  duplicate.championDoubleKillEventPacketOutcome.event_count += 1;
  duplicate.championDoubleKillEventPacketOutcome.input_count += 1;
  const result = associate(duplicate.replay, duplicate);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  assert.match(result.error, /duplicate/);

  const duplicateGroup = fixture();
  const copy = structuredClone(duplicateGroup.championMultipleKillDieHeroDeathPairOutcome.events[0]);
  for (const ref of [copy.raw_packet_ref, copy.on_champion_multiple_kill_raw_packet_ref,
    copy.on_champion_die_raw_packet_ref, ...copy.hero_death_raw_packet_refs,
    ...copy.raw_packet_refs]) {
    ref.decompressed_block_offset += 1;
    ref.decompressed_payload_offset += 1;
  }
  duplicateGroup.championMultipleKillDieHeroDeathPairOutcome.events.push(copy);
  duplicateGroup.championMultipleKillDieHeroDeathPairOutcome.event_count += 1;
  duplicateGroup.championMultipleKillDieHeroDeathPairOutcome.pair_count += 1;
  assert.equal(associate(duplicateGroup.replay, duplicateGroup).status, 'INCONSISTENT');
});

test('821 double-kill-named packet group rejects wrong order, outer param and opaque value', () => {
  const order = fixture([{ timeMs: 1000, sourceParam: 0x400000b0,
    victimParam: 0x400001ae, multiOpaque08: 2, hasDouble: true,
    doubleBeforeDie: true }]);
  assert.match(associate(order.replay, order).error, /order/);
  const rawParam = fixture([{ timeMs: 1000, sourceParam: 0x400000b0,
    victimParam: 0x400001ae, multiOpaque08: 2, hasDouble: true,
    doubleParam: 0x400000b1 }]);
  const rawResult = associate(rawParam.replay, rawParam);
  assert.equal(rawResult.status, 'INCONSISTENT');
  assert.match(rawResult.error, /raw parameters/);
  const opaque = fixture([{ timeMs: 1000, sourceParam: 0x400000b0,
    victimParam: 0x400001ae, multiOpaque08: 1, hasDouble: true }]);
  const opaqueResult = associate(opaque.replay, opaque);
  assert.equal(opaqueResult.status, 'INCONSISTENT');
  assert.match(opaqueResult.error, /anonymous \+0x08/);
});

test('821 double-kill-named packet group requires exact upstream identity and intact refs', () => {
  const wrongImage = fixture();
  wrongImage.championDoubleKillEventPacketOutcome.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
  const wrongProfile = fixture();
  wrongProfile.championMultipleKillDieHeroDeathPairOutcome.profile_id = 'foreign';
  assert.equal(associate(wrongProfile.replay, wrongProfile).status, 'INCONSISTENT');
  const wrongSha = fixture();
  wrongSha.championDoubleKillEventPacketOutcome.events[0].replay_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongSha.replay, wrongSha).status, 'INCONSISTENT');
  const damagedRef = fixture();
  damagedRef.championMultipleKillDieHeroDeathPairOutcome.events[0]
    .on_champion_multiple_kill_raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64);
  assert.equal(associate(damagedRef.replay, damagedRef).status, 'INCONSISTENT');
});
