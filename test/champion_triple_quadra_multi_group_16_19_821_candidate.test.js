'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_triple_quadra_event_packet_candidate');
const { CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_multiple_kill_die_hero_death_pair_candidate');
const { CHAMPION_TRIPLE_QUADRA_MULTI_GROUP_821_PROFILE: profile,
  associateChampionTripleQuadraMultiGroupCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_champion_triple_quadra_multi_group_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MULTI_GROUP_STATUS = 'CANDIDATE_821_ON_CHAMPION_MULTIPLE_KILL_DIE_HERO_DIE_PACKET_GROUP';
const CHILDREN = new Map([
  [0x000c, { name: 'OnChampionTripleKill', rawEventIdHex: '0x49c8' }],
  [0x000d, { name: 'OnChampionQuadraKill', rawEventIdHex: '0x4988' }],
]);

function packet(packetId, rawParam, length, timeMs) {
  const payload = Buffer.alloc(length, packetId & 0xff);
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
    multiOpaque08: 3, childId: 0x000c },
  { timeMs: 2000, sourceParam: 0x400000b1, victimParam: 0x400000af,
    multiOpaque08: 1 },
  { timeMs: 3000, sourceParam: 0x400000b2, victimParam: 0x400000b3,
    multiOpaque08: 4, childId: 0x000d },
]) {
  const body = Buffer.concat([
    packet(0x0999, 0, 10, 0),
    ...specs.flatMap((spec) => {
      const die = packet(0x040a, spec.victimParam, 116, spec.timeMs);
      const named = spec.childId
        ? packet(0x040a, spec.namedParam ?? spec.sourceParam, 104,
          spec.namedTimeMs ?? spec.timeMs) : null;
      const multi = packet(0x040a, spec.sourceParam, 88, spec.timeMs);
      const heroPrimary = packet(0x0259, spec.victimParam, 5, spec.timeMs);
      const heroPaired = packet(0x0438, spec.victimParam, 37, spec.timeMs);
      if (spec.namedBeforeDie) {
        return [named, die, multi, heroPrimary, heroPaired];
      }
      if (spec.namedAfterMulti) {
        return [die, multi, named, heroPrimary, heroPaired];
      }
      return [die, ...(named ? [named] : []), multi, heroPrimary, heroPaired];
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
  const namedEvents = [];
  const groupEvents = [];
  for (const spec of specs) {
    const die = find(spec.timeMs, 0x040a, 116);
    const multi = find(spec.timeMs, 0x040a, 88);
    const heroPrimary = find(spec.timeMs, 0x0259, 5);
    const heroPaired = find(spec.timeMs, 0x0438, 37);
    if (spec.childId) {
      const target = find(spec.namedTimeMs ?? spec.timeMs, 0x040a, 104);
      const child = CHILDREN.get(spec.childId);
      namedEvents.push({
        event_type: 'CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_CANDIDATE',
        game_version: BUILD,
        build_profile: CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE.id,
        replay_sha256: replay.source_sha256, replay_time_ms: target.replay_time_ms,
        raw_param: target.raw_param, child_event_id: spec.childId,
        registered_event_name: child.name, raw_event_id_hex: child.rawEventIdHex,
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
    championTripleQuadraEventPacketOutcome: {
      status: 'CANDIDATE',
      profile_id: CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE.id,
      evidence_runtime_image_sha256: IMAGE_SHA256,
      runtime_image_sha256: IMAGE_SHA256,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      input_packet_id: 0x040a,
      input_count: namedEvents.length, target_packet_count: namedEvents.length,
      event_count: namedEvents.length, events: namedEvents,
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

test('821 triple/quadra named packet groups join exact keys and preserve raw refs', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(profile.capability, 'champion_triple_quadra_multi_group');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.pair_count, 2);
  assert.equal(result.on_champion_triple_quadra_count, 2);
  assert.equal(result.on_champion_multiple_kill_group_count, 3);
  assert.equal(result.matched_multi_u32_0x08_3_count, 1);
  assert.equal(result.matched_multi_u32_0x08_4_count, 1);
  assert.equal(result.excluded_other_multi_u32_0x08_count, 1);
  assert.deepEqual(result.events.map((row) => row.replay_time_ms), [1000, 3000]);
  assert.deepEqual(result.events.map((row) => row.on_champion_triple_quadra_child_event_id),
    [0x000c, 0x000d]);
  const row = result.events[0];
  assert.equal(row.event_type,
    'CHAMPION_TRIPLE_QUADRA_MULTI_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE');
  assert.deepEqual(row.raw_packet_refs.map((item) => item.payload_length),
    [116, 104, 88, 5, 37]);
  assert.equal(row.on_champion_triple_quadra_raw_param,
    row.on_champion_multiple_kill_raw_param);
  assert.equal(row.on_champion_triple_quadra_raw_packet_ref.raw_payload_sha256,
    values.championTripleQuadraEventPacketOutcome.events[0]
      .raw_packet_ref.raw_payload_sha256);
  for (const field of ['killer', 'victim', 'actor', 'effective_triple_kill',
    'effective_quadra_kill', 'kill_count', 'on_champion_triple_quadra_event_u32_0x04']) {
    assert.equal(field in row, false);
  }
});

test('821 triple/quadra named packet groups reject missing, unavailable and wrong-build inputs', () => {
  const values = fixture();
  assert.equal(associate(values.replay, {}).status, 'MISSING_INPUT');
  const unavailable = fixture();
  unavailable.championTripleQuadraEventPacketOutcome.status = 'PROFILE_UNAVAILABLE';
  assert.equal(associate(unavailable.replay, unavailable).status, 'MISSING_INPUT');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
  const corrupt = fixture();
  corrupt.replay.buffer[0] ^= 1;
  assert.equal(associate(corrupt.replay, corrupt).status, 'DECODE_FAILED');
});

test('821 triple/quadra named packet groups reject unmatched and absent selected Multi keys', () => {
  const shifted = fixture([{ timeMs: 1000, namedTimeMs: 1001,
    sourceParam: 0x400000b0, victimParam: 0x400001ae,
    multiOpaque08: 3, childId: 0x000c }]);
  const shiftedResult = associate(shifted.replay, shifted);
  assert.equal(shiftedResult.status, 'INCONSISTENT');
  assert.equal(shiftedResult.events, null);
  assert.equal(shiftedResult.diagnostics.unmatched_on_champion_triple_quadra_count, 1);
  assert.equal(shiftedResult.diagnostics.unpaired_multi_u32_0x08_3_or_4_count, 1);

  const absent = fixture([
    { timeMs: 1000, sourceParam: 0x400000b0, victimParam: 0x400001ae,
      multiOpaque08: 3, childId: 0x000c },
    { timeMs: 2000, sourceParam: 0x400000b1, victimParam: 0x400000af,
      multiOpaque08: 4 },
  ]);
  const absentResult = associate(absent.replay, absent);
  assert.equal(absentResult.status, 'INCONSISTENT');
  assert.equal(absentResult.events, null);
  assert.equal(absentResult.diagnostics.unpaired_multi_u32_0x08_3_or_4_count, 1);
});

test('821 triple/quadra named packet groups reject wrong child-to-Multi mapping and packet order', () => {
  const mismapped = fixture([{ timeMs: 1000, sourceParam: 0x400000b0,
    victimParam: 0x400001ae, multiOpaque08: 4, childId: 0x000c }]);
  const mappedResult = associate(mismapped.replay, mismapped);
  assert.equal(mappedResult.status, 'INCONSISTENT');
  assert.match(mappedResult.error, /anonymous \+0x08/);
  const order = fixture([{ timeMs: 1000, sourceParam: 0x400000b0,
    victimParam: 0x400001ae, multiOpaque08: 3, childId: 0x000c,
    namedAfterMulti: true }]);
  assert.match(associate(order.replay, order).error, /order/);
  const rawParam = fixture([{ timeMs: 1000, sourceParam: 0x400000b0,
    victimParam: 0x400001ae, multiOpaque08: 3, childId: 0x000c,
    namedParam: 0x400000b1 }]);
  assert.match(associate(rawParam.replay, rawParam).error, /raw parameters/);
});

test('821 triple/quadra named packet groups reject duplicate keys and invalid identities', () => {
  const duplicate = fixture();
  const extra = structuredClone(duplicate.championTripleQuadraEventPacketOutcome.events[0]);
  extra.raw_packet_ref.decompressed_block_offset += 1;
  extra.raw_packet_ref.decompressed_payload_offset += 1;
  duplicate.championTripleQuadraEventPacketOutcome.events.push(extra);
  duplicate.championTripleQuadraEventPacketOutcome.event_count += 1;
  duplicate.championTripleQuadraEventPacketOutcome.target_packet_count += 1;
  duplicate.championTripleQuadraEventPacketOutcome.input_count += 1;
  assert.match(associate(duplicate.replay, duplicate).error, /duplicate/);

  const wrongImage = fixture();
  wrongImage.championTripleQuadraEventPacketOutcome.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
  const wrongName = fixture();
  wrongName.championTripleQuadraEventPacketOutcome.events[0].registered_event_name =
    'OnChampionQuadraKill';
  assert.equal(associate(wrongName.replay, wrongName).status, 'INCONSISTENT');
  const wrongSha = fixture();
  wrongSha.championTripleQuadraEventPacketOutcome.events[0].replay_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongSha.replay, wrongSha).status, 'INCONSISTENT');
  const damagedRef = fixture();
  damagedRef.championMultipleKillDieHeroDeathPairOutcome.events[0]
    .on_champion_multiple_kill_raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64);
  assert.equal(associate(damagedRef.replay, damagedRef).status, 'INCONSISTENT');
});
