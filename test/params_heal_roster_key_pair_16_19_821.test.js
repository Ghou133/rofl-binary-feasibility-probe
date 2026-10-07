'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const { resolveCapability } = require('../src/build_registry');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { parseOne } = require('../src/cli');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { PARAMS_HEAL_PACKET_CANDIDATE_PROFILE_821: HEAL_PROFILE } =
  require('../src/decoders/rofl_16_19_821_params_heal_packet_candidate');
const { HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE } =
  require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const { PARAMS_HEAL_ROSTER_KEY_PAIR_821_PROFILE: PAIR_PROFILE,
  associateParamsHealRosterKeys821: associate } =
  require('../src/decoders/rofl_16_19_821_params_heal_roster_key_pair_candidate');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const HEAL_EVIDENCE = 'CANDIDATE_EXACT_RUNTIME_PARAMS_HEAL_REPORT';
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE ?? null;
const REPLAY_DIR = process.env.ROFL_821_REPLAY_DIR ?? null;

function packet(id, param, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture(version = BUILD) {
  const keys = [
    [FIRST_KEY + 1, FIRST_KEY + 1],
    [FIRST_KEY + 2, FIRST_KEY + 3],
    [0x40003b78, FIRST_KEY + 4],
    [0x40003b79, 0x40003b80],
    [FIRST_KEY + 1 + 0x100, 0],
  ];
  const replay = replayFromChunks([
    { stream: 1, body: Buffer.concat(keys.map((_, index) =>
      packet(0x040a, FIRST_KEY + index, Buffer.alloc(60, index + 1),
        1000 + index * 100))) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x0089, FIRST_KEY + index, Buffer.alloc(1263, index), 2000))) },
  ], version);
  const healRefs = [];
  const rosterRefs = [];
  const walked = walkBlocks(replay, (block, chunk) => {
    const ref = {
      source_path: replay.source_path, replay_sha256: replay.source_sha256,
      chunk_index: chunk.index, chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
      decompressed_block_offset: block.offset,
      decompressed_payload_offset: block.payload_offset,
      packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
      payload_length: block.payload_length, raw_param: block.param >>> 0,
      raw_payload_sha256: sha(block.payload),
    };
    if (block.packet_id === 0x040a) healRefs.push(ref);
    else rosterRefs.push(ref);
  }, { strict: true });
  assert.equal(walked.errors.length, 0);
  const metadataSha = sha('metadata');
  const statsSha = sha('stats');
  const rosterRows = rosterRefs.map((ref, index) => ({
    event_type: 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: ROSTER_PROFILE.id,
    replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
    hero_raw_param: FIRST_KEY + index,
    participant_id_candidate: index + 1, metadata_index_candidate: index,
    champion_metadata: `Champion${index + 1}`,
    team_id_metadata: index < 5 ? 100 : 200,
    team_metadata: index < 5 ? 'blue' : 'red',
    role_metadata: ['top', 'jungle', 'mid', 'adc', 'support'][index % 5],
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    confidence: 'CANDIDATE',
    semantic_status: ROSTER_PROFILE.evidence_status,
    roster_to_metadata_status: ROSTER_PROFILE.evidence_status,
    per_packet_actor_status: 'UNKNOWN', raw_packet_ref: ref,
  }));
  const healRows = healRefs.map((ref, index) => ({
    event_type: 'PARAMS_HEAL_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: HEAL_PROFILE.id,
    replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
    raw_param: ref.raw_param, event_id: 0x004b,
    reported_amount_candidate: 50 + index,
    event_entity_u32_0x04: keys[index][0],
    event_entity_u32_0x14: keys[index][1],
    raw_event_id_hex: '0x4958', event_blob_sha256: sha(`heal-${index}`),
    confidence: 'CANDIDATE', semantic_status: HEAL_EVIDENCE,
    raw_packet_ref: ref,
  }));
  const paramsHealPacketOutcome = {
    status: 'CANDIDATE', profile_id: HEAL_PROFILE.id,
    evidence_status: HEAL_EVIDENCE,
    input_packet_id: 0x040a, child_event_id: 0x004b,
    input_count: healRows.length, event_count: healRows.length,
    events: healRows, runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
    runtime_image_sha256: HEAL_PROFILE.evidence_runtime_image_sha256,
  };
  const heroRosterMetadataBridgeOutcome = {
    status: 'CANDIDATE', profile_id: ROSTER_PROFILE.id,
    evidence_status: ROSTER_PROFILE.evidence_status,
    input_packet_id: 0x0089, input_count: 10, event_count: 10,
    unique_kda_match_count: 10, metadata_player_count: 10,
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    events: rosterRows,
  };
  return { replay, paramsHealPacketOutcome, heroRosterMetadataBridgeOutcome };
}

test('ParamsHeal fields independently pair by full u32 and retain every report', () => {
  const input = fixture();
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.source_report_count, 5);
  assert.equal(result.event_count, 5);
  assert.equal(result.matched_0x04_count, 2);
  assert.equal(result.matched_0x14_count, 3);
  assert.equal(result.both_matched_count, 2);
  assert.equal(result.both_nonroster_count, 2);
  assert.equal(result.only_0x04_matched_count, 0);
  assert.equal(result.only_0x14_matched_count, 1);
  assert.equal(result.unequal_fields_count, 4);
  assert.equal(result.plus_0x100_alias_excluded_0x04_count, 1);
  assert.equal(result.zero_0x14_count, 1);
  assert.equal(result.events[0].roster_match_0x04.participant_id_candidate, 2);
  assert.equal(result.events[1].roster_match_0x14.participant_id_candidate, 4);
  assert.equal(result.events[2].roster_match_0x04.status, 'NOT_IN_TEN_KEY_ROSTER');
  assert.equal(result.events[2].roster_match_0x14.participant_id_candidate, 5);
  assert.equal(result.events[3].roster_match_0x14.roster_keyframe_packet_ref, null);
  assert.equal(result.events[4].roster_match_0x04.status, 'NOT_IN_TEN_KEY_ROSTER');
  assert.equal(result.events[4].raw_packet_ref.packet_id, 0x040a);
  assert.equal(result.events[0].roster_match_0x04.roster_keyframe_packet_ref.packet_id,
    0x0089);
  assert.equal(result.events[0].field_role_status, 'UNKNOWN');
  assert.equal(result.events[0].packet_actor_status, 'UNKNOWN');
  assert.equal(result.events[0].effective_heal_status, 'UNKNOWN');
  assert.doesNotMatch(JSON.stringify(result.events), /puuid|riot_id|effective_healing_amount/i);
  assert.equal(resolveCapability(BUILD, PAIR_PROFILE.capability).status, 'CANDIDATE');
  assert.equal(resolveCapability('16.19.820.7193', PAIR_PROFILE.capability).status,
    'UNAVAILABLE');
});

test('zero roster matches remain candidate rows, not an empty or successful heal claim', () => {
  const input = fixture();
  for (const row of input.paramsHealPacketOutcome.events) {
    row.event_entity_u32_0x04 = 0x40003b78;
    row.event_entity_u32_0x14 = 0x40003b79;
  }
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 5);
  assert.equal(result.matched_0x04_count, 0);
  assert.equal(result.matched_0x14_count, 0);
  assert.equal(result.both_nonroster_count, 5);
  assert.ok(result.events.every((row) => row.effective_heal_status === 'UNKNOWN'));
});

test('missing, neighboring-build and malformed source inputs fail without pair rows', () => {
  const input = fixture();
  const missing = associate(input.replay, {
    paramsHealPacketOutcome: input.paramsHealPacketOutcome,
  });
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);
  const wrongBuild = fixture('16.19.820.7193');
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
  const damaged = fixture();
  damaged.paramsHealPacketOutcome.events[4].raw_packet_ref.raw_param = 0;
  assert.equal(associate(damaged.replay, damaged).status, 'DECODE_FAILED');
  const incomplete = fixture();
  incomplete.heroRosterMetadataBridgeOutcome.events[9].raw_packet_ref.raw_param = 0;
  assert.equal(associate(incomplete.replay, incomplete).status, 'DECODE_FAILED');
  const wrongImage = fixture();
  wrongImage.paramsHealPacketOutcome.runtime_image_sha256 = sha('wrong');
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'DECODE_FAILED');
  const excess = fixture();
  excess.paramsHealPacketOutcome.input_count = 20_001;
  assert.equal(associate(excess.replay, excess).status, 'DECODE_FAILED');
});

test('real exact-821 API and CLI keep all reports and asymmetric negatives', {
  skip: !IMAGE || !fs.existsSync(IMAGE) || !REPLAY_DIR
    || !fs.existsSync(path.join(REPLAY_DIR, 'KR_8392938200.rofl'))
    || !fs.existsSync(path.join(REPLAY_DIR, 'KR_8393872512.rofl')),
}, () => {
  const first = path.join(REPLAY_DIR, 'KR_8392938200.rofl');
  const second = path.join(REPLAY_DIR, 'KR_8393872512.rofl');
  const decoded = decodeSemanticReplay(parseReplayFile(first), {
    capabilities: [PAIR_PROFILE.capability], runtimeImagePath: IMAGE,
  });
  const firstResult = decoded.capability_results[PAIR_PROFILE.capability];
  assert.equal(firstResult.status, 'CANDIDATE', firstResult.error);
  assert.equal(firstResult.event_count, 6059);
  assert.equal(firstResult.both_nonroster_count, 1304);
  assert.equal(decoded.events.params_heal_roster_key_pair_candidates.length, 6059);
  const parsed = parseOne(second, {
    semantic: true, events: [PAIR_PROFILE.capability],
    runtimeImage: IMAGE, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true, parsed.error);
  const secondResult = parsed.analysis.semantic.capability_results[PAIR_PROFILE.capability];
  assert.equal(secondResult.status, 'CANDIDATE', secondResult.error);
  assert.equal(secondResult.event_count, 6297);
  assert.equal(secondResult.only_0x14_matched_count, 33);
  assert.equal(secondResult.only_0x04_matched_count, 0);
  assert.ok(parsed.analysis.events.params_heal_roster_key_pair_candidates.some(
    (row) => row.roster_match_0x04.status === 'NOT_IN_TEN_KEY_ROSTER'
      && row.roster_match_0x14.status === 'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY'
      && row.field_role_status === 'UNKNOWN'
      && row.effective_heal_status === 'UNKNOWN'));
});
