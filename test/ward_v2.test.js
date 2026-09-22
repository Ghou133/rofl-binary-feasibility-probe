const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  WARD_P0_PROFILE,
  WARD_SPAWN_PROFILE,
  isWardSpellIdentifier,
  buildWardCastCandidates,
  buildWardOutputs,
  writeWardOutputs,
} = require('../src/ward_pipeline_v2');
const { packetRefKey } = require('../src/provenance_v2');

function replay() {
  return {
    source_path: 'synthetic.rofl',
    source_sha256: 'replay-sha',
    header: { version: WARD_P0_PROFILE.replay_version },
    tail: { stats: [{ SKIN: 'Lulu' }, { SKIN: 'Jinx' }] },
    chunks: [{ index: 3, chunk_id: 4, stream_tag: 1, stream: 'game_chunk', offset: 100, body_offset: 117,
      decompressed: Buffer.alloc(0) }],
  };
}

test('Ward P0 candidate preserves CastSpell raw provenance and does not claim ward facts', () => {
  const source = replay();
  source.chunks[0].decompressed = Buffer.from([0]);
  // Build through a stub walker input is intentionally avoided; candidate shape is tested directly below.
  const row = require('../src/ward_pipeline_v2').candidateFromBlock(source, source.chunks[0], {
    packet_id: 0x0459, payload_length: 3, payload: Buffer.from('010203', 'hex'),
    param: 0x400000ae, timestamp_ms: 1234, offset: 20, payload_offset: 27,
  }, 0);
  assert.equal(row.schema_version, 2);
  assert.equal(row.candidate_status, 'INFERRED');
  assert.equal(row.caster_participant_id, 1);
  assert.equal(row.caster_champion, 'Lulu');
  assert.equal(row.ward_type, null);
  assert.equal(row.raw_packet_ref.replay_sha256, 'replay-sha');
  assert.equal(row.raw_packet_ref.payload_length, 3);
});

test('Ward outputs expose an explicit unavailable event surface and writer', () => {
  const source = replay();
  const outputs = buildWardOutputs(source, { candidates: [] });
  assert.equal(outputs.schema_version, 2);
  assert.deepEqual(outputs.ward_events, []);
  assert.deepEqual(outputs.ward_lifecycles, []);
  assert.deepEqual(outputs.ward_cast_spawn_matches, []);
  assert.deepEqual(outputs.ward_heatmap_input, []);
  assert.equal(outputs.provenance.fact_source, 'ROFL_REPLAY_PACKET_BYTES');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ward-v2-'));
  const files = writeWardOutputs(dir, outputs);
  assert.ok(fs.existsSync(files.candidates_path));
  assert.ok(fs.existsSync(files.events_path));
  assert.ok(fs.existsSync(files.events_csv_path));
  assert.ok(fs.existsSync(files.lifecycles_path));
  assert.ok(fs.existsSync(files.spawn_matches_path));
  assert.ok(fs.existsSync(files.heatmap_input_path));
  assert.ok(fs.existsSync(files.provenance_path));
  assert.ok(fs.existsSync(files.outputs_path));
  assert.equal(fs.readFileSync(files.candidates_path, 'utf8'), '');
  assert.match(fs.readFileSync(files.heatmap_input_csv_path, 'utf8'), /^game_id,/);
});

test('Ward raw parameter mapping rejects non-participant entities', () => {
  const source = replay();
  const row = require('../src/ward_pipeline_v2').candidateFromBlock(source, source.chunks[0], {
    packet_id: 0x0459, payload_length: 1, payload: Buffer.from([0]),
    param: 0x400000ad, timestamp_ms: 0, offset: 1, payload_offset: 2,
  }, 0);
  assert.equal(row.caster_participant_id, null);
  assert.equal(row.caster_network_id, null);
  assert.equal(row.field_confidence.caster_network_id, 'UNAVAILABLE');
});

test('Ward candidate extraction rejects unsupported Replay versions', () => {
  assert.throws(
    () => buildWardCastCandidates({ header: { version: '16.14.1' }, chunks: [] }),
    (error) => error.code === 'WARD_REPLAY_VERSION_UNSUPPORTED',
  );
});

test('Verified CastSpell ward conversion filters sweepers and preserves target coordinates', () => {
  const source = replay();
  const outputs = buildWardOutputs(source, { spell_events: [
    {
      replay_time_ms: 4567,
      caster_network_id: 0x400000ae,
      caster_participant_id: 1,
      caster_champion: 'Lulu',
      caster_team_id: 100,
      spell_key: 0x1234,
      spell_identifier: 'TrinketTotemLvl1',
      spell_name: 'Stealth Ward',
      target_position: { x: 100, y: 200, z: 300 },
      confidence: 'VERIFIED_DIRECT',
      semantic_status: 'VERIFIED_DIRECT',
      raw_packet_ref: {
        packet_id: WARD_P0_PROFILE.replay_block_packet_id,
        replay_sha256: 'replay-sha',
        payload_sha256: 'packet-sha',
      },
    },
    { replay_time_ms: 5000, spell_identifier: 'TrinketSweeperLvl3' },
  ] });
  assert.equal(outputs.ward_cast_candidates.length, 1);
  const row = outputs.ward_cast_candidates[0];
  assert.equal(row.candidate_status, 'VERIFIED');
  assert.equal(row.position_source, 'CAST_TARGET_DIRECT');
  assert.deepEqual([row.cast_target_x, row.cast_target_y, row.cast_target_z], [100, 200, 300]);
  assert.equal(outputs.ward_events.length, 1);
  assert.equal(outputs.ward_events[0].event_status, 'CAST_OBSERVED_SPAWN_UNAVAILABLE');
  assert.equal(outputs.ward_events[0].actual_x, null);
  assert.equal(outputs.ward_events[0].position_source, 'CAST_TARGET_DIRECT');
  assert.equal(outputs.ward_heatmap_input.length, 1);
  assert.equal(outputs.ward_heatmap_input[0].is_spawn_position, false);
  assert.equal(outputs.ward_heatmap_input[0].coordinate_system, 'SUMMONERS_RIFT');
  assert.equal(outputs.ward_heatmap_input[0].normalized_x, null);
  assert.equal(outputs.ward_cast_spawn_matches.length, 0);
  assert.equal(outputs.provenance.fact_source, 'ROFL_REPLAY_PACKET_BYTES');
});

test('Ward identifier policy is exact and keeps unobserved or sweeper actions out', () => {
  assert.equal(isWardSpellIdentifier('TrinketTotemLvl1'), true);
  assert.equal(isWardSpellIdentifier('TrinketTotemLvl2'), false);
  assert.equal(isWardSpellIdentifier('SightWard'), false);
  assert.equal(isWardSpellIdentifier('TrinketSweeperLvl3'), false);
  assert.equal(isWardSpellIdentifier('JinxEMineSight'), false);
});

test('Verified ward conversion rejects semantic rows from another replay', () => {
  const source = replay();
  const outputs = buildWardOutputs(source, { spell_events: [{
    replay_time_ms: 1,
    spell_identifier: 'TrinketTotemLvl1',
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    raw_packet_ref: {
      packet_id: WARD_P0_PROFILE.replay_block_packet_id,
      replay_sha256: 'other-replay',
    },
  }] });
  assert.deepEqual(outputs.ward_cast_candidates, []);
  assert.deepEqual(outputs.ward_events, []);
  assert.deepEqual(outputs.ward_heatmap_input, []);
});

function verifiedWardSpell(overrides = {}) {
  return {
    replay_time_ms: 10000,
    caster_network_id: 0x400000ae,
    caster_participant_id: 1,
    caster_champion: 'Lulu',
    caster_team_id: 100,
    spell_key: 0x0fb93891,
    spell_identifier: 'TrinketTotemLvl1',
    target_position: { x: 100, y: 12, z: 200 },
    target_position_end: { x: 480, y: 12, z: 600 },
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    raw_packet_ref: {
      packet_id: WARD_P0_PROFILE.replay_block_packet_id,
      replay_sha256: 'replay-sha',
      payload_sha256: 'cast-packet-sha',
    },
    ...overrides,
  };
}

function verifiedWardSpawn(overrides = {}) {
  return {
    replay_time_ms: 10025,
    entity_network_id: 0x4000abcd,
    owner_network_id: 0x400000ae,
    entity_name: 'YellowTrinket',
    position: { x: 481, height: 12, y: 601 },
    decoder_profile: WARD_SPAWN_PROFILE.id,
    decoder_return_al: 1,
    fully_consumed: true,
    field_confidence: {
      position: 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
      entity_network_id: 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
      owner_network_id: 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
      entity_name: 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
    },
    raw_packet_ref: {
      packet_id: WARD_SPAWN_PROFILE.replay_packet_id,
      replay_sha256: 'replay-sha',
      chunk_index: 3,
      decompressed_block_offset: 100,
      payload_length: 67,
      raw_param: 0x4000abcd,
      payload_sha256: 'b'.repeat(64),
    },
    ...overrides,
  };
}

test('Verified WardSpawn rows enrich a matched cast without substituting CastSpell coordinates', () => {
  const spawn = verifiedWardSpawn();
  const removeRef = {
    ...spawn.raw_packet_ref,
    decompressed_block_offset: 200,
    payload_sha256: 'c'.repeat(64),
  };
  const packetProvenanceIndex = new Map([
    [packetRefKey(3, 100, WARD_SPAWN_PROFILE.replay_packet_id), {
      replay_sha256: 'replay-sha',
      packet_id: WARD_SPAWN_PROFILE.replay_packet_id,
      timestamp_ms: 10025,
      payload_length: 67,
      raw_param: 0x4000abcd,
      raw_payload_sha256: 'b'.repeat(64),
    }],
    [packetRefKey(3, 200, WARD_SPAWN_PROFILE.replay_packet_id), {
      replay_sha256: 'replay-sha',
      packet_id: WARD_SPAWN_PROFILE.replay_packet_id,
      timestamp_ms: 91025,
      payload_length: 67,
      raw_param: 0x4000abcd,
      raw_payload_sha256: 'c'.repeat(64),
    }],
  ]);
  const outputs = buildWardOutputs(replay(), {
    spell_events: [verifiedWardSpell()],
    ward_spawn_events: [spawn],
    ward_spawn_input_sha256: WARD_SPAWN_PROFILE.artifact_sha256.ward_spawns,
    ward_lifecycle_input_sha256: WARD_SPAWN_PROFILE.artifact_sha256.ward_lifecycles,
    packet_provenance_index: packetProvenanceIndex,
    ward_lifecycles: [{
      ward_network_id: 0x4000abcd,
      spawn_time_ms: 10025,
      remove_time_ms: 91025,
      duration_ms: 81000,
      removal_reason: 'CORPSE_PACKET_DERIVED',
      spawn_raw_packet_ref: spawn.raw_packet_ref,
      remove_raw_packet_ref: removeRef,
    }],
  });
  const candidate = outputs.ward_cast_candidates[0];
  const match = outputs.ward_cast_spawn_matches[0];
  assert.equal(outputs.status, 'WARD_SPAWN_POSITION_VERIFIED_DIRECT');
  assert.equal(outputs.ward_spawn_position_status, 'VERIFIED_DIRECT');
  assert.deepEqual(
    [candidate.cast_target_x, candidate.cast_target_y, candidate.cast_target_z], [100, 12, 200],
  );
  assert.deepEqual(
    [candidate.cast_target_end_x, candidate.cast_target_end_y, candidate.cast_target_end_z], [480, 12, 600],
  );
  assert.deepEqual([candidate.actual_x, candidate.actual_y], [481, 601]);
  assert.equal(candidate.position_source, 'ENTITY_SPAWN_DIRECT');
  assert.equal(match.time_delta_ms, 25);
  assert.ok(match.coordinate_error_start_like > 500);
  assert.ok(match.coordinate_error_end < 2);
  assert.equal(outputs.ward_events[0].event_status, 'ENTITY_SPAWN_DIRECT');
  assert.equal(outputs.ward_events[0].ward_network_id, 0x4000abcd);
  assert.equal(outputs.ward_events[0].despawn_time_ms, 91025);
  assert.equal(outputs.ward_events[0].lifecycle_status, 'DERIVED_CORPSE_REMOVAL');
  assert.equal(outputs.ward_lifecycle_status, 'DERIVED_CORPSE_REMOVAL');
  assert.equal(outputs.ward_heatmap_input[0].is_spawn_position, true);
  assert.equal(outputs.ward_heatmap_input[0].ward_network_id, 0x4000abcd);
  assert.deepEqual(
    [outputs.ward_heatmap_input[0].x, outputs.ward_heatmap_input[0].y], [481, 601],
  );
});

test('Self-asserted WardSpawn markers cannot upgrade output without pinned artifact and packet hashes', () => {
  const outputs = buildWardOutputs(replay(), {
    spell_events: [verifiedWardSpell()],
    ward_spawn_events: [verifiedWardSpawn()],
  });
  assert.equal(outputs.ward_spawn_position_status, 'UNAVAILABLE');
  assert.equal(outputs.ward_cast_spawn_matches.length, 0);
  assert.equal(outputs.ward_events[0].actual_x, null);
});

test('WardSpawn rows with another replay or incomplete direct field provenance are rejected', () => {
  const outputs = buildWardOutputs(replay(), {
    spell_events: [verifiedWardSpell()],
    ward_spawn_events: [
      verifiedWardSpawn({ replay_sha256: 'other-replay' }),
      verifiedWardSpawn({ field_confidence: { position: 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE' } }),
    ],
  });
  assert.equal(outputs.ward_cast_spawn_matches.length, 0);
  assert.equal(outputs.ward_spawn_position_status, 'UNAVAILABLE');
  assert.equal(outputs.ward_cast_candidates[0].actual_x, null);
  assert.equal(outputs.ward_heatmap_input[0].is_spawn_position, false);
});

test('A verified spawn without a same-owner nonnegative cast match does not upgrade the output', () => {
  const outputs = buildWardOutputs(replay(), {
    spell_events: [verifiedWardSpell()],
    ward_spawn_events: [verifiedWardSpawn({ replay_time_ms: 9999 })],
  });
  assert.equal(outputs.status, 'WARD_CAST_POSITION_VERIFIED_DIRECT');
  assert.equal(outputs.ward_cast_spawn_matches.length, 0);
  assert.equal(outputs.ward_events[0].event_status, 'CAST_OBSERVED_SPAWN_UNAVAILABLE');
  assert.equal(outputs.ward_heatmap_input[0].position_source, 'CAST_TARGET_DIRECT');
});
