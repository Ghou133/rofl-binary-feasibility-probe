'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.821.7343';
const PAIR = 'face_direction_keyframe_roster_pair';
const EVENT = 'face_direction_keyframe_roster_pair_candidates';
const IMAGE_SHA = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(id, payload, param, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function replay(version = BUILD) {
  return replayFromChunks([{ stream: 2, body: Buffer.concat([
    packet(0x0089, Buffer.alloc(1263), 0x400000ae, 1000),
    packet(0x038e, Buffer.from('83000000000000000000000000', 'hex'),
      0x400000ae, 1000),
  ]) }], version);
}

function stubbedRuntime(t, { snapshotStatus = 'CANDIDATE' } = {}) {
  const face = require('../src/decoders/rofl_16_19_821_face_direction_packet_candidate');
  const snapshot = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
  const pair = require('../src/decoders/rofl_16_19_821_face_direction_keyframe_roster_pair_candidate');
  const semanticPath = require.resolve('../src/semantic_api');
  const cliPath = require.resolve('../src/cli');
  const priorSemantic = require.cache[semanticPath];
  const priorCli = require.cache[cliPath];
  const calls = { face: 0, snapshot: 0, pair: 0 };
  const original = {
    face: face.decodeFaceDirectionPacketCandidates821,
    snapshot: snapshot.decodeHeroFloatSnapshotCandidates821,
    pair: pair.associateFaceDirectionKeyframeRosterPairs821,
  };
  face.decodeFaceDirectionPacketCandidates821 = () => {
    calls.face += 1;
    return { status: 'CANDIDATE', input_packet_id: 0x038e, input_count: 1,
      event_count: 1, runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: IMAGE_SHA, events: [{ source: 'face' }] };
  };
  snapshot.decodeHeroFloatSnapshotCandidates821 = (_input, capability) => {
    assert.equal(capability, 'hero_minions_killed_snapshot');
    calls.snapshot += 1;
    return snapshotStatus === 'CANDIDATE'
      ? { status: 'CANDIDATE', input_packet_id: 0x0089, input_count: 1,
        event_count: 1, runtime_image_used: false,
        runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
        events: [{ source: 'snapshot' }] }
      : { status: snapshotStatus, input_count: null, event_count: null,
        events: null, error: 'snapshot unavailable' };
  };
  pair.associateFaceDirectionKeyframeRosterPairs821 = (_input, outcomes) => {
    calls.pair += 1;
    assert.equal(outcomes.faceDirectionPacketOutcome.status, 'CANDIDATE');
    assert.equal(outcomes.minionsKilledSnapshotOutcome.status, snapshotStatus);
    if (snapshotStatus !== 'CANDIDATE') {
      return { status: 'UNAVAILABLE', input_count: null, event_count: null,
        events: null, dependency_statuses: {
          face_direction_packet: 'CANDIDATE',
          hero_minions_killed_snapshot: snapshotStatus,
        } };
    }
    const statsRef = { packet_id: 0x0089 };
    const faceRef = { packet_id: 0x038e };
    return { status: 'CANDIDATE', input_count: 2, event_count: 1,
      input_packet_id: 0x038e, runtime_image_status: 'MATCHED_USED',
      runtime_image_used: true, runtime_image_sha256: IMAGE_SHA,
      events: [{ event_type: 'FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_CANDIDATE',
        replay_time_ms: 1000, hero_raw_param: 0x400000ae,
        hero_stats_participant_id_candidate: 1,
        pair_basis: 'SAME_KEYFRAME_CHUNK_TIME_FULL_RAW_PARAM_STATS_BEFORE_FACE',
        actor_assignment_status: 'UNKNOWN',
        semantic_direction_effect_status: 'UNKNOWN',
        hero_stats_raw_packet_ref: statsRef,
        face_direction_raw_packet_ref: faceRef,
        raw_packet_refs: [statsRef, faceRef] }] };
  };
  delete require.cache[semanticPath];
  delete require.cache[cliPath];
  t.after(() => {
    face.decodeFaceDirectionPacketCandidates821 = original.face;
    snapshot.decodeHeroFloatSnapshotCandidates821 = original.snapshot;
    pair.associateFaceDirectionKeyframeRosterPairs821 = original.pair;
    if (priorSemantic) require.cache[semanticPath] = priorSemantic;
    else delete require.cache[semanticPath];
    if (priorCli) require.cache[cliPath] = priorCli;
    else delete require.cache[cliPath];
  });
  return { calls, semantic: require('../src/semantic_api'), cli: require('../src/cli') };
}

test('821 FaceDirection roster pair is a selectable exact-build, image-and-tail capability', () => {
  const { resolveCapability } = require('../src/build_registry');
  const { capabilityQuery } = require('../src/cli');
  const capability = resolveCapability(BUILD, PAIR);
  assert.equal(capability.status, 'CANDIDATE');
  assert.deepEqual(capability.capability_profile.depends_on,
    ['face_direction_packet', 'hero_minions_killed_snapshot']);
  assert.notEqual(resolveCapability('16.19.820.7193', PAIR).status, 'CANDIDATE');
  const queried = capabilityQuery(replay()).capabilities.find((row) =>
    row.capability === PAIR);
  assert.equal(queried.output, EVENT);
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(queried.missing_inputs, ['exact_runtime_image']);
  assert.ok(queried.required_inputs.some((row) =>
    row.name === 'replay_tail_MINIONS_KILLED'));
});

test('pair-only API and CLI decode hidden sources once and emit only the pair', async (t) => {
  const { calls, semantic, cli } = stubbedRuntime(t);
  const input = replay();
  const decoded = semantic.decodeSemanticReplay(input, {
    capabilities: [PAIR], runtimeImagePath: 'synthetic-image',
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.deepEqual(Object.keys(decoded.capability_results), [PAIR]);
  assert.deepEqual(Object.keys(decoded.events), [EVENT]);
  assert.equal(decoded.runtime_image_used, true);
  assert.equal(decoded.decoded_packet_count, 2);
  assert.deepEqual(calls, { face: 1, snapshot: 1, pair: 1 });

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-face-pair-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const inputPath = path.join(directory, 'sample.rofl');
  const output = path.join(directory, 'output');
  fs.writeFileSync(inputPath, input.buffer);
  const exitCode = await cli.main(['decode', inputPath, '--events', PAIR,
    '--runtime-image', inputPath, '--event-jsonl-only', '--out-dir', output]);
  assert.equal(exitCode, 0);
  assert.deepEqual(calls, { face: 2, snapshot: 2, pair: 2 });
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semanticRun = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  assert.equal(semanticRun.status, 'CANDIDATE');
  assert.equal(semanticRun.runtime_image_used, true);
  assert.deepEqual(semanticRun.requested_capabilities, [PAIR]);
  assert.equal(fs.existsSync(path.join(replayDirectory,
    'face_direction_packet_candidates.jsonl')), false);
  assert.equal(fs.existsSync(path.join(replayDirectory,
    'hero_minions_killed_snapshot_candidates.jsonl')), false);
  const rows = fs.readFileSync(path.join(replayDirectory, `${EVENT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map(JSON.parse);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].hero_stats_participant_id_candidate, 1);
  assert.equal(rows[0].semantic_direction_effect_status, 'UNKNOWN');
});

test('pair failure retains separately selected source rows and reuses each outcome', (t) => {
  const { calls, semantic } = stubbedRuntime(t, { snapshotStatus: 'MISSING_INPUT' });
  const decoded = semantic.decodeSemanticReplay(replay(), {
    capabilities: [PAIR, 'face_direction_packet', 'hero_minions_killed_snapshot'],
    runtimeImagePath: 'synthetic-image',
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results[PAIR].status, 'UNAVAILABLE');
  assert.equal(decoded.capability_results.face_direction_packet.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_minions_killed_snapshot.status, 'MISSING_INPUT');
  assert.equal(decoded.events.face_direction_packet_candidates.length, 1);
  assert.equal(decoded.events[EVENT], undefined);
  assert.deepEqual(calls, { face: 1, snapshot: 1, pair: 1 });
});
