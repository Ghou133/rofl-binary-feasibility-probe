'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'face_direction_packet';
const EVENT = 'face_direction_packet_candidates';
const PACKET_ID = 0x038e;

function packet(payload, param = 0x40000088, timeMs = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(PACKET_ID, 9);
  header.writeUInt32LE(param >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function shape(size, marker) {
  const payload = Buffer.alloc(size);
  payload[0] = marker;
  return payload;
}

function replay(chunks = [{ stream: 2, body: packet(shape(13, 0x83)) }],
  version = BUILD) {
  return replayFromChunks(chunks, version);
}

function rawRef(input) {
  let found = null;
  walkBlocks(input, (block, chunk) => {
    if (found || block.packet_id !== PACKET_ID) return;
    found = {
      source_path: input.source_path ?? null,
      replay_sha256: input.source_sha256,
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
      raw_payload_sha256: crypto.createHash('sha256')
        .update(block.payload).digest('hex'),
    };
  }, { strict: true });
  return found;
}

test('821 FaceDirection registry and CLI capability query require exact build and image', () => {
  const { resolveBuildProfile, resolveCapability } = require('../src/build_registry');
  const { capabilityQuery } = require('../src/cli');
  const input = replay();
  const resolved = resolveBuildProfile(input);
  assert.equal(resolved.status, 'SUPPORTED');
  assert.equal(resolved.profile.packet_routes[CAPABILITY], PACKET_ID);
  const capability = resolveCapability(BUILD, CAPABILITY);
  assert.equal(capability.status, 'CANDIDATE');
  assert.equal(capability.capability_profile.replay_version, BUILD);
  const row = capabilityQuery(input).capabilities.find((item) =>
    item.capability === CAPABILITY);
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(row.missing_inputs, ['exact_runtime_image']);
  assert.equal(row.output, EVENT);
  assert.match(row.validation_pending.join(' '), /no actor.*position.*path/i);
  assert.notEqual(resolveCapability('16.19.820.7193', CAPABILITY).status,
    'CANDIDATE');
});

test('821 shared scan retains all observed FaceDirection shapes and rejects overflow', () => {
  const input = replay([
    { stream: 2, body: packet(shape(13, 0x83), 0x40000088, 0) },
    { stream: 1, body: packet(shape(17, 0x87), 0x400000b9, 1342) },
    { stream: 1, body: packet(shape(13, 0x93), 0x400000b6, 61139) },
  ]);
  const scan = collect821Routes(input, [CAPABILITY]);
  const selected = rowsFor821Capability(input, scan, CAPABILITY);
  assert.equal(selected.scanned_block_count, 3);
  assert.deepEqual(selected.rows.map(({ block, chunk }) =>
    [chunk.stream, block.packet_id, block.payload_length, block.payload[0]]), [
    ['keyframe', PACKET_ID, 13, 0x83],
    ['game_chunk', PACKET_ID, 17, 0x87],
    ['game_chunk', PACKET_ID, 13, 0x93],
  ]);
  const excess = replay([{ stream: 1,
    body: Buffer.concat(Array.from({ length: 32_769 }, () =>
      packet(shape(13, 0x93)))) }]);
  const overflow = rowsFor821Capability(excess,
    collect821Routes(excess, [CAPABILITY]), CAPABILITY);
  assert.equal(overflow.observed_packet_count_minimum, 32_769);
  assert.equal('rows' in overflow, false);
});

test('selected API and CLI retain missing-image boundary without candidate rows', async (t) => {
  const { decodeSemanticReplay } = require('../src/semantic_api');
  const input = replay();
  const decoded = decodeSemanticReplay(input, { capabilities: [CAPABILITY] });
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(decoded.capability_results[CAPABILITY].missing_input, 'runtime_image');
  assert.equal(decoded.events?.[EVENT], undefined);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-face-missing-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const inputPath = path.join(directory, 'sample.rofl');
  const output = path.join(directory, 'output');
  fs.writeFileSync(inputPath, input.buffer);
  const result = await require('../src/cli').main([
    'decode', inputPath, '--events', CAPABILITY,
    '--event-jsonl-only', '--out-dir', output,
  ]);
  assert.equal(result, 2);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(fs.existsSync(path.join(replayDirectory, `${EVENT}.jsonl`)), false);
});

test('selected API and CLI write independent candidate rows with packet provenance', async (t) => {
  const faceModule = require('../src/decoders/rofl_16_19_821_face_direction_packet_candidate');
  const original = faceModule.decodeFaceDirectionPacketCandidates821;
  const semanticPath = require.resolve('../src/semantic_api');
  const cliPath = require.resolve('../src/cli');
  const previousSemantic = require.cache[semanticPath];
  const previousCli = require.cache[cliPath];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-face-selected-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const inputPath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const output = path.join(directory, 'output');
  fs.writeFileSync(inputPath, replay().buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  faceModule.decodeFaceDirectionPacketCandidates821 = (input) => {
    const ref = rawRef(input);
    const row = {
      event_type: 'FACE_DIRECTION_PACKET_CANDIDATE',
      game_version: BUILD, replay_time_ms: ref.replay_time_ms,
      raw_param: ref.raw_param,
      packet_vector_xyz_f32_candidate: [0, 1, 0],
      optional_scalar_f32_candidate: null,
      semantic_direction_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', raw_packet_ref: ref,
    };
    return {
      status: 'CANDIDATE', input_count: 1, event_count: 1,
      input_packet_id: PACKET_ID,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      events: [row],
    };
  };
  delete require.cache[semanticPath];
  delete require.cache[cliPath];
  try {
    const { decodeSemanticReplay } = require('../src/semantic_api');
    const cli = require('../src/cli');
    const decoded = decodeSemanticReplay(replay(), {
      capabilities: [CAPABILITY], runtimeImagePath: imagePath,
    });
    assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
    assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
    assert.equal(decoded.events[EVENT].length, 1);
    assert.equal(decoded.events[EVENT][0].raw_packet_ref.packet_id, PACKET_ID);
    assert.equal(decoded.events[EVENT][0].semantic_direction_effect_status, 'UNKNOWN');
    for (const field of ['actor', 'participant_id', 'position', 'path']) {
      assert.equal(field in decoded.events[EVENT][0], false);
    }

    const exitCode = await cli.main(['decode', inputPath, '--events', CAPABILITY,
      '--runtime-image', imagePath, '--event-jsonl-only', '--out-dir', output]);
    assert.equal(exitCode, 0);
    const acceptance = JSON.parse(fs.readFileSync(path.join(output,
      'acceptance_summary.json'), 'utf8'));
    const replayDirectory = path.join(output,
      acceptance.replay_artifacts[0].artifact_directory);
    const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
      'semantic_run.json'), 'utf8'));
    assert.equal(semantic.status, 'CANDIDATE');
    assert.equal(semantic.capability_results[CAPABILITY].status, 'CANDIDATE');
    const rows = fs.readFileSync(path.join(replayDirectory, `${EVENT}.jsonl`), 'utf8')
      .trim().split(/\r?\n/).map(JSON.parse);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].raw_packet_ref.source_path, path.resolve(inputPath));
    assert.equal(rows[0].raw_packet_ref.packet_id, PACKET_ID);
    assert.equal(rows[0].semantic_direction_effect_status, 'UNKNOWN');
  } finally {
    faceModule.decodeFaceDirectionPacketCandidates821 = original;
    if (previousSemantic) require.cache[semanticPath] = previousSemantic;
    else delete require.cache[semanticPath];
    if (previousCli) require.cache[cliPath] = previousCli;
    else delete require.cache[cliPath];
  }
});
