'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveBuildProfile, resolveCapability } = require('../src/build_registry');
const { capabilityQuery, parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');
const { INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821: profile } =
  require('../src/decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'increment_minion_kills_packet';
const OUTPUT = 'increment_minion_kills_packet_candidates';

function packet(packetId, payloadHex, rawParam, timeMs = 1000) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay(extraChunks = []) {
  return replayFromChunks([{ stream: 1, body: Buffer.concat([
    packet(0x03a7, '380718', 0x400000ae),
    packet(0x02d9, '070718', 0x400000ae),
    packet(0x03a7, '390718', 0x400000af, 2000),
  ]) }, ...extraChunks], BUILD);
}

function nativeResult(request) {
  const lookupBytes = {
    [0x400000ae]: '8bd7d7e7',
    [0x400000af]: 'cbd7d7e7',
  };
  return {
    status: 'PASS',
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    callback_transform_sha256: profile.evidence_callback_transform_sha256,
    results: request.packets.map((row, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: row.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
      native_packet_id: 0x03a7, native_raw_param: row.raw_param,
      native_object_lookup_key_bytes_hex: lookupBytes[row.raw_param],
      callback_lookup_key_candidate: row.raw_param,
    })),
  };
}

test('821 0x03a7 registry and shared scan expose only the exact packet candidate', () => {
  const input = replay();
  const resolved = resolveBuildProfile(input);
  assert.equal(resolved.status, 'SUPPORTED');
  assert.equal(resolved.profile.packet_routes[CAPABILITY], 0x03a7);
  assert.equal(resolveCapability(BUILD, CAPABILITY).status, 'CANDIDATE');
  const row = capabilityQuery(input).capabilities.find((item) =>
    item.capability === CAPABILITY);
  assert.equal(row.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(row.missing_inputs, ['exact_runtime_image']);
  assert.equal(row.output, OUTPUT);
  assert.match(row.validation_pending.join(' '), /no proven lookup success/);

  const scan = collect821Routes(input, [CAPABILITY]);
  const selected = rowsFor821Capability(input, scan, CAPABILITY);
  assert.equal(selected.scanned_block_count, 3);
  assert.deepEqual(selected.rows.map(({ block, chunk }) =>
    [block.packet_id, block.param, block.payload.toString('hex'), chunk.stream]), [
    [0x03a7, 0x400000ae, '380718', 'game_chunk'],
    [0x03a7, 0x400000af, '390718', 'game_chunk'],
  ]);
});

test('821 0x03a7 API and CLI preserve missing-image and packet-local candidate status', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay();
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));

  const missing = decodeSemanticReplay(input, { capabilities: [CAPABILITY] });
  assert.equal(missing.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(missing.capability_results[CAPABILITY].runtime_image_status, 'MISSING');
  assert.equal(missing.events, null);
  const missingCli = parseOne(filePath, { semantic: true, events: [CAPABILITY],
    strict: true, timelineLimit: 0 });
  assert.equal(missingCli.ok, true);
  assert.equal(missingCli.analysis.semantic.capability_results[CAPABILITY].status,
    'MISSING_INPUT');
  assert.deepEqual(missingCli.analysis.events, {});

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_increment_minion_kills_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.payload_hex]), [
      [0x03a7, '380718'], [0x03a7, '390718'],
    ]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: [CAPABILITY], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].runtime_image_status, 'MATCHED_USED');
  assert.equal(decoded.decoded_packet_count, 2);
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  assert.equal(decoded.events[OUTPUT].length, 2);
  assert.equal(decoded.events[OUTPUT][0].callback_lookup_key_candidate, 0x400000ae);
  assert.equal(decoded.events[OUTPUT][0].raw_packet_ref.packet_id, 0x03a7);
  assert.equal(decoded.events[OUTPUT][0].semantic_cs_effect_status, 'UNKNOWN');
  assert.equal(decoded.events[OUTPUT][0].conditional_counter_write_status, 'UNKNOWN');
  for (const name of ['participant_id_candidate', 'minion_id', 'last_hit', 'cs_delta']) {
    assert.equal(name in decoded.events[OUTPUT][0], false);
  }

  const parsed = parseOne(filePath, { semantic: true, events: [CAPABILITY],
    runtimeImage: imagePath, strict: true, timelineLimit: 0 });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.status, 'CANDIDATE');
  assert.equal(parsed.analysis.semantic.capability_results[CAPABILITY].runtime_image_status,
    'MATCHED_USED');
  assert.deepEqual(parsed.analysis.events[OUTPUT].map((row) => row.raw_param),
    [0x400000ae, 0x400000af]);
  assert.equal(native.mock.callCount(), 2);
});

test('821 0x03a7 does not turn an image mismatch or non-game route into events', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-mismatch-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, 'image.bin');
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 2, stderr: 'runtime image SHA-256 mismatch', stdout: '',
  }));
  const mismatch = decodeSemanticReplay(replay(), {
    capabilities: [CAPABILITY], runtimeImagePath: imagePath,
  });
  assert.equal(mismatch.capability_results[CAPABILITY].status, 'DECODE_FAILED');
  assert.equal(mismatch.capability_results[CAPABILITY].runtime_image_status,
    'HASH_MISMATCH');
  assert.equal(mismatch.events, null);

  const wrongStream = replay([{ stream: 2,
    body: packet(0x03a7, '380718', 0x400000ae) }]);
  const rejected = decodeSemanticReplay(wrongStream, { capabilities: [CAPABILITY] });
  assert.equal(rejected.capability_results[CAPABILITY].status, 'DECODE_FAILED');
  assert.equal(rejected.events, null);
});

test('821 0x03a7 shared and standalone scans explicitly reject oversized input', () => {
  const repeated = packet(0x03a7, '380718', 0x400000ae);
  const input = replayFromChunks([{ stream: 1,
    body: Buffer.concat(Array.from({ length: 10_001 }, () => repeated)) }], BUILD);
  const scan = collect821Routes(input, [CAPABILITY]);
  const bounded = rowsFor821Capability(input, scan, CAPABILITY);
  assert.equal(bounded.observed_packet_count_minimum, 10_001);
  assert.equal('rows' in bounded, false);
  for (const options of [
    { capabilities: [CAPABILITY], candidate821Scan: scan },
    { capabilities: [CAPABILITY] },
  ]) {
    const decoded = decodeSemanticReplay(input, options);
    assert.equal(decoded.capability_results[CAPABILITY].status, 'UNSUPPORTED');
    assert.equal(decoded.capability_results[CAPABILITY].observed_packet_count_minimum,
      10_001);
    assert.equal(decoded.events, null);
  }
});
