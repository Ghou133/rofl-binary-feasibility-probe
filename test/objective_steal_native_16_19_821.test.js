'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile, walkBlocks } = require('../src/rofl');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const imagePath = process.env.ROFL_821_RUNTIME_IMAGE;
const replayDirectory = process.env.ROFL_821_REPLAY_DIR;
const sourceNames = ['KR_8393872512.rofl', 'KR_8394041123.rofl'];
const sourcePaths = replayDirectory
  ? sourceNames.map((name) => path.resolve(replayDirectory, name)) : [];
const hasInputs = Boolean(imagePath && fs.existsSync(imagePath)
  && sourcePaths.length === 2 && sourcePaths.every((name) => fs.existsSync(name)));
const skip = hasInputs ? false
  : 'private exact-821 runtime image and two KR Replay sources unavailable';
const script = path.resolve(__dirname,
  '../scripts/decode_objective_steal_event_packet_16_19_821.py');

function originalPacket(replayPath) {
  const replay = parseReplayFile(replayPath);
  assert.equal(replay.header.version, BUILD);
  const rows = [];
  const walked = walkBlocks(replay, (block, chunk) => {
    if (chunk.stream_tag === 1 && block.packet_id === 0x040a
        && block.payload_length === 133) {
      rows.push({
        packet_id: block.packet_id,
        stream_tag: chunk.stream_tag,
        raw_param: block.param >>> 0,
        payload_hex: block.payload.toString('hex'),
      });
    }
  }, { includeStreams: [1], strict: true });
  assert.equal(walked.errors.length, 0);
  assert.equal(rows.length, 1);
  return rows[0];
}

function native(packets, image = imagePath) {
  const result = childProcess.spawnSync(process.env.PYTHON || 'python',
    ['-B', script, '--image', image], {
      input: JSON.stringify({ replay_version: BUILD, packets }),
      encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 30000,
    });
  assert.equal(result.error, undefined, result.error?.message);
  return { code: result.status, data: JSON.parse(result.stdout), stderr: result.stderr };
}

test('exact 821 native objective-steal route fully consumes both original child packets',
  { skip }, () => {
    const packets = sourcePaths.map(originalPacket);
    const result = native(packets);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.data.status, 'PASS');
    assert.equal(result.data.runtime_image_sha256, IMAGE_SHA256);
    assert.deepEqual(result.data.results.map((row) => row.event_id),
      [0x00d6, 0x00be]);
    assert.deepEqual(result.data.results.map((row) => row.raw_event_id_hex),
      ['0x490c', '0x499e']);
    for (const row of result.data.results) {
      assert.equal(row.status, 'DECODED');
      assert.equal(row.deserialize_return_al, 1);
      assert.equal(row.bytes_consumed, 133);
      assert.equal(row.event_blob_length, 124);
      assert.match(row.event_blob_hex, /^[0-9a-f]{248}$/);
      assert.match(row.event_blob_sha256, /^[0-9a-f]{64}$/);
    }
  });

test('exact 821 native objective-steal route rejects a foreign child and truncated parent',
  { skip }, () => {
    const worm = originalPacket(sourcePaths[0]);
    const mutated = Buffer.from(worm.payload_hex, 'hex');
    mutated[mutated.length - 2] ^= 1;
    const foreign = native([{ ...worm, payload_hex: mutated.toString('hex') }]);
    assert.equal(foreign.code, 1);
    assert.equal(foreign.data.status, 'ERROR');
    assert.deepEqual(foreign.data.results, []);
    assert.match(foreign.data.error, /unexpected length-133 OnEvent child/);
    const truncated = native([{ ...worm, payload_hex: worm.payload_hex.slice(0, -2) }]);
    assert.equal(truncated.code, 1);
    assert.equal(truncated.data.status, 'ERROR');
    assert.deepEqual(truncated.data.results, []);
    assert.match(truncated.data.error, /133-byte OnEvent packet/);
  });

test('exact 821 native objective-steal route rejects a different runtime image',
  { skip }, () => {
    const worm = originalPacket(sourcePaths[0]);
    const result = native([worm], __filename);
    assert.equal(result.code, 1);
    assert.equal(result.data.status, 'ERROR');
    assert.deepEqual(result.data.results, []);
    assert.match(result.data.error, /runtime image SHA-256 mismatch/);
  });
