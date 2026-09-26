'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const imagePath = process.env.ROFL_821_RUNTIME_IMAGE;
const hasImage = Boolean(imagePath && fs.existsSync(imagePath));
const python = process.env.PYTHON || 'python';
const script = path.resolve(__dirname,
  '../scripts/decode_first_blood_assist_event_packet_16_19_821.py');
const TARGET = 'd4bdb9b33db3b3b3b3b332eb01e94de4';
const FOREIGN = 'c0bdb94b3db3b3b3b37f32eb01e94dca';

function decode(packets, image = imagePath) {
  const run = childProcess.spawnSync(python, ['-B', script, '--image', image], {
    input: JSON.stringify({ replay_version: '16.19.821.7343', packets }),
    encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 30000,
  });
  assert.equal(run.error, undefined, run.error?.message);
  return { code: run.status, data: JSON.parse(run.stdout), stderr: run.stderr };
}

function packet(payload_hex, raw_param = 1073742003) {
  return { packet_id: 0x040a, stream_tag: 1, raw_param, payload_hex };
}

test('exact 821 native route distinguishes target and foreign child with pinned image',
  { skip: hasImage ? false : 'exact private runtime image unavailable' }, () => {
    const result = decode([packet(TARGET), packet(FOREIGN)]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.data.status, 'PASS');
    assert.deepEqual(result.data.results.map((row) => row.status),
      ['DECODED', 'EXCLUDED_CHILD']);
    assert.deepEqual(result.data.results.map((row) => row.event_id), [0x0017, 0x002c]);
    assert.deepEqual(result.data.results.map((row) => row.bytes_consumed), [16, 16]);
    assert.equal(result.data.results[0].event_blob_hex, 'd501000000000000');
  });

test('exact 821 native route fails closed on malformed same-length child and wrong image',
  { skip: hasImage ? false : 'exact private runtime image unavailable' }, () => {
    const malformed = decode([packet(`${TARGET.slice(0, -2)}e5`)]);
    assert.equal(malformed.code, 1);
    assert.equal(malformed.data.status, 'ERROR');
    assert.deepEqual(malformed.data.results, []);
    const wrongImage = decode([packet(TARGET)], script);
    assert.equal(wrongImage.code, 1);
    assert.equal(wrongImage.data.status, 'ERROR');
    assert.deepEqual(wrongImage.data.results, []);
    assert.match(wrongImage.data.error, /image|size|SHA-256/i);
  });

test('exact 821 name-table label must match before packet decoding',
  { skip: hasImage ? false : 'exact private runtime image unavailable' }, () => {
    const code = [
      'import sys',
      'from pathlib import Path',
      'sys.path.insert(0, sys.argv[2])',
      'from decode_first_blood_assist_event_packet_16_19_821 import verify_image_route',
      'image = bytearray(Path(sys.argv[1]).read_bytes())',
      'verify_image_route(image)',
      'image[0x1ae76d0] ^= 1',
      'try:',
      '    verify_image_route(image)',
      'except ValueError as error:',
      '    assert "name-table label differs" in str(error), str(error)',
      'else:',
      '    raise AssertionError("tampered name table was accepted")',
    ].join('\n');
    const run = childProcess.spawnSync(python, ['-B', '-c', code,
      imagePath, path.resolve(__dirname, '../scripts')], {
      encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 30000,
    });
    assert.equal(run.error, undefined, run.error?.message);
    assert.equal(run.status, 0, run.stderr);
  });
