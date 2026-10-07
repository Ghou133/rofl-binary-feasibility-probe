'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');
const { DIGEST_SCHEMA, batchDigest, replayDigestStart, replayDigestBatch } =
  require('../src/decoders/rofl_16_19_821_cast_spell_ans_native_digest');

const NATIVE_ROW = Object.freeze({
  raw_param: 0x400000ae,
  bytes_consumed: 129,
  raw_payload_sha256: 'ab'.repeat(32),
  opaque_flag_0x148: 1,
  opaque_i32_0x14c: -80444,
  raw_f32_bytes_hex: 'ff57f6cd',
  raw_u8_0x140_hex: '5f', opaque_u8_0x140: 13,
  raw_nested_bits_0x24_hex: 'c6', opaque_nested_bits_0x24: 1,
  raw_u32_0x1c_hex: 'cee352e7', opaque_u32_0x1c: 1531465011,
  raw_u32_0x4c_hex: '7525f20b', opaque_u32_0x4c: 1073742460,
  raw_f32_0xa0_hex: '5858c8d6',
  raw_u32_0x28_hex: '9194b8fb', opaque_u32_0x28: 137424977,
});

test('V9 canonical native-output digest agrees across Python and JavaScript', () => {
  const rows = [NATIVE_ROW, { ...NATIVE_ROW, raw_param: 0x4000023c,
    raw_payload_sha256: 'cd'.repeat(32), opaque_u32_0x28: 190941627,
    raw_u32_0x28_hex: '7cef92cb' }];
  const python = process.env.PYTHON || 'python';
  const scriptDirectory = path.resolve(__dirname, '../scripts');
  const run = spawnSync(python, ['-B', '-c',
    'import json,sys; sys.path.insert(0,sys.argv[1]); from cast_spell_ans_native_digest_16_19_821 import SCHEMA,batch_digest; print(json.dumps({"schema":SCHEMA,"sha256":batch_digest(json.load(sys.stdin))}))',
    scriptDirectory], { input: JSON.stringify(rows), encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr || run.error?.message);
  const native = JSON.parse(run.stdout);
  assert.equal(native.schema, DIGEST_SCHEMA);
  assert.equal(native.sha256, batchDigest(rows));
  const saved = rows.map((row) => ({ ...row,
    raw_packet_ref: { payload_length: row.bytes_consumed,
      raw_payload_sha256: row.raw_payload_sha256 },
    raw_f32_0xe0_bytes_hex: row.raw_f32_bytes_hex,
    raw_f32_0xa0_bytes_hex: row.raw_f32_0xa0_hex }));
  assert.equal(batchDigest(saved, true), native.sha256);
  const replay = replayDigestStart('12'.repeat(32));
  replayDigestBatch(replay, 0, rows.length, native.sha256);
  assert.match(replay.digest('hex'), /^[0-9a-f]{64}$/);
});
