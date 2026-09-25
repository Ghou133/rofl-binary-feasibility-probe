'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const ROWS = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'on_event_next_followup_821', 'target_rows.jsonl');
const SCRIPT = path.resolve(__dirname, '..', 'scripts',
  'decode_revive_ally_event_packet_16_19_821.py');
const LOCAL_INPUTS = fs.existsSync(IMAGE) && fs.existsSync(ROWS);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function evidenceRows() {
  const rows = fs.readFileSync(ROWS, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  const target = rows.filter((row) => row.child_event_id_hex === '0x002c');
  const foreign = rows.find((row) => row.child_event_id_hex === '0x0017');
  assert.equal(target.length, 3);
  assert.ok(foreign);
  assert.ok(target.every((row) => row.replay_name === 'KR_8394041123.rofl'
    && row.payload_length === 16 && row.native_full_consumed
    && row.native_blob_length === 8 && row.raw_event_id_hex === '0x49ca'));
  assert.equal(foreign.payload_length, 16);
  return { target, foreign };
}

function packet(row) {
  return { packet_id: 0x040a, stream_tag: 1,
    raw_param: row.raw_param, payload_hex: row.payload_hex };
}

function invoke(packets, replayVersion = BUILD, image = IMAGE) {
  return childProcess.spawnSync(process.env.PYTHON || 'python', [
    '-B', SCRIPT, '--image', image,
  ], {
    input: JSON.stringify({ replay_version: replayVersion, packets }),
    encoding: 'utf8', timeout: 60000,
  });
}

function assertAtomicError(run, pattern) {
  assert.equal(run.status, 1, run.stderr || run.error?.message);
  const output = JSON.parse(run.stdout);
  assert.equal(output.status, 'ERROR');
  assert.deepEqual(output.results, []);
  assert.match(output.error, pattern);
}

test('821 native OnReviveAlly helper decodes all 3 observed child 0x002c packets', {
  skip: !LOCAL_INPUTS ? 'requires exact-build image and ignored raw-row evidence' : false,
}, () => {
  const { target } = evidenceRows();
  const packets = target.map(packet);
  const run = invoke(packets);
  assert.equal(run.status, 0, run.stderr || run.error?.message);
  const output = JSON.parse(run.stdout);
  assert.equal(output.status, 'PASS');
  assert.equal(output.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(output.results.length, 3);
  for (const [index, result] of output.results.entries()) {
    const source = target[index];
    assert.equal(result.status, 'DECODED');
    assert.equal(result.input_index, index);
    assert.equal(result.raw_param, source.raw_param);
    assert.equal(result.raw_payload_sha256,
      sha256(Buffer.from(source.payload_hex, 'hex')));
    assert.equal(result.raw_payload_sha256, source.raw_payload_sha256);
    assert.equal(result.deserialize_return_al, 1);
    assert.equal(result.bytes_consumed, 16);
    assert.equal(result.native_packet_id, 0x040a);
    assert.equal(result.native_raw_param, source.raw_param);
    assert.equal(result.event_id, 0x002c);
    assert.equal(result.raw_event_id_hex, '0x49ca');
    assert.equal(result.event_blob_length, 8);
    assert.equal(result.event_blob_hex, source.native_blob_hex);
    assert.equal(result.event_blob_sha256, source.native_blob_sha256);
    assert.equal(result.event_u32_0x04, source.u32_0x04);
    for (const field of ['actor', 'target', 'revived', 'effective_revive']) {
      assert.equal(Object.hasOwn(result, field), false);
    }
  }
});

test('821 native OnReviveAlly helper rejects same-length foreign child and bad inputs atomically', {
  skip: !LOCAL_INPUTS ? 'requires exact-build image and ignored raw-row evidence' : false,
}, () => {
  const { target, foreign } = evidenceRows();
  const first = packet(target[0]);
  const controls = [
    [packet(foreign), /unexpected length-16 OnEvent child\/raw ID/i],
    [{ ...first, payload_hex: first.payload_hex.slice(0, -2) }, /16-byte|payload/i],
    [{ ...first, payload_hex: `${first.payload_hex}00` }, /16-byte|payload/i],
    [{ ...first, packet_id: 0x0438 }, /packet ID|route/i],
    [{ ...first, stream_tag: 2 }, /game stream/i],
  ];
  for (const [control, pattern] of controls) {
    assertAtomicError(invoke([first, control]), pattern);
  }
  assertAtomicError(invoke([first], '16.19.820.7193'), /replay_version/i);
  assertAtomicError(invoke([first], BUILD, ROWS), /image|SHA-256/i);
  assertAtomicError(invoke([first], BUILD, `${IMAGE}.absent`), /image|missing/i);
});
