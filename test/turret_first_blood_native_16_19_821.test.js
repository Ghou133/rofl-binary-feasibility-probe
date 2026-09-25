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
const SOURCE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'heal_report_821_next', 'on_event_packets.jsonl');
const SCRIPT = path.resolve(__dirname, '..', 'scripts',
  'decode_turret_first_blood_event_packet_16_19_821.py');
const LOCAL_INPUTS = fs.existsSync(IMAGE) && fs.existsSync(SOURCE);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function evidenceRows() {
  const rows = fs.readFileSync(SOURCE, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  const target = rows.filter((row) => row.payload_length === 116
    && row.payload_hex.endsWith('9586'));
  assert.equal(target.length, 11);
  assert.equal(new Set(target.map((row) => row.replay_name)).size, 11);
  return target;
}

function foreignRows() {
  const rows = fs.readFileSync(SOURCE, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  const controls = new Map([
    ['9548', 0x0004], ['9506', 0x0035],
    ['9566', 0x003b], ['9518', 0x0046],
  ]);
  return [...controls].map(([suffix, childId]) => {
    const row = rows.find((candidate) => candidate.payload_length === 116
      && candidate.payload_hex.endsWith(suffix));
    assert.ok(row, `missing real same-length child 0x${childId.toString(16)}`);
    return { row, childId };
  });
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

test('821 native OnTurretFirstBlood helper fully decodes 11 observed child 0x003d packets', {
  skip: !LOCAL_INPUTS ? 'requires exact-build image and ignored raw-row evidence' : false,
}, () => {
  const target = evidenceRows();
  const run = invoke(target.map(packet));
  assert.equal(run.status, 0, run.stderr || run.error?.message);
  const output = JSON.parse(run.stdout);
  assert.equal(output.status, 'PASS');
  assert.equal(output.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(output.results.length, target.length);
  for (const [index, result] of output.results.entries()) {
    const source = target[index];
    assert.equal(result.status, 'DECODED');
    assert.equal(result.input_index, index);
    assert.equal(result.raw_param, source.raw_param);
    assert.equal(result.raw_payload_sha256,
      sha256(Buffer.from(source.payload_hex, 'hex')));
    assert.equal(result.deserialize_return_al, 1);
    assert.equal(result.bytes_consumed, 116);
    assert.equal(result.native_packet_id, 0x040a);
    assert.equal(result.native_raw_param, source.raw_param);
    assert.equal(result.event_id, 0x003d);
    assert.equal(result.raw_event_id_hex, '0x4986');
    assert.equal(result.event_blob_length, 108);
    assert.equal(result.event_blob_hex.length, 216);
    assert.equal(result.event_blob_sha256,
      sha256(Buffer.from(result.event_blob_hex, 'hex')));
    for (const field of ['actor', 'target', 'turret', 'turret_die',
      'effective_death', 'state_transition']) {
      assert.equal(Object.hasOwn(result, field), false);
    }
  }
});

test('821 native OnTurretFirstBlood helper rejects all four real same-length foreign children atomically', {
  skip: !LOCAL_INPUTS ? 'requires exact-build image and ignored raw-row evidence' : false,
}, () => {
  const first = packet(evidenceRows()[0]);
  for (const { row, childId } of foreignRows()) {
    assertAtomicError(invoke([first, packet(row)]),
      new RegExp(`unexpected length-116 OnEvent child/raw ID: 0x${childId.toString(16).padStart(4, '0')}/`));
  }
});

test('821 native OnTurretFirstBlood helper rejects malformed route, build, payload, and image', {
  skip: !LOCAL_INPUTS ? 'requires exact-build image and ignored raw-row evidence' : false,
}, () => {
  const first = packet(evidenceRows()[0]);
  const controls = [
    [{ ...first, payload_hex: first.payload_hex.slice(0, -2) }, /116-byte|payload/i],
    [{ ...first, payload_hex: `${first.payload_hex}00` }, /116-byte|payload/i],
    [{ ...first, packet_id: 0x0438 }, /packet ID|route/i],
    [{ ...first, stream_tag: 2 }, /game stream/i],
  ];
  for (const [control, pattern] of controls) {
    assertAtomicError(invoke([first, control]), pattern);
  }
  assertAtomicError(invoke([first], '16.19.820.7193'), /replay_version/i);
  assertAtomicError(invoke([first], BUILD, SOURCE), /image|SHA-256/i);
  assertAtomicError(invoke([first], BUILD, `${IMAGE}.absent`), /image|missing/i);
});
