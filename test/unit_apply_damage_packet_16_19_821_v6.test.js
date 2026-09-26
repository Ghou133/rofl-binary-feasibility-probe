'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: activeV5,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821: v6,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V5_ID_821: v5Id,
  decodeUnitApplyDamagePacketCandidates821: decodeV5,
  decodeUnitApplyDamagePacketCandidates821V6: decodeV6,
  decodeUnitApplyDamageCallbackU32At1cFromEncoded821: decodeAt1c,
  decodeUnitApplyDamageU32At1cFromRawSpan821: decodeRawAt1c,
  UNIT_APPLY_DAMAGE_U32_0X1C_RAW_CALL_RVA_BY_SELECTOR_821: rawCalls,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const REPLAY_DIR = process.env.ROFL_821_REPLAY_DIR;
const REPLAY_A = REPLAY_DIR && path.join(REPLAY_DIR, 'KR_8392938200.rofl');
const REPLAY_B = REPLAY_DIR && path.join(REPLAY_DIR, 'KR_8393872512.rofl');
const HAS_IMAGE = Boolean(IMAGE && fs.existsSync(IMAGE));
const HAS_REPLAYS = Boolean(REPLAY_A && REPLAY_B
  && fs.existsSync(REPLAY_A) && fs.existsSync(REPLAY_B));

// Original game-stream rows from KR_8392938200, at selectors 0 and 1.
const ROWS = [
  { rawParam: 1073742259, payloadHex: '54814747c6c4d9a90b6ef07c44e2ecaf5b75' },
  { rawParam: 1073742446, payloadHex: '72959d41c6d904810b00f17252b4ded07ecd6b75' },
];

function packet({ rawParam, payloadHex }) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(1.5, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x005f, 9);
  header.writeUInt32LE(rawParam, 11);
  return Buffer.concat([header, payload]);
}

function fixture(rows = ROWS, version = BUILD) {
  return replayFromChunks([{
    stream: 1, body: Buffer.concat(rows.map(packet)),
  }], version);
}

test('821 packet V6 is opt-in and its +0x1c callback transform is pinned', () => {
  assert.equal(activeV5.id, v5Id);
  assert.equal(v6.id, v5Id.replace(/v5$/, 'v6'));
  assert.equal(decodeAt1c('05050505'), 0);
  assert.equal(decodeAt1c('c0f305e5'), 1073742954);
  assert.equal(decodeAt1c('f7f305e5'), 1073742876);
  assert.equal(decodeAt1c('0000'), null);
  assert.equal(decodeRawAt1c('00f1'), 1073742954);
  assert.equal(decodeRawAt1c('0fc486'), 1073758543);
  assert.equal(decodeRawAt1c('00'), null);
  assert.equal(decodeRawAt1c('00f100'), null);
  assert.equal(rawCalls[1], '0xf4a5cd');
  assert.equal(rawCalls[6], undefined);
  assert.equal(v6.evidence_callback_u32_0x1c_table_sha256,
    '5acd891ce46e85484de06fa22f6cece25e6bfcc4c258094863c98d225ea3dc18');
  assert.equal(decodeV6(fixture([], '16.19.820.7193')).status, 'UNSUPPORTED');
});

test('821 packet V6 keeps V5 output intact and binds two original native rows',
  { skip: !HAS_IMAGE && 'ROFL_821_RUNTIME_IMAGE exact mapped image is unavailable' }, () => {
    const old = decodeV5(fixture(), { runtimeImagePath: IMAGE });
    const out = decodeV6(fixture(), { runtimeImagePath: IMAGE });
    assert.equal(old.status, 'CANDIDATE', old.error);
    assert.equal(old.profile_id, v5Id);
    assert.equal(old.events[0].native_callback_u32_0x1c_candidate, undefined);
    assert.equal(old.native_callback_u32_0x1c_full_write_count, undefined);
    assert.equal(out.status, 'CANDIDATE', out.error);
    assert.equal(out.profile_id, v6.id);
    assert.equal(out.native_callback_u32_0x1c_full_write_count, 2);
    assert.deepEqual(out.native_callback_u32_0x1c_source_counts,
      { RAW_READER: 1, CONSTANT_0: 1 });
    assert.deepEqual(out.events.map((row) => ({
      selector: row.header_selector_bits_12_14,
      value: row.native_callback_u32_0x1c_candidate,
      source: row.native_callback_u32_0x1c_source,
      call: row.native_callback_u32_0x1c_raw_call_rva,
      offset: row.native_callback_u32_0x1c_raw_offset,
      bytes: row.native_callback_u32_0x1c_raw_bytes_hex,
    })), [
      { selector: 0, value: 0, source: 'CONSTANT_0',
        call: null, offset: null, bytes: null },
      { selector: 1, value: 1073742954, source: 'RAW_READER',
        call: '0xf4a5cd', offset: 9, bytes: '00f1' },
    ]);
    assert.equal(out.events[0].semantic_effect_status, 'UNKNOWN');
    assert.equal(out.events[1].confidence, 'CANDIDATE');
  });

test('821 packet V6 rejects wrong image, unconsumed packet, and selector 6',
  { skip: !HAS_IMAGE && 'ROFL_821_RUNTIME_IMAGE exact mapped image is unavailable' }, (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'damage-v6-821-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const wrongImage = path.join(directory, 'wrong.bin');
    fs.writeFileSync(wrongImage, 'not the exact mapped image');
    const wrong = decodeV6(fixture(), { runtimeImagePath: wrongImage });
    assert.equal(wrong.status, 'DECODE_FAILED');
    assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
    assert.equal(wrong.events, null);

    const unconsumed = decodeV6(fixture([{
      rawParam: 0x40004007,
      payloadHex: '71875e460b083dbaef3aa6ec39b975',
    }]), { runtimeImagePath: IMAGE });
    assert.equal(unconsumed.status, 'DECODE_FAILED');
    assert.equal(unconsumed.native_witness_status, 'FAILED');
    assert.equal(unconsumed.events, null);

    const selector6 = decodeV6(fixture([{
      rawParam: ROWS[0].rawParam,
      payloadHex: `54e14747${ROWS[0].payloadHex.slice(8)}`,
    }]), { runtimeImagePath: IMAGE });
    assert.equal(selector6.status, 'DECODE_FAILED');
    assert.match(selector6.error, /selector 6|outside.*scope/);
    assert.equal(selector6.events, null);
  });

test('821 packet V6 rejects forged +0x1c value, source, call, span, write or table',
  { skip: !HAS_IMAGE && 'ROFL_821_RUNTIME_IMAGE exact mapped image is unavailable' }, (t) => {
    const realSpawnSync = childProcess.spawnSync;
    for (const change of ['value', 'source', 'call', 'span', 'write_count', 'table_hash']) {
      t.mock.method(childProcess, 'spawnSync', (...args) => {
        const run = realSpawnSync(...args);
        assert.equal(run.status, 0, run.stderr);
        const native = JSON.parse(run.stdout);
        const row = native.native_u32_0x1c_rows[0];
        if (change === 'value') row[2] += 1;
        if (change === 'source') row[3] = 'CONSTANT_0';
        if (change === 'call') row[4] = '0xf4a742';
        if (change === 'span') row[6] = 'ffff';
        if (change === 'write_count') native.native_u32_0x1c_full_write_count = 0;
        if (change === 'table_hash') native.callback_u32_0x1c_table_sha256 = '0'.repeat(64);
        return { ...run, stdout: JSON.stringify(native) };
      });
      const out = decodeV6(fixture([ROWS[1]]), { runtimeImagePath: IMAGE });
      assert.equal(out.status, 'DECODE_FAILED', change);
      assert.equal(out.native_witness_status, 'FAILED', change);
      assert.equal(out.events, null, change);
      t.mock.restoreAll();
    }
  });

test('821 packet V6 fully witnesses +0x1c on two original KR Replays',
  { skip: (!HAS_IMAGE || !HAS_REPLAYS)
    && 'ROFL_821_RUNTIME_IMAGE or ROFL_821_REPLAY_DIR with two KR Replays is unavailable' }, () => {
    const cases = [
      { replay: REPLAY_A, count: 64824, raw: 3289, constant: 61535,
        span2: 472, span3: 2817 },
      { replay: REPLAY_B, count: 60358, raw: 0, constant: 60358,
        span2: 0, span3: 0 },
    ];
    for (const expected of cases) {
      const out = decodeV6(parseReplayFile(expected.replay), { runtimeImagePath: IMAGE });
      assert.equal(out.status, 'CANDIDATE', out.error);
      assert.equal(out.event_count, expected.count);
      assert.equal(out.native_full_success_count, expected.count);
      assert.equal(out.native_callback_u32_0x1c_full_write_count, expected.count);
      assert.deepEqual(out.native_callback_u32_0x1c_source_counts,
        { RAW_READER: expected.raw, CONSTANT_0: expected.constant });
      const spans = { 2: 0, 3: 0 };
      for (const row of out.events) {
        assert.equal(row.build_profile, v6.id);
        assert.equal(row.raw_packet_ref.packet_id, 0x005f);
        assert.equal(row.semantic_effect_status, 'UNKNOWN');
        assert.equal(decodeAt1c(row.native_callback_u32_0x1c_encoded_bytes_hex),
          row.native_callback_u32_0x1c_candidate);
        if (row.native_callback_u32_0x1c_source === 'RAW_READER') {
          assert.equal(decodeRawAt1c(row.native_callback_u32_0x1c_raw_bytes_hex),
            row.native_callback_u32_0x1c_candidate);
          const length = row.native_callback_u32_0x1c_raw_bytes_hex.length / 2;
          spans[length] = (spans[length] || 0) + 1;
        }
      }
      assert.deepEqual(spans, { 2: expected.span2, 3: expected.span3 });
    }
  });
