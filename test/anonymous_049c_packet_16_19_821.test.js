'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeAnonymous049cPacketCandidates821: decode, callbackRequestError } =
  require('../src/decoders/rofl_16_19_821_anonymous_049c_packet_candidate');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { resolveBuildProfile } = require('../src/build_registry');
const { capabilityQuery } = require('../src/cli');

const BUILD = '16.19.821.7343';
const CAP = 'anonymous_049c_packet';
function fixture() {
  // Framing/selection fixture only; these bytes are not a semantic/native packet.
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1); header.writeUInt32LE(5, 5);
  header.writeUInt16LE(0x049c, 9); header.writeUInt32LE(0x400000ae, 11);
  return replayFromChunks([{ stream: 1, body: Buffer.concat([header, Buffer.alloc(5)]) }], BUILD);
}

test('0x049c registers only the exact-821 opt-in candidate with explicit native preflight', () => {
  assert.ok(resolveBuildProfile(BUILD).profile.candidate_capabilities.includes(CAP));
  assert.ok(!resolveBuildProfile('16.19.820.7193').profile.candidate_capabilities.includes(CAP));
  const document = capabilityQuery(fixture(), { events: [CAP] });
  assert.equal(document.capabilities.length, 1);
  const selected = document.capabilities[0];
  assert.ok(selected.missing_inputs.includes('exact_runtime_image'));
  assert.ok(selected.required_inputs.some((input) => /python/i.test(input.name)));
  assert.equal(selected.output, 'anonymous_049c_packet_candidates');
});

test('0x049c rejects absent, foreign and wrong-size native inputs without emitting rows', (t) => {
  const replay = fixture();
  assert.equal(decode(replay).status, 'MISSING_INPUT');
  const foreign = fixture(); foreign.header.version = '16.19.820.7193';
  assert.equal(decode(foreign).status, 'UNSUPPORTED');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-049c-image-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'not-an-image.bin'); fs.writeFileSync(image, 'x');
  const wrong = decode(replay, { runtimeImagePath: image });
  assert.equal(wrong.status, 'INCONSISTENT');
  assert.equal(wrong.runtime_image_status, 'SIZE_MISMATCH');
  assert.equal(wrong.events, null); assert.equal(wrong.event_count, null);
  replay.buffer[0] ^= 1;
  assert.equal(decode(replay).status, 'DECODE_FAILED');
});

test('0x049c shared scan copies selected raw source and rejects foreign/unselected/mutated tokens', () => {
  const replay = fixture();
  const token = collect821Routes(replay, [CAP]);
  const selected = rowsFor821Capability(replay, token, CAP);
  assert.equal(selected.rows.length, 1);
  assert.equal(selected.rows[0].block.packet_id, 0x049c);
  selected.rows[0].block.payload[0] = 255;
  assert.equal(rowsFor821Capability(replay, token, CAP).rows[0].block.payload[0], 0);
  assert.ok(rowsFor821Capability(fixture(), token, CAP).error);
  const other = collect821Routes(replay, ['hero_death']);
  assert.ok(rowsFor821Capability(replay, other, CAP).error);
  replay.buffer[0] ^= 1;
  assert.ok(rowsFor821Capability(replay, token, CAP).error);
});

test('0x049c exact-build API propagates missing native dependency as unavailable data', () => {
  const decoded = decodeSemanticReplay(fixture(), { capabilities: [CAP] });
  assert.equal(decoded.capability_results[CAP].status, 'MISSING_INPUT');
  assert.equal(decoded.events, null);
  assert.equal(decoded.decoded_packet_count, 0);
});

function callbackFixture(operation) {
  // Artificial output-schema fixture, not a native/replay validation witness.
  const row = {
    native_nested_field_bytes_hex: { '0x18': 'bb', '0x1c': operation === 1 ? '01000000' : '02000000' },
    native_byte_vector_hex: operation === 1 ? '12' : '416200',
    callback_request_candidate: {
      status: 'CANDIDATE_STATIC_RECEIVE_DATAFLOW', registered_packet_class: 'PKT_ChangeSlotSpellData_s',
      registered_receiver_class: 'AIBaseClient', operation_selector: operation, slot_index: 0,
      value_decode_witness: 'NATIVE_PACKET_ONLY_CALLBACK_PREFIX', receiver_entity_status: 'UNKNOWN',
      application_status: 'NOT_OBSERVED', callback_stop_rva: operation === 1 ? '0x24ec26' : '0x24ecdf',
    },
  };
  Object.assign(row.callback_request_candidate, operation === 1 ? {
    operation_kind: 'SLOT_BYTE_FIELD_WRITE_REQUEST', requested_u8: 18,
    receiver_field_offset: '0x2f', receiver_field_meaning: 'UNKNOWN', native_lookup_index: 0,
  } : { operation_kind: 'SLOT_NAME_CHANGE_REQUEST', requested_name_bytes_hex: '4162',
    requested_name_ascii: 'Ab', native_name_comparison_hash_u32: 1650, anonymous_control_bytes: [0, 0, 0] });
  return row;
}

test('0x049c callback witness rejects promoted effects, foreign classes and wrong source index', () => {
  for (const operation of [1, 2]) {
    const original = callbackFixture(operation);
    assert.equal(callbackRequestError(original), null);
    for (const [field, value] of [['application_status', 'APPLIED'], ['receiver_entity_status', 'CONFIRMED'],
      ['registered_packet_class', 'PKT_ChangeSlotSpellData_Summoner_s'], ['slot_index', 1]]) {
      const changed = structuredClone(original); changed.callback_request_candidate[field] = value;
      assert.ok(callbackRequestError(changed), field);
    }
  }
});

test('0x049c callback operation payloads must remain byte-for-byte reversible', () => {
  const byte = callbackFixture(1);
  byte.callback_request_candidate.requested_u8 = 7;
  assert.ok(callbackRequestError(byte));
  const name = callbackFixture(2);
  name.callback_request_candidate.requested_name_ascii = 'Ac';
  assert.ok(callbackRequestError(name));
  name.callback_request_candidate.requested_name_ascii = 'Ab';
  name.callback_request_candidate.native_name_comparison_hash_u32++;
  assert.ok(callbackRequestError(name));
  name.callback_request_candidate.native_name_comparison_hash_u32--;
  name.native_byte_vector_hex = '41006200';
  assert.ok(callbackRequestError(name));
});

test('0x049c unsupported callback selectors cannot be claimed as decoded requests', () => {
  const row = callbackFixture(1); row.native_nested_field_bytes_hex['0x1c'] = '03000000';
  row.callback_request_candidate = { status: 'UNOBSERVED_OPERATION', operation_selector: 3,
    application_status: 'NOT_OBSERVED' };
  assert.equal(callbackRequestError(row), null);
  row.callback_request_candidate.status = 'CANDIDATE_STATIC_RECEIVE_DATAFLOW';
  assert.ok(callbackRequestError(row));
});
