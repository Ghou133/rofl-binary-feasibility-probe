'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeAnonymous049cPacketCandidates821: decode, decodeSpellSlotChangeRequestCandidates821: decodeFamily,
  callbackRequestError } =
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

test('slot-change family is exact-821 opt-in with native dependency and null unavailable events', () => {
  const cap = 'spell_slot_change_request';
  assert.ok(resolveBuildProfile(BUILD).profile.candidate_capabilities.includes(cap));
  assert.ok(!resolveBuildProfile('16.19.820.7193').profile.candidate_capabilities.includes(cap));
  const query = capabilityQuery(fixture(), {events:[cap]}).capabilities[0];
  assert.equal(query.output, 'spell_slot_change_request_candidates');
  assert.ok(query.missing_inputs.includes('exact_runtime_image'));
  assert.ok(query.required_inputs.some(input => /python/i.test(input.name)));
  assert.equal(decodeFamily(fixture()).status,'MISSING_INPUT');
  assert.equal(decodeSemanticReplay(fixture(),{capabilities:[cap]}).events,null);
});

test('slot-change family shared scan binds all three routes and retains the legacy selection', () => {
  const packet = (id,length) => {
    const head=Buffer.alloc(15);head.writeFloatLE(1,1);head.writeUInt32LE(length,5);
    head.writeUInt16LE(id,9);head.writeUInt32LE(0x400000ae,11);
    return Buffer.concat([head,Buffer.alloc(length)]);
  };
  const replay=replayFromChunks([{stream:1,body:Buffer.concat([packet(0x049c,5),packet(0x028e,19)])},
    {stream:2,body:packet(0x0375,5)}],BUILD);
  const token=collect821Routes(replay,[CAP,'spell_slot_change_request']);
  assert.deepEqual(rowsFor821Capability(replay,token,'spell_slot_change_request').rows.map(r=>r.block.packet_id),
    [0x049c,0x028e,0x0375]);
  assert.equal(rowsFor821Capability(replay,token,CAP).rows.length,1);
  assert.ok(rowsFor821Capability(replay,collect821Routes(replay,[CAP]),'spell_slot_change_request').error);
});

test('OwnerOnly callback requests reject audience guesses, gated-field and word-vector disagreement', () => {
  const row=callbackFixture(1);row.native_packet_id=0x0375;
  row.native_nested_field_bytes_hex['0x1c']='06000000';
  row.callback_request_candidate={...row.callback_request_candidate,
    registered_packet_class:'PKT_ChangeSlotSpellData_OwnerOnly_s',operation_selector:6,
    operation_kind:'SLOT_GATED_BYTE_FIELD_WRITE_REQUEST',callback_stop_rva:'0x24ed5e',
    receiver_field_offset:'0xe8',callee_has_state_gate:true};
  assert.equal(callbackRequestError(row),null);
  row.callback_request_candidate.receiver_field_offset='0x2f';
  assert.ok(callbackRequestError(row));
  row.native_nested_field_bytes_hex['0x1c']='07000000';row.native_byte_vector_hex='0100000040';
  row.callback_request_candidate={...row.callback_request_candidate,operation_selector:7,
    operation_kind:'SLOT_DWORD_VECTOR_CHANGE_REQUEST',callback_stop_rva:'0x24ed7b',
    requested_word_count:1,requested_words_u32:[0x40000000],nested_holder_vector_offset:'0x40',
    word_meaning:'UNKNOWN',word_decode_witness:'NATIVE_CALLEE_PACKET_ONLY_VECTOR_CONSTRUCTION'};
  assert.equal(callbackRequestError(row),null);
  row.callback_request_candidate.requested_words_u32[0]++;
  assert.ok(callbackRequestError(row));
  row.callback_request_candidate.requested_words_u32[0]--;
  row.native_byte_vector_hex='00';
  assert.ok(callbackRequestError(row));
  row.native_byte_vector_hex='0100000040';
  row.callback_request_candidate.registered_packet_class='PKT_ChangeSlotSpellData_Summoner_s';
  assert.ok(callbackRequestError(row));
});
