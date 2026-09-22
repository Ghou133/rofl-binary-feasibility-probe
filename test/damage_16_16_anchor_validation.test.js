'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  collectDetailsDamageAnchors,
  createDamageAnchorValidation,
  matchDetailsDamageAnchors,
} = require('../src/validation/damage_16_16');

function details() {
  return { json: { frames: [{ events: [{
    type: 'CHAMPION_KILL', timestamp: 1000, victimId: 2,
    victimDamageReceived: [
      { participantId: 8, physicalDamage: 42, magicDamage: 0, trueDamage: 0 },
      { participantId: 7, physicalDamage: 0, magicDamage: 30, trueDamage: 0 },
      { participantId: 6, physicalDamage: 0, magicDamage: 0, trueDamage: 5 },
    ],
  }] }] } };
}

function row(sourceParticipant, amount, typeCode, index) {
  return {
    replay_time_ms: 1001 + index,
    packet_id: 0x017f,
    payload_length: 17,
    raw_param: 0x400000af,
    raw_payload_sha256: `payload-${index}`,
    fully_consumed: true,
    deserialize_return_al: 1,
    decoded_fields: {
      field_10_u32: 0x400000ad + sourceParticipant,
      field_14_u32: 0x400000af,
      field_24_f32: amount,
      field_28_u8: typeCode,
      field_2c_f32: 0,
      field_30_u32: 0,
    },
  };
}

test('DETAILS damage anchors retain exact source path and positive components only', () => {
  const anchors = collectDetailsDamageAnchors(details());
  assert.equal(anchors.length, 3);
  assert.deepEqual(anchors.map((anchor) => anchor.damage_type), ['true', 'magic', 'physical']);
  assert.ok(anchors.every((anchor) => anchor.details_path.startsWith('$.json.frames[0]')));
});

test('damage anchor matching is one-to-one and does not select on the tested type code', () => {
  const anchors = collectDetailsDamageAnchors(details());
  const rows = [row(8, 42.4, 0, 0), row(7, 30.2, 1, 1), row(6, 5.1, 2, 2)];
  const matched = matchDetailsDamageAnchors(anchors, rows);
  assert.equal(matched.matches.length, 3);
  assert.equal(matched.unmatched.length, 0);
  assert.ok(matched.matches.every((match) => match.damage_type_code_matches));
});

test('validation requires independent observations of physical, magic, and true codes', () => {
  const rows = [row(8, 42.4, 0, 0), row(7, 30.2, 1, 1), row(6, 5.1, 2, 2)];
  const validation = createDamageAnchorValidation({ details: details(), decodedRows: rows });
  assert.equal(validation.status, 'PASS');
  assert.deepEqual(validation.damage_type_match_counts, { physical: 1, magic: 1, true: 1 });
  assert.equal(validation.amount_semantic_stage, 'UNKNOWN');
  assert.equal(validation.protected_holdout.read, false);

  const mismatch = createDamageAnchorValidation({
    details: details(),
    decodedRows: [row(8, 42.4, 0, 0), row(7, 30.2, 0, 1), row(6, 5.1, 2, 2)],
  });
  assert.equal(mismatch.status, 'FAIL');
  assert.equal(mismatch.damage_type_mismatch_count, 1);
});

