'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821: damageV6,
  decodeUnitApplyDamageCallbackU32At1cFromEncoded821,
  decodeUnitApplyDamageU32At1cFromRawSpan821,
  UNIT_APPLY_DAMAGE_U32_0X1C_RAW_CALL_RVA_BY_SELECTOR_821: rawCalls } =
  require('../../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const { UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V4_821: rosterV4 } =
  require('../../src/decoders/rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const { UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V4_821: lookupV4 } =
  require('../../src/decoders/rofl_16_19_821_unit_apply_damage_lookup_roster_key_candidate');
const { UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_PROFILE_V4_821: lookup2cV4 } =
  require('../../src/decoders/rofl_16_19_821_unit_apply_damage_lookup2c_roster_key_candidate');
const { HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V4_821: deathV4 } =
  require('../../src/decoders/rofl_16_19_821_hero_death_damage_lookup_key_cooccurrence_candidate');

const profiles = Object.freeze({
  unit_apply_damage_roster_key_pair: rosterV4,
  unit_apply_damage_lookup_roster_key_pair: lookupV4,
  unit_apply_damage_lookup2c_roster_key_pair: lookup2cV4,
  hero_death_damage_lookup_key_cooccurrence: deathV4,
});
const capabilityByEvent = Object.freeze({
  unit_apply_damage_roster_key_candidates: 'unit_apply_damage_roster_key_pair',
  unit_apply_damage_lookup_roster_key_candidates:
    'unit_apply_damage_lookup_roster_key_pair',
  unit_apply_damage_lookup2c_roster_key_candidates:
    'unit_apply_damage_lookup2c_roster_key_pair',
  hero_death_damage_lookup_key_cooccurrence_candidates:
    'hero_death_damage_lookup_key_cooccurrence',
});
const RAW_PACKET = '72959d41c6d904810b00f17252b4ded07ecd6b75';
const RAW_ENCODED = 'c0f305e5';

function attachU32At1c(packet, raw) {
  const ref = packet.unit_apply_damage_raw_packet_ref;
  const payload = Buffer.from(ref.raw_payload_hex, 'hex');
  const selector = (payload[1] >>> 4) & 7;
  packet.header_selector_bits_12_14 = selector;
  packet.native_callback_u32_0x1c_candidate = raw
    ? decodeUnitApplyDamageU32At1cFromRawSpan821('00f1') : 0;
  packet.native_callback_u32_0x1c_encoded_bytes_hex = raw
    ? RAW_ENCODED : '05050505';
  packet.native_callback_u32_0x1c_source = raw ? 'RAW_READER' : 'CONSTANT_0';
  packet.native_callback_u32_0x1c_raw_call_rva = raw ? rawCalls[selector] : null;
  packet.native_callback_u32_0x1c_raw_offset = raw ? 9 : null;
  packet.native_callback_u32_0x1c_raw_bytes_hex = raw ? '00f1' : null;
  assert.equal(decodeUnitApplyDamageCallbackU32At1cFromEncoded821(
    packet.native_callback_u32_0x1c_encoded_bytes_hex),
  packet.native_callback_u32_0x1c_candidate);
}

function useRawPacket(row, packet) {
  const ref = packet.unit_apply_damage_raw_packet_ref;
  const oldPosition = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  const payload = Buffer.from(RAW_PACKET, 'hex');
  ref.raw_payload_hex = RAW_PACKET;
  ref.raw_payload_sha256 = crypto.createHash('sha256').update(payload).digest('hex');
  ref.payload_length = payload.length;
  for (const copy of row.raw_packet_refs) {
    if (copy.packet_id === 0x005f
        && `${copy.chunk_index}/${copy.decompressed_block_offset}` === oldPosition) {
      copy.raw_payload_hex = ref.raw_payload_hex;
      copy.raw_payload_sha256 = ref.raw_payload_sha256;
      copy.payload_length = ref.payload_length;
    }
  }
}

function promoteSavedAssociationV4(directory, eventKey, { rawRowIndex = null } = {}) {
  const capability = capabilityByEvent[eventKey];
  const profile = profiles[capability];
  assert.ok(profile, `unknown V4 association event ${eventKey}`);
  const eventFile = path.join(directory, `${eventKey}.jsonl`);
  const rows = fs.readFileSync(eventFile, 'utf8').trimEnd()
    .split('\n').map((line) => JSON.parse(line));
  let rawCount = 0;
  rows.forEach((row, index) => {
    row.build_profile = profile.id;
    const packets = row.same_time_victim_key24_packet_candidates ?? [row];
    packets.forEach((packet, packetIndex) => {
      const raw = index === rawRowIndex && packetIndex === 0;
      if (raw) {
        useRawPacket(row, packet);
        rawCount += 1;
      }
      attachU32At1c(packet, raw);
    });
  });
  if (rawRowIndex !== null) assert.equal(rawCount, 1);
  fs.writeFileSync(eventFile, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const file = path.join(directory, basename);
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    const caps = basename === 'semantic_run.json'
      ? doc.capability_results : doc.semantic.capability_results;
    const damage = caps.unit_apply_damage_packet;
    const count = damage.event_count;
    const proof = {
      evidence_callback_u32_0x1c_table_sha256:
        damageV6.evidence_callback_u32_0x1c_table_sha256,
      native_callback_u32_0x1c_full_write_count: count,
      native_callback_u32_0x1c_source_counts: {
        RAW_READER: rawCount, CONSTANT_0: count - rawCount,
      },
    };
    damage.profile_id = damageV6.id;
    Object.assign(damage, structuredClone(proof));
    for (const [name, association] of Object.entries(profiles)) {
      const result = caps[name];
      if (!result || !result.profile_id?.endsWith('-v3')) continue;
      result.profile_id = association.id;
      if (result.known_limits) result.known_limits = [...association.known_limits];
      Object.assign(result, structuredClone(proof));
    }
    fs.writeFileSync(file, JSON.stringify(doc));
  }
  return rows;
}

module.exports = { promoteSavedAssociationV4, RAW_PACKET };
