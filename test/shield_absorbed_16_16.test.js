'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { createCapabilityManifest } = require('../src/capability_manifest');
const decoder = require('../src/decoders/rofl_16_16_805_0442');
const { shieldAbsorbedFromFullyConsumedRow, validateShieldCallbackDisassembly } =
  require('../src/decoders/shield_absorbed_16_16');

const ROOT = path.resolve(__dirname, '..');

test('published 16.16 SHIELD_ABSORBED profile and canonical API consume all 12 pinned rows', () => {
  const evidence = path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure');
  const rows = fs.readFileSync(path.join(evidence, 'packet_01e1_neutral_decoded.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map(JSON.parse);
  const image = fs.readFileSync(path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
    'runtime', 'league_16.16.805.0442.memory.bin'));
  const table = image.subarray(0x01a27950, 0x01a27a50);
  const events = rows.map((row) => shieldAbsorbedFromFullyConsumedRow(row, table));
  assert.equal(events.length, 12);
  assert.ok(events.every((event) => event?.semantic === 'SHIELD_ABSORBED'
    && event.evidence === 'VERIFIED_DIRECT' && event.absorbed_amount > 0
    && event.source_network_id === null && event.shield_instance_id === null
    && event.remaining_amount === null));
  assert.equal(decoder.semanticProfileFor('shield_absorbed', decoder.REPLAY_VERSION).profile.client_opcode,
    0x01e1);
  const record = createCapabilityManifest().build_profiles[decoder.REPLAY_VERSION].records
    .find((row) => row.semantic_capability === 'SHIELD_ABSORBED');
  assert.equal(record.evidence_grade, 'VERIFIED_DIRECT');
  assert.equal(record.validation_status, 'PASS');
  assert.equal(record.sample_count.event_count, 12);
});

test('migration fingerprint and oracle preserve the route move and bounded publication', () => {
  const evidence = path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure');
  const fingerprint = JSON.parse(fs.readFileSync(path.join(evidence,
    'shield_absorbed_semantic_fingerprint.json'), 'utf8'));
  const decision = JSON.parse(fs.readFileSync(path.join(evidence,
    'shield_absorbed_migration_oracle_decision.json'), 'utf8'));
  assert.equal(fingerprint.semantic_name, 'SHIELD_ABSORBED');
  assert.deepEqual(fingerprint.build_bindings.map((row) => row.binding.route), ['0x0017', '0x01e1']);
  const legacyManifest = path.join(ROOT, 'artifacts', 'protection_v4_probe',
    'packet_0017_all14.jsonl.manifest.json');
  const expectedLegacyManifestSha = crypto.createHash('sha256').update(fs.readFileSync(legacyManifest)).digest('hex');
  assert.equal(fingerprint.build_bindings[0].provenance.replay_set_manifest_sha256,
    expectedLegacyManifestSha);
  const legacyIdentity = JSON.parse(fs.readFileSync(legacyManifest, 'utf8'));
  assert.equal(legacyIdentity.replay_count, 14);
  assert.equal(legacyIdentity.selected_packet_count, 2);
  assert.equal(decision.status, 'AUTO_VERIFIED_WITH_ROUTE_MOVE');
  assert.equal(decision.selected_candidate_id, 'route-0x01e1-unit-apply-shield-damage');
});

test('callback inverse implementation is byte-bound to pinned disassembly and runtime image', () => {
  const disassembly = fs.readFileSync(path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure',
    'runtime_01e1_callback_disassembly.json'));
  const image = fs.readFileSync(path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
    'runtime', 'league_16.16.805.0442.memory.bin'));
  assert.equal(validateShieldCallbackDisassembly(disassembly, image), true);
  const corruptedImage = Buffer.from(image); corruptedImage[0x002a7934] ^= 1;
  assert.throws(() => validateShieldCallbackDisassembly(disassembly, corruptedImage), /identity mismatch/);
  const corruptedOperation = Buffer.from(disassembly);
  const marker = corruptedOperation.indexOf(Buffer.from('"mnemonic": "ror"'));
  assert.ok(marker >= 0); corruptedOperation[marker + 14] = 'x'.charCodeAt(0);
  assert.throws(() => validateShieldCallbackDisassembly(corruptedOperation, image), /identity mismatch/);
});
