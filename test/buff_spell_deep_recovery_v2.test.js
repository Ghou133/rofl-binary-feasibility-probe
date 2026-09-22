'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'buff_spell',
);

function readJson(...segments) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, ...segments), 'utf8').replace(/^\uFEFF/, ''));
}

function artifactJson(name) {
  return readJson(
    'artifacts',
    'full_semantic_deep_recovery_v2',
    'buff_spell',
    name,
  );
}

function ratio(numerator, denominator) {
  return numerator / denominator;
}

test('buff/spell deep-recovery governance gate is exact-build and research-only', () => {
  const gate = fs.readFileSync(path.join(ARTIFACT_ROOT, 'ARCHITECTURE_GATE.md'), 'utf8');
  assert.match(gate, /PROJECT_CONTEXT_LOADED = YES/);
  assert.match(gate, /ARCHITECTURE_GATE = PASS/);
  assert.match(gate, /16\.16\.805\.0442/);
  assert.match(gate, /no public API or feature\s+pack is authorized/i);
});

test('native callback decoders fully consume every selected exact-build row', () => {
  const callbacks = artifactJson('buff_spell_callback_decoded_latest_four.summary.json');
  const onEvent = artifactJson('packet_0371_deep_summary_latest_four.json');

  assert.equal(callbacks.build, '16.16.805.0442');
  assert.equal(callbacks.status, 'PASS');
  assert.equal(callbacks.selected_route_rows, 354854);
  assert.equal(callbacks.deserialize_success_rows, callbacks.selected_route_rows);
  assert.equal(callbacks.fully_consumed_rows, callbacks.selected_route_rows);
  assert.deepEqual(callbacks.route_counts, {
    '0x0123': 71236,
    '0x01cf': 21013,
    '0x0326': 143422,
    '0x041f': 43813,
    '0x043c': 22174,
    '0x045b': 53196,
  });
  assert.equal(
    callbacks.runtime_image.sha256,
    '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55',
  );

  assert.equal(onEvent.input_route_rows, 34690);
  assert.equal(onEvent.deserialize_success_rows, 34690);
  assert.equal(onEvent.fully_consumed_rows, 34690);
  assert.equal(onEvent.selected_candidate_rows, 30618);
});

test('buff field sequence promotes hash/source structure while preserving stack/time limits', () => {
  const analysis = artifactJson('buff_spell_damage_deep_analysis_latest_four.json');
  const buff = analysis.buff;
  const remove = buff.add_remove_same_entity_slot;
  const update = buff.update_same_entity_slot_prior_add;

  assert.equal(analysis.status, 'PASS');
  assert.equal(analysis.build, '16.16.805.0442');
  assert.ok(ratio(remove.prior_add_field_exact_hash_matches['0x04'], remove.remove_with_prior_add) > 0.97);
  assert.ok(ratio(update['0x0123:source_equals_add_0x20'], update['0x0123:prior_add_same_entity_slot']) > 0.95);
  assert.ok(ratio(update['0x043c:source_equals_add_0x20'], update['0x043c:prior_add_same_entity_slot']) > 0.98);
  assert.ok(ratio(update['0x041f:u32_a_equals_add_hash'], update['0x041f:prior_add_same_entity_slot']) > 0.98);

  const byte02 = buff.add_byte_candidate_histograms['0x02'];
  const addCount = byte02.reduce((sum, entry) => sum + entry.count, 0);
  assert.equal(addCount, 143422);
  assert.equal(byte02.find((entry) => entry.value === 1).count, 142989);
  assert.ok(
    ratio(
      update['0x0123:first_count_equals_add_byte_0x02'],
      update['0x0123:first_count_update_after_add'],
    ) > 0.78,
  );
  assert.ok(
    update['0x0123:first_count_equals_add_byte_0x02']
      > update['0x0123:first_count_equals_add_byte_0x01'],
  );
  assert.match(buff.decision.stack_or_count, /^KEEP_STRUCTURAL_CANDIDATE/);
  assert.match(buff.decision.time_fields, /DO_NOT_ASSUME_DURATION_OR_EXPIRY/);
});

test('cast and damage exact-key neighborhoods remain attribution candidates, not causality', () => {
  const analysis = artifactJson('buff_spell_damage_deep_analysis_latest_four.json');
  assert.equal(analysis.cast.row_count, 21013);
  assert.equal(analysis.cast.unique_spell_key_count, 235);
  assert.ok(analysis.cast.caster_relations.cast_time_within_1ms_of_replay / 21013 > 0.94);
  assert.ok(analysis.cast.cast_time_minus_replay_time_ms.min < -8000);

  assert.equal(analysis.damage.shape_counts.rows, 266332);
  assert.equal(analysis.damage.amount_sign_counts.positive, 266026);
  assert.equal(analysis.damage.amount_sign_counts.zero, 306);

  const forward = analysis.cast_damage_attribution.cast_forward_counts;
  const backward = analysis.cast_damage_attribution.damage_backward_counts;
  const exactForward = forward.cast_any_exact_key_caster_or_chain_owner_damage_2000ms;
  const exactBackward = backward.damage_prior_exact_key_caster_or_chain_owner_cast_2000ms;
  assert.equal(exactForward, 6525);
  assert.ok(exactForward / forward.cast_total_2000ms > 0);
  assert.ok(exactForward / forward.cast_total_2000ms < 0.5);
  assert.equal(exactBackward, 15205);
  assert.ok(exactBackward / backward.damage_total_2000ms < 0.1);
  assert.equal(
    analysis.cast_damage_attribution.decision.near_time_only,
    'REJECT_AS_CAUSAL_PROOF',
  );
});

test('heal/shield anchors distinguish gross reporting from effective or absorbed stages', () => {
  const analysis = artifactJson('buff_spell_damage_deep_analysis_latest_four.json');
  const protection = analysis.heal_shield_on_event;
  const shape = protection.shape_and_team_counts;
  const anchors = protection.summary_anchor_comparison.counts;

  assert.equal(shape['event_0x004b'], 28404);
  assert.equal(shape['event_0x004b:opposing_team'], 0);
  assert.equal(shape['event_0x00ed'], 1107);
  assert.equal(shape['event_0x00ee'], 1107);
  assert.deepEqual(protection.shield_grant_receive_exact_blob_multiset, {
    exact_pair_count: 1107,
    unpaired_receive_count: 0,
    unpaired_grant_count: 0,
    canonicalization_recommendation: 'retain receive 0x00ed; drop exact duplicate grant 0x00ee',
  });

  assert.equal(anchors['0x004b:participant_sources'], 40);
  assert.equal(anchors['0x004b:within_10pct_anchor'], 37);
  assert.equal(anchors['0x004b:within_25pct_anchor'], 40);
  assert.equal(anchors['0x00ed:participant_sources'], 27);
  assert.equal(anchors['0x00ed:positive_raw_zero_anchor'], 20);
  assert.equal(anchors['0x00ed:within_25pct_anchor'], 0);
  assert.match(protection.decision.heal_amount_stage, /REJECT_EFFECTIVE_HEAL_CLAIM/);
  assert.match(protection.decision.shield_amount_stage, /REJECT_REMAINING_OR_ABSORBED_CLAIM/);
});

test('missile, 0x0199, 0x0310, and Death anchors enforce negative boundaries', () => {
  const analysis = artifactJson('buff_spell_damage_deep_analysis_latest_four.json');
  const neighbors = analysis.missile_and_negative_controls;
  const lifecycle = neighbors.missile_same_param_lifecycle_transitions;
  const missile = neighbors.cast_to_missile_route_neighborhood;

  assert.equal(lifecycle['0x0135->0x0465:same_param'], 16573);
  assert.equal(lifecycle['0x0135->0x0465:same_param_same_time'], 15872);
  assert.equal(lifecycle['0x0465->0x02e1:same_param'], 3001);
  assert.equal(lifecycle['0x0465->0x02e0:same_param'], 949);
  assert.ok(missile.cast_ambiguous_multiple_missile_routes_100ms > 15000);
  assert.equal(neighbors.route_counts['0x0199'], 362796);
  assert.equal(neighbors.payload_size_counts['0x0199:2'], 181398);
  assert.equal(neighbors.payload_size_counts['0x0199:3'], 181398);
  assert.match(neighbors.decision.packet_0199, /^REJECT_GAMEPLAY_SPELL_SEMANTIC/);

  const item = readJson(
    'artifacts',
    'full_semantic_baseline_v1',
    'runtime_candidates',
    'packet_0310_shape_emulation_summary_16_16.json',
  );
  assert.equal(item.profile_source.profile.name, 'PKT_S2C_SetItemCharges_s');
  assert.equal(item.client_opcode, '0x0310');
  assert.equal(item.successful_full_consume_count, 28);
  assert.match(item.profile_source.layout_notes.receive_flow, /owner lookup/);

  const death = readJson(
    'artifacts',
    'hero_combat_state_v2',
    'death',
    'death_16_16_route_anchor_validation.json',
  );
  assert.equal(death.status, 'PASS');
  assert.equal(death.exact_build, '16.16.805.0442');
  assert.equal(death.matched_count, 301);
  assert.ok(death.semantic_scope.unavailable_or_unknown.includes('killer'));
  assert.ok(death.semantic_scope.unavailable_or_unknown.includes('kill_credit'));
});

test('dedicated scripts retain explicit protected-input path guards', () => {
  for (const script of [
    'export_buff_spell_deep_recovery_rows.js',
    'decode_buff_spell_callbacks_16_16_deep.py',
    'decode_on_event_16_16_deep.py',
    'analyze_buff_spell_damage_deep.py',
  ]) {
    const source = fs.readFileSync(path.join(ROOT, 'scripts', script), 'utf8');
    assert.match(source, /holdout/i, script);
    assert.match(source, /reject|assertAllowed/i, script);
  }
});

