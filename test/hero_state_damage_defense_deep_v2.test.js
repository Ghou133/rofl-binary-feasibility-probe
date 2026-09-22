'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  ATTACK_SPEED_PRESENCE_TABLE_RVA,
  BUFF_ADJUSTMENT_TABLE_RVA,
  decodeAttackSpeedObjectHex,
  decodeBuffAdjustmentKindByte,
  decodeBuffAdjustmentRecordObjectHex,
  decodeDeathTimerStorage,
  participantNetworkId,
} = require('../scripts/analyze_hero_state_damage_defense_deep_v2');

const ROOT = path.resolve(__dirname, '..');
const REPORT_PATH = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'hero_state',
  'hero_state_damage_defense_deep_report_16_16.json',
);
const DEATH_EVENTS_PATH = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'hero_state',
  'packet_0074_death_timer_events.jsonl',
);
const ATTACK_SPEED_EVENTS_PATH = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'hero_state',
  'packet_00dd_attack_speed_cap_override_events.jsonl',
);
const BUFF_ADJUSTMENT_EVENTS_PATH = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'hero_state',
  'packet_0412_buff_stat_adjustment_events.jsonl',
);
const RUNTIME_IMAGE_PATH = path.join(
  ROOT,
  'artifacts',
  'new_build_rofl_compatibility_gate_v1',
  'runtime',
  'league_16.16.805.0442.memory.bin',
);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

test('16.16 death-timer callback byte inverse recovers exact floats', () => {
  assert.equal(decodeDeathTimerStorage(Buffer.from('99999794', 'hex')), 10);
  assert.equal(decodeDeathTimerStorage(Buffer.from('99999894', 'hex')), 12);
  assert.equal(participantNetworkId(2), 0x400000af);
});

test('16.16 attack-speed-cap callback inverse recovers neutral plaintext fields', () => {
  const image = fs.readFileSync(RUNTIME_IMAGE_PATH);
  const table = Buffer.from(image.subarray(
    ATTACK_SPEED_PRESENCE_TABLE_RVA,
    ATTACK_SPEED_PRESENCE_TABLE_RVA + 0x100,
  ));
  assert.deepEqual(
    decodeAttackSpeedObjectHex(
      '2807b14101000000dd00e6e6b2000040a3e6e6e61f1f494fabab56dfb8e6e6e6',
      table,
    ),
    {
      field_14_present: false,
      field_18_present: true,
      field_14_plain_f32: null,
      field_18_plain_f32: 90,
    },
  );
  assert.deepEqual(
    decodeAttackSpeedObjectHex(
      '2807b14101000000dd00e6e6b6000040c8e6e6e61f1f16beababeb4bb8e6e6e6',
      table,
    ),
    {
      field_14_present: true,
      field_18_present: true,
      field_14_plain_f32: 0.625,
      field_18_plain_f32: 0.625,
    },
  );
});

test('16.16 buff-adjustment consumer inverse recovers all neutral record fields', () => {
  const image = fs.readFileSync(RUNTIME_IMAGE_PATH);
  const table = Buffer.from(image.subarray(
    BUFF_ADJUSTMENT_TABLE_RVA,
    BUFF_ADJUSTMENT_TABLE_RVA + 0x100,
  ));
  assert.equal(decodeBuffAdjustmentKindByte(186), 6);
  assert.deepEqual(
    decodeBuffAdjustmentRecordObjectHex(
      '606ab14101000000a3a3a3a36c872fedfa0000009f375094f0f0a090',
      table,
    ),
    {
      adjustment_kind_plain_u8: 0,
      field_a_plain_f32: 0,
      field_b_plain_f32: 718.1090698242188,
      field_c_plain_f32: 0.05000000074505806,
      field_d_plain_f32: 5,
    },
  );
});

test('deep report saturates bounded hero-state candidates without overpromotion', () => {
  const report = readJson(REPORT_PATH);
  const routes = report.routes;

  assert.equal(report.exact_build, '16.16.805.0442');
  assert.equal(report.project_context_loaded, true);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.status, 'SATURATED_NO_PERSISTENT_STATE_PROMOTION');
  assert.equal(report.corpus.safe_replay_total, 8);
  assert.equal(report.corpus.parser_error_count, 0);

  const heroStats = routes['0x010c_hero_stats_negative_control'];
  assert.equal(heroStats.route_role, 'NEGATIVE_CONTROL');
  assert.equal(heroStats.known_route_semantics, 'HERO_CUMULATIVE_SCOREBOARD_STATS');
  assert.equal(heroStats.latest_four_full_corpus.event_count, 1370);
  assert.equal(heroStats.latest_four_full_corpus.exact_success_full_consume_count, 1370);
  assert.deepEqual(heroStats.latest_four_full_corpus.stream_counts, { keyframe: 1370 });
  assert.equal(heroStats.direct_live_hp_defense_resource_carrier, false);

  const formula = routes['0x042f_stat_formula_outputs'];
  assert.equal(formula.combined_row_count, 130484);
  assert.equal(formula.combined_exact_success_full_consume_count, 130484);
  assert.equal(formula.combined_anchored_nontrivial_scalar_match_count, 0);
  assert.equal(formula.direct_hp_defense_resource_carrier, false);

  const replicate = routes['0x01dc_replicate_fields'];
  assert.equal(replicate.combined_row_count, 26507);
  assert.equal(replicate.latest_four.exact_emulation.success_full_consume, 13163);
  assert.equal(replicate.paired_p0.exact_success_full_consume_count, 13344);
  assert.equal(replicate.paired_p0.nonempty_field_value_vector_count, 0);

  const buffAdjustments = routes['0x0412_buff_update_stat_adjustments'];
  const buffExact = buffAdjustments.exact_plaintext_recovery;
  assert.equal(buffExact.row_count, 714);
  assert.equal(buffExact.exact_success_full_consume_count, 714);
  assert.equal(buffExact.record_count, 714);
  assert.equal(buffExact.finite_record_count, 714);
  assert.deepEqual(buffExact.record_length_counts, { 1: 714 });
  assert.deepEqual(buffExact.adjustment_kind_counts, { 0: 714 });
  assert.equal(buffExact.standard_adjustment_count, 711);
  assert.equal(buffExact.clear_sentinel_count, 3);
  assert.equal(buffExact.unexplained_decoded_shape_count, 0);
  assert.equal(buffExact.anchored_persistent_scalar_match_count, 0);
  assert.equal(buffAdjustments.research_decoder_promotion_recommended, true);
  assert.equal(buffAdjustments.field_role_promotion_recommended, false);

  for (const route of ['0x0259', '0x03f8', '0x04df']) {
    assert.deepEqual(routes['0x0259_03f8_04df_absence'][route], {
      latest_four_count: 0,
      paired_p0_count: 0,
    });
  }

  const ticks = routes['0x02cf_health_bar_variable_ticks'];
  assert.equal(ticks.combined_row_count, 60604);
  assert.equal(ticks.latest_four.exact_success_full_consume_count, ticks.latest_four.row_count);
  assert.equal(ticks.paired_p0.exact_success_full_consume_count, ticks.paired_p0.row_count);
  assert.equal(ticks.combined_hero_nonempty_vector_row_count, 0);
  assert.equal(ticks.direct_hp_scalar_present, false);

  assert.equal(routes['0x00d2_show_health_bar'].combined_row_count, 72815);
  assert.equal(
    routes['0x00d2_show_health_bar'].latest_four.exact_success_full_consume_count,
    routes['0x00d2_show_health_bar'].latest_four.row_count,
  );
  assert.equal(
    routes['0x00d2_show_health_bar'].paired_p0.exact_success_full_consume_count,
    routes['0x00d2_show_health_bar'].paired_p0.row_count,
  );
  assert.equal(routes['0x00d2_show_health_bar'].hp_scalar_present, false);
  assert.equal(routes['0x03dc_stat_stone_game_delta'].combined_row_count, 55106);
  assert.equal(routes['0x0345_npc_level_up_global'].combined_hero_network_id_row_count, 0);
  assert.equal(
    routes['0x0345_npc_level_up_global'].latest_four.exact_success_full_consume_count,
    routes['0x0345_npc_level_up_global'].latest_four.row_count,
  );
  assert.equal(
    routes['0x0345_npc_level_up_global'].paired_p0.exact_success_full_consume_count,
    routes['0x0345_npc_level_up_global'].paired_p0.row_count,
  );
  assert.equal(
    routes['0x00dd_attack_speed_cap_overrides'].latest_four.exact_success_full_consume_count,
    routes['0x00dd_attack_speed_cap_overrides'].latest_four.row_count,
  );
  assert.equal(
    routes['0x00dd_attack_speed_cap_overrides'].paired_p0.exact_success_full_consume_count,
    routes['0x00dd_attack_speed_cap_overrides'].paired_p0.row_count,
  );
  const attackSpeed = routes['0x00dd_attack_speed_cap_overrides'];
  const attackSpeedExact = attackSpeed.exact_plaintext_recovery;
  assert.equal(attackSpeedExact.row_count, 69840);
  assert.equal(attackSpeedExact.exact_success_full_consume_count, 69840);
  assert.equal(attackSpeedExact.present_row_count, 9428);
  assert.equal(attackSpeedExact.hero_present_row_count, 9093);
  assert.deepEqual(attackSpeedExact.payload_presence_shape_counts, {
    '1:00': 60412,
    '1:01': 141,
    '5:01': 149,
    '9:11': 9138,
  });
  assert.equal(attackSpeedExact.field_18_clear_sentinel_count, 141);
  assert.equal(attackSpeedExact.field_18_90_value_count, 149);
  assert.equal(attackSpeedExact.both_fields_equal_ramp_count, 9138);
  assert.equal(attackSpeedExact.unexplained_decoded_shape_count, 0);
  assert.equal(attackSpeedExact.both_present_equal_value_count, 9138);
  assert.equal(attackSpeed.research_decoder_promotion_recommended, true);
  assert.equal(attackSpeed.field_role_promotion_recommended, false);

  const route0474 = routes['0x0474_champion_specific_negative_control'];
  assert.equal(route0474.event_count, 107192);
  assert.equal(route0474.dominant_champion, 'Zilean');
  assert.equal(route0474.dominant_champion_event_count, 106999);
  assert.equal(route0474.dominant_payload_hex, '605f');
  assert.equal(route0474.dominant_payload_rate, 1);
  assert.equal(route0474.counterexample_count, 193);
  assert.equal(route0474.general_hero_persistent_state_hypothesis_rejected, true);
  assert.equal(route0474.positive_semantic_claim, null);
  assert.equal(
    report.evidence_hashes.route_0474_champion_specific_audit.sha256,
    '9abfa6667248655e6e4c1ee92c51ac816c237e484e35b65e25c97d0adaf78249',
  );

  const route02d4 = routes['0x02d4_auxiliary_batch_negative_control'];
  assert.equal(route02d4.event_count, 192201);
  assert.equal(route02d4.timestamp_group_count, 44492);
  assert.equal(route02d4.groups_without_damage, 11594);
  assert.equal(route02d4.maximum_group_size, 458);
  assert.equal(route02d4.giant_group_at_least_100_rows_count, 59);
  assert.equal(
    route02d4.sampled_raw_param_matches_damage_source_or_target_within_10ms_rate,
    0.0274375,
  );
  assert.equal(route02d4.direct_damage_semantic_rejected, true);
  assert.equal(route02d4.direct_entity_scalar_semantic_rejected, true);
  assert.equal(route02d4.recovered_bounded_structure.byte_0_high_five_bits.primary_row_count, 192191);
  assert.equal(route02d4.recovered_bounded_structure.byte_0_high_five_bits.alternate_row_count, 10);
  assert.equal(route02d4.recovered_bounded_structure.byte_0_high_five_bits.known_branch_coverage_rate, 1);
  assert.equal(route02d4.positive_semantic_claim, null);
  assert.equal(
    report.evidence_hashes.route_02d4_auxiliary_batch_audit.sha256,
    '7fab264e904844144f3f57d744dc13b3ed7f5ce7c7521c7ffbb003360864cba5',
  );

  const death = routes['0x0074_update_death_timer'].combined;
  assert.equal(death.row_count, 608);
  assert.equal(death.exact_success_full_consume_count, 608);
  assert.equal(death.finite_timer_count, 608);
  assert.equal(death.p0_death_anchor_match.status, 'MATCH');
  assert.equal(death.p0_death_anchor_match.timestamp_delta_ms, 1);
  assert.equal(death.p0_death_anchor_match.death_timer_seconds, 12);
  assert.equal(death.p0_death_anchor_match.projected_end_inside_details_respawn_frame_bound, true);

  assert.equal(report.damage_stage.matched_anchor_count, 6);
  assert.equal(report.damage_stage.damage_type_mismatch_count, 0);
  assert.equal(report.damage_stage.recorded_component_residual.sample_count, 6);
  assert.equal(
    report.damage_stage.recorded_component_residual.max_absolute_residual,
    0.4387931823730469,
  );
  assert.equal(report.damage_stage.effective_hp_loss_residual.status, 'NOT_COMPUTABLE');
  assert.equal(report.damage_stage.pre_mitigation_residual.status, 'NOT_COMPUTABLE');
  assert.equal(report.damage_stage.amount_semantic_stage, 'RECORDED_COMPONENT_STAGE_UNKNOWN');

  for (const field of ['current_hp', 'max_hp', 'armor', 'magic_resist', 'current_resource']) {
    assert.equal(report.semantic_availability[field], 'UNAVAILABLE');
  }
  assert.equal(report.promotion_decision.persistent_hero_state, 'NO_PROMOTION');
  assert.equal(report.promotion_decision.damage_amount_stage, 'NO_PROMOTION');
  assert.equal(report.promotion_decision.death_timer_research_event, 'PROMOTION_RECOMMENDED');
  assert.equal(
    report.promotion_decision.buff_stat_adjustment_research_decoder,
    'PROMOTION_RECOMMENDED',
  );
  assert.equal(report.promotion_decision.buff_stat_adjustment_field_roles, 'NO_PROMOTION');
  assert.equal(
    report.promotion_decision.attack_speed_cap_override_research_decoder,
    'PROMOTION_RECOMMENDED',
  );
  assert.equal(report.promotion_decision.attack_speed_cap_override_field_roles, 'NO_PROMOTION');

  const allowedDecisions = new Set(['PROMOTE', 'KEEP_CANDIDATE', 'REJECT', 'REPURPOSE']);
  for (const decision of [
    ...report.route_decisions,
    ...report.capability_decisions,
    ...report.domain_decisions,
  ]) {
    assert.ok(allowedDecisions.has(decision.decision));
    assert.equal(typeof decision.evidence_exhausted, 'boolean');
    assert.ok(Array.isArray(decision.next_required_evidence));
  }
  assert.ok(report.route_decisions.some((decision) => decision.packet_discriminator === '0x0412'
    && decision.candidate === 'NEUTRAL_STRUCTURAL_PLAINTEXT_DECODER'
    && decision.decision === 'PROMOTE'));
  assert.ok(report.route_decisions.some((decision) => decision.packet_discriminator === '0x0412'
    && decision.candidate === 'NAMED_BUFF_STAT_ADJUSTMENT_FIELD_ROLES'
    && decision.decision === 'KEEP_CANDIDATE'));
  assert.ok(report.route_decisions.some((decision) => decision.packet_discriminator === '0x00dd'
    && decision.candidate === 'NEUTRAL_STRUCTURAL_PLAINTEXT_DECODER'
    && decision.decision === 'PROMOTE'));
  assert.ok(report.route_decisions.some((decision) => decision.packet_discriminator === '0x00dd'
    && decision.candidate === 'NAMED_ATTACK_SPEED_CAP_OVERRIDE_FIELD_ROLES'
    && decision.decision === 'KEEP_CANDIDATE'));
  assert.equal(
    report.domain_decisions.find(
      (decision) => decision.domain === 'HERO_PERSISTENT_HP_DEFENSE_RESOURCE_STATE',
    ).decision,
    'REJECT',
  );
});

test('death-timer research event artifact is exact and contains the P0 anchor', () => {
  const events = fs.readFileSync(DEATH_EVENTS_PATH, 'utf8')
    .trim()
    .split(/\r?\n/)
    .map(JSON.parse);
  assert.equal(events.length, 608);
  assert.ok(events.every((event) => Number.isFinite(event.death_timer_seconds)));
  assert.ok(events.some((event) => event.replay_time_ms === 238173
    && event.entity_network_id === 0x400000af
    && event.death_timer_seconds === 12));
});

test('attack-speed-cap research artifact contains only decoded update rows', () => {
  const events = fs.readFileSync(ATTACK_SPEED_EVENTS_PATH, 'utf8')
    .trim()
    .split(/\r?\n/)
    .map(JSON.parse);
  assert.equal(events.length, 9428);
  assert.ok(events.every((event) => event.field_14_present || event.field_18_present));
  assert.ok(events.some((event) => event.replay_time_ms === 260
    && event.entity_network_id === 0x400000b6
    && event.field_14_plain_f32 === 0.625
    && event.field_18_plain_f32 === 0.625));
  assert.ok(events.some((event) => event.source_packet.payload_length === 1
    && event.field_14_plain_f32 === null
    && event.field_18_plain_f32 === -1));
});

test('buff-stat-adjustment research artifact contains exact standard and clear shapes', () => {
  const events = fs.readFileSync(BUFF_ADJUSTMENT_EVENTS_PATH, 'utf8')
    .trim()
    .split(/\r?\n/)
    .map(JSON.parse);
  assert.equal(events.length, 714);
  assert.ok(events.every((event) => event.adjustment_kind_plain_u8 === 0));
  assert.ok(events.some((event) => event.replay_time_ms === 718109
    && event.outer_update_kind_plain_u8 === 6
    && event.field_a_plain_f32 === 0
    && event.field_b_plain_f32 === 718.1090698242188
    && event.field_c_plain_f32 === 0.05000000074505806
    && event.field_d_plain_f32 === 5));
  assert.equal(events.filter((event) => event.field_a_plain_f32 === -1
    && event.field_c_plain_f32 === -1
    && event.field_d_plain_f32 === 0).length, 3);
});
