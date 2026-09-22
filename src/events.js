const EVENT_TYPES = Object.freeze([
  'damage',
  'spell_cast',
  'death',
  'position',
  'item_purchase',
  'buff',
  'shield',
  'heal',
  'protection',
  'level_transition',
]);

const CONFIDENCE = Object.freeze([
  'VERIFIED_DIRECT',
  'VERIFIED_DERIVED',
  'PARTIAL',
  'INFERRED',
  'UNVERIFIED',
  'UNAVAILABLE',
  'VERIFIED',
  'DERIVED',
  'CANDIDATE',
  'UNSUPPORTED_VERSION',
]);

function baseEvent(eventType, fields = {}) {
  if (!EVENT_TYPES.includes(eventType)) throw new Error(`Unsupported event type: ${eventType}`);
  return {
    event_type: eventType,
    game_version: null,
    patch: null,
    build_profile: null,
    replay_time_ms: null,
    source_network_id: null,
    target_network_id: null,
    source_participant_id: null,
    target_participant_id: null,
    source_champion: null,
    target_champion: null,
    confidence: 'UNVERIFIED',
    raw_packet_ref: null,
    ...fields,
  };
}

function damageEvent(fields = {}) {
  return baseEvent('damage', {
    amount: null,
    pre_mitigation_amount: null,
    post_mitigation_amount: null,
    effective_damage: null,
    damage_type: null,
    damage_type_code: null,
    damage_result_code: null,
    spell_key: null,
    spell_key_hex: null,
    source_type: null,
    spell: null,
    spell_slot: null,
    item: null,
    rune: null,
    passive: null,
    on_hit: null,
    damage_over_time: null,
    execute: null,
    is_basic_attack: null,
    is_critical: null,
    ...fields,
  });
}

function spellCastEvent(fields = {}) {
  return baseEvent('spell_cast', {
    caster_network_id: null,
    spell_slot: null,
    spell_identifier: null,
    target_network_id: null,
    position: null,
    cast_start: null,
    cast_result: null,
    ...fields,
  });
}

function deathEvent(fields = {}) {
  return baseEvent('death', {
    victim_network_id: null,
    killer_network_id: null,
    ...fields,
  });
}

function buffEvent(fields = {}) {
  return baseEvent('buff', {
    buff_operation: null,
    buff_slot: null,
    buff_name_hash: null,
    buff_type: null,
    stack_count: null,
    duration_seconds: null,
    running_time_seconds: null,
    removal_time_seconds: null,
    is_hidden: null,
    package_hash: null,
    lifecycle_id: null,
    lifecycle_match_status: null,
    ...fields,
  });
}

function shieldEvent(fields = {}) {
  return baseEvent('shield', {
    protection_event_id: null,
    shield_instance_id: null,
    shield_type: null,
    generated_amount: null,
    remaining_amount: null,
    absorbed_amount: null,
    unused_amount: null,
    apply_time_ms: null,
    remove_time_ms: null,
    spell_identifier: null,
    spell_slot: null,
    raw_packet_refs: [],
    ...fields,
  });
}

function healEvent(fields = {}) {
  return baseEvent('heal', {
    protection_event_id: null,
    direct_heal_amount: null,
    raw_heal_amount: null,
    effective_heal_amount: null,
    overheal_amount: null,
    spell_identifier: null,
    spell_slot: null,
    raw_packet_refs: [],
    ...fields,
  });
}

function protectionEvent(fields = {}) {
  return baseEvent('protection', {
    protection_event_id: null,
    protection_type: null,
    generated_amount: null,
    remaining_amount: null,
    absorbed_amount: null,
    unused_amount: null,
    direct_heal_amount: null,
    raw_heal_amount: null,
    effective_heal_amount: null,
    overheal_amount: null,
    temporary_hp_amount: null,
    protection_start_ms: null,
    protection_end_ms: null,
    spell_identifier: null,
    spell_slot: null,
    raw_packet_refs: [],
    ...fields,
  });
}

function positionEvent(fields = {}) {
  return baseEvent('position', {
    network_id: null,
    x: null,
    y: null,
    resolution_ms: null,
    interpolation: null,
    ...fields,
  });
}

function levelTransitionEvent(fields = {}) {
  return baseEvent('level_transition', {
    timestamp_ms: null,
    entity_network_id: null,
    participant_id: null,
    champion: null,
    champion_id: null,
    raw_field_10: null,
    raw_field_11: null,
    level_before: null,
    level_after: null,
    transition_evidence: 'UNVERIFIED',
    level_mapping_evidence: 'UNAVAILABLE',
    game_version: null,
    is_initialization: false,
    ...fields,
  });
}

function buildCombatWindow(death, damageEvents, spellEvents, positionEvents, options = {}) {
  const deathTime = Number.isFinite(death?.replay_time_ms) ? death.replay_time_ms : null;
  const victimNetworkId = death?.victim_network_id ?? death?.target_network_id ?? null;
  const victimDamage = victimNetworkId === null
    ? []
    : damageEvents.filter((event) => event.target_network_id === victimNetworkId);
  const fixed = {};
  for (const seconds of [5, 10, 15]) {
    const start = deathTime === null ? null : deathTime - seconds * 1000;
    fixed[`fixed_${seconds}s`] = {
      start_ms: start,
      end_ms: deathTime,
      damage_events: filterWindow(victimDamage, start, deathTime),
      spell_events: filterWindow(spellEvents, start, deathTime),
      position_events: filterWindow(positionEvents, start, deathTime),
    };
  }

  const gapMs = options.damageGapMs ?? 2500;
  const relevantDamage = deathTime === null ? [] : victimDamage
    .filter((event) => event.replay_time_ms !== null && event.replay_time_ms <= deathTime)
    .sort((a, b) => a.replay_time_ms - b.replay_time_ms);
  let heuristicStart = deathTime;
  for (let index = relevantDamage.length - 1; index >= 0; index -= 1) {
    const previous = relevantDamage[index - 1];
    const current = relevantDamage[index];
    if (!previous || current.replay_time_ms - previous.replay_time_ms > gapMs) {
      heuristicStart = current.replay_time_ms;
      break;
    }
    heuristicStart = previous.replay_time_ms;
  }
  if (relevantDamage.length === 0) {
    heuristicStart = null;
  }
  const heuristic = {
    start_ms: heuristicStart,
    end_ms: deathTime,
    duration_ms: heuristicStart === null || deathTime === null
      ? null
      : Math.max(0, deathTime - heuristicStart),
    rule: `walk backward through damage events; a gap greater than ${gapMs} ms starts a new combat window`,
    damage_events: filterWindow(victimDamage, heuristicStart, deathTime),
    spell_events: filterWindow(spellEvents, heuristicStart, deathTime),
    position_events: filterWindow(positionEvents, heuristicStart, deathTime),
  };
  return {
    victim_network_id: death?.victim_network_id ?? null,
    death_time_ms: deathTime,
    fixed,
    heuristic,
    confidence: 'DERIVED',
  };
}

function filterWindow(events, start, end) {
  if (start === null || end === null) return [];
  return events.filter((event) => event.replay_time_ms !== null
    && event.replay_time_ms >= start
    && event.replay_time_ms <= end);
}

function buildAdcDeathRecord(fields = {}) {
  return {
    match_id: null,
    replay_path: null,
    replay_sha256: null,
    adc: null,
    adc_participant_id: null,
    support: null,
    support_participant_id: null,
    death_time_ms: null,
    combat_start_ms: null,
    combat_duration_ms: null,
    killer: null,
    attackers: [],
    nearby_enemy_count: null,
    nearby_ally_count: null,
    support_distance: null,
    support_spell_casts: [],
    hp_at_combat_start: null,
    effective_external_protection: null,
    time_to_die_ms: null,
    candidate_classification: null,
    confidence: 'UNVERIFIED',
    ...fields,
  };
}

module.exports = {
  EVENT_TYPES,
  CONFIDENCE,
  baseEvent,
  damageEvent,
  spellCastEvent,
  deathEvent,
  buffEvent,
  shieldEvent,
  healEvent,
  protectionEvent,
  positionEvent,
  levelTransitionEvent,
  buildCombatWindow,
  buildAdcDeathRecord,
};
