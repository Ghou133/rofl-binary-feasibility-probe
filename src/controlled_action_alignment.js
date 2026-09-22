'use strict';

// This module deliberately aligns controlled action labels only to event groups
// that already have direct typed semantics.  It does not inspect raw routes and
// a timestamp match is never a scalar oracle or a semantic promotion.

const DIRECT_TYPED_ACTIONS = Object.freeze({
  TAKE_ISOLATED_DAMAGE: Object.freeze({ event_groups: ['damage_events'], identity_role: 'target' }),
  HEAL: Object.freeze({ event_groups: ['heal_events'], identity_role: 'subject' }),
  SHIELD: Object.freeze({ event_groups: ['shield_events'], identity_role: 'subject' }),
  DEATH: Object.freeze({ event_groups: ['death_events'], identity_role: 'victim' }),
  RESPAWN: Object.freeze({ event_groups: ['respawn_events', 'reincarnate_alive_events'], identity_role: 'participant' }),
  LEVEL_UP: Object.freeze({ event_groups: ['level_transition_events'], identity_role: 'participant' }),
});

const ITEM_ACTION_PREFIX = /^(BUY|SELL|UNDO)_(HP|ARMOR|MAGIC_RESIST)_ITEM$/;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function timestampOf(event) {
  for (const field of ['timestamp_ms', 'replay_time_ms', 'respawn_timestamp_ms']) {
    if (Number.isFinite(event?.[field])) return Number(event[field]);
  }
  return null;
}

function expectedEntityNetworkId(participantId) {
  return Number.isSafeInteger(participantId) && participantId > 0
    ? (0x400000ad + participantId) >>> 0
    : null;
}

function actionSteps(anchor) {
  switch (anchor.action) {
    case 'TAKE_ISOLATED_DAMAGE_THEN_NATURAL_REGEN':
      return ['TAKE_ISOLATED_DAMAGE', 'NATURAL_REGEN'];
    case 'SHIELD_THEN_TAKE_ISOLATED_DAMAGE':
      return ['SHIELD', 'TAKE_ISOLATED_DAMAGE'];
    default:
      return [anchor.action];
  }
}

function relevantIdentityFields(role) {
  if (role === 'target') return ['target_participant_id', 'target_network_id'];
  if (role === 'subject') return ['subject_entity_id', 'target_network_id', 'target_participant_id'];
  if (role === 'victim') return ['victim_participant_id', 'target_participant_id', 'target_network_id'];
  return ['participant_id', 'entity_network_id', 'subject_network_id'];
}

function relevantChampionFields(role) {
  if (role === 'target') return ['target_champion'];
  if (role === 'victim') return ['victim_champion', 'target_champion'];
  return ['champion'];
}

function eventMatchesIdentity(event, definition, identity) {
  const expectedParticipantId = identity?.participant_id ?? null;
  const expectedNetworkId = identity?.entity_network_id
    ?? expectedEntityNetworkId(expectedParticipantId);
  const fields = relevantIdentityFields(definition.identity_role);
  const observed = fields.filter((field) => event[field] !== null && event[field] !== undefined);
  if (observed.length === 0) return { matches: false, status: 'UNAVAILABLE_NO_EVENT_IDENTITY_FIELD' };

  for (const field of observed) {
    const value = event[field];
    const isParticipant = field.includes('participant');
    const expected = isParticipant ? expectedParticipantId : expectedNetworkId;
    if (expected === null || expected === undefined || Number(value) !== Number(expected)) {
      return { matches: false, status: 'IDENTITY_MISMATCH', field };
    }
  }
  const championFields = relevantChampionFields(definition.identity_role)
    .filter((field) => typeof event[field] === 'string' && event[field].trim() !== '');
  for (const field of championFields) {
    if (typeof identity.champion === 'string'
        && event[field].trim().toLowerCase() !== identity.champion.toLowerCase()) {
      return { matches: false, status: 'CHAMPION_IDENTITY_MISMATCH', field };
    }
  }
  return { matches: true, status: 'MATCHED', fields: [...observed, ...championFields] };
}

function canonicalEventsForDefinition(decoded, definition) {
  const events = isObject(decoded?.events) ? decoded.events : {};
  // semantic_api deliberately exposes respawn as a canonical group plus an
  // historical alias.  The canonical group is authoritative; appending the
  // alias would turn one event into two candidates.
  if (definition === DIRECT_TYPED_ACTIONS.RESPAWN) {
    const group = Array.isArray(events.respawn_events)
      ? 'respawn_events'
      : 'reincarnate_alive_events';
    const groupRows = Array.isArray(events[group]) ? events[group] : [];
    return groupRows.map((event) => ({ event_group: group, event }));
  }
  const rows = [];
  for (const group of definition.event_groups) {
    const groupRows = Array.isArray(events[group]) ? events[group] : [];
    for (const event of groupRows) rows.push({ event_group: group, event });
  }
  return rows;
}

function verifiedTypedScope(event, scope) {
  const replaySha256 = typeof event?.replay_sha256 === 'string'
    ? event.replay_sha256.toLowerCase() : null;
  const buildValues = [event?.exact_build, event?.game_version]
    .filter((value) => typeof value === 'string' && value.trim() !== '');
  const semanticStatus = typeof event?.semantic_status === 'string' ? event.semantic_status : null;
  const confidence = typeof event?.confidence === 'string' ? event.confidence : null;
  const verified = /^(VERIFIED|SEMANTIC_VERIFIED)/.test(semanticStatus ?? '')
    && /^(VERIFIED|SEMANTIC_VERIFIED)/.test(confidence ?? '');
  const buildMatches = buildValues.length > 0 && buildValues.every((value) => value === scope.exact_build);
  return {
    matches: replaySha256 === scope.replay_sha256 && buildMatches && verified,
    replay_sha256: replaySha256,
    exact_builds: buildValues,
    semantic_status: semanticStatus,
    confidence,
  };
}

function eventAudit(event) {
  return {
    semantic_status: event.semantic_status ?? null,
    confidence: event.confidence ?? null,
    decoder_profile: event.decoder_profile ?? event.build_profile ?? null,
    raw_payload_sha256: event.raw_payload_sha256
      ?? event.raw_packet_ref?.raw_payload_sha256
      ?? event.raw_packet_ref?.payload_sha256
      ?? null,
  };
}

function unresolvedStep(anchor, action, status, extra = {}) {
  return {
    action: action,
    alignment_status: status,
    causal_support_only: true,
    scalar_ground_truth: false,
    automatic_promotion: 'FORBIDDEN',
    action_timestamp_ms: anchor.timestamp_ms,
    ...extra,
  };
}

function alignDirectStep(anchor, action, decoded, identity, scope, windowMs) {
  const definition = DIRECT_TYPED_ACTIONS[action];
  if (!definition) {
    return unresolvedStep(anchor, action, 'UNRESOLVED_NO_DIRECT_TYPED_EVENT');
  }
  const candidates = canonicalEventsForDefinition(decoded, definition)
    .map(({ event_group, event }) => {
      const eventTimestampMs = timestampOf(event);
      const identityResult = eventMatchesIdentity(event, definition, identity);
      const scopeResult = verifiedTypedScope(event, scope);
      return {
        event_group, event, event_timestamp_ms: eventTimestampMs, identity_result: identityResult, scope_result: scopeResult,
      };
    })
    .filter((candidate) => candidate.event_timestamp_ms !== null
      && Math.abs(candidate.event_timestamp_ms - anchor.timestamp_ms) <= windowMs)
    .filter((candidate) => candidate.scope_result.matches)
    .filter((candidate) => candidate.identity_result.matches);

  if (candidates.length !== 1) {
    return unresolvedStep(anchor, action,
      candidates.length === 0 ? 'UNRESOLVED_NO_UNIQUE_CANONICAL_EVENT' : 'AMBIGUOUS_MULTIPLE_CANONICAL_EVENTS', {
        candidate_count: candidates.length,
        candidate_event_groups: [...new Set(candidates.map((candidate) => candidate.event_group))].sort(),
      });
  }
  const candidate = candidates[0];
  return {
    ...unresolvedStep(anchor, action, 'MATCHED_DIRECT_TYPED_EVENT'),
    event_group: candidate.event_group,
    semantic_event_type: candidate.event.event_type ?? candidate.event.semantic_type ?? null,
    event_timestamp_ms: candidate.event_timestamp_ms,
    offset_ms: candidate.event_timestamp_ms - anchor.timestamp_ms,
    identity_fields_constrained: candidate.identity_result.fields,
    event_audit: eventAudit(candidate.event),
  };
}

function alignAnchor(anchor, decoded, identity, scope, windowMs) {
  const steps = actionSteps(anchor)
    .map((action) => alignDirectStep(anchor, action, decoded, identity, scope, windowMs));
  const matchedSteps = steps.filter((step) => step.alignment_status === 'MATCHED_DIRECT_TYPED_EVENT');
  const timestamps = matchedSteps.map((step) => step.event_timestamp_ms);
  const ordered = timestamps.every((value, index) => index === 0 || timestamps[index - 1] <= value);
  if (matchedSteps.length > 1 && !ordered) {
    for (const step of steps) {
      if (step.alignment_status === 'MATCHED_DIRECT_TYPED_EVENT') {
        step.alignment_status = 'UNRESOLVED_COMPOSITE_SEQUENCE_ORDER';
      }
    }
  }
  return {
    schema_version: 'CONTROLLED_ACTION_SEMANTIC_ALIGNMENT_V1',
    anchor_id: anchor.anchor_id,
    ordinal: anchor.ordinal,
    action: anchor.action,
    action_timestamp_ms: anchor.timestamp_ms,
    alignment_window_ms: windowMs,
    causal_support_only: true,
    scalar_ground_truth: false,
    automatic_promotion: 'FORBIDDEN',
    composite_sequence_order_conserved: ordered,
    step_count: steps.length,
    steps,
  };
}

function alignControlledActions(anchors, decoded, options = {}) {
  if (!Array.isArray(anchors)) throw new TypeError('anchors must be an array');
  if (!isObject(decoded)) throw new TypeError('decoded must be an object');
  const windowMs = Number(options.window_ms);
  if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
    throw new RangeError('window_ms must be a positive integer');
  }
  const identity = {
    participant_id: options.participant_id ?? null,
    entity_network_id: options.entity_network_id ?? expectedEntityNetworkId(options.participant_id),
    champion: typeof options.champion === 'string' ? options.champion.trim() : null,
  };
  if (!Number.isSafeInteger(identity.participant_id) || identity.participant_id <= 0) {
    throw new TypeError('participant_id must be a positive integer');
  }
  const scope = {
    replay_sha256: typeof options.replay_sha256 === 'string'
      ? options.replay_sha256.toLowerCase() : null,
    exact_build: typeof options.exact_build === 'string' ? options.exact_build : null,
  };
  if (!/^[0-9a-f]{64}$/.test(scope.replay_sha256 ?? '')) {
    throw new TypeError('replay_sha256 must be a SHA-256 hex digest');
  }
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(scope.exact_build ?? '')) {
    throw new TypeError('exact_build must be an exact N.N.N.N build');
  }

  const canonicalItemEvents = Array.isArray(decoded.events?.item_events) ? decoded.events.item_events : [];
  const alignments = anchors.map((anchor) => {
    if (ITEM_ACTION_PREFIX.test(anchor.action)) {
      const status = canonicalItemEvents.length === 0
        ? 'UNRESOLVED_NO_CANONICAL_ITEM_EVENT'
        : 'UNRESOLVED_NO_VERIFIED_TYPED_ITEM_OPERATION';
      return {
        schema_version: 'CONTROLLED_ACTION_SEMANTIC_ALIGNMENT_V1',
        anchor_id: anchor.anchor_id,
        ordinal: anchor.ordinal,
        action: anchor.action,
        action_timestamp_ms: anchor.timestamp_ms,
        alignment_window_ms: windowMs,
        causal_support_only: true,
        scalar_ground_truth: false,
        automatic_promotion: 'FORBIDDEN',
        composite_sequence_order_conserved: true,
        step_count: 1,
        steps: [unresolvedStep(anchor, anchor.action, status, {
          canonical_item_event_count: canonicalItemEvents.length,
        })],
      };
    }
    return alignAnchor(anchor, decoded, identity, scope, windowMs);
  });
  const steps = alignments.flatMap((alignment) => alignment.steps);
  return {
    schema_version: 'CONTROLLED_ACTION_SEMANTIC_ALIGNMENT_SET_V1',
    alignment_status: 'CAUSAL_SUPPORT_ONLY_NO_AUTOMATIC_PROMOTION',
    causal_support_only: true,
    scalar_ground_truth: false,
    automatic_promotion: 'FORBIDDEN',
    replay_sha256: scope.replay_sha256,
    exact_build: scope.exact_build,
    identity: {
      participant_id: identity.participant_id,
      entity_network_id: identity.entity_network_id,
      champion: identity.champion,
    },
    alignment_window_ms: windowMs,
    input_action_anchor_count: anchors.length,
    alignment_count: alignments.length,
    action_anchor_count_conserved: alignments.length === anchors.length,
    atomic_step_count: steps.length,
    matched_direct_typed_step_count: steps.filter((step) => step.alignment_status === 'MATCHED_DIRECT_TYPED_EVENT').length,
    unresolved_step_count: steps.filter((step) => step.alignment_status !== 'MATCHED_DIRECT_TYPED_EVENT').length,
    alignments,
  };
}

module.exports = {
  DIRECT_TYPED_ACTIONS,
  alignControlledActions,
  expectedEntityNetworkId,
};
