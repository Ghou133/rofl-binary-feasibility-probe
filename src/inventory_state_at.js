'use strict';

// This module deliberately consumes only already-published item semantics.  It does
// not decode packets, identify transactions, or turn a substitution-map update into
// an inventory mutation.

const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const SLOT_COUNT = 10;
const SAFE_EVENT_TYPES = new Set([
  'ITEM_STATE_SNAPSHOT',
  'ITEM_STATE_SET',
  'ITEM_SWAP',
  'ITEM_SUBSTITUTION_MAP_UPDATE',
  'SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT',
  'INVENTORY_MUTATION_UNKNOWN',
]);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertSafeArtifactPath(inputPath) {
  if (typeof inputPath !== 'string' || inputPath.length === 0) {
    throw new TypeError('artifact path must be a non-empty string');
  }
  const direct = inputPath.replace(/\\/g, '/').toLowerCase();
  if (/(^|\/)jungle_objective_holdout(?:_v1)?(\/|$)|(^|\/)holdout(\/|$)/.test(direct)) {
    throw new Error(`protected Holdout path is forbidden: ${inputPath}`);
  }
  const resolved = path.resolve(inputPath);
  let ancestor = resolved;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) throw new Error(`no existing ancestor for artifact path: ${inputPath}`);
    ancestor = parent;
  }
  const realAncestor = fs.realpathSync.native(ancestor);
  const suffix = path.relative(ancestor, resolved);
  const real = suffix ? path.join(realAncestor, suffix) : realAncestor;
  const canonical = real.replace(/\\/g, '/').toLowerCase();
  if (/(^|\/)jungle_objective_holdout(?:_v1)?(\/|$)|(^|\/)holdout(\/|$)/.test(canonical)) {
    throw new Error(`protected Holdout realpath is forbidden: ${inputPath}`);
  }
  return real;
}

function exactBuildOf(event) {
  return event.exact_build ?? event.game_version ?? event.replay_version ?? null;
}

function eventTime(event) {
  const time = event.replay_time_ms ?? event.timestamp_ms;
  if (!Number.isInteger(time) || time < 0) throw new TypeError('inventory event needs non-negative integer replay_time_ms');
  return time;
}

function entityOf(event) {
  const entity = event.subject_entity_id ?? event.entity_id ?? event.entity_network_id;
  if (!Number.isInteger(entity) || entity < 0) throw new TypeError('inventory event needs integer subject_entity_id');
  return entity >>> 0;
}

function eventKind(event) {
  const type = event.event_type ?? event.operation;
  if (!SAFE_EVENT_TYPES.has(type)) throw new Error(`unpublished inventory event type: ${type}`);
  return type;
}

function normalizeEntry(entry) {
  const slot = entry.slot_index ?? entry.slot;
  const item = entry.item_identifier ?? entry.item_id;
  const stack = entry.stack_count ?? entry.quantity;
  if (!Number.isInteger(slot) || slot < 0 || slot >= SLOT_COUNT) throw new RangeError('inventory slot is out of range');
  if ((typeof item !== 'string' && !Number.isInteger(item)) || String(item).length === 0) {
    throw new TypeError('inventory entry needs an item identifier');
  }
  if (!Number.isInteger(stack) || stack < 0) throw new TypeError('inventory entry needs non-negative integer stack_count');
  return Object.freeze({ slot_index: slot, item_identifier: String(item), stack_count: stack });
}

function emptySlots(sourceProvenance) {
  return Array.from({ length: SLOT_COUNT }, (_unused, slot_index) => ({
    slot_index,
    item_identifier: null,
    stack_count: null,
    state: 'EMPTY_CONFIRMED_BY_FULL_SNAPSHOT',
    provenance: clone(sourceProvenance),
  }));
}

function fullSnapshotSlots(entries, sourceProvenance) {
  const slots = emptySlots(sourceProvenance);
  const seen = new Set();
  for (const raw of entries) {
    const entry = normalizeEntry(raw);
    if (seen.has(entry.slot_index)) throw new Error(`duplicate inventory slot ${entry.slot_index}`);
    seen.add(entry.slot_index);
    slots[entry.slot_index] = {
      ...entry,
      state: 'DIRECT_SNAPSHOT_ENTRY',
      provenance: clone(sourceProvenance),
    };
  }
  return slots;
}

function setSlot(slots, rawEntry, sourceProvenance) {
  const result = slots.map((slot) => ({ ...slot }));
  const entry = normalizeEntry(rawEntry);
  result[entry.slot_index] = {
    ...entry,
    state: 'DIRECT_SLOT_SET',
    provenance: clone(sourceProvenance),
  };
  return result;
}

function provenance(event, kind) {
  return {
    event_type: kind,
    semantic_status: event.semantic_status ?? event.confidence ?? 'VERIFIED_DIRECT',
    replay_sha256: event.replay_sha256 ?? event.raw_packet_ref?.replay_sha256 ?? null,
    raw_payload_sha256: event.raw_payload_sha256 ?? event.raw_packet_ref?.payload_sha256 ?? null,
    raw_packet_ref: event.raw_packet_ref ? clone(event.raw_packet_ref) : null,
    decoder_profile: event.decoder_profile ?? null,
  };
}

function normalizedEvent(event, sourceIndex) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('inventory event must be an object');
  const kind = eventKind(event);
  const exactBuild = exactBuildOf(event);
  if (exactBuild !== EXACT_BUILD) throw new Error(`inventory state supports only ${EXACT_BUILD}; got ${exactBuild}`);
  if (typeof event.source_artifact_path === 'string') assertSafeArtifactPath(event.source_artifact_path);
  const eventProvenance = provenance(event, kind);
  const result = {
    kind,
    exact_build: exactBuild,
    entity_id: entityOf(event),
    replay_time_ms: eventTime(event),
    source_index: sourceIndex,
    event_order: Number.isInteger(event.occurrence_index) ? event.occurrence_index : sourceIndex,
    event_id: event.event_id ?? null,
    provenance: eventProvenance,
    snapshot_scope: event.snapshot_scope ?? null,
  };
  if (kind === 'ITEM_STATE_SNAPSHOT') {
    if (!Array.isArray(event.inventory_entries)) throw new TypeError('full inventory snapshot requires inventory_entries');
    result.slots = fullSnapshotSlots(event.inventory_entries, eventProvenance);
    result.snapshot_scope = event.snapshot_scope ?? 'LIVE_STREAM_RESET';
    if (!['LIVE_STREAM_RESET', 'KEYFRAME_OBSERVATION'].includes(result.snapshot_scope)) {
      throw new Error(`unsupported inventory snapshot scope: ${result.snapshot_scope}`);
    }
  }
  if (kind === 'ITEM_STATE_SET') {
    result.entry = normalizeEntry({
      slot_index: event.slot_index,
      item_identifier: event.item_identifier ?? event.item_id,
      stack_count: event.stack_count ?? event.quantity,
    });
  }
  if (kind === 'ITEM_SWAP') {
    const first = event.source_slot_index ?? event.first_slot_index;
    const second = event.target_slot_index ?? event.second_slot_index;
    if (!Number.isInteger(first) || !Number.isInteger(second)
        || first < 0 || first > 5 || second < 0 || second > 5) {
      throw new RangeError('inventory swap needs direct slots in domain 0..5');
    }
    result.swap_slots = [first, second];
  }
  if (kind === 'SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT') {
    result.stage = Number.isInteger(event.stage) ? event.stage : null;
  }
  return result;
}

function eventCompare(left, right) {
  return left.replay_time_ms - right.replay_time_ms
    || left.event_order - right.event_order
    || left.source_index - right.source_index;
}

function freshTimeline(entityId) {
  return {
    entity_id: entityId,
    current_full_slots: null,
    current_partial_slots: new Map(),
    ambiguity: null,
    last_live_snapshot: null,
    last_keyframe_snapshot: null,
    support_stage: null,
    records: [],
  };
}

function materializeTimeline(events) {
  const byEntity = new Map();
  for (const event of [...events].sort(eventCompare)) {
    if (!byEntity.has(event.entity_id)) byEntity.set(event.entity_id, freshTimeline(event.entity_id));
    const timeline = byEntity.get(event.entity_id);
    const record = {
      replay_time_ms: event.replay_time_ms,
      event_id: event.event_id,
      kind: event.kind,
      provenance: event.provenance,
      snapshot_scope: event.snapshot_scope,
      state_after: null,
    };
    if (event.kind === 'ITEM_STATE_SNAPSHOT') {
      if (event.snapshot_scope === 'LIVE_STREAM_RESET') {
        timeline.current_full_slots = event.slots;
        timeline.current_partial_slots = new Map();
        timeline.ambiguity = null;
        timeline.last_live_snapshot = event;
      } else {
        timeline.last_keyframe_snapshot = event;
      }
      record.state_after = 'DIRECT_SNAPSHOT';
    } else if (event.kind === 'ITEM_STATE_SET') {
      if (timeline.current_full_slots && !timeline.ambiguity) {
        timeline.current_full_slots = setSlot(
          timeline.current_full_slots,
          event.entry,
          event.provenance,
        );
        timeline.last_live_snapshot = {
          ...event,
          slots: timeline.current_full_slots,
          snapshot_scope: 'DIRECT_SLOT_SET_ON_LIVE_STATE',
          state_basis: 'COMPOSITE_AFTER_DIRECT_SLOT_SET',
        };
      } else {
        timeline.current_partial_slots.set(event.entry.slot_index, {
          ...event.entry,
          state: 'DIRECT_SLOT_SET',
        });
      }
      record.state_after = timeline.current_full_slots ? 'DIRECT_SLOT_SET_ON_LIVE_STATE' : 'PARTIAL_DIRECT_SLOT_SET';
    } else if (event.kind === 'ITEM_SWAP' || event.kind === 'INVENTORY_MUTATION_UNKNOWN') {
      // The published swap carrier deliberately has no item identity.  A state
      // query therefore fails closed instead of projecting prior identities.
      timeline.current_full_slots = null;
      timeline.current_partial_slots = new Map();
      timeline.ambiguity = {
        replay_time_ms: event.replay_time_ms,
        reason: event.kind === 'ITEM_SWAP' ? 'SWAP_HAS_NO_PUBLISHED_ITEM_IDENTITY' : 'UNKNOWN_INVENTORY_MUTATION',
        provenance: event.provenance,
      };
      record.state_after = 'AMBIGUOUS';
    } else if (event.kind === 'SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT') {
      timeline.support_stage = { replay_time_ms: event.replay_time_ms, stage: event.stage, provenance: event.provenance };
      record.state_after = 'SUPPORT_STAGE_OBSERVED';
    } else {
      // A substitution map is direct protocol state but explicitly not a player
      // inventory transform, so it cannot change a timeline.
      record.state_after = 'NO_INVENTORY_MEMBERSHIP_MUTATION';
    }
    timeline.records.push(record);
  }
  return byEntity;
}

function inventoryStateIndex(events, options = {}) {
  if (!Array.isArray(events)) throw new TypeError('inventory state input must be an array');
  if (options.exact_build != null && options.exact_build !== EXACT_BUILD) {
    throw new Error(`inventory state supports only ${EXACT_BUILD}`);
  }
  const normalized = events.map(normalizedEvent);
  return Object.freeze({
    schema: 'ROFL_INVENTORY_STATE_AT_V1',
    exact_build: EXACT_BUILD,
    nearest_build_fallback: 'FORBIDDEN',
    source_event_count: normalized.length,
    events: Object.freeze(normalized.sort(eventCompare)),
    timelines: materializeTimeline(normalized),
  });
}

function stateFromFull(snapshot, entityId, queryTime, kind) {
  return {
    status: kind,
    exact_build: EXACT_BUILD,
    entity_id: entityId,
    replay_time_ms: queryTime,
    observed_at_ms: snapshot.replay_time_ms,
    validity_interval: {
      start_ms: snapshot.replay_time_ms,
      end_ms_exclusive: null,
      basis: kind === 'DIRECT_SNAPSHOT' ? 'EXACT_OBSERVATION_TIME_ONLY'
        : kind === 'DERIVED_COMPOSITE_STATE' || kind === 'CARRIED_FORWARD_COMPOSITE_STATE'
          ? 'COMPOSITE_OF_FULL_SNAPSHOT_AND_DIRECT_SLOT_SET'
          : 'LIVE_SNAPSHOT_CARRIED_FORWARD_UNTIL_PUBLISHED_AMBIGUITY',
    },
    completeness: 'COMPLETE',
    slots: clone(snapshot.slots),
    provenance: clone(snapshot.provenance),
    known_limits: [
      'No buy, sell, undo, transform, or use cause is inferred.',
      'A later published swap or unknown mutation invalidates carried-forward state.',
    ],
  };
}

function unknownState(entityId, queryTime, reason, provenance = null) {
  return {
    status: 'UNKNOWN',
    exact_build: EXACT_BUILD,
    entity_id: entityId,
    replay_time_ms: queryTime,
    observed_at_ms: null,
    validity_interval: null,
    completeness: 'UNKNOWN',
    slots: null,
    provenance: provenance ? clone(provenance) : null,
    reason,
    known_limits: ['No state is invented across an ambiguous mutation or unsupported time interval.'],
  };
}

function inventory_state_at(index, entityId, replayTimeMs, options = {}) {
  if (!index || index.schema !== 'ROFL_INVENTORY_STATE_AT_V1') throw new TypeError('invalid inventory state index');
  if (options.exact_build != null && options.exact_build !== EXACT_BUILD) {
    return unknownState(entityId, replayTimeMs, 'UNSUPPORTED_EXACT_BUILD');
  }
  if (!Number.isInteger(entityId) || !Number.isInteger(replayTimeMs) || replayTimeMs < 0) {
    throw new TypeError('entityId and replayTimeMs must be non-negative integers');
  }
  const events = index.events.filter((event) => event.entity_id === (entityId >>> 0)
    && event.replay_time_ms <= replayTimeMs);
  if (!events.length) return unknownState(entityId, replayTimeMs, 'NO_PUBLISHED_INVENTORY_STATE_AT_OR_BEFORE_TIME');

  let live = null;
  let partial = new Map();
  let ambiguity = null;
  let directKeyframe = null;
  for (const event of events) {
    if (event.kind === 'ITEM_STATE_SNAPSHOT') {
      if (event.snapshot_scope === 'LIVE_STREAM_RESET') {
        live = event;
        partial = new Map();
        ambiguity = null;
      } else if (event.replay_time_ms === replayTimeMs) {
        directKeyframe = event;
      }
    } else if (event.kind === 'ITEM_STATE_SET') {
      if (live && !ambiguity) {
        live = {
          ...event,
          slots: setSlot(live.slots, event.entry, event.provenance),
          snapshot_scope: 'DIRECT_SLOT_SET_ON_LIVE_STATE',
          state_basis: 'COMPOSITE_AFTER_DIRECT_SLOT_SET',
        };
      } else {
        partial.set(event.entry.slot_index, {
          ...event.entry,
          state: 'DIRECT_SLOT_SET',
          provenance: clone(event.provenance),
        });
      }
    } else if (event.kind === 'ITEM_SWAP' || event.kind === 'INVENTORY_MUTATION_UNKNOWN') {
      live = null;
      partial = new Map();
      ambiguity = {
        replay_time_ms: event.replay_time_ms,
        reason: event.kind === 'ITEM_SWAP' ? 'SWAP_HAS_NO_PUBLISHED_ITEM_IDENTITY' : 'UNKNOWN_INVENTORY_MUTATION',
        provenance: event.provenance,
      };
      directKeyframe = null;
    }
  }
  if (directKeyframe) return stateFromFull(directKeyframe, entityId, replayTimeMs, 'DIRECT_SNAPSHOT');
  if (ambiguity) return unknownState(entityId, replayTimeMs, ambiguity.reason, ambiguity.provenance);
  if (live) {
    const composite = live.state_basis === 'COMPOSITE_AFTER_DIRECT_SLOT_SET';
    return stateFromFull(live, entityId, replayTimeMs, composite
      ? (live.replay_time_ms === replayTimeMs ? 'DERIVED_COMPOSITE_STATE' : 'CARRIED_FORWARD_COMPOSITE_STATE')
      : (live.replay_time_ms === replayTimeMs ? 'DIRECT_SNAPSHOT' : 'CARRIED_FORWARD'));
  }
  if (partial.size) {
    return {
      status: 'PARTIAL_DIRECT_SLOT_SET',
      exact_build: EXACT_BUILD,
      entity_id: entityId,
      replay_time_ms: replayTimeMs,
      observed_at_ms: Math.max(...events.filter((event) => event.kind === 'ITEM_STATE_SET').map((event) => event.replay_time_ms)),
      validity_interval: { start_ms: null, end_ms_exclusive: null, basis: 'DIRECT_SLOT_OBSERVATION_ONLY' },
      completeness: 'PARTIAL',
      slots: Array.from(partial.values()).sort((a, b) => a.slot_index - b.slot_index),
      provenance: clone(events.filter((event) => event.kind === 'ITEM_STATE_SET')
        .at(-1)?.provenance ?? null),
      known_limits: ['Only directly set slots are known; all other inventory slots are UNKNOWN.'],
    };
  }
  return unknownState(entityId, replayTimeMs, 'NO_PUBLISHED_INVENTORY_STATE_AT_OR_BEFORE_TIME');
}

module.exports = {
  EXACT_BUILD,
  SLOT_COUNT,
  assertSafeArtifactPath,
  inventoryStateIndex,
  inventory_state_at,
};
