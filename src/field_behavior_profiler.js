'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { formatOpcode, parseReplayFile, walkBlocks } = require('./rofl');

const FIELD_BEHAVIOR_SCHEMA_VERSION = 'FIELD_BEHAVIOR_PROFILE_V1';
const ANALYZER_VERSION = 'field-behavior-profiler-v1.2';
const TYPED_FIELD_SCHEMA_VERSION = 'FIELD_BEHAVIOR_TYPED_FIELD_SCHEMA_V1';
const RAW_FIELD_SCHEMA_VERSION = 'FIELD_BEHAVIOR_RAW_FIELD_SCHEMA_V1';
const ANCHOR_TYPES = Object.freeze([
  'damage',
  'heal',
  'shield',
  'death',
  'respawn',
  'level',
  'item_change',
  'cast',
  'ward',
  'movement',
]);
const FIELD_BEHAVIOR_COVERAGE_MATRIX = Object.freeze({
  value_representations: Object.freeze({
    float32: Object.freeze({ status: 'SUPPORTED_DIRECT_UNALIGNED_LE' }),
    float64: Object.freeze({ status: 'SUPPORTED_DIRECT_UNALIGNED_LE' }),
    int8: Object.freeze({ status: 'SUPPORTED_DIRECT' }),
    int16: Object.freeze({ status: 'SUPPORTED_DIRECT_UNALIGNED_LE' }),
    int32: Object.freeze({ status: 'SUPPORTED_DIRECT_UNALIGNED_LE' }),
    int64: Object.freeze({ status: 'SUPPORTED_EXACT_BIGINT_UNALIGNED_LE' }),
    uint32: Object.freeze({ status: 'SUPPORTED_DIRECT_UNALIGNED_LE' }),
    uint16: Object.freeze({ status: 'SUPPORTED_DIRECT_UNALIGNED_LE' }),
    uint8: Object.freeze({ status: 'SUPPORTED_DIRECT' }),
    uint64: Object.freeze({ status: 'SUPPORTED_EXACT_BIGINT_UNALIGNED_LE' }),
    bitfield: Object.freeze({
      status: 'SUPPORTED_ONE_BIT_AUTO_AND_CONFIGURED_CROSS_BYTE_LSB0',
      safety: 'Cross-byte ranges require an explicit field schema.',
    }),
    packed: Object.freeze({
      status: 'SUPPORTED_INTRA_BYTE_AUTO_AND_CONFIGURED_ARBITRARY_BITS_LSB0',
      safety: 'Arbitrary-width ranges require an explicit field schema; varints require a codec and remain unavailable.',
    }),
    identifiers: Object.freeze({
      status: 'SUPPORTED_CONFIGURED_TYPED_CANDIDATE_METRICS',
      available: 'Distinctness, repetition, entity-binding, transition, and per-Replay candidate metrics.',
      safety: 'Identifier type must be declared by an explicit decoded-field schema and never names network semantics.',
    }),
    vectors: Object.freeze({
      status: 'SUPPORTED_CONFIGURED_TYPED_COMPONENTS_AND_MAGNITUDE',
      available: 'Explicit decoded vector2/vector3/vector4 arrays or component paths receive component and magnitude summaries.',
      safety: 'No byte scan is interpreted as a vector without a schema; coordinate frames and semantic labels remain unavailable.',
    }),
    strings: Object.freeze({
      status: 'SUPPORTED_CONFIGURED_TYPED_VALUES_ONLY',
      safety: 'Arbitrary bytes are never decoded as text; missing schema is UNAVAILABLE_REQUIRES_EXPLICIT_SCHEMA.',
    }),
    hashes: Object.freeze({
      status: 'SUPPORTED_CONFIGURED_OPAQUE_VALUES_AND_DICTIONARY_COVERAGE',
      safety: 'No hash algorithm or semantic label is inferred. Dictionary matches are configuration provenance only.',
    }),
  }),
  anchors: Object.freeze(Object.fromEntries(ANCHOR_TYPES.map((type) => [type, Object.freeze({
    status: 'SUPPORTED_SAME_REPLAY_ENTITY_WINDOW_CANDIDATE_CORRELATION',
  })]))),
});

const PRIMITIVE_TYPES = Object.freeze({
  float32: Object.freeze({ size: 4, read: (buffer, offset) => buffer.readFloatLE(offset) }),
  float64: Object.freeze({ size: 8, read: (buffer, offset) => buffer.readDoubleLE(offset) }),
  int8: Object.freeze({ size: 1, read: (buffer, offset) => buffer.readInt8(offset) }),
  int16: Object.freeze({ size: 2, read: (buffer, offset) => buffer.readInt16LE(offset) }),
  int32: Object.freeze({ size: 4, read: (buffer, offset) => buffer.readInt32LE(offset) }),
  int64: Object.freeze({
    size: 8,
    exact_integer: true,
    read: (buffer, offset) => buffer.readBigInt64LE(offset),
  }),
  uint32: Object.freeze({ size: 4, read: (buffer, offset) => buffer.readUInt32LE(offset) }),
  uint16: Object.freeze({ size: 2, read: (buffer, offset) => buffer.readUInt16LE(offset) }),
  uint8: Object.freeze({ size: 1, read: (buffer, offset) => buffer.readUInt8(offset) }),
  uint64: Object.freeze({
    size: 8,
    exact_integer: true,
    read: (buffer, offset) => buffer.readBigUInt64LE(offset),
  }),
});

function strictCompare(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function cleanNumber(value) {
  if (!Number.isFinite(value)) return null;
  if (Object.is(value, -0)) return 0;
  return Number(value.toPrecision(12));
}

function ratio(numerator, denominator) {
  return denominator === 0 ? 0 : cleanNumber(numerator / denominator);
}

function integerOption(value, fallback, name, minimum = 1) {
  if (value === undefined || value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new TypeError(`${name} must be an integer >= ${minimum}`);
  }
  return parsed;
}

function safeNumericValue(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'bigint') return null;
  const projected = Number(value);
  return Number.isSafeInteger(projected) && BigInt(projected) === value ? projected : null;
}

class ExactIntegerSummary {
  constructor() {
    this.count = 0;
    this.zeroCount = 0;
    this.min = null;
    this.max = null;
  }

  observe(value) {
    if (typeof value !== 'bigint') return false;
    this.count += 1;
    if (value === 0n) this.zeroCount += 1;
    if (this.min === null || value < this.min) this.min = value;
    if (this.max === null || value > this.max) this.max = value;
    return true;
  }

  finalize() {
    return {
      status: this.count === 0 ? 'UNAVAILABLE_NO_EXACT_INTEGER_VALUES' : 'AVAILABLE_EXACT_DECIMAL',
      sample_count: this.count,
      range_decimal: {
        min: this.min === null ? null : this.min.toString(),
        max: this.max === null ? null : this.max.toString(),
        span: this.min === null ? null : (this.max - this.min).toString(),
      },
      zero_rate: this.count === 0 ? null : ratio(this.zeroCount, this.count),
      json_representation: 'DECIMAL_STRING_TO_AVOID_IEEE754_PRECISION_LOSS',
    };
  }
}

class ExactIntegerDeltaSummary extends ExactIntegerSummary {
  constructor() {
    super();
    this.negativeCount = 0;
    this.positiveCount = 0;
  }

  observe(value) {
    if (!super.observe(value)) return false;
    if (value < 0n) this.negativeCount += 1;
    else if (value > 0n) this.positiveCount += 1;
    return true;
  }

  finalize() {
    const summary = super.finalize();
    return {
      ...summary,
      transition_count: summary.sample_count,
      changed_count: this.negativeCount + this.positiveCount,
      change_rate: summary.sample_count === 0
        ? null : ratio(this.negativeCount + this.positiveCount, summary.sample_count),
      negative_count: this.negativeCount,
      zero_count: this.zeroCount,
      positive_count: this.positiveCount,
      negative_rate: summary.sample_count === 0 ? null : ratio(this.negativeCount, summary.sample_count),
      positive_rate: summary.sample_count === 0 ? null : ratio(this.positiveCount, summary.sample_count),
    };
  }
}

class ExactIntegerGroupAccumulator {
  constructor(identity) {
    this.identity = identity;
    this.stats = new ExactIntegerSummary();
    this.deltas = new ExactIntegerDeltaSummary();
    this.hasLast = false;
    this.last = 0n;
  }

  observe(value) {
    this.stats.observe(value);
    if (this.hasLast) this.deltas.observe(value - this.last);
    this.last = value;
    this.hasLast = true;
  }

  finalize() {
    const stats = this.stats.finalize();
    const deltas = this.deltas.finalize();
    return {
      ...this.identity,
      observation_count: stats.sample_count,
      range_decimal: stats.range_decimal,
      zero_rate: stats.zero_rate,
      transition_count: deltas.transition_count,
      change_rate: deltas.change_rate,
      stability_index: deltas.transition_count === 0 ? null : ratio(deltas.zero_count, deltas.transition_count),
    };
  }
}

function fnv1a(value) {
  let hash = 0x811c9dc5;
  for (const byte of Buffer.from(String(value), 'utf8')) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function mix32(value) {
  let mixed = value >>> 0;
  mixed ^= mixed >>> 16;
  mixed = Math.imul(mixed, 0x7feb352d) >>> 0;
  mixed ^= mixed >>> 15;
  mixed = Math.imul(mixed, 0x846ca68b) >>> 0;
  mixed ^= mixed >>> 16;
  return mixed >>> 0;
}

class DeterministicReservoir {
  constructor(limit = 512, seed = 0) {
    this.limit = integerOption(limit, 512, 'reservoir limit');
    this.seed = typeof seed === 'number' ? seed >>> 0 : fnv1a(seed);
    this.seen = 0;
    this.values = [];
  }

  observe(value) {
    this.seen += 1;
    if (this.values.length < this.limit) {
      this.values.push(value);
      return;
    }
    const choice = mix32((this.seen ^ this.seed) >>> 0) % this.seen;
    if (choice < this.limit) this.values[choice] = value;
  }

  median() {
    if (this.values.length === 0) return null;
    const sorted = [...this.values].sort((left, right) => left - right);
    const middle = Math.floor(sorted.length / 2);
    return cleanNumber(sorted.length % 2 === 1
      ? sorted[middle]
      : (sorted[middle - 1] + sorted[middle]) / 2);
  }
}

class RunningStats {
  constructor(options = {}) {
    this.count = 0;
    this.zeroCount = 0;
    this.min = Infinity;
    this.max = -Infinity;
    this.mean = 0;
    this.m2 = 0;
    this.reservoir = new DeterministicReservoir(
      options.medianSampleLimit ?? 512,
      options.seed ?? 0,
    );
  }

  observe(value) {
    if (!Number.isFinite(value)) return false;
    this.count += 1;
    if (value === 0) this.zeroCount += 1;
    this.min = Math.min(this.min, value);
    this.max = Math.max(this.max, value);
    const delta = value - this.mean;
    this.mean += delta / this.count;
    const deltaAfter = value - this.mean;
    this.m2 += delta * deltaAfter;
    this.reservoir.observe(value);
    return true;
  }

  finalize() {
    if (this.count === 0) {
      return {
        sample_count: 0,
        range: { min: null, max: null, span: null },
        mean: null,
        median: null,
        variance: null,
        variance_kind: 'population',
        zero_rate: null,
        median_sample_count: 0,
        median_is_approximate: false,
      };
    }
    return {
      sample_count: this.count,
      range: {
        min: cleanNumber(this.min),
        max: cleanNumber(this.max),
        span: cleanNumber(this.max - this.min),
      },
      mean: cleanNumber(this.mean),
      median: this.reservoir.median(),
      variance: cleanNumber(this.m2 / this.count),
      variance_kind: 'population',
      zero_rate: ratio(this.zeroCount, this.count),
      median_sample_count: this.reservoir.values.length,
      median_is_approximate: this.reservoir.seen > this.reservoir.values.length,
    };
  }
}

class DeltaStats {
  constructor(options = {}) {
    this.stats = new RunningStats(options);
    this.changedCount = 0;
    this.negativeCount = 0;
    this.positiveCount = 0;
    this.zeroCount = 0;
  }

  observe(delta) {
    if (!this.stats.observe(delta)) return false;
    if (delta < 0) this.negativeCount += 1;
    else if (delta > 0) this.positiveCount += 1;
    else this.zeroCount += 1;
    if (delta !== 0) this.changedCount += 1;
    return true;
  }

  finalize() {
    const summary = this.stats.finalize();
    return {
      transition_count: summary.sample_count,
      range: summary.range,
      mean: summary.mean,
      median: summary.median,
      variance: summary.variance,
      variance_kind: summary.variance_kind,
      negative_count: this.negativeCount,
      zero_count: this.zeroCount,
      positive_count: this.positiveCount,
      negative_rate: summary.sample_count === 0 ? null : ratio(this.negativeCount, summary.sample_count),
      zero_rate: summary.sample_count === 0 ? null : ratio(this.zeroCount, summary.sample_count),
      positive_rate: summary.sample_count === 0 ? null : ratio(this.positiveCount, summary.sample_count),
      median_sample_count: summary.median_sample_count,
      median_is_approximate: summary.median_is_approximate,
    };
  }
}

class PearsonAccumulator {
  constructor() {
    this.count = 0;
    this.sumX = 0;
    this.sumY = 0;
    this.sumXX = 0;
    this.sumYY = 0;
    this.sumXY = 0;
  }

  observe(x, y) {
    if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
    this.count += 1;
    this.sumX += x;
    this.sumY += y;
    this.sumXX += x * x;
    this.sumYY += y * y;
    this.sumXY += x * y;
    return true;
  }

  coefficient() {
    if (this.count < 2) return null;
    const numerator = (this.count * this.sumXY) - (this.sumX * this.sumY);
    const left = (this.count * this.sumXX) - (this.sumX * this.sumX);
    const right = (this.count * this.sumYY) - (this.sumY * this.sumY);
    const denominator = Math.sqrt(left * right);
    return denominator > 0 && Number.isFinite(denominator)
      ? cleanNumber(numerator / denominator)
      : null;
  }
}

function canonicalAnchorType(value) {
  if (value === null || value === undefined) return null;
  const normalized = String(value).trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    damage: 'damage',
    hero_damage: 'damage',
    heal: 'heal',
    healing: 'heal',
    shield: 'shield',
    shielding: 'shield',
    shield_apply: 'shield',
    shield_applied: 'shield',
    shield_damage: 'shield',
    shield_absorb: 'shield',
    death: 'death',
    hero_death: 'death',
    respawn: 'respawn',
    hero_respawn: 'respawn',
    level: 'level',
    level_up: 'level',
    level_transition: 'level',
    item: 'item_change',
    item_change: 'item_change',
    item_purchase: 'item_change',
    item_sell: 'item_change',
    item_undo: 'item_change',
    cast: 'cast',
    cast_spell: 'cast',
    spell_cast: 'cast',
    ability_cast: 'cast',
    ward: 'ward',
    ward_spawn: 'ward',
    ward_place: 'ward',
    ward_placed: 'ward',
    movement: 'movement',
    move: 'movement',
    path: 'movement',
    position: 'movement',
    position_update: 'movement',
  };
  return aliases[normalized] ?? null;
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function finiteNumber(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === '') continue;
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function normalizeAnchor(record, options = {}) {
  if (!record || typeof record !== 'object') return null;
  const eventType = canonicalAnchorType(firstDefined(
    options.defaultEventType,
    record.event_type,
    record.eventType,
    record.type,
    record.operation,
  ));
  if (!eventType) return null;
  const replayKey = firstDefined(
    record.replay_key,
    record.replay_sha256,
    record.source_sha256,
    record.raw_packet_ref?.replay_sha256,
    options.defaultReplayKey,
  );
  const replayTimeMs = finiteNumber(
    record.replay_time_ms,
    record.timestamp_ms,
    record.time_ms,
    Number.isFinite(Number(record.timestamp)) ? Number(record.timestamp) * 1000 : null,
  );
  let entityId;
  if (eventType === 'death') {
    entityId = firstDefined(record.victim_network_id, record.target_network_id);
  } else if (eventType === 'damage' || eventType === 'heal' || eventType === 'shield') {
    entityId = firstDefined(
      record.target_network_id,
      record.target_entity_id,
      record.entity_network_id,
      record.entity_id,
    );
  } else if (eventType === 'cast') {
    entityId = firstDefined(
      record.caster_network_id,
      record.source_network_id,
      record.owner_network_id,
      record.entity_network_id,
      record.entity_id,
    );
  } else if (eventType === 'ward') {
    entityId = firstDefined(
      record.owner_network_id,
      record.caster_network_id,
      record.source_network_id,
      record.entity_network_id,
      record.entity_id,
    );
  } else if (eventType === 'movement') {
    entityId = firstDefined(
      record.entity_network_id,
      record.source_network_id,
      record.champion_network_id,
      record.entity_id,
      record.raw_param,
    );
  } else {
    entityId = firstDefined(
      record.entity_network_id,
      record.champion_network_id,
      record.target_network_id,
      record.victim_network_id,
      record.owner_network_id,
      record.caster_network_id,
      record.source_network_id,
      record.entity_id,
      record.raw_param,
    );
  }
  const numericEntity = finiteNumber(entityId);
  if (replayKey === undefined || replayKey === null || replayTimeMs === null || numericEntity === null) {
    return null;
  }
  let amount = finiteNumber(
    record.amount,
    record.damage_amount,
    record.heal_amount,
    record.shield_amount,
    record.absorbed_amount,
    record.distance,
    record.distance_delta,
    record.movement_distance,
    record.stat_delta,
    record.value_delta,
    record.delta,
  );
  if (amount === null && eventType === 'level') {
    const before = finiteNumber(record.level_before);
    const after = finiteNumber(record.level_after, record.level);
    if (before !== null && after !== null) amount = after - before;
  }
  return {
    event_type: eventType,
    replay_key: String(replayKey),
    replay_time_ms: Math.round(replayTimeMs),
    entity_id: numericEntity,
    amount,
    champion: firstDefined(
      record.target_champion,
      record.victim_champion,
      record.champion,
    ) ?? null,
    evidence_grade: firstDefined(
      record.evidence_grade,
      record.semantic_status,
      record.confidence,
    ) ?? 'SOURCE_REPORTED',
  };
}

function normalizeAnchors(records, options = {}) {
  if (!Array.isArray(records)) throw new TypeError('anchors must be an array');
  const anchors = [];
  let rejectedCount = 0;
  for (const record of records) {
    const normalized = normalizeAnchor(record, options);
    if (normalized) anchors.push(normalized);
    else rejectedCount += 1;
  }
  anchors.sort((left, right) => strictCompare(left.replay_key, right.replay_key)
    || left.entity_id - right.entity_id
    || left.replay_time_ms - right.replay_time_ms
    || strictCompare(left.event_type, right.event_type));
  return { anchors, rejected_count: rejectedCount };
}

function lowerBound(rows, value) {
  let low = 0;
  let high = rows.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (rows[middle].replay_time_ms < value) low = middle + 1;
    else high = middle;
  }
  return low;
}

class AnchorIndex {
  constructor(anchors = []) {
    this.rows = [];
    this.bySeriesAndType = new Map();
    this.counts = Object.fromEntries(ANCHOR_TYPES.map((type) => [type, 0]));
    for (const anchor of anchors) {
      const normalized = normalizeAnchor(anchor) ?? anchor;
      if (!normalized || !ANCHOR_TYPES.includes(normalized.event_type)) continue;
      this.rows.push(normalized);
      this.counts[normalized.event_type] += 1;
      const key = this.key(normalized.replay_key, normalized.entity_id, normalized.event_type);
      if (!this.bySeriesAndType.has(key)) this.bySeriesAndType.set(key, []);
      this.bySeriesAndType.get(key).push(normalized);
    }
    for (const rows of this.bySeriesAndType.values()) {
      rows.sort((left, right) => left.replay_time_ms - right.replay_time_ms);
    }
  }

  key(replayKey, entityId, eventType) {
    return `${String(replayKey)}\u0000${String(entityId)}\u0000${eventType}`;
  }

  query(replayKey, entityId, eventType, beforeTimeMs, afterTimeMs, windowMs) {
    const result = { count: 0, numeric_count: 0, amount_sum: 0 };
    if (!Number.isFinite(beforeTimeMs) || !Number.isFinite(afterTimeMs)
        || afterTimeMs < beforeTimeMs || afterTimeMs - beforeTimeMs > windowMs * 2) {
      return result;
    }
    const rows = this.bySeriesAndType.get(this.key(replayKey, entityId, eventType)) ?? [];
    const start = lowerBound(rows, beforeTimeMs);
    for (let index = start; index < rows.length; index += 1) {
      const row = rows[index];
      if (row.replay_time_ms > afterTimeMs) break;
      if (row.replay_time_ms <= beforeTimeMs) continue;
      if (row.replay_time_ms - beforeTimeMs > windowMs
          || afterTimeMs - row.replay_time_ms > windowMs) continue;
      result.count += 1;
      if (Number.isFinite(row.amount)) {
        result.numeric_count += 1;
        result.amount_sum += row.amount;
      }
    }
    return result;
  }

  inventory() {
    return {
      total_anchor_count: this.rows.length,
      counts: { ...this.counts },
      matching_policy: 'SAME_REPLAY_AND_ENTITY; EVENT_MUST_FALL_BETWEEN_CONSECUTIVE_SAMPLED_OBSERVATIONS; BOTH_SIDES_WITHIN_WINDOW',
    };
  }
}

class AnchorCorrelationAccumulator {
  constructor(eventType, anchorCount, options = {}) {
    this.eventType = eventType;
    this.anchorCount = anchorCount;
    this.transitionCorrelation = new PearsonAccumulator();
    this.amountCorrelation = new PearsonAccumulator();
    this.eventDeltas = new DeltaStats({
      medianSampleLimit: options.medianSampleLimit,
      seed: `${options.seed ?? ''}:${eventType}:event-delta`,
    });
    this.eligibleTransitionCount = 0;
    this.eventTransitionCount = 0;
    this.matchedAnchorCount = 0;
    this.expectedDirectionMatchCount = 0;
  }

  expectedDirectionMatches(delta) {
    if (this.eventType === 'damage' || this.eventType === 'death') return delta < 0;
    if (this.eventType === 'heal' || this.eventType === 'respawn') return delta > 0;
    return delta !== 0;
  }

  expectedDirectionPolicy() {
    if (this.eventType === 'damage' || this.eventType === 'death') return 'NEGATIVE_DELTA';
    if (this.eventType === 'heal' || this.eventType === 'respawn') return 'POSITIVE_DELTA';
    return 'NONZERO_DELTA_DIRECTION_AGNOSTIC';
  }

  observe(delta, aggregate) {
    this.eligibleTransitionCount += 1;
    const predictor = aggregate.numeric_count > 0 ? aggregate.amount_sum : aggregate.count;
    this.transitionCorrelation.observe(predictor, delta);
    if (aggregate.count === 0) return;
    this.eventTransitionCount += 1;
    this.matchedAnchorCount += aggregate.count;
    this.eventDeltas.observe(delta);
    if (this.expectedDirectionMatches(delta)) this.expectedDirectionMatchCount += 1;
    if (aggregate.numeric_count > 0) this.amountCorrelation.observe(aggregate.amount_sum, delta);
  }

  finalize(windowMs) {
    let status = 'AVAILABLE_CANDIDATE_CORRELATION';
    if (this.anchorCount === 0) status = 'UNAVAILABLE_NO_ANCHORS';
    else if (this.eventTransitionCount === 0) status = 'INSUFFICIENT_MATCHED_TRANSITIONS';
    else if (this.eventTransitionCount < 2) status = 'INSUFFICIENT_SAMPLE';
    return {
      status,
      evidence_grade: 'CANDIDATE',
      semantic_claim: null,
      anchor_count: this.anchorCount,
      matched_anchor_count: this.matchedAnchorCount,
      eligible_transition_count: this.eligibleTransitionCount,
      event_transition_count: this.eventTransitionCount,
      coefficient: this.transitionCorrelation.coefficient(),
      coefficient_basis: 'PEARSON_R_OF_FIELD_DELTA_VS_SUMMED_ANCHOR_AMOUNT_OR_EVENT_COUNT_PER_ELIGIBLE_TRANSITION',
      amount_correlation: this.amountCorrelation.coefficient(),
      expected_direction_rate: this.eventTransitionCount === 0
        ? null : ratio(this.expectedDirectionMatchCount, this.eventTransitionCount),
      expected_direction_policy: this.expectedDirectionPolicy(),
      event_delta_distribution: this.eventDeltas.finalize(),
      anchor_window_ms: windowMs,
      warning: 'Correlation and expected-direction rate are candidate-ranking diagnostics, not field semantics.',
    };
  }
}

function primitiveFieldDefinitions(maxPayloadLength, options = {}) {
  const stride = integerOption(options.offsetStride, 1, 'offsetStride');
  const requested = options.types ?? Object.keys(PRIMITIVE_TYPES);
  const definitions = [];
  for (const type of requested) {
    const descriptor = PRIMITIVE_TYPES[type];
    if (!descriptor) throw new TypeError(`unsupported primitive type: ${type}`);
    for (let offset = 0; offset + descriptor.size <= maxPayloadLength; offset += stride) {
      definitions.push({
        field_id: `${type}@${offset}`,
        kind: 'primitive',
        offset,
        type,
        byte_length: descriptor.size,
        bit_offset: null,
        bit_width: null,
        endianness: descriptor.size === 1 ? 'not_applicable' : 'little',
        exact_integer: descriptor.exact_integer === true,
        configured: false,
      });
    }
  }
  return definitions;
}

function bitAndPackedFieldDefinitions(offsets) {
  const definitions = [];
  for (const offset of [...new Set(offsets)].sort((left, right) => left - right)) {
    for (let bitOffset = 0; bitOffset < 8; bitOffset += 1) {
      definitions.push({
        field_id: `bitfield@${offset}:${bitOffset}:1`,
        kind: 'bitfield_candidate',
        offset,
        type: 'bitfield_candidate',
        byte_length: 1,
        bit_offset: bitOffset,
        bit_width: 1,
        endianness: 'not_applicable',
        signed: false,
        configured: false,
      });
    }
    for (let bitOffset = 0; bitOffset < 8; bitOffset += 2) {
      definitions.push({
        field_id: `packed_uint2@${offset}:${bitOffset}:2`,
        kind: 'packed_field_candidate',
        offset,
        type: 'packed_uint2_candidate',
        byte_length: 1,
        bit_offset: bitOffset,
        bit_width: 2,
        endianness: 'not_applicable',
        signed: false,
        configured: false,
      });
    }
    for (let bitOffset = 0; bitOffset < 8; bitOffset += 4) {
      definitions.push({
        field_id: `packed_uint4@${offset}:${bitOffset}:4`,
        kind: 'packed_field_candidate',
        offset,
        type: 'packed_uint4_candidate',
        byte_length: 1,
        bit_offset: bitOffset,
        bit_width: 4,
        endianness: 'not_applicable',
        signed: false,
        configured: false,
      });
    }
  }
  return definitions;
}

function configuredRawFieldDefinitions(schemaOrFields) {
  if (schemaOrFields === undefined || schemaOrFields === null) return [];
  if (!Array.isArray(schemaOrFields) && schemaOrFields.schema !== RAW_FIELD_SCHEMA_VERSION) {
    throw new Error(`configured raw field schema must declare ${RAW_FIELD_SCHEMA_VERSION}`);
  }
  const fields = Array.isArray(schemaOrFields) ? schemaOrFields : schemaOrFields.fields;
  if (!Array.isArray(fields)) throw new TypeError('configured raw field schema requires a fields array');
  const definitions = [];
  const identifiers = new Set();
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (!field || typeof field !== 'object') throw new TypeError(`configured field ${index} must be an object`);
    const offset = Number(field.offset);
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new TypeError(`configured field ${index} requires a non-negative integer offset`);
    }
    const declaredType = String(field.type ?? '').trim().toLowerCase();
    let definition;
    if (PRIMITIVE_TYPES[declaredType]) {
      const descriptor = PRIMITIVE_TYPES[declaredType];
      definition = {
        field_id: field.field_id ?? `${declaredType}@${offset}:configured`,
        kind: 'primitive',
        offset,
        type: declaredType,
        byte_length: descriptor.size,
        bit_offset: null,
        bit_width: null,
        endianness: descriptor.size === 1 ? 'not_applicable' : 'little',
        exact_integer: descriptor.exact_integer === true,
      };
    } else if (['bitfield', 'packed_bits', 'packed'].includes(declaredType)) {
      const bitOffset = Number(field.bit_offset ?? 0);
      const bitWidth = Number(field.bit_width);
      if (!Number.isSafeInteger(bitOffset) || bitOffset < 0) {
        throw new TypeError(`configured field ${index} bit_offset must be a non-negative integer`);
      }
      if (!Number.isSafeInteger(bitWidth) || bitWidth < 1 || bitWidth > 64) {
        throw new TypeError(`configured field ${index} bit_width must be in [1, 64]`);
      }
      const signed = field.signed === true;
      definition = {
        field_id: field.field_id
          ?? `${signed ? 'packed_int' : 'packed_uint'}${bitWidth}@${offset}:${bitOffset}:configured`,
        kind: bitWidth === 1 ? 'bitfield_candidate' : 'packed_field_candidate',
        offset,
        type: bitWidth === 1
          ? 'configured_bitfield_candidate'
          : `configured_packed_${signed ? 'int' : 'uint'}${bitWidth}_candidate`,
        byte_length: Math.ceil((bitOffset + bitWidth) / 8),
        bit_offset: bitOffset,
        bit_width: bitWidth,
        endianness: 'little_lsb0',
        signed,
        exact_integer: bitWidth > 53,
      };
    } else {
      throw new TypeError(`configured field ${index} has unsupported raw type: ${declaredType || '(missing)'}`);
    }
    definition.configured = true;
    definition.schema_index = index;
    definition.semantic_claim = null;
    definition.configuration_note = field.note ?? null;
    if (typeof definition.field_id !== 'string' || definition.field_id.length === 0) {
      throw new TypeError(`configured field ${index} requires a non-empty field_id`);
    }
    if (identifiers.has(definition.field_id)) throw new Error(`duplicate configured field_id: ${definition.field_id}`);
    identifiers.add(definition.field_id);
    definitions.push(definition);
  }
  return definitions;
}

function readPackedBitsLE(payload, offset, bitOffset, bitWidth, signed = false) {
  if (!Buffer.isBuffer(payload)) throw new TypeError('packet payload must be a Buffer');
  if (!Number.isSafeInteger(offset) || offset < 0
      || !Number.isSafeInteger(bitOffset) || bitOffset < 0
      || !Number.isSafeInteger(bitWidth) || bitWidth < 1 || bitWidth > 64) {
    throw new TypeError('packed bit read requires offset >= 0, bit_offset >= 0, and bit_width in [1, 64]');
  }
  const byteLength = Math.ceil((bitOffset + bitWidth) / 8);
  if (offset + byteLength > payload.length) return null;
  let carrier = 0n;
  for (let index = 0; index < byteLength; index += 1) {
    carrier |= BigInt(payload[offset + index]) << BigInt(index * 8);
  }
  const width = BigInt(bitWidth);
  const mask = (1n << width) - 1n;
  let value = (carrier >> BigInt(bitOffset)) & mask;
  if (signed && (value & (1n << (width - 1n))) !== 0n) value -= 1n << width;
  const projected = safeNumericValue(value);
  return projected === null ? value : projected;
}

function readField(payload, definition) {
  if (!Buffer.isBuffer(payload)) throw new TypeError('packet payload must be a Buffer');
  if (definition.offset < 0 || definition.offset + definition.byte_length > payload.length) return null;
  if (definition.kind === 'primitive') {
    return PRIMITIVE_TYPES[definition.type].read(payload, definition.offset);
  }
  return readPackedBitsLE(
    payload,
    definition.offset,
    definition.bit_offset,
    definition.bit_width,
    definition.signed === true,
  );
}

function seriesKey(record) {
  return `${record.replay_key}\u0000${String(record.entity_id)}`;
}

class BasicFieldAccumulator {
  constructor(definition, options = {}) {
    this.definition = definition;
    this.totalAttempts = 0;
    this.invalidCount = 0;
    this.validObservationCount = 0;
    this.stats = new RunningStats({
      medianSampleLimit: Math.min(options.medianSampleLimit ?? 128, 128),
      seed: `${definition.field_id}:preliminary`,
    });
    this.deltas = new DeltaStats({
      medianSampleLimit: Math.min(options.medianSampleLimit ?? 128, 128),
      seed: `${definition.field_id}:preliminary-delta`,
    });
    this.lastBySeries = new Map();
    this.exactStats = new ExactIntegerSummary();
    this.exactDeltas = new ExactIntegerDeltaSummary();
    this.lastExactBySeries = new Map();
  }

  observe(record, value) {
    this.totalAttempts += 1;
    if (typeof value === 'bigint') {
      this.validObservationCount += 1;
      this.exactStats.observe(value);
      const key = seriesKey(record);
      if (this.lastExactBySeries.has(key)) {
        this.exactDeltas.observe(value - this.lastExactBySeries.get(key));
      }
      this.lastExactBySeries.set(key, value);
      const projected = safeNumericValue(value);
      if (projected !== null) {
        this.stats.observe(projected);
        if (this.lastBySeries.has(key)) this.deltas.observe(projected - this.lastBySeries.get(key));
        this.lastBySeries.set(key, projected);
      }
      return;
    }
    if (!Number.isFinite(value)) {
      this.invalidCount += 1;
      return;
    }
    this.validObservationCount += 1;
    this.stats.observe(value);
    const key = seriesKey(record);
    if (this.lastBySeries.has(key)) this.deltas.observe(value - this.lastBySeries.get(key));
    this.lastBySeries.set(key, value);
  }

  finalize(routeRecordCount) {
    const stats = this.stats.finalize();
    const deltas = this.deltas.finalize();
    const exactStats = this.exactStats.finalize();
    const exactDeltas = this.exactDeltas.finalize();
    const coverageRate = ratio(this.totalAttempts, routeRecordCount);
    const validRate = ratio(this.validObservationCount, this.totalAttempts);
    const changeRate = exactDeltas.transition_count > 0
      ? exactDeltas.change_rate
      : deltas.transition_count === 0
        ? null : ratio(this.deltas.changedCount, deltas.transition_count);
    let score = 0;
    score += 25 * coverageRate;
    score += 25 * validRate;
    const exactVariable = exactStats.range_decimal.min !== null
      && exactStats.range_decimal.min !== exactStats.range_decimal.max;
    if ((stats.range.span !== null && stats.range.span > 0) || exactVariable) score += 15;
    if (changeRate !== null && changeRate > 0) {
      score += 10 + (10 * (1 - Math.abs(changeRate - 0.5) / 0.5));
    }
    const zeroRate = exactStats.sample_count > 0 ? exactStats.zero_rate : stats.zero_rate;
    if (zeroRate !== null && zeroRate < 1) score += 10;
    const maximumAbsolute = stats.range.min === null ? null : Math.max(
      Math.abs(stats.range.min),
      Math.abs(stats.range.max),
    );
    if (this.definition.type.startsWith('float') && maximumAbsolute !== null) {
      if (maximumAbsolute > 0 && maximumAbsolute < 1e-30) score -= 30;
      else if (maximumAbsolute > 1e12) score -= 20;
      else if (maximumAbsolute >= 1e-4 && maximumAbsolute <= 1e7) score += 10;
    } else if (maximumAbsolute !== null && maximumAbsolute <= 1e6) {
      score += 5;
    }
    if (this.definition.offset % this.definition.byte_length === 0) score += 2;
    return {
      definition: this.definition,
      observation_count: this.validObservationCount,
      numeric_observation_count: stats.sample_count,
      attempted_observation_count: this.totalAttempts,
      invalid_value_count: this.invalidCount,
      coverage_rate: coverageRate,
      valid_rate: validRate,
      range: stats.range,
      exact_integer_statistics: exactStats.sample_count > 0 ? {
        ...exactStats,
        delta_distribution: exactDeltas,
      } : null,
      zero_rate: zeroRate,
      change_rate: changeRate,
      preliminary_score: cleanNumber(Math.max(0, Math.min(100, score))),
    };
  }
}

class GroupAccumulator {
  constructor(identity, options = {}) {
    this.identity = identity;
    this.stats = new RunningStats(options);
    this.deltas = new DeltaStats(options);
    this.trajectoryLimit = Number.isSafeInteger(options.trajectoryLimit)
      && options.trajectoryLimit > 0 ? options.trajectoryLimit : 0;
    this.trajectorySeed = fnv1a(options.seed ?? JSON.stringify(identity));
    this.trajectorySeen = 0;
    this.trajectory = [];
  }

  observe(value, delta = null, observation = null) {
    this.stats.observe(value);
    if (delta !== null) this.deltas.observe(delta);
    if (this.trajectoryLimit > 0 && observation) {
      this.trajectorySeen += 1;
      const point = {
        replay_time_ms: observation.replay_time_ms,
        sequence: observation.sequence,
        value: cleanNumber(value),
      };
      if (this.trajectory.length < this.trajectoryLimit) this.trajectory.push(point);
      else {
        const choice = mix32((this.trajectorySeen ^ this.trajectorySeed) >>> 0)
          % this.trajectorySeen;
        if (choice < this.trajectoryLimit) this.trajectory[choice] = point;
      }
    }
  }

  finalize() {
    const stats = this.stats.finalize();
    const deltas = this.deltas.finalize();
    const trajectory = [...this.trajectory].sort((left, right) => (
      (left.replay_time_ms ?? Number.MAX_SAFE_INTEGER)
        - (right.replay_time_ms ?? Number.MAX_SAFE_INTEGER)
      || left.sequence - right.sequence
    ));
    const result = {
      ...this.identity,
      observation_count: stats.sample_count,
      range: stats.range,
      mean: stats.mean,
      median: stats.median,
      variance: stats.variance,
      zero_rate: stats.zero_rate,
      transition_count: deltas.transition_count,
      change_rate: deltas.transition_count === 0
        ? null : ratio(this.deltas.changedCount, deltas.transition_count),
      stability_index: deltas.transition_count === 0
        ? null : ratio(deltas.zero_count, deltas.transition_count),
    };
    if (this.trajectoryLimit > 0) {
      result.trajectory_observation_count = this.trajectorySeen;
      result.trajectory_sample_count = trajectory.length;
      result.trajectory_is_sampled = this.trajectorySeen > trajectory.length;
      result.trajectory = trajectory;
    }
    return result;
  }
}

class FieldAccumulator {
  constructor(definition, anchorIndex, options = {}) {
    this.definition = definition;
    this.anchorIndex = anchorIndex;
    this.anchorWindowMs = options.anchorWindowMs ?? 5000;
    this.maxReportedEntities = options.maxReportedEntities ?? 100;
    this.maxTrajectoryPointsPerEntity = options.maxTrajectoryPointsPerEntity ?? 0;
    this.totalAttempts = 0;
    this.invalidCount = 0;
    this.validObservationCount = 0;
    this.unsafeIntegerObservationCount = 0;
    this.unsafeIntegerDeltaCount = 0;
    this.outOfOrderCount = 0;
    this.stats = new RunningStats({
      medianSampleLimit: options.medianSampleLimit,
      seed: definition.field_id,
    });
    this.deltas = new DeltaStats({
      medianSampleLimit: options.medianSampleLimit,
      seed: `${definition.field_id}:delta`,
    });
    this.lastBySeries = new Map();
    this.exactStats = new ExactIntegerSummary();
    this.exactDeltas = new ExactIntegerDeltaSummary();
    this.lastExactBySeries = new Map();
    this.exactEntityGroups = new Map();
    this.exactChampionGroups = new Map();
    this.entityGroups = new Map();
    this.championGroups = new Map();
    this.correlations = Object.fromEntries(ANCHOR_TYPES.map((eventType) => [eventType,
      new AnchorCorrelationAccumulator(eventType, anchorIndex.counts[eventType], {
        medianSampleLimit: options.medianSampleLimit,
        seed: definition.field_id,
      })]));
  }

  entityGroup(record) {
    const key = seriesKey(record);
    if (!this.entityGroups.has(key)) {
      this.entityGroups.set(key, new GroupAccumulator({
        replay_key: record.replay_key,
        entity_id: record.entity_id,
        champion: record.champion ?? null,
      }, {
        seed: `${this.definition.field_id}:${key}`,
        medianSampleLimit: 128,
        trajectoryLimit: this.maxTrajectoryPointsPerEntity,
      }));
    }
    return this.entityGroups.get(key);
  }

  championGroup(record) {
    if (!record.champion) return null;
    const key = String(record.champion);
    if (!this.championGroups.has(key)) {
      this.championGroups.set(key, new GroupAccumulator({ champion: key }, {
        seed: `${this.definition.field_id}:champion:${key}`,
        medianSampleLimit: 256,
      }));
    }
    return this.championGroups.get(key);
  }

  exactEntityGroup(record) {
    const key = seriesKey(record);
    if (!this.exactEntityGroups.has(key)) {
      this.exactEntityGroups.set(key, new ExactIntegerGroupAccumulator({
        replay_key: record.replay_key,
        entity_id: record.entity_id,
        champion: record.champion ?? null,
      }));
    }
    return this.exactEntityGroups.get(key);
  }

  exactChampionGroup(record) {
    if (!record.champion) return null;
    const key = String(record.champion);
    if (!this.exactChampionGroups.has(key)) {
      this.exactChampionGroups.set(key, new ExactIntegerGroupAccumulator({ champion: key }));
    }
    return this.exactChampionGroups.get(key);
  }

  observeAnchorCorrelations(record, previous, delta) {
    const timesComparable = Number.isFinite(previous.replay_time_ms)
      && Number.isFinite(record.replay_time_ms);
    if (timesComparable && record.replay_time_ms < previous.replay_time_ms) {
      this.outOfOrderCount += 1;
      return false;
    }
    if (timesComparable
        && record.replay_time_ms - previous.replay_time_ms <= this.anchorWindowMs * 2) {
      for (const eventType of ANCHOR_TYPES) {
        const aggregate = this.anchorIndex.query(
          record.replay_key,
          record.entity_id,
          eventType,
          previous.replay_time_ms,
          record.replay_time_ms,
          this.anchorWindowMs,
        );
        this.correlations[eventType].observe(delta, aggregate);
      }
    }
    return true;
  }

  observe(record, value) {
    this.totalAttempts += 1;
    if (typeof value === 'bigint') {
      this.validObservationCount += 1;
      this.exactStats.observe(value);
      const key = seriesKey(record);
      const previous = this.lastExactBySeries.get(key) ?? null;
      let numericDelta = null;
      if (previous) {
        const exactDelta = value - previous.value;
        this.exactDeltas.observe(exactDelta);
        numericDelta = safeNumericValue(exactDelta);
        if (numericDelta === null) this.unsafeIntegerDeltaCount += 1;
        else {
          this.deltas.observe(numericDelta);
          this.observeAnchorCorrelations(record, previous, numericDelta);
        }
      }
      this.exactEntityGroup(record).observe(value);
      const exactChampion = this.exactChampionGroup(record);
      if (exactChampion) exactChampion.observe(value);
      const projected = safeNumericValue(value);
      if (projected === null) this.unsafeIntegerObservationCount += 1;
      else {
        this.stats.observe(projected);
        this.entityGroup(record).observe(projected, numericDelta, {
          replay_time_ms: record.replay_time_ms,
          sequence: record.sequence,
        });
        const champion = this.championGroup(record);
        if (champion) champion.observe(projected, numericDelta);
      }
      this.lastExactBySeries.set(key, {
        value,
        replay_time_ms: record.replay_time_ms,
      });
      return;
    }
    if (!Number.isFinite(value)) {
      this.invalidCount += 1;
      return;
    }
    this.validObservationCount += 1;
    this.stats.observe(value);
    const key = seriesKey(record);
    const previous = this.lastBySeries.get(key) ?? null;
    let delta = null;
    if (previous) {
      if (this.observeAnchorCorrelations(record, previous, value - previous.value)) {
        delta = value - previous.value;
        this.deltas.observe(delta);
      }
    }
    this.entityGroup(record).observe(value, delta, {
      replay_time_ms: record.replay_time_ms,
      sequence: record.sequence,
    });
    const champion = this.championGroup(record);
    if (champion) champion.observe(value, delta);
    this.lastBySeries.set(key, {
      value,
      replay_time_ms: record.replay_time_ms,
    });
  }

  finalize(routeRecordCount) {
    const stats = this.stats.finalize();
    const deltas = this.deltas.finalize();
    const exactStats = this.exactStats.finalize();
    const exactDeltas = this.exactDeltas.finalize();
    const numericEntityRows = [...this.entityGroups.values()]
      .map((group) => group.finalize())
      .sort((left, right) => right.observation_count - left.observation_count
        || strictCompare(left.replay_key, right.replay_key)
        || strictCompare(left.entity_id, right.entity_id));
    const exactEntityRows = [...this.exactEntityGroups.values()]
      .map((group) => group.finalize())
      .sort((left, right) => right.observation_count - left.observation_count
        || strictCompare(left.replay_key, right.replay_key)
        || strictCompare(left.entity_id, right.entity_id));
    const entityRows = exactStats.sample_count > 0 ? exactEntityRows : numericEntityRows;
    const reportedEntities = entityRows.slice(0, this.maxReportedEntities);
    const comparableEntities = entityRows.filter((row) => row.stability_index !== null);
    const numericChampionRows = [...this.championGroups.values()]
      .map((group) => group.finalize())
      .sort((left, right) => strictCompare(left.champion, right.champion));
    const exactChampionRows = [...this.exactChampionGroups.values()]
      .map((group) => group.finalize())
      .sort((left, right) => strictCompare(left.champion, right.champion));
    const championRows = exactStats.sample_count > 0 ? exactChampionRows : numericChampionRows;
    const correlations = Object.fromEntries(ANCHOR_TYPES.map((eventType) => [
      `correlation_with_${eventType}`,
      this.correlations[eventType].finalize(this.anchorWindowMs),
    ]));
    const field = {
      field_id: this.definition.field_id,
      kind: this.definition.kind,
      offset: this.definition.offset,
      type: this.definition.type,
      byte_length: this.definition.byte_length,
      bit_offset: this.definition.bit_offset,
      bit_width: this.definition.bit_width,
      endianness: this.definition.endianness,
      signed: this.definition.signed ?? null,
      configured: this.definition.configured === true,
      configuration_note: this.definition.configuration_note ?? null,
      observation_count: this.validObservationCount,
      numeric_observation_count: stats.sample_count,
      attempted_observation_count: this.totalAttempts,
      invalid_value_count: this.invalidCount,
      unsafe_integer_observation_count: this.unsafeIntegerObservationCount,
      coverage_rate: ratio(this.totalAttempts, routeRecordCount),
      valid_rate: ratio(this.validObservationCount, this.totalAttempts),
      range: stats.range,
      mean: stats.mean,
      median: stats.median,
      variance: stats.variance,
      variance_kind: stats.variance_kind,
      zero_rate: stats.zero_rate,
      change_rate: exactDeltas.transition_count > 0
        ? exactDeltas.change_rate
        : deltas.transition_count === 0
          ? null : ratio(this.deltas.changedCount, deltas.transition_count),
      delta_distribution: deltas,
      exact_integer_statistics: exactStats.sample_count === 0 ? {
        status: 'NOT_APPLICABLE_NON_64_BIT_VALUE',
      } : {
        ...exactStats,
        safe_numeric_projection_count: stats.sample_count,
        unsafe_numeric_projection_count: this.unsafeIntegerObservationCount,
        numeric_statistics_status: this.unsafeIntegerObservationCount === 0
          ? 'AVAILABLE_ALL_VALUES_EXACTLY_PROJECTED_TO_SAFE_INTEGER'
          : stats.sample_count === 0
            ? 'NOT_COMPUTABLE_WITHOUT_IEEE754_PRECISION_LOSS'
            : 'PARTIAL_SAFE_INTEGER_PROJECTION',
        delta_distribution: exactDeltas,
        unsafe_numeric_delta_count: this.unsafeIntegerDeltaCount,
      },
      per_entity_stability: {
        status: entityRows.length === 0 ? 'UNAVAILABLE' : 'AVAILABLE_DESCRIPTIVE_ONLY',
        entity_series_count: entityRows.length,
        comparable_entity_series_count: comparableEntities.length,
        reported_entity_series_count: reportedEntities.length,
        truncated: reportedEntities.length < entityRows.length,
        mean_stability_index: comparableEntities.length === 0 ? null : cleanNumber(
          comparableEntities.reduce((sum, row) => sum + row.stability_index, 0)
            / comparableEntities.length,
        ),
        entities: reportedEntities,
        value_representation: exactStats.sample_count > 0 ? 'EXACT_DECIMAL_STRING' : 'NUMBER',
        warning: 'Stability is the unchanged-transition rate in sampled protocol values; it is not behavioral meaning.',
      },
      per_champion_behavior: {
        status: championRows.length === 0
          ? 'UNAVAILABLE_NO_CHAMPION_MAPPING'
          : 'AVAILABLE_DESCRIPTIVE_ONLY',
        champion_count: championRows.length,
        champions: championRows,
        value_representation: exactStats.sample_count > 0 ? 'EXACT_DECIMAL_STRING' : 'NUMBER',
        warning: 'Champion grouping is descriptive packet-field behavior only and does not establish a semantic field.',
      },
      ...correlations,
      out_of_order_transition_count: this.outOfOrderCount,
      evidence_grade: 'CANDIDATE',
      semantic_status: 'UNKNOWN_FIELD_CANDIDATE',
      semantic_claim: null,
      heuristic_only: true,
      heuristic_warning: 'The score ranks candidates only; it cannot promote or name a semantic field.',
    };
    field.heuristic_candidate_score = heuristicCandidateScore(field);
    return field;
  }
}

function heuristicCandidateScore(field) {
  let score = 0;
  score += 20 * (field.coverage_rate ?? 0);
  score += 20 * (field.valid_rate ?? 0);
  const exactRange = field.exact_integer_statistics?.range_decimal;
  if ((field.range.span !== null && field.range.span > 0)
      || (exactRange?.min !== null && exactRange?.min !== exactRange?.max)) score += 15;
  if (field.change_rate !== null && field.change_rate > 0) {
    score += 10 + (10 * (1 - Math.abs(field.change_rate - 0.5) / 0.5));
  }
  if (field.per_entity_stability.comparable_entity_series_count > 0) score += 5;
  const coefficients = ANCHOR_TYPES.map((eventType) => field[`correlation_with_${eventType}`]?.coefficient)
    .filter(Number.isFinite)
    .map(Math.abs);
  if (coefficients.length > 0) score += 15 * Math.max(...coefficients);
  const maximumAbsolute = field.range.min === null ? null : Math.max(
    Math.abs(field.range.min),
    Math.abs(field.range.max),
  );
  if (field.type.startsWith('float') && maximumAbsolute !== null) {
    if (maximumAbsolute > 0 && maximumAbsolute < 1e-30) score -= 30;
    else if (maximumAbsolute > 1e12) score -= 20;
    else if (maximumAbsolute >= 1e-4 && maximumAbsolute <= 1e7) score += 10;
  } else if (maximumAbsolute !== null && maximumAbsolute <= 1e6) {
    score += 5;
  }
  if (field.offset % field.byte_length === 0) score += 2;
  if (field.invalid_value_count > field.observation_count) score -= 20;
  return cleanNumber(Math.max(0, Math.min(100, score)));
}

function normalizePacketRecord(record, sequence = 0) {
  if (!record || typeof record !== 'object') throw new TypeError('packet record must be an object');
  const payload = Buffer.isBuffer(record.payload)
    ? record.payload
    : typeof firstDefined(record.raw_payload_hex, record.payload_hex) === 'string'
      ? Buffer.from(firstDefined(record.raw_payload_hex, record.payload_hex), 'hex')
      : null;
  if (!payload) throw new TypeError('packet record requires payload Buffer or raw_payload_hex');
  const packetId = finiteNumber(record.packet_id, record.packet_discriminator);
  if (!Number.isSafeInteger(packetId) || packetId < 0 || packetId > 0xffff) {
    throw new TypeError('packet record requires an unsigned 16-bit packet_id');
  }
  const replayKey = firstDefined(
    record.replay_key,
    record.replay_sha256,
    record.source_sha256,
    record.raw_packet_ref?.replay_sha256,
    record.replay_path,
    record.source_path,
  );
  if (replayKey === undefined || replayKey === null) {
    throw new TypeError('packet record requires replay provenance key or SHA-256');
  }
  const entityId = finiteNumber(record.entity_id, record.entity_network_id, record.raw_param, record.param);
  return {
    build: firstDefined(record.build, record.game_version, record.replay_version) ?? null,
    packet_id: packetId,
    payload,
    payload_length: payload.length,
    replay_key: String(replayKey),
    replay_time_ms: finiteNumber(record.replay_time_ms, record.timestamp_ms),
    entity_id: entityId ?? 'PACKET_SCOPE',
    champion: firstDefined(record.champion, record.target_champion, record.entity_champion) ?? null,
    participant_id: finiteNumber(record.participant_id, record.target_participant_id),
    chunk_stream: firstDefined(record.chunk_stream, record.stream) ?? null,
    sequence: Number.isSafeInteger(record.sequence) ? record.sequence : sequence,
    source_path: firstDefined(record.replay_path, record.source_path) ?? null,
    payload_source_field: record.payload_source_field ?? 'raw_payload_hex',
  };
}

function packetRecordComparator(left, right) {
  return strictCompare(left.replay_key, right.replay_key)
    || strictCompare(left.entity_id, right.entity_id)
    || (left.replay_time_ms ?? Number.MAX_SAFE_INTEGER) - (right.replay_time_ms ?? Number.MAX_SAFE_INTEGER)
    || left.sequence - right.sequence;
}

function selectPrimitiveDefinitions(preliminaryRows, maximumPerType) {
  const selected = [];
  for (const type of Object.keys(PRIMITIVE_TYPES)) {
    selected.push(...preliminaryRows.filter((row) => row.definition.type === type)
      .sort((left, right) => right.preliminary_score - left.preliminary_score
        || right.observation_count - left.observation_count
        || left.definition.offset - right.definition.offset)
      .slice(0, maximumPerType)
      .map((row) => row.definition));
  }
  return selected;
}

function selectCarrierOffsets(preliminaryRows, maximumOffsets) {
  return preliminaryRows.filter((row) => row.definition.type === 'uint8')
    .sort((left, right) => {
      const leftVariable = left.range.span !== null && left.range.span > 0 ? 1 : 0;
      const rightVariable = right.range.span !== null && right.range.span > 0 ? 1 : 0;
      return rightVariable - leftVariable
        || (right.change_rate ?? -1) - (left.change_rate ?? -1)
        || right.preliminary_score - left.preliminary_score
        || left.definition.offset - right.definition.offset;
    })
    .slice(0, maximumOffsets)
    .map((row) => row.definition.offset);
}

function profileRouteRecords(inputRecords, options = {}) {
  if (!Array.isArray(inputRecords) || inputRecords.length === 0) {
    throw new TypeError('profileRouteRecords requires at least one packet record');
  }
  const records = inputRecords.map((record, index) => normalizePacketRecord(record, index))
    .sort(packetRecordComparator);
  const packetId = records[0].packet_id;
  if (records.some((record) => record.packet_id !== packetId)) {
    throw new Error('profileRouteRecords accepts exactly one packet route');
  }
  const builds = [...new Set(records.map((record) => record.build).filter(Boolean))].sort(strictCompare);
  if (builds.length > 1) throw new Error(`profileRouteRecords cannot merge exact builds: ${builds.join(', ')}`);
  const maxPayloadBytes = integerOption(options.maxPayloadBytes, 2048, 'maxPayloadBytes');
  const observedMaximum = Math.max(...records.map((record) => record.payload.length));
  const scannedMaximum = Math.min(observedMaximum, maxPayloadBytes);
  const primitiveDefinitions = primitiveFieldDefinitions(scannedMaximum, options);
  const preliminary = new Map(primitiveDefinitions.map((definition) => [
    definition.field_id,
    new BasicFieldAccumulator(definition, options),
  ]));
  for (const record of records) {
    for (const definition of primitiveDefinitions) {
      if (definition.offset + definition.byte_length > record.payload.length) continue;
      preliminary.get(definition.field_id).observe(record, readField(record.payload, definition));
    }
  }
  const preliminaryRows = [...preliminary.values()].map((accumulator) => accumulator.finalize(records.length));
  const maximumPerType = integerOption(options.maxCandidatesPerType, 64, 'maxCandidatesPerType');
  const maximumCarrierOffsets = integerOption(options.maxPackedCarrierOffsets, 64, 'maxPackedCarrierOffsets');
  const selectedPrimitive = selectPrimitiveDefinitions(preliminaryRows, maximumPerType);
  const carrierOffsets = selectCarrierOffsets(preliminaryRows, maximumCarrierOffsets);
  const packedDefinitions = bitAndPackedFieldDefinitions(carrierOffsets);
  const configuredDefinitions = configuredRawFieldDefinitions(options.configuredFields);
  const definitions = [...selectedPrimitive, ...packedDefinitions, ...configuredDefinitions];
  if (new Set(definitions.map((definition) => definition.field_id)).size !== definitions.length) {
    throw new Error('configured field_id collides with an automatically generated field_id');
  }
  const anchorIndex = options.anchorIndex instanceof AnchorIndex
    ? options.anchorIndex : new AnchorIndex(options.anchors ?? []);
  const accumulators = new Map(definitions.map((definition) => [
    definition.field_id,
    new FieldAccumulator(definition, anchorIndex, options),
  ]));
  for (const record of records) {
    for (const definition of definitions) {
      if (definition.offset + definition.byte_length > record.payload.length) continue;
      accumulators.get(definition.field_id).observe(record, readField(record.payload, definition));
    }
  }
  const fields = [...accumulators.values()].map((accumulator) => accumulator.finalize(records.length));
  fields.sort((left, right) => right.heuristic_candidate_score - left.heuristic_candidate_score
    || left.offset - right.offset
    || strictCompare(left.type, right.type));
  const maxTrajectoryFields = Number.isSafeInteger(options.maxTrajectoryFields)
    && options.maxTrajectoryFields > 0 ? options.maxTrajectoryFields : 0;
  fields.forEach((field, index) => {
    field.heuristic_candidate_rank = index + 1;
    const included = index < maxTrajectoryFields
      && (options.maxTrajectoryPointsPerEntity ?? 0) > 0;
    field.per_entity_stability.trajectory_status = included
      ? 'BOUNDED_SAMPLED_TRAJECTORIES_INCLUDED'
      : 'NOT_INCLUDED_BY_OUTPUT_POLICY';
    if (!included) {
      for (const entity of field.per_entity_stability.entities) {
        delete entity.trajectory_observation_count;
        delete entity.trajectory_sample_count;
        delete entity.trajectory_is_sampled;
        delete entity.trajectory;
      }
    }
  });
  return {
    packet_id: packetId,
    packet_discriminator: formatOpcode(packetId),
    build: records[0].build,
    observed_record_count: options.observedRecordCount ?? records.length,
    profiled_record_count: records.length,
    sample_rate: ratio(records.length, options.observedRecordCount ?? records.length),
    sampling_method: options.samplingMethod ?? 'ALL_SELECTED_RECORDS',
    profiled_value_source: options.payloadSource ?? records[0].payload_source_field ?? 'raw_payload_hex',
    observed_max_payload_length: observedMaximum,
    scanned_max_payload_length: scannedMaximum,
    payload_truncated_by_policy: observedMaximum > scannedMaximum,
    selection_policy: {
      primitive_scan: 'EVERY_CONFIGURED_OFFSET; LIGHTWEIGHT_FIRST_PASS',
      full_primitive_candidates_per_type: maximumPerType,
      bitfield_and_packed_carrier_offsets: carrierOffsets,
      maximum_bitfield_and_packed_carrier_offsets: maximumCarrierOffsets,
      configured_field_count: configuredDefinitions.length,
      configured_field_policy: configuredDefinitions.length === 0
        ? 'UNAVAILABLE_REQUIRES_EXPLICIT_SCHEMA'
        : 'EXPLICIT_SCHEMA_ONLY_NO_SEMANTIC_PROMOTION',
      warning: 'Selection and scores are heuristic candidate ranking only.',
    },
    primitive_fields: fields.filter((field) => field.kind === 'primitive' && !field.configured),
    bitfield_candidates: fields.filter((field) => field.kind === 'bitfield_candidate' && !field.configured),
    packed_field_candidates: fields.filter((field) => field.kind === 'packed_field_candidate' && !field.configured),
    configured_fields: fields.filter((field) => field.configured),
  };
}

function routeSelectionScore(row) {
  let score = Number(row.candidate_score ?? 0);
  if (row.entity_candidate?.kind === 'CHAMPION_NETWORK_ID_RANGE_CANDIDATE') score += 100;
  if (row.structural_candidate_class?.includes('HERO_BOUND')) score += 100;
  if (row.confidence === 'CANDIDATE' || row.evidence_grade === 'CANDIDATE') score += 10;
  const maximumPayload = (row.payload_size_distribution ?? []).reduce(
    (maximum, item) => Math.max(maximum, Number(item.payload_length) || 0),
    0,
  );
  if (maximumPayload >= 4) score += 10;
  if (maximumPayload >= 16) score += 10;
  if (Number(row.count) >= 10) score += 5;
  if (Number(row.count) >= 100) score += 5;
  return score;
}

function numericPacketId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffff) return value;
  if (typeof value === 'string' && /^(?:0x)?[0-9a-f]+$/i.test(value)) {
    const parsed = Number.parseInt(value, 16);
    if (Number.isSafeInteger(parsed) && parsed <= 0xffff) return parsed;
  }
  throw new TypeError(`invalid packet route: ${String(value)}`);
}

function candidateRoutesFromReport(report, options = {}) {
  if (!report || typeof report !== 'object') throw new TypeError('candidate report must be an object');
  const maximumRoutes = integerOption(options.maxRoutes, 5, 'maxRoutes');
  const candidates = [];
  for (const row of report.priority_route_candidates ?? []) {
    candidates.push({ ...row, source_section: 'priority_route_candidates' });
  }
  for (const row of report.ranked_structural_candidates ?? []) {
    candidates.push({ ...row, source_section: 'ranked_structural_candidates' });
  }
  for (const row of report.packets ?? []) {
    const unregistered = row.currently_decoded_as_status === 'UNREGISTERED_EXACT_BUILD_RAW_ONLY';
    const candidate = row.confidence === 'CANDIDATE';
    if (unregistered && candidate) candidates.push({ ...row, source_section: 'packets' });
  }
  const selected = new Map();
  for (const row of candidates) {
    const packetId = numericPacketId(firstDefined(row.packet_id, row.packet_discriminator));
    const existing = selected.get(packetId);
    const normalized = {
      packet_id: packetId,
      packet_discriminator: formatOpcode(packetId),
      source_section: row.source_section,
      candidate_score: routeSelectionScore(row),
      evidence_grade: row.evidence_grade ?? row.confidence ?? 'CANDIDATE',
      structural_candidate_class: row.structural_candidate_class ?? row.hypothesis ?? null,
      observed_count: Number.isFinite(Number(row.count)) ? Number(row.count) : null,
    };
    if (!existing || normalized.candidate_score > existing.candidate_score) selected.set(packetId, normalized);
  }
  return [...selected.values()]
    .sort((left, right) => right.candidate_score - left.candidate_score
      || left.packet_id - right.packet_id)
    .slice(0, maximumRoutes);
}

function participantForNetworkId(networkId, replay) {
  if (!Number.isInteger(networkId) || networkId < 0x400000ae || networkId > 0x400000b7) return null;
  const participantId = networkId - 0x400000ad;
  const row = Array.isArray(replay.tail?.stats) ? replay.tail.stats[participantId - 1] : null;
  return {
    participant_id: participantId,
    champion: row?.SKIN ?? null,
  };
}

class RouteReservoir {
  constructor(packetId, limit) {
    this.packetId = packetId;
    this.limit = limit;
    this.seen = 0;
    this.records = [];
  }

  observe(record) {
    this.seen += 1;
    if (this.records.length < this.limit) {
      this.records.push(record);
      return;
    }
    const choice = mix32((this.seen ^ this.packetId ^ 0xa5a5a5a5) >>> 0) % this.seen;
    if (choice < this.limit) this.records[choice] = record;
  }
}

function collectPacketRecordsFromReplayFiles(replayPaths, routeIds, options = {}) {
  if (!Array.isArray(replayPaths) || replayPaths.length === 0) {
    throw new TypeError('at least one .rofl input is required');
  }
  if (!Array.isArray(routeIds) || routeIds.length === 0) {
    throw new TypeError('at least one packet route is required');
  }
  const routes = [...new Set(routeIds.map(numericPacketId))].sort((left, right) => left - right);
  const routeSet = new Set(routes);
  const maximum = integerOption(
    options.maxObservationsPerRoute,
    25000,
    'maxObservationsPerRoute',
  );
  const reservoirs = new Map(routes.map((packetId) => [packetId, new RouteReservoir(packetId, maximum)]));
  const sources = [];
  const observedBuilds = new Set();
  let sequence = 0;
  for (const replayPath of [...replayPaths].map((value) => path.resolve(value)).sort(strictCompare)) {
    const replay = parseReplayFile(replayPath);
    if (options.targetBuild && replay.header.version !== options.targetBuild) {
      throw new Error(`exact-build profiler expected ${options.targetBuild}; got ${replay.header.version} for ${replayPath}`);
    }
    observedBuilds.add(replay.header.version);
    if (observedBuilds.size > 1) {
      throw new Error(`field behavior profiles cannot merge exact builds: ${[...observedBuilds].sort(strictCompare).join(', ')}`);
    }
    const walk = walkBlocks(replay, (block, chunk) => {
      if (!routeSet.has(block.packet_id)) return;
      const participant = participantForNetworkId(block.param, replay);
      reservoirs.get(block.packet_id).observe({
        build: replay.header.version,
        packet_id: block.packet_id,
        payload: Buffer.from(block.payload),
        payload_length: block.payload_length,
        replay_key: replay.source_sha256,
        replay_time_ms: block.timestamp_ms,
        entity_id: block.param >>> 0,
        champion: participant?.champion ?? null,
        participant_id: participant?.participant_id ?? null,
        chunk_stream: chunk.stream,
        sequence: sequence++,
      });
    }, { includeStreams: options.includeStreams ?? [1, 2, 3], strict: options.strict !== false });
    if (walk.errors.length > 0) {
      throw new Error(`strict packet walk failed for ${replay.source_path}: ${walk.errors.length} error(s)`);
    }
    sources.push({
      source_path: replay.source_path,
      source_sha256: replay.source_sha256,
      game_version: replay.header.version,
      framed_block_count: walk.block_count,
    });
  }
  return {
    sources,
    routes: new Map([...reservoirs.entries()].map(([packetId, reservoir]) => [packetId, {
      records: reservoir.records,
      observed_record_count: reservoir.seen,
      sampling_method: reservoir.seen > reservoir.records.length
        ? 'DETERMINISTIC_ALGORITHM_R_RESERVOIR'
        : 'ALL_SELECTED_RECORDS',
    }])),
  };
}

function valueAtPath(record, fieldPath) {
  if (typeof fieldPath !== 'string' || fieldPath.trim().length === 0) {
    throw new TypeError('field path must be a non-empty dotted path');
  }
  return fieldPath.split('.').reduce((value, key) => (
    value && typeof value === 'object' ? value[key] : undefined
  ), record);
}

const TYPED_CATEGORICAL_TYPES = new Set(['identifier', 'enum', 'categorical', 'string', 'hash']);
const TYPED_VECTOR_TYPES = new Set(['vector', 'vector2', 'vector3', 'vector4']);

function validateTypedFieldSchema(schema) {
  if (!schema || typeof schema !== 'object') throw new TypeError('typed field schema must be an object');
  if (schema.schema !== TYPED_FIELD_SCHEMA_VERSION) {
    throw new Error(`typed field schema must declare ${TYPED_FIELD_SCHEMA_VERSION}`);
  }
  if (!Array.isArray(schema.fields) || schema.fields.length === 0) {
    throw new TypeError('typed field schema requires a non-empty fields array');
  }
  const identifiers = new Set();
  const fields = schema.fields.map((field, index) => {
    if (!field || typeof field !== 'object') throw new TypeError(`typed field ${index} must be an object`);
    const fieldId = field.field_id;
    if (typeof fieldId !== 'string' || fieldId.length === 0) {
      throw new TypeError(`typed field ${index} requires a non-empty field_id`);
    }
    if (identifiers.has(fieldId)) throw new Error(`duplicate typed field_id: ${fieldId}`);
    identifiers.add(fieldId);
    const type = String(field.type ?? '').trim().toLowerCase();
    if (!PRIMITIVE_TYPES[type] && !TYPED_CATEGORICAL_TYPES.has(type) && !TYPED_VECTOR_TYPES.has(type)) {
      throw new TypeError(`typed field ${fieldId} has unsupported type: ${type || '(missing)'}`);
    }
    if (!TYPED_VECTOR_TYPES.has(type)) {
      if (typeof field.path !== 'string' || field.path.length === 0) {
        throw new TypeError(`typed field ${fieldId} requires a dotted path`);
      }
      return Object.freeze({ ...field, field_id: fieldId, type, semantic_claim: null });
    }
    const impliedDimensions = type === 'vector' ? null : Number(type.slice(-1));
    const dimensions = Number(field.dimensions ?? impliedDimensions);
    if (!Number.isSafeInteger(dimensions) || dimensions < 2 || dimensions > 4) {
      throw new TypeError(`typed vector ${fieldId} dimensions must be in [2, 4]`);
    }
    const componentType = String(field.component_type ?? 'float32').toLowerCase();
    if (!PRIMITIVE_TYPES[componentType]) {
      throw new TypeError(`typed vector ${fieldId} has unsupported component_type: ${componentType}`);
    }
    let components = null;
    if (field.components !== undefined && field.components !== null) {
      if (!Array.isArray(field.components) || field.components.length !== dimensions) {
        throw new TypeError(`typed vector ${fieldId} components must contain exactly ${dimensions} entries`);
      }
      components = field.components.map((component, componentIndex) => {
        const normalized = typeof component === 'string'
          ? { path: component, name: ['x', 'y', 'z', 'w'][componentIndex] }
          : component;
        if (!normalized || typeof normalized.path !== 'string' || normalized.path.length === 0) {
          throw new TypeError(`typed vector ${fieldId} component ${componentIndex} requires a path`);
        }
        return {
          name: String(normalized.name ?? ['x', 'y', 'z', 'w'][componentIndex]),
          path: normalized.path,
        };
      });
    } else if (typeof field.path !== 'string' || field.path.length === 0) {
      throw new TypeError(`typed vector ${fieldId} requires path or component paths`);
    }
    return Object.freeze({
      ...field,
      field_id: fieldId,
      type,
      dimensions,
      component_type: componentType,
      components,
      semantic_claim: null,
    });
  });
  return Object.freeze({
    schema: TYPED_FIELD_SCHEMA_VERSION,
    adapter: 'EXPLICIT_DECODED_FIELD_PATHS',
    fields,
    semantic_claim: null,
  });
}

function parseTypedNumeric(type, value) {
  if (type === 'int64' || type === 'uint64') {
    let parsed;
    try {
      if (typeof value === 'bigint') parsed = value;
      else if (typeof value === 'number' && Number.isSafeInteger(value)) parsed = BigInt(value);
      else if (typeof value === 'string' && /^-?(?:0|[1-9][0-9]*)$/.test(value)) parsed = BigInt(value);
      else return null;
    } catch {
      return null;
    }
    const minimum = type === 'int64' ? -(1n << 63n) : 0n;
    const maximum = type === 'int64' ? (1n << 63n) - 1n : (1n << 64n) - 1n;
    return parsed >= minimum && parsed <= maximum ? parsed : null;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  if (type === 'float32' || type === 'float64') return value;
  if (!Number.isInteger(value)) return null;
  const ranges = {
    int8: [-0x80, 0x7f],
    int16: [-0x8000, 0x7fff],
    int32: [-0x80000000, 0x7fffffff],
    uint8: [0, 0xff],
    uint16: [0, 0xffff],
    uint32: [0, 0xffffffff],
  };
  const range = ranges[type];
  return range && value >= range[0] && value <= range[1] ? value : null;
}

function canonicalCategoricalValue(value) {
  if (typeof value === 'string') return { key: `string:${value}`, value, value_type: 'string' };
  if (typeof value === 'boolean') return { key: `boolean:${value}`, value, value_type: 'boolean' };
  if (typeof value === 'bigint') {
    return { key: `bigint:${value.toString()}`, value: value.toString(), value_type: 'bigint_decimal' };
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return { key: `number:${Object.is(value, -0) ? 0 : value}`, value: cleanNumber(value), value_type: 'number' };
  }
  return null;
}

function entropyBits(rows, total) {
  if (total === 0) return null;
  let entropy = 0;
  for (const row of rows) {
    const probability = row.count / total;
    entropy -= probability * Math.log2(probability);
  }
  return cleanNumber(entropy);
}

function finalizeCategoricalGroup(group) {
  const rows = [...group.counts.values()].sort((left, right) => right.count - left.count
    || strictCompare(left.key, right.key));
  return {
    ...group.identity,
    observation_count: group.count,
    distinct_count: rows.length,
    dominant_value_rate: group.count === 0 ? null : ratio(rows[0]?.count ?? 0, group.count),
    transition_count: group.transitionCount,
    change_rate: group.transitionCount === 0 ? null : ratio(group.changedCount, group.transitionCount),
    stability_index: group.transitionCount === 0
      ? null : ratio(group.transitionCount - group.changedCount, group.transitionCount),
  };
}

function cramerV(contingency) {
  const rows = [...contingency.values()];
  const columns = [...new Set(rows.flatMap((row) => [...row.values.keys()]))].sort(strictCompare);
  if (rows.length < 2 || columns.length < 2) {
    return { status: 'NOT_COMPUTABLE_INSUFFICIENT_CATEGORIES', coefficient: null };
  }
  const columnTotals = new Map(columns.map((column) => [column, 0]));
  let total = 0;
  for (const row of rows) {
    total += row.count;
    for (const [column, count] of row.values) columnTotals.set(column, columnTotals.get(column) + count);
  }
  if (total === 0) return { status: 'NOT_COMPUTABLE_NO_OBSERVATIONS', coefficient: null };
  let chiSquare = 0;
  for (const row of rows) {
    for (const column of columns) {
      const expected = (row.count * columnTotals.get(column)) / total;
      const observed = row.values.get(column) ?? 0;
      if (expected > 0) chiSquare += ((observed - expected) ** 2) / expected;
    }
  }
  const denominator = total * Math.min(rows.length - 1, columns.length - 1);
  return {
    status: denominator > 0 ? 'AVAILABLE_DESCRIPTIVE_ONLY' : 'NOT_COMPUTABLE_INSUFFICIENT_CATEGORIES',
    coefficient: denominator > 0 ? cleanNumber(Math.sqrt(chiSquare / denominator)) : null,
    sample_count: total,
    category_count: rows.length,
    champion_count: columns.length,
    method: 'CRAMERS_V_UNCORRECTED',
    warning: 'Association is descriptive candidate evidence and cannot establish a field meaning.',
  };
}

class TypedCategoricalAccumulator {
  constructor(field, options = {}) {
    this.field = field;
    this.maxReportedEntities = options.maxReportedEntities ?? 100;
    this.attemptCount = 0;
    this.missingCount = 0;
    this.invalidCount = 0;
    this.counts = new Map();
    this.transitions = new Map();
    this.transitionCount = 0;
    this.changedCount = 0;
    this.lastBySeries = new Map();
    this.entityGroups = new Map();
    this.championGroups = new Map();
    this.valueEntities = new Map();
    this.replayValues = new Map();
    this.championContingency = new Map();
    this.stringLengths = new RunningStats({ seed: `${field.field_id}:string-length` });
    const dictionary = Array.isArray(field.dictionary)
      ? field.dictionary
      : field.dictionary && typeof field.dictionary === 'object'
        ? Object.keys(field.dictionary)
        : [];
    this.dictionaryValues = new Set(dictionary.map((value) => String(value)));
    this.dictionaryMatchCount = 0;
  }

  group(map, key, identity) {
    if (!map.has(key)) {
      map.set(key, {
        identity,
        count: 0,
        counts: new Map(),
        transitionCount: 0,
        changedCount: 0,
        lastKey: null,
      });
    }
    return map.get(key);
  }

  observeGroup(group, normalized) {
    group.count += 1;
    if (!group.counts.has(normalized.key)) group.counts.set(normalized.key, { ...normalized, count: 0 });
    group.counts.get(normalized.key).count += 1;
    if (group.lastKey !== null) {
      group.transitionCount += 1;
      if (group.lastKey !== normalized.key) group.changedCount += 1;
    }
    group.lastKey = normalized.key;
  }

  observe(record, value) {
    this.attemptCount += 1;
    if (value === undefined || value === null) {
      this.missingCount += 1;
      return;
    }
    const normalized = canonicalCategoricalValue(value);
    if (!normalized || (this.field.type === 'string' && typeof value !== 'string')) {
      this.invalidCount += 1;
      return;
    }
    if (!this.counts.has(normalized.key)) this.counts.set(normalized.key, { ...normalized, count: 0 });
    this.counts.get(normalized.key).count += 1;
    const key = seriesKey(record);
    if (this.lastBySeries.has(key)) {
      const previous = this.lastBySeries.get(key);
      this.transitionCount += 1;
      if (previous !== normalized.key) this.changedCount += 1;
      const transitionKey = `${previous}\u0000${normalized.key}`;
      this.transitions.set(transitionKey, (this.transitions.get(transitionKey) ?? 0) + 1);
    }
    this.lastBySeries.set(key, normalized.key);
    const entityGroup = this.group(this.entityGroups, key, {
      replay_key: record.replay_key,
      entity_id: record.entity_id,
      champion: record.champion ?? null,
    });
    this.observeGroup(entityGroup, normalized);
    if (record.champion) {
      const champion = String(record.champion);
      const championGroup = this.group(this.championGroups, champion, { champion });
      this.observeGroup(championGroup, normalized);
      if (!this.championContingency.has(normalized.key)) {
        this.championContingency.set(normalized.key, { count: 0, values: new Map() });
      }
      const row = this.championContingency.get(normalized.key);
      row.count += 1;
      row.values.set(champion, (row.values.get(champion) ?? 0) + 1);
    }
    if (!this.valueEntities.has(normalized.key)) this.valueEntities.set(normalized.key, new Set());
    this.valueEntities.get(normalized.key).add(key);
    if (!this.replayValues.has(record.replay_key)) this.replayValues.set(record.replay_key, new Set());
    this.replayValues.get(record.replay_key).add(normalized.key);
    if (typeof value === 'string') this.stringLengths.observe(value.length);
    if (this.field.type === 'hash' && this.dictionaryValues.has(String(normalized.value))) {
      this.dictionaryMatchCount += 1;
    }
  }

  finalize(routeRecordCount) {
    const categoryRows = [...this.counts.values()].sort((left, right) => right.count - left.count
      || strictCompare(left.key, right.key));
    const observationCount = categoryRows.reduce((sum, row) => sum + row.count, 0);
    const entityRows = [...this.entityGroups.values()].map(finalizeCategoricalGroup)
      .sort((left, right) => right.observation_count - left.observation_count
        || strictCompare(left.replay_key, right.replay_key)
        || strictCompare(left.entity_id, right.entity_id));
    const reportedEntities = entityRows.slice(0, this.maxReportedEntities);
    const comparableEntities = entityRows.filter((row) => row.stability_index !== null);
    const championRows = [...this.championGroups.values()].map(finalizeCategoricalGroup)
      .sort((left, right) => strictCompare(left.champion, right.champion));
    const singletonCount = categoryRows.filter((row) => row.count === 1).length;
    const singleEntityValueCount = [...this.valueEntities.values()].filter((values) => values.size === 1).length;
    const singleValueEntityCount = [...this.entityGroups.values()].filter((group) => group.counts.size === 1).length;
    const topTransitions = [...this.transitions.entries()].map(([key, count]) => {
      const [fromKey, toKey] = key.split('\u0000');
      return { from_key: fromKey, to_key: toKey, count };
    }).sort((left, right) => right.count - left.count
      || strictCompare(left.from_key, right.from_key)
      || strictCompare(left.to_key, right.to_key)).slice(0, 64);
    const unavailableCorrelation = Object.fromEntries(ANCHOR_TYPES.map((eventType) => [
      `correlation_with_${eventType}`,
      {
        status: 'NOT_COMPUTABLE_CATEGORICAL_ANCHOR_TEST_NOT_DECLARED',
        evidence_grade: 'CANDIDATE',
        semantic_claim: null,
      },
    ]));
    const field = {
      field_id: this.field.field_id,
      kind: 'typed_decoded_field',
      path: this.field.path,
      offset: null,
      type: this.field.type,
      byte_length: null,
      bit_offset: null,
      bit_width: null,
      endianness: 'not_applicable_decoded_value',
      configured: true,
      observation_count: observationCount,
      attempted_observation_count: routeRecordCount,
      missing_value_count: this.missingCount,
      invalid_value_count: this.invalidCount,
      coverage_rate: ratio(observationCount, routeRecordCount),
      valid_rate: ratio(observationCount, routeRecordCount - this.missingCount),
      range: { min: null, max: null, span: null },
      mean: null,
      median: null,
      variance: null,
      variance_kind: null,
      zero_rate: null,
      numeric_statistics_status: 'NOT_COMPUTABLE_NON_NUMERIC_CONFIGURED_TYPE',
      change_rate: this.transitionCount === 0 ? null : ratio(this.changedCount, this.transitionCount),
      delta_distribution: {
        status: 'NOT_COMPUTABLE_CATEGORICAL_VALUES_HAVE_NO_NUMERIC_DELTA',
        transition_count: this.transitionCount,
        changed_count: this.changedCount,
        top_transitions: topTransitions,
      },
      categorical_statistics: {
        status: observationCount === 0 ? 'UNAVAILABLE_NO_VALID_VALUES' : 'AVAILABLE_DESCRIPTIVE_ONLY',
        distinct_count: categoryRows.length,
        entropy_bits: entropyBits(categoryRows, observationCount),
        dominant_value_rate: observationCount === 0 ? null : ratio(categoryRows[0]?.count ?? 0, observationCount),
        singleton_value_count: singletonCount,
        singleton_distinct_rate: categoryRows.length === 0 ? null : ratio(singletonCount, categoryRows.length),
        top_values: categoryRows.slice(0, 64).map(({ key, value, value_type: valueType, count }) => ({
          key,
          value,
          value_type: valueType,
          count,
          rate: ratio(count, observationCount),
        })),
        values_truncated: categoryRows.length > 64,
      },
      identifier_candidate_metrics: this.field.type !== 'identifier' ? {
        status: 'NOT_APPLICABLE_TYPE_NOT_DECLARED_IDENTIFIER',
      } : {
        status: observationCount === 0 ? 'UNAVAILABLE_NO_VALID_VALUES' : 'AVAILABLE_CANDIDATE_METRICS',
        semantic_claim: null,
        distinct_value_count: categoryRows.length,
        observation_uniqueness_rate: ratio(categoryRows.length, observationCount),
        repeated_observation_rate: ratio(observationCount - singletonCount, observationCount),
        single_entity_value_count: singleEntityValueCount,
        single_entity_value_rate: ratio(singleEntityValueCount, categoryRows.length),
        entity_series_count: entityRows.length,
        single_value_entity_series_count: singleValueEntityCount,
        single_value_entity_series_rate: ratio(singleValueEntityCount, entityRows.length),
        replay_scoped_distinct_counts: [...this.replayValues.entries()]
          .sort((left, right) => strictCompare(left[0], right[0]))
          .map(([replayKey, values]) => ({ replay_key: replayKey, distinct_value_count: values.size })),
        warning: 'These metrics rank identifier-shaped values only and do not identify a network ID, GUID, participant, or event key.',
      },
      string_statistics: this.field.type !== 'string' ? {
        status: 'NOT_APPLICABLE_TYPE_NOT_DECLARED_STRING',
      } : {
        status: observationCount === 0 ? 'UNAVAILABLE_NO_VALID_VALUES' : 'AVAILABLE_CONFIGURED_DECODED_STRING',
        length: this.stringLengths.finalize(),
        encoding: 'ALREADY_DECODED_BY_UPSTREAM_EXPLICIT_FIELD',
        raw_byte_decoding_attempted: false,
      },
      hash_candidate_statistics: this.field.type !== 'hash' ? {
        status: 'NOT_APPLICABLE_TYPE_NOT_DECLARED_HASH',
      } : {
        status: observationCount === 0 ? 'UNAVAILABLE_NO_VALID_VALUES' : 'AVAILABLE_CONFIGURED_OPAQUE_HASH_CANDIDATE',
        algorithm_claim: null,
        dictionary_status: this.dictionaryValues.size === 0
          ? 'NOT_COMPUTABLE_NO_CONFIGURED_DICTIONARY'
          : 'AVAILABLE_CONFIGURED_DICTIONARY_COVERAGE_ONLY',
        dictionary_entry_count: this.dictionaryValues.size,
        dictionary_match_count: this.dictionaryMatchCount,
        dictionary_match_rate: this.dictionaryValues.size === 0
          ? null : ratio(this.dictionaryMatchCount, observationCount),
        warning: 'A configured dictionary match does not prove an algorithm or semantic label.',
      },
      per_entity_stability: {
        status: entityRows.length === 0 ? 'UNAVAILABLE' : 'AVAILABLE_CATEGORICAL_DESCRIPTIVE_ONLY',
        entity_series_count: entityRows.length,
        comparable_entity_series_count: comparableEntities.length,
        reported_entity_series_count: reportedEntities.length,
        truncated: reportedEntities.length < entityRows.length,
        mean_stability_index: comparableEntities.length === 0 ? null : cleanNumber(
          comparableEntities.reduce((sum, row) => sum + row.stability_index, 0) / comparableEntities.length,
        ),
        trajectory_status: 'NOT_COMPUTABLE_CATEGORICAL_TRAJECTORY_VALUES_NOT_EMITTED',
        entities: reportedEntities,
      },
      per_champion_behavior: {
        status: championRows.length === 0
          ? 'UNAVAILABLE_NO_CHAMPION_MAPPING' : 'AVAILABLE_CATEGORICAL_DESCRIPTIVE_ONLY',
        champion_count: championRows.length,
        champions: championRows,
        categorical_association: cramerV(this.championContingency),
      },
      ...unavailableCorrelation,
      evidence_grade: 'CANDIDATE',
      semantic_status: 'UNKNOWN_CONFIGURED_TYPED_FIELD_CANDIDATE',
      semantic_claim: null,
      heuristic_only: true,
      heuristic_warning: 'Typed declaration enables representation-aware statistics only; it cannot promote or name semantics.',
    };
    let score = 40 * field.coverage_rate;
    if (categoryRows.length > 1) score += 20;
    if (field.change_rate !== null && field.change_rate > 0) score += 20;
    if (comparableEntities.length > 0) score += 10;
    if (field.per_champion_behavior.categorical_association.coefficient !== null) score += 10;
    field.heuristic_candidate_score = cleanNumber(Math.max(0, Math.min(100, score)));
    return field;
  }
}

class TypedNumericAccumulator {
  constructor(field, anchorIndex, options = {}) {
    this.field = field;
    this.missingCount = 0;
    this.invalidCount = 0;
    this.inner = new FieldAccumulator({
      field_id: field.field_id,
      kind: 'typed_decoded_field',
      offset: null,
      type: field.type,
      byte_length: null,
      bit_offset: null,
      bit_width: null,
      endianness: 'not_applicable_decoded_value',
      configured: true,
      configuration_note: field.note ?? null,
    }, anchorIndex, options);
  }

  observe(record, value) {
    if (value === undefined || value === null) {
      this.missingCount += 1;
      return;
    }
    const parsed = parseTypedNumeric(this.field.type, value);
    if (parsed === null) {
      this.invalidCount += 1;
      return;
    }
    this.inner.observe(record, parsed);
  }

  finalize(routeRecordCount) {
    const field = this.inner.finalize(routeRecordCount);
    field.path = this.field.path;
    field.attempted_observation_count = routeRecordCount;
    field.missing_value_count = this.missingCount;
    field.invalid_value_count = this.invalidCount;
    field.coverage_rate = ratio(field.observation_count, routeRecordCount);
    field.valid_rate = ratio(field.observation_count, routeRecordCount - this.missingCount);
    field.semantic_status = 'UNKNOWN_CONFIGURED_TYPED_FIELD_CANDIDATE';
    field.heuristic_candidate_score = heuristicCandidateScore(field);
    return field;
  }
}

class TypedVectorAccumulator {
  constructor(field, anchorIndex, options = {}) {
    this.field = field;
    this.missingCount = 0;
    this.invalidCount = 0;
    this.observationCount = 0;
    this.transitionCount = 0;
    this.changedCount = 0;
    this.lastBySeries = new Map();
    const names = field.components?.map((component) => component.name)
      ?? ['x', 'y', 'z', 'w'].slice(0, field.dimensions);
    this.components = names.map((name) => new TypedNumericAccumulator({
      field_id: `${field.field_id}.${name}`,
      path: field.components?.find((component) => component.name === name)?.path
        ?? `${field.path}[${names.indexOf(name)}]`,
      type: field.component_type,
      note: 'Explicit vector component; coordinate semantics unknown.',
    }, anchorIndex, options));
    this.magnitude = new TypedNumericAccumulator({
      field_id: `${field.field_id}.magnitude`,
      path: field.path ?? 'configured_component_paths',
      type: 'float64',
      note: 'Euclidean magnitude of explicitly configured decoded components.',
    }, anchorIndex, options);
  }

  values(record) {
    const source = record.source_row;
    if (this.field.components) return this.field.components.map((component) => valueAtPath(source, component.path));
    const value = valueAtPath(source, this.field.path);
    return Array.isArray(value) ? value.slice(0, this.field.dimensions) : value;
  }

  observe(record) {
    const values = this.values(record);
    if (values === undefined || values === null) {
      this.missingCount += 1;
      return;
    }
    if (!Array.isArray(values) || values.length !== this.field.dimensions) {
      this.invalidCount += 1;
      return;
    }
    const parsed = values.map((value) => parseTypedNumeric(this.field.component_type, value));
    const numeric = parsed.map((value) => (typeof value === 'bigint' ? safeNumericValue(value) : value));
    if (numeric.some((value) => value === null)) {
      this.invalidCount += 1;
      return;
    }
    this.observationCount += 1;
    numeric.forEach((value, index) => this.components[index].observe(record, value));
    this.magnitude.observe(record, Math.sqrt(numeric.reduce((sum, value) => sum + (value * value), 0)));
    const key = seriesKey(record);
    if (this.lastBySeries.has(key)) {
      this.transitionCount += 1;
      if (numeric.some((value, index) => value !== this.lastBySeries.get(key)[index])) this.changedCount += 1;
    }
    this.lastBySeries.set(key, numeric);
  }

  finalize(routeRecordCount) {
    const componentFields = this.components.map((component) => component.finalize(routeRecordCount));
    const magnitudeField = this.magnitude.finalize(routeRecordCount);
    return {
      field_id: this.field.field_id,
      kind: 'typed_decoded_vector',
      path: this.field.path ?? null,
      component_paths: this.field.components ?? null,
      offset: null,
      type: this.field.type,
      component_type: this.field.component_type,
      dimensions: this.field.dimensions,
      configured: true,
      observation_count: this.observationCount,
      attempted_observation_count: routeRecordCount,
      missing_value_count: this.missingCount,
      invalid_value_count: this.invalidCount,
      coverage_rate: ratio(this.observationCount, routeRecordCount),
      valid_rate: ratio(this.observationCount, routeRecordCount - this.missingCount),
      range: magnitudeField.range,
      mean: magnitudeField.mean,
      median: magnitudeField.median,
      variance: magnitudeField.variance,
      variance_kind: magnitudeField.variance_kind,
      zero_rate: magnitudeField.zero_rate,
      change_rate: this.transitionCount === 0 ? null : ratio(this.changedCount, this.transitionCount),
      delta_distribution: magnitudeField.delta_distribution,
      vector_statistics: {
        status: this.observationCount === 0
          ? 'UNAVAILABLE_NO_VALID_CONFIGURED_VECTORS' : 'AVAILABLE_CONFIGURED_DECODED_VECTOR',
        component_fields: componentFields,
        magnitude_field: magnitudeField,
        direction_statistics: {
          status: 'NOT_COMPUTABLE_COORDINATE_FRAME_AND_DIRECTION_SEMANTICS_UNDECLARED',
        },
      },
      per_entity_stability: {
        status: 'AVAILABLE_VIA_COMPONENT_AND_MAGNITUDE_FIELDS',
        component_fields: componentFields.map((field) => ({
          field_id: field.field_id,
          per_entity_stability: field.per_entity_stability,
        })),
      },
      per_champion_behavior: magnitudeField.per_champion_behavior,
      ...Object.fromEntries(ANCHOR_TYPES.map((eventType) => [
        `correlation_with_${eventType}`,
        magnitudeField[`correlation_with_${eventType}`],
      ])),
      evidence_grade: 'CANDIDATE',
      semantic_status: 'UNKNOWN_CONFIGURED_TYPED_VECTOR_CANDIDATE',
      semantic_claim: null,
      heuristic_only: true,
      heuristic_warning: 'Vector configuration establishes representation only; magnitude and correlations cannot promote semantics.',
      heuristic_candidate_score: Math.max(
        magnitudeField.heuristic_candidate_score,
        ...componentFields.map((field) => field.heuristic_candidate_score),
      ),
    };
  }
}

function normalizeTypedPacketRecord(record, sequence = 0) {
  if (!record || typeof record !== 'object') throw new TypeError('typed packet record must be an object');
  const packetId = numericPacketId(firstDefined(record.packet_id, record.packet_discriminator));
  const replayKey = firstDefined(
    record.replay_key,
    record.replay_sha256,
    record.source_sha256,
    record.raw_packet_ref?.replay_sha256,
    record.replay_path,
    record.source_path,
  );
  if (replayKey === undefined || replayKey === null) {
    throw new TypeError('typed packet record requires replay provenance key or SHA-256');
  }
  return {
    build: firstDefined(record.build, record.game_version, record.replay_version) ?? null,
    packet_id: packetId,
    replay_key: String(replayKey),
    replay_time_ms: finiteNumber(record.replay_time_ms, record.timestamp_ms),
    entity_id: finiteNumber(record.entity_id, record.entity_network_id, record.raw_param, record.param)
      ?? 'PACKET_SCOPE',
    champion: firstDefined(record.champion, record.target_champion, record.entity_champion) ?? null,
    participant_id: finiteNumber(record.participant_id, record.target_participant_id),
    chunk_stream: firstDefined(record.chunk_stream, record.stream) ?? null,
    sequence: Number.isSafeInteger(record.sequence)
      ? record.sequence
      : Number.isSafeInteger(record.occurrence_index) ? record.occurrence_index : sequence,
    source_path: firstDefined(record.replay_path, record.source_path) ?? null,
    source_row: record,
  };
}

function typedPacketRecordsFromDecodedFields(records, schema, options = {}) {
  if (!Array.isArray(records)) throw new TypeError('decoded packet rows must be an array');
  const validatedSchema = validateTypedFieldSchema(schema);
  const accepted = [];
  const rejected = {
    not_fully_consumed: 0,
    wrong_build: 0,
    invalid_metadata: 0,
  };
  for (let index = 0; index < records.length; index += 1) {
    const row = records[index];
    if (options.requireFullyConsumed !== false && row?.fully_consumed === false) {
      rejected.not_fully_consumed += 1;
      continue;
    }
    const build = firstDefined(row?.build, row?.game_version, row?.replay_version);
    if (options.targetBuild && build !== options.targetBuild) {
      rejected.wrong_build += 1;
      continue;
    }
    try {
      accepted.push(normalizeTypedPacketRecord(row, index));
    } catch {
      rejected.invalid_metadata += 1;
    }
  }
  return {
    records: accepted,
    schema: validatedSchema,
    input_row_count: records.length,
    accepted_row_count: accepted.length,
    rejected_row_count: Object.values(rejected).reduce((sum, count) => sum + count, 0),
    rejected,
    require_fully_consumed: options.requireFullyConsumed !== false,
    champion_mapping: {
      status: accepted.some((record) => record.champion)
        ? 'AVAILABLE_EXPLICIT_RECORD_VALUES_ONLY'
        : 'UNAVAILABLE_NO_EXPLICIT_MAPPING',
      replay_tail_lookup_attempted: false,
      safety: 'Typed adapter never opens replay_path implicitly.',
    },
  };
}

function profileTypedRouteRecords(inputRecords, schema, options = {}) {
  if (!Array.isArray(inputRecords) || inputRecords.length === 0) {
    throw new TypeError('profileTypedRouteRecords requires at least one typed packet record');
  }
  const validatedSchema = validateTypedFieldSchema(schema);
  const records = inputRecords.map((record, index) => (
    record?.source_row ? record : normalizeTypedPacketRecord(record, index)
  )).sort(packetRecordComparator);
  const packetId = records[0].packet_id;
  if (records.some((record) => record.packet_id !== packetId)) {
    throw new Error('profileTypedRouteRecords accepts exactly one packet route');
  }
  const builds = [...new Set(records.map((record) => record.build).filter(Boolean))].sort(strictCompare);
  if (builds.length > 1) throw new Error(`profileTypedRouteRecords cannot merge exact builds: ${builds.join(', ')}`);
  const anchorIndex = options.anchorIndex instanceof AnchorIndex
    ? options.anchorIndex : new AnchorIndex(options.anchors ?? []);
  const accumulators = validatedSchema.fields.map((field) => {
    if (PRIMITIVE_TYPES[field.type]) return new TypedNumericAccumulator(field, anchorIndex, options);
    if (TYPED_VECTOR_TYPES.has(field.type)) return new TypedVectorAccumulator(field, anchorIndex, options);
    return new TypedCategoricalAccumulator(field, options);
  });
  for (const record of records) {
    accumulators.forEach((accumulator, index) => {
      const field = validatedSchema.fields[index];
      if (TYPED_VECTOR_TYPES.has(field.type)) accumulator.observe(record);
      else accumulator.observe(record, valueAtPath(record.source_row, field.path));
    });
  }
  const fields = accumulators.map((accumulator) => accumulator.finalize(records.length))
    .sort((left, right) => right.heuristic_candidate_score - left.heuristic_candidate_score
      || strictCompare(left.field_id, right.field_id));
  fields.forEach((field, index) => { field.heuristic_candidate_rank = index + 1; });
  return {
    packet_id: packetId,
    packet_discriminator: formatOpcode(packetId),
    build: records[0].build,
    observed_record_count: options.observedRecordCount ?? records.length,
    profiled_record_count: records.length,
    sample_rate: ratio(records.length, options.observedRecordCount ?? records.length),
    sampling_method: options.samplingMethod ?? 'ALL_SELECTED_RECORDS',
    profiled_value_source: 'EXPLICIT_TYPED_DECODED_FIELD_SCHEMA',
    schema_field_count: validatedSchema.fields.length,
    configured_typed_fields: fields,
  };
}

function createTypedFieldBehaviorProfile({
  packetRecords,
  fieldSchema,
  fieldSchemaSource = null,
  packetRecordSources = [],
  packetRecordExtraction = null,
  routeIds = [],
  anchors = [],
  anchorSources = [],
  targetBuild = null,
  options = {},
} = {}) {
  if (!Array.isArray(packetRecords) || packetRecords.length === 0) {
    throw new TypeError('typed profile requires at least one decoded packet record');
  }
  const validatedSchema = validateTypedFieldSchema(fieldSchema);
  const records = packetRecords.map((record, index) => (
    record?.source_row ? record : normalizeTypedPacketRecord(record, index)
  ));
  const inferredRoutes = [...new Set(records.map((record) => record.packet_id))].sort((left, right) => left - right);
  const selectedRouteIds = routeIds.length > 0
    ? [...new Set(routeIds.map(numericPacketId))].sort((left, right) => left - right)
    : inferredRoutes;
  if (selectedRouteIds.length === 0) throw new Error('no typed packet routes selected');
  const observedBuilds = new Set(records.map((record) => record.build).filter(Boolean));
  if (targetBuild && [...observedBuilds].some((build) => build !== targetBuild)) {
    throw new Error(`exact-build typed profiler expected ${targetBuild}; got ${[...observedBuilds].join(', ')}`);
  }
  if (observedBuilds.size > 1) {
    throw new Error(`typed field profiles cannot merge exact builds: ${[...observedBuilds].sort(strictCompare).join(', ')}`);
  }
  const normalizedAnchors = normalizeAnchors(anchors);
  const anchorIndex = new AnchorIndex(normalizedAnchors.anchors);
  const maximum = integerOption(options.maxObservationsPerRoute, 25000, 'maxObservationsPerRoute');
  const reservoirs = new Map(selectedRouteIds.map((packetId) => [packetId, new RouteReservoir(packetId, maximum)]));
  for (const record of records) {
    if (reservoirs.has(record.packet_id)) reservoirs.get(record.packet_id).observe(record);
  }
  const selectedRoutes = selectedRouteIds.map((packetId) => ({
    packet_id: packetId,
    packet_discriminator: formatOpcode(packetId),
    source_section: 'EXPLICIT_TYPED_DECODED_FIELD_SCHEMA',
    evidence_grade: 'CANDIDATE',
    route_role: options.routeRole ?? 'CANDIDATE',
    known_route_semantics: options.knownRouteSemantics ?? null,
  }));
  const routeProfiles = selectedRoutes.map((selected) => {
    const reservoir = reservoirs.get(selected.packet_id);
    if (!reservoir || reservoir.records.length === 0) {
      return {
        ...selected,
        build: targetBuild,
        excluded_from_combat_state_ranking: selected.route_role === 'NEGATIVE_CONTROL',
        status: 'UNAVAILABLE_NOT_OBSERVED_IN_INPUT',
        observed_record_count: 0,
        profiled_record_count: 0,
        configured_typed_fields: [],
      };
    }
    return {
      status: selected.route_role === 'NEGATIVE_CONTROL'
        ? 'NEGATIVE_CONTROL_PROFILE_AVAILABLE' : 'CANDIDATE_PROFILE_AVAILABLE',
      route_role: selected.route_role,
      known_route_semantics: selected.known_route_semantics,
      excluded_from_combat_state_ranking: selected.route_role === 'NEGATIVE_CONTROL',
      route_selection: selected,
      ...profileTypedRouteRecords(reservoir.records, validatedSchema, {
        ...options,
        anchorIndex,
        observedRecordCount: reservoir.seen,
        samplingMethod: reservoir.seen > reservoir.records.length
          ? 'DETERMINISTIC_ALGORITHM_R_RESERVOIR' : 'ALL_SELECTED_RECORDS',
      }),
    };
  });
  const rankedCandidates = routeProfiles.filter((route) => !route.excluded_from_combat_state_ranking)
    .flatMap((route) => (route.configured_typed_fields ?? []).map((field) => ({
      packet_id: route.packet_id,
      packet_discriminator: route.packet_discriminator,
      field_id: field.field_id,
      path: field.path ?? null,
      type: field.type,
      heuristic_candidate_score: field.heuristic_candidate_score,
      evidence_grade: 'CANDIDATE',
      semantic_claim: null,
    }))).sort((left, right) => right.heuristic_candidate_score - left.heuristic_candidate_score
      || left.packet_id - right.packet_id || strictCompare(left.field_id, right.field_id));
  rankedCandidates.forEach((row, index) => { row.heuristic_candidate_rank = index + 1; });
  const sourceMap = new Map();
  for (const record of records) {
    if (!sourceMap.has(record.replay_key)) {
      sourceMap.set(record.replay_key, {
        source_path: record.source_path,
        source_sha256: record.replay_key,
        game_version: record.build,
        source_kind: 'DECODED_TYPED_FIELD_EXPORT',
        selected_record_count: 0,
      });
    }
    sourceMap.get(record.replay_key).selected_record_count += 1;
  }
  return {
    schema: FIELD_BEHAVIOR_SCHEMA_VERSION,
    schema_version: 1,
    analyzer_version: ANALYZER_VERSION,
    exact_build_only: true,
    target_build: targetBuild ?? records[0].build ?? null,
    evidence_grade: 'CANDIDATE',
    semantic_status: 'FIELD_BEHAVIOR_CANDIDATE_RANKING_ONLY',
    semantic_claim: null,
    field_type_support: {
      typed_decoded_field_adapter: TYPED_FIELD_SCHEMA_VERSION,
      configured_types: [...Object.keys(PRIMITIVE_TYPES), ...TYPED_CATEGORICAL_TYPES, ...TYPED_VECTOR_TYPES],
      missing_schema_status: 'UNAVAILABLE_REQUIRES_EXPLICIT_SCHEMA',
    },
    coverage_matrix: FIELD_BEHAVIOR_COVERAGE_MATRIX,
    input: {
      input_mode: 'DECODED_TYPED_FIELD_EXPORT',
      replay_count: sourceMap.size,
      replays: [...sourceMap.values()].sort((left, right) => strictCompare(left.source_sha256, right.source_sha256)),
      packet_record_sources: packetRecordSources,
      packet_record_extraction: packetRecordExtraction,
      typed_field_schema: {
        schema: validatedSchema.schema,
        field_count: validatedSchema.fields.length,
        source: fieldSchemaSource,
        semantic_claim: null,
      },
      selected_routes: selectedRoutes,
      anchors: {
        ...anchorIndex.inventory(),
        rejected_anchor_count: normalizedAnchors.rejected_count,
        sources: anchorSources,
      },
    },
    route_profiles: routeProfiles,
    ranked_candidates: rankedCandidates.slice(0, options.maxRankedCandidates ?? 500),
    ranking_policy: {
      status: 'HEURISTIC_ONLY',
      promotion_authority: 'NONE',
      negative_controls_excluded: true,
      warning: 'Explicit types enable statistics only. Paths, categories, vectors, associations, and scores cannot establish semantics.',
    },
    limitations: [
      'Typed values are accepted only from explicit dotted paths declared by FIELD_BEHAVIOR_TYPED_FIELD_SCHEMA_V1.',
      'Strings are never decoded from arbitrary bytes; hash algorithms and identifier meanings are never inferred.',
      'Categorical anchor tests remain NOT_COMPUTABLE unless a future explicit test design is declared.',
      'Vector direction and coordinate-frame semantics remain NOT_COMPUTABLE; only configured components and Euclidean magnitude are summarized.',
      'Routes annotated NEGATIVE_CONTROL are excluded from candidate ranking.',
    ],
  };
}

function championMappingFromRecord(record, replayCache) {
  const explicitChampion = firstDefined(
    record?.champion,
    record?.target_champion,
    record?.entity_champion,
  );
  if (explicitChampion !== undefined && explicitChampion !== null && explicitChampion !== '') {
    return {
      champion: String(explicitChampion),
      participant_id: finiteNumber(record?.participant_id, record?.target_participant_id),
      source: 'EXPLICIT_PACKET_RECORD',
    };
  }
  const replayPath = firstDefined(record?.replay_path, record?.source_path);
  const networkId = finiteNumber(
    record?.entity_id,
    record?.entity_network_id,
    record?.raw_param,
    record?.param,
  );
  if (typeof replayPath !== 'string' || replayPath.length === 0 || !Number.isInteger(networkId)) {
    return null;
  }
  const resolvedPath = path.resolve(replayPath);
  if (!replayCache.has(resolvedPath)) {
    try {
      replayCache.set(resolvedPath, { replay: parseReplayFile(resolvedPath), error: null });
    } catch (error) {
      replayCache.set(resolvedPath, { replay: null, error: error.message });
    }
  }
  const cached = replayCache.get(resolvedPath);
  if (!cached.replay) return null;
  const participant = participantForNetworkId(networkId, cached.replay);
  if (!participant?.champion) return null;
  return {
    champion: participant.champion,
    participant_id: participant.participant_id,
    source: 'REPLAY_TAIL_PARTICIPANT_MAPPING',
  };
}

function packetRecordsFromHexField(records, hexField, options = {}) {
  if (!Array.isArray(records)) throw new TypeError('decoded packet rows must be an array');
  const accepted = [];
  const replayCache = new Map();
  const championMapping = {
    explicit_packet_record_count: 0,
    replay_tail_mapped_record_count: 0,
    unmapped_record_count: 0,
  };
  const rejected = {
    missing_hex_field: 0,
    invalid_hex: 0,
    not_fully_consumed: 0,
    wrong_build: 0,
  };
  for (let index = 0; index < records.length; index += 1) {
    const row = records[index];
    if (options.requireFullyConsumed !== false && row?.fully_consumed === false) {
      rejected.not_fully_consumed += 1;
      continue;
    }
    const build = firstDefined(row?.build, row?.game_version, row?.replay_version);
    if (options.targetBuild && build !== options.targetBuild) {
      rejected.wrong_build += 1;
      continue;
    }
    const hex = valueAtPath(row, hexField);
    if (hex === undefined || hex === null || hex === '') {
      rejected.missing_hex_field += 1;
      continue;
    }
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
      rejected.invalid_hex += 1;
      continue;
    }
    const mapping = options.enrichChampionFromReplayTail === false
      ? championMappingFromRecord({
        champion: firstDefined(row?.champion, row?.target_champion, row?.entity_champion),
        participant_id: firstDefined(row?.participant_id, row?.target_participant_id),
      }, replayCache)
      : championMappingFromRecord(row, replayCache);
    if (mapping?.source === 'EXPLICIT_PACKET_RECORD') championMapping.explicit_packet_record_count += 1;
    else if (mapping?.source === 'REPLAY_TAIL_PARTICIPANT_MAPPING') {
      championMapping.replay_tail_mapped_record_count += 1;
    } else championMapping.unmapped_record_count += 1;
    accepted.push(normalizePacketRecord({
      ...row,
      payload: Buffer.from(hex, 'hex'),
      raw_payload_hex: undefined,
      payload_source_field: hexField,
      champion: mapping?.champion ?? null,
      participant_id: mapping?.participant_id ?? null,
      sequence: Number.isSafeInteger(row.occurrence_index) ? row.occurrence_index : index,
    }, index));
  }
  return {
    records: accepted,
    input_row_count: records.length,
    accepted_row_count: accepted.length,
    rejected_row_count: Object.values(rejected).reduce((sum, count) => sum + count, 0),
    rejected,
    hex_field: hexField,
    require_fully_consumed: options.requireFullyConsumed !== false,
    champion_mapping: {
      ...championMapping,
      replay_source_count: replayCache.size,
      replay_parse_error_count: [...replayCache.values()].filter((entry) => entry.error).length,
      status: championMapping.explicit_packet_record_count
          + championMapping.replay_tail_mapped_record_count > 0
        ? 'AVAILABLE_DESCRIPTIVE_MAPPING'
        : 'UNAVAILABLE_NO_MAPPING',
    },
  };
}

function collectPacketRecordsFromExport(packetRecords, routeIds, options = {}) {
  if (!Array.isArray(packetRecords) || packetRecords.length === 0) {
    throw new TypeError('at least one decoded packet record is required');
  }
  const records = packetRecords.map((record, index) => normalizePacketRecord(record, index));
  const inferredRoutes = [...new Set(records.map((record) => record.packet_id))]
    .sort((left, right) => left - right);
  const routes = routeIds?.length > 0
    ? [...new Set(routeIds.map(numericPacketId))].sort((left, right) => left - right)
    : inferredRoutes;
  const routeSet = new Set(routes);
  const maximum = integerOption(
    options.maxObservationsPerRoute,
    25000,
    'maxObservationsPerRoute',
  );
  const reservoirs = new Map(routes.map((packetId) => [packetId, new RouteReservoir(packetId, maximum)]));
  const observedBuilds = new Set();
  const sourceMap = new Map();
  for (const record of records) {
    if (!routeSet.has(record.packet_id)) continue;
    if (options.targetBuild && record.build !== options.targetBuild) {
      throw new Error(`exact-build profiler expected ${options.targetBuild}; got ${record.build ?? 'UNKNOWN'}`);
    }
    if (record.build) observedBuilds.add(record.build);
    if (observedBuilds.size > 1) {
      throw new Error(`field behavior profiles cannot merge exact builds: ${[...observedBuilds].sort(strictCompare).join(', ')}`);
    }
    reservoirs.get(record.packet_id).observe(record);
    let source = sourceMap.get(record.replay_key);
    if (!source) {
      source = {
        source_path: record.source_path,
        source_sha256: record.replay_key,
        game_version: record.build,
        selected_record_count: 0,
        source_kind: 'DECODED_HEX_FIELD_EXPORT',
      };
      sourceMap.set(record.replay_key, source);
    }
    source.selected_record_count += 1;
  }
  return {
    sources: [...sourceMap.values()].sort((left, right) => strictCompare(left.source_sha256, right.source_sha256)),
    routes: new Map([...reservoirs.entries()].map(([packetId, reservoir]) => [packetId, {
      records: reservoir.records,
      observed_record_count: reservoir.seen,
      sampling_method: reservoir.seen > reservoir.records.length
        ? 'DETERMINISTIC_ALGORITHM_R_RESERVOIR'
        : 'ALL_SELECTED_RECORDS',
    }])),
  };
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function createFieldBehaviorProfile({
  replayPaths = [],
  packetRecords = null,
  packetRecordSources = [],
  packetRecordExtraction = null,
  routeIds,
  candidateReport = null,
  candidateReportPath = null,
  anchors = [],
  anchorSources = [],
  targetBuild = null,
  options = {},
} = {}) {
  const inferredPacketRoutes = Array.isArray(packetRecords)
    ? [...new Set(packetRecords.map((record) => numericPacketId(
      firstDefined(record.packet_id, record.packet_discriminator),
    )))].sort((left, right) => left - right)
    : [];
  const selectedRoutes = routeIds?.length > 0
    ? [...new Set(routeIds.map(numericPacketId))].map((packetId) => ({
      packet_id: packetId,
      packet_discriminator: formatOpcode(packetId),
      source_section: 'EXPLICIT_ROUTE',
      candidate_score: null,
      evidence_grade: 'CANDIDATE',
      structural_candidate_class: null,
      observed_count: null,
      route_role: options.routeRole ?? 'CANDIDATE',
      known_route_semantics: options.knownRouteSemantics ?? null,
    }))
    : candidateReport
      ? candidateRoutesFromReport(candidateReport, { maxRoutes: options.maxRoutes })
      : inferredPacketRoutes.map((packetId) => ({
        packet_id: packetId,
        packet_discriminator: formatOpcode(packetId),
        source_section: 'INFERRED_FROM_DECODED_PACKET_EXPORT',
        candidate_score: null,
        evidence_grade: 'CANDIDATE',
        structural_candidate_class: null,
        observed_count: null,
        route_role: options.routeRole ?? 'CANDIDATE',
        known_route_semantics: options.knownRouteSemantics ?? null,
      }));
  for (const selected of selectedRoutes) {
    if (!selected.route_role) selected.route_role = options.routeRole ?? 'CANDIDATE';
    if (!selected.known_route_semantics) selected.known_route_semantics = options.knownRouteSemantics ?? null;
  }
  if (selectedRoutes.length === 0) throw new Error('no candidate packet routes selected');
  const normalizedAnchors = normalizeAnchors(anchors);
  const anchorIndex = new AnchorIndex(normalizedAnchors.anchors);
  const inputMode = Array.isArray(packetRecords) ? 'DECODED_HEX_FIELD_EXPORT' : 'RAW_ROFL_PACKET_WALK';
  const collected = inputMode === 'DECODED_HEX_FIELD_EXPORT'
    ? collectPacketRecordsFromExport(
      packetRecords,
      selectedRoutes.map((row) => row.packet_id),
      { ...options, targetBuild },
    )
    : collectPacketRecordsFromReplayFiles(
      replayPaths,
      selectedRoutes.map((row) => row.packet_id),
      { ...options, targetBuild },
    );
  const routeProfiles = [];
  for (const selected of selectedRoutes) {
    const observed = collected.routes.get(selected.packet_id);
    if (!observed || observed.records.length === 0) {
      routeProfiles.push({
        packet_id: selected.packet_id,
        packet_discriminator: selected.packet_discriminator,
        build: targetBuild,
        route_role: selected.route_role,
        known_route_semantics: selected.known_route_semantics,
        excluded_from_combat_state_ranking: selected.route_role === 'NEGATIVE_CONTROL',
        status: 'UNAVAILABLE_NOT_OBSERVED_IN_INPUT',
        observed_record_count: 0,
        profiled_record_count: 0,
        primitive_fields: [],
        bitfield_candidates: [],
        packed_field_candidates: [],
        configured_fields: [],
      });
      continue;
    }
    routeProfiles.push({
      status: selected.route_role === 'NEGATIVE_CONTROL'
        ? 'NEGATIVE_CONTROL_PROFILE_AVAILABLE'
        : 'CANDIDATE_PROFILE_AVAILABLE',
      route_role: selected.route_role,
      known_route_semantics: selected.known_route_semantics,
      excluded_from_combat_state_ranking: selected.route_role === 'NEGATIVE_CONTROL',
      route_selection: selected,
      ...profileRouteRecords(observed.records, {
        ...options,
        anchorIndex,
        observedRecordCount: observed.observed_record_count,
        samplingMethod: observed.sampling_method,
        payloadSource: packetRecordExtraction?.hex_field ?? undefined,
      }),
    });
  }
  const rankedCandidates = routeProfiles.filter((route) => !route.excluded_from_combat_state_ranking)
    .flatMap((route) => [
    ...(route.primitive_fields ?? []),
    ...(route.bitfield_candidates ?? []),
    ...(route.packed_field_candidates ?? []),
    ...(route.configured_fields ?? []),
  ].map((field) => ({
    packet_id: route.packet_id,
    packet_discriminator: route.packet_discriminator,
    field_id: field.field_id,
    offset: field.offset,
    type: field.type,
    heuristic_candidate_score: field.heuristic_candidate_score,
    evidence_grade: 'CANDIDATE',
    semantic_claim: null,
  }))).sort((left, right) => right.heuristic_candidate_score - left.heuristic_candidate_score
    || left.packet_id - right.packet_id
    || left.offset - right.offset
    || strictCompare(left.type, right.type));
  rankedCandidates.forEach((row, index) => { row.heuristic_candidate_rank = index + 1; });
  const candidateReportProvenance = candidateReportPath ? {
    source_path: path.resolve(candidateReportPath),
    source_sha256: sha256File(candidateReportPath),
    schema: candidateReport?.schema ?? candidateReport?.schema_version ?? null,
  } : null;
  return {
    schema: FIELD_BEHAVIOR_SCHEMA_VERSION,
    schema_version: 1,
    analyzer_version: ANALYZER_VERSION,
    exact_build_only: true,
    target_build: targetBuild ?? collected.sources[0]?.game_version ?? null,
    evidence_grade: 'CANDIDATE',
    semantic_status: 'FIELD_BEHAVIOR_CANDIDATE_RANKING_ONLY',
    semantic_claim: null,
    field_type_support: {
      primitive: Object.keys(PRIMITIVE_TYPES),
      bitfield_candidates: true,
      packed_field_candidates: [
        'automatic_uint2_lanes',
        'automatic_uint4_lanes',
        'configured_lsb0_unsigned_or_signed_width_1_to_64',
      ],
      configured_raw_fields: 'EXPLICIT_SCHEMA_ONLY',
      typed_decoded_field_adapter: TYPED_FIELD_SCHEMA_VERSION,
      typed_schema_absence_status: 'UNAVAILABLE_REQUIRES_EXPLICIT_SCHEMA',
      byte_order: 'little_endian_for_multibyte_primitives',
    },
    coverage_matrix: FIELD_BEHAVIOR_COVERAGE_MATRIX,
    input: {
      input_mode: inputMode,
      replay_count: collected.sources.length,
      replays: collected.sources,
      packet_record_sources: packetRecordSources,
      packet_record_extraction: packetRecordExtraction,
      selected_routes: selectedRoutes,
      candidate_report: candidateReportProvenance,
      anchors: {
        ...anchorIndex.inventory(),
        rejected_anchor_count: normalizedAnchors.rejected_count,
        sources: anchorSources,
      },
    },
    route_profiles: routeProfiles,
    ranked_candidates: rankedCandidates.slice(0, options.maxRankedCandidates ?? 500),
    ranking_policy: {
      status: 'HEURISTIC_ONLY',
      promotion_authority: 'NONE',
      negative_controls_excluded: true,
      warning: 'Offsets, numeric behavior, correlations, and heuristic scores rank unknown candidates only. They do not identify HP, defenses, resources, or any other semantic field.',
    },
    limitations: [
      'Fixed-offset reads describe raw payload bytes and may cross variable-length or encoded fields.',
      'NaN and infinite float interpretations are counted as invalid observations and excluded from numeric summaries.',
      'Correlation is computed only for same-Replay, same-entity anchors bracketed by sampled observations within the configured window.',
      'Missing anchors remain unavailable and never become observed zero correlation.',
      'Reservoir sampling is deterministic and explicitly reported when a route exceeds the configured observation cap.',
      'Per-champion output is descriptive packet-field behavior, not player or champion behavioral inference.',
      'When a decoded object/blob hex field is profiled, offsets are relative to that exact exported field rather than the original Replay payload.',
      'Routes annotated NEGATIVE_CONTROL are excluded from combat-state candidate ranking even if generic correlations are numerically large.',
      'Configured cross-byte/packed fields use explicit LSB0 little-endian ranges; varint codecs remain unavailable without an exact declared codec.',
      '64-bit integers retain exact decimal-string ranges and deltas; mean/variance are partial or unavailable when values cannot be projected exactly into IEEE-754 safe integers.',
    ],
  };
}

function writeFieldBehaviorProfile(outputPath, report) {
  const target = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  return target;
}

module.exports = {
  ANALYZER_VERSION,
  ANCHOR_TYPES,
  AnchorIndex,
  DeterministicReservoir,
  FIELD_BEHAVIOR_SCHEMA_VERSION,
  FIELD_BEHAVIOR_COVERAGE_MATRIX,
  RAW_FIELD_SCHEMA_VERSION,
  TYPED_FIELD_SCHEMA_VERSION,
  PRIMITIVE_TYPES,
  RunningStats,
  bitAndPackedFieldDefinitions,
  candidateRoutesFromReport,
  canonicalAnchorType,
  cleanNumber,
  collectPacketRecordsFromExport,
  collectPacketRecordsFromReplayFiles,
  configuredRawFieldDefinitions,
  createFieldBehaviorProfile,
  createTypedFieldBehaviorProfile,
  heuristicCandidateScore,
  normalizeAnchor,
  normalizeAnchors,
  normalizePacketRecord,
  numericPacketId,
  packetRecordsFromHexField,
  parseTypedNumeric,
  primitiveFieldDefinitions,
  profileRouteRecords,
  profileTypedRouteRecords,
  readField,
  readPackedBitsLE,
  strictCompare,
  valueAtPath,
  typedPacketRecordsFromDecodedFields,
  validateTypedFieldSchema,
  writeFieldBehaviorProfile,
};
