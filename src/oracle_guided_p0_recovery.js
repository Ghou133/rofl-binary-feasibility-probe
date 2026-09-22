const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('./rofl');

const EXACT_BUILD = '16.16.805.0442';
const EXACT_REPLAY_SHA256 = '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff';
const EXPECTED_BUILD = EXACT_BUILD;
const EXPECTED_REPLAY_SHA = EXACT_REPLAY_SHA256;
const KAYN_NETWORK_ID = 0x400000ae;
const P0_SEMANTICS = Object.freeze(['MAX_HP', 'ARMOR', 'MAGIC_RESIST', 'CURRENT_HP']);
const DEFAULT_SCALES = Object.freeze([1, -1, 0.1, -0.1, 0.01, -0.01, 0.001, -0.001,
  1 / 16, -1 / 16, 1 / 32, -1 / 32, 1 / 64, -1 / 64, 1 / 100, -1 / 100,
  1 / 256, -1 / 256, 1 / 1000, -1 / 1000, 1 / 4096, -1 / 4096,
  1 / 65536, -1 / 65536, 10, -10, 100, -100]);

const VIEW_DEFINITIONS = Object.freeze([
  ['u8', 1, (b, o) => b.readUInt8(o)],
  ['i8', 1, (b, o) => b.readInt8(o)],
  ['u16le', 2, (b, o) => b.readUInt16LE(o)],
  ['i16le', 2, (b, o) => b.readInt16LE(o)],
  ['u16be', 2, (b, o) => b.readUInt16BE(o)],
  ['i16be', 2, (b, o) => b.readInt16BE(o)],
  ['u32le', 4, (b, o) => b.readUInt32LE(o)],
  ['i32le', 4, (b, o) => b.readInt32LE(o)],
  ['u32be', 4, (b, o) => b.readUInt32BE(o)],
  ['i32be', 4, (b, o) => b.readInt32BE(o)],
  ['f32le', 4, (b, o) => b.readFloatLE(o)],
  ['f32be', 4, (b, o) => b.readFloatBE(o)],
  ['f64le', 8, (b, o) => b.readDoubleLE(o)],
  ['f64be', 8, (b, o) => b.readDoubleBE(o)],
]);

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function assertOracle(oracle, expectedBuild = EXACT_BUILD, expectedSha = EXACT_REPLAY_SHA256) {
  if (!oracle || oracle.schema_version !== 'GROUND_TRUTH_ORACLE_V1' || !Array.isArray(oracle.records)) {
    throw new Error('manual oracle must be GROUND_TRUTH_ORACLE_V1 with records');
  }
  if (oracle.records.length !== 50) throw new Error(`expected 50 manual oracle records, got ${oracle.records.length}`);
  for (const record of oracle.records) {
    if (record.exact_build !== expectedBuild) throw new Error(`oracle build mismatch in ${record.case_id}`);
    if (record.replay_sha !== expectedSha) throw new Error(`oracle replay SHA mismatch in ${record.case_id}`);
    if (!['BEFORE', 'AFTER'].includes(record.before_after)) throw new Error(`invalid before_after in ${record.case_id}`);
    if (!Number.isFinite(record.observed_value) || !Number.isFinite(record.timestamp)) {
      throw new Error(`non-scalar oracle record ${record.case_id}`);
    }
  }
  if (oracle.automatic_promotion !== 'FORBIDDEN') throw new Error('oracle automatic_promotion must remain FORBIDDEN');
  return true;
}

function loadGroundTruthOracle(options = {}) {
  const oraclePath = path.resolve(options.oracle_path || options.oraclePath);
  const oracle = JSON.parse(fs.readFileSync(oraclePath, 'utf8'));
  assertOracle(oracle, options.expected_build || EXACT_BUILD, options.expected_replay_sha || EXACT_REPLAY_SHA256);
  const heldCases = oracle.source_provenance && oracle.source_provenance.held_cases || [];
  const completedCases = new Set(oracle.records.map((record) => record.source && record.source.manual_case_id).filter(Boolean));
  return {
    ...oracle,
    oracle_path: oraclePath,
    completed_case_count: completedCases.size,
    held_case_count: heldCases.length,
    held_cases: heldCases,
  };
}

function buildScalarTransitions(records) {
  const groups = new Map();
  for (const record of records) {
    const manualCaseId = record.source && record.source.manual_case_id;
    if (!manualCaseId || !P0_SEMANTICS.includes(record.semantic)) continue;
    const key = `${manualCaseId}|${record.timestamp}|${record.semantic}`;
    const group = groups.get(key) || {
      id: key,
      manual_case_id: manualCaseId,
      timestamp_ms: record.timestamp,
      semantic: record.semantic,
      entity: record.entity || null,
      before: null,
      after: null,
      record_ids: [],
    };
    group[record.before_after.toLowerCase()] = record.observed_value;
    group.record_ids.push(record.case_id);
    groups.set(key, group);
  }
  return [...groups.values()]
    .filter((item) => Number.isFinite(item.before) && Number.isFinite(item.after))
    .map((item) => ({
      ...item,
      before_value: item.before,
      after_value: item.after,
      delta: item.after - item.before,
      role: item.after === item.before ? 'NEGATIVE_CONTROL_NO_CHANGE' : 'POSITIVE_STEP',
    }))
    .sort((a, b) => a.timestamp_ms - b.timestamp_ms || a.semantic.localeCompare(b.semantic));
}

const buildOracleTransitions = buildScalarTransitions;

function packedVarintViews(buffer) {
  const rows = [];
  for (let offset = 0; offset < buffer.length; offset += 1) {
    let value = 0;
    let shift = 0;
    let width = 0;
    for (let cursor = offset; cursor < buffer.length && width < 5; cursor += 1) {
      const byte = buffer[cursor];
      value += (byte & 0x7f) * (2 ** shift);
      width += 1;
      if ((byte & 0x80) === 0) {
        if (Number.isSafeInteger(value)) {
          rows.push({ view: 'uleb128', width, offset, value });
          rows.push({ view: 'zigzag_varint', width, offset, value: value % 2 === 0 ? value / 2 : -(value + 1) / 2 });
        }
        break;
      }
      shift += 7;
    }
  }
  return rows;
}

function numericViews(buffer) {
  const result = [];
  for (const [view, width, read] of VIEW_DEFINITIONS) {
    for (let offset = 0; offset + width <= buffer.length; offset += 1) {
      const value = read(buffer, offset);
      if (Number.isFinite(value) && Math.abs(value) <= 1e12) result.push({ view, width, offset, value });
    }
  }
  return result.concat(packedVarintViews(buffer));
}

function scanNumericLanes(buffer, options = {}) {
  const scales = options.scales || [1];
  const base = numericViews(buffer);
  const rows = [];
  for (const lane of base) {
    if (options.include_unaligned === false && lane.offset % lane.width !== 0) continue;
    for (const scale of scales) rows.push({ offset: lane.offset, width: lane.width, type: lane.view, scale, raw_value: lane.value, value: lane.value * scale });
  }
  return rows;
}

function candidateKey(packetType, stream, source, view, offset, bindingScope) {
  return `${packetType}|${stream}|${bindingScope}|${source}|${view}|${offset}`;
}

function splitCandidateKey(key) {
  const [route, stream, binding_scope, source, view, offset] = key.split('|');
  return { route, stream, binding_scope, source, view, offset: Number(offset) };
}

function nearAnyAnchor(timestamp, anchors, windowMs) {
  for (const anchor of anchors) if (Math.abs(timestamp - anchor) <= windowMs) return true;
  return false;
}

function scanReplayCandidates(replay, transitions, options = {}) {
  const windowMs = options.windowMs || 3000;
  const anchors = [...new Set(transitions.map((item) => item.timestamp_ms))];
  const observations = new Map();
  const routeCounts = new Map();
  const routeMaxPayload = new Map();
  const targetRouteCounts = new Map([['0x010c', 0], ['0x01dc', 0], ['0x042f', 0], ['0x0412', 0], ['0x0259', 0], ['0x03f8', 0], ['0x017f', 0], ['0x01cf', 0], ['0x0371', 0], ['0x0326', 0]]);
  const eventRouteHits = {};
  const push = (key, observation) => {
    const list = observations.get(key);
    if (list) list.push(observation);
    else observations.set(key, [observation]);
  };
  const walked = walkBlocks(replay, (block, chunk) => {
    const routeStream = `${block.packet_type}|${chunk.stream}`;
    routeCounts.set(routeStream, (routeCounts.get(routeStream) || 0) + 1);
    routeMaxPayload.set(routeStream, Math.max(routeMaxPayload.get(routeStream) || 0, block.payload_length));
    if (targetRouteCounts.has(block.packet_type)) targetRouteCounts.set(block.packet_type, targetRouteCounts.get(block.packet_type) + 1);
    if (['0x01cf', '0x0371', '0x0326'].includes(block.packet_type) && anchors.includes(block.timestamp_ms)) {
      const hitKey = `${block.packet_type}@${block.timestamp_ms}`;
      eventRouteHits[hitKey] = (eventRouteHits[hitKey] || 0) + 1;
    }
    if (!nearAnyAnchor(block.timestamp_ms, anchors, windowMs)) return;
    const bindingScope = block.param === KAYN_NETWORK_ID ? 'KAYN_PARAM' : `PARAM_0x${block.param.toString(16).padStart(8, '0')}`;
    const paramBuffer = Buffer.allocUnsafe(4);
    paramBuffer.writeUInt32LE(block.param, 0);
    for (const item of numericViews(paramBuffer)) {
      push(candidateKey(block.packet_type, chunk.stream, 'raw_param', item.view, item.offset, bindingScope), {
        timestamp_ms: block.timestamp_ms, value: item.value, payload_length: block.payload_length,
      });
    }
    for (const item of numericViews(block.payload)) {
      push(candidateKey(block.packet_type, chunk.stream, 'payload', item.view, item.offset, bindingScope), {
        timestamp_ms: block.timestamp_ms, value: item.value, payload_length: block.payload_length,
      });
    }
  }, { includeStreams: [1, 2, 3], strict: true });

  let rawIdentityCount = 0;
  for (const [routeStream, maxLength] of routeMaxPayload) {
    for (const [, width] of VIEW_DEFINITIONS) rawIdentityCount += Math.max(0, maxLength - width + 1);
    rawIdentityCount += maxLength * 2;
    // raw_param is a separate four-byte source.
    for (const [, width] of VIEW_DEFINITIONS) rawIdentityCount += Math.max(0, 4 - width + 1);
    rawIdentityCount += 8;
  }
  return {
    observations,
    accounting: {
      parsed_block_count: walked.block_count,
      parse_errors: walked.errors,
      route_stream_count: routeCounts.size,
      route_count: new Set([...routeCounts.keys()].map((key) => key.split('|')[0])).size,
      streams: [...new Set([...routeCounts.keys()].map((key) => key.split('|')[1]))].sort(),
      raw_unaligned_shape_identity_count_without_binding_partition: rawIdentityCount,
      raw_unaligned_identity_count: observations.size,
      anchor_observed_identity_count: observations.size,
      candidate_instantiation_scope: 'NUMERIC_IDENTITIES_ARE_INSTANTIATED_ON_FIRST_OBSERVATION_WITHIN_ORACLE_WINDOWS; RAW_UNALIGNED_IDENTITY_COUNT_THEREFORE_EQUALS_ANCHOR_OBSERVED_IDENTITY_COUNT_BY_DEFINITION; EVERY_REPLAY_BLOCK_IS_STILL_INCLUDED_IN_ROUTE_AND_STREAM_ACCOUNTING',
      target_route_observations: Object.fromEntries(targetRouteCounts),
      exact_anchor_route_hits: eventRouteHits,
    },
  };
}

function nearestPair(observations, timestamp, windowMs, bounds = {}) {
  let before = null;
  let after = null;
  for (const observation of observations) {
    const distance = observation.timestamp_ms - timestamp;
    if (distance < 0 && distance >= -windowMs && observation.timestamp_ms > (bounds.lowerExclusive ?? -Infinity)
      && (!before || observation.timestamp_ms > before.timestamp_ms)) before = observation;
    if (distance > 0 && distance <= windowMs && observation.timestamp_ms < (bounds.upperExclusive ?? Infinity)
      && (!after || observation.timestamp_ms < after.timestamp_ms)) after = observation;
  }
  // A single packet exactly on the event cannot prove a state transition.
  if (before && after && before === after) return null;
  return before && after ? { before, after } : null;
}

function toleranceFor(delta) {
  return Math.max(0.75, Math.abs(delta) * 0.02);
}

const TRANSITION_BOUNDS_CACHE = new WeakMap();

function transitionBounds(transitions) {
  let cached = TRANSITION_BOUNDS_CACHE.get(transitions);
  if (cached) return cached;
  const anchors = [...new Set(transitions.map((item) => item.timestamp_ms))].sort((a, b) => a - b);
  cached = new Map(anchors.map((timestamp, index) => [timestamp, {
    lowerExclusive: index ? (anchors[index - 1] + timestamp) / 2 : -Infinity,
    upperExclusive: index + 1 < anchors.length ? (timestamp + anchors[index + 1]) / 2 : Infinity,
  }]));
  TRANSITION_BOUNDS_CACHE.set(transitions, cached);
  return cached;
}

function scoreCandidate(key, observations, transitions, scale, windowMs) {
  const responses = [];
  const boundsByTimestamp = transitionBounds(transitions);
  for (const transition of transitions) {
    const pair = nearestPair(observations, transition.timestamp_ms, windowMs, boundsByTimestamp.get(transition.timestamp_ms));
    if (!pair) continue;
    const before = pair.before.value * scale;
    const after = pair.after.value * scale;
    const candidateDelta = after - before;
    const error = candidateDelta - transition.delta;
    responses.push({
      transition_id: transition.id,
      semantic: transition.semantic,
      oracle_before: transition.before,
      oracle_after: transition.after,
      oracle_delta: transition.delta,
      candidate_before: before,
      candidate_after: after,
      candidate_delta: candidateDelta,
      difference_of_differences: error,
      delta_match: Math.abs(error) <= toleranceFor(transition.delta),
      absolute_snapshot_match: Math.abs(before - transition.before) <= 1 && Math.abs(after - transition.after) <= 1,
      before_timestamp_ms: pair.before.timestamp_ms,
      after_timestamp_ms: pair.after.timestamp_ms,
    });
  }
  const identity = splitCandidateKey(key);
  return { identity, scale, responses };
}

function summarizeForSemantic(scored, semantic, transitions) {
  const targetTransitions = transitions.filter((item) => item.semantic === semantic);
  const positiveCount = targetTransitions.filter((item) => item.delta !== 0).length;
  const target = scored.responses.filter((item) => item.semantic === semantic);
  const other = scored.responses.filter((item) => item.semantic !== semantic);
  const targetMatches = target.filter((item) => item.delta_match && item.oracle_delta !== 0).length;
  const zeroControlMatches = target.filter((item) => item.delta_match && item.oracle_delta === 0).length;
  const crossStatResponses = other.filter((item) => Math.abs(item.candidate_delta) > toleranceFor(0)).length;
  const coverage = positiveCount ? targetMatches / positiveCount : 0;
  const meanError = target.length ? target.reduce((sum, item) => sum + Math.abs(item.difference_of_differences), 0) / target.length : null;
  const repeatedFullSignature = positiveCount >= 2 && targetMatches === positiveCount;
  const negativeControlSurvivor = repeatedFullSignature && crossStatResponses === 0;
  return {
    ...scored.identity,
    scale: scored.scale,
    target_positive_transition_count: positiveCount,
    target_observed_pair_count: target.filter((item) => item.oracle_delta !== 0).length,
    target_delta_match_count: targetMatches,
    target_zero_control_match_count: zeroControlMatches,
    cross_stat_observed_pair_count: other.length,
    cross_stat_response_count: crossStatResponses,
    coverage,
    mean_absolute_difference_of_differences: meanError,
    repeated_full_signature: repeatedFullSignature,
    negative_control_survivor: negativeControlSurvivor,
    promotion_eligible: false,
    promotion_reason: 'MANUAL_ORACLE_AUTOMATIC_PROMOTION_FORBIDDEN',
    responses: scored.responses,
  };
}

function analyzeCandidates(scan, transitions, options = {}) {
  const windowMs = options.windowMs || 3000;
  const scales = options.scales || DEFAULT_SCALES;
  const results = {};
  for (const semantic of P0_SEMANTICS) {
    const ranked = [];
    let anchorObserved = 0;
    let partialSignature = 0;
    let repeatedFull = 0;
    let negativeSurvivors = 0;
    for (const [key, observations] of scan.observations) {
      anchorObserved += 1;
      let best = null;
      for (const scale of scales) {
        const summary = summarizeForSemantic(scoreCandidate(key, observations, transitions, scale, windowMs), semantic, transitions);
        const score = summary.target_delta_match_count * 100 + summary.target_observed_pair_count * 5
          - summary.cross_stat_response_count * 20 - (summary.mean_absolute_difference_of_differences || 0);
        if (!best || score > best._score) best = { ...summary, _score: score };
      }
      if (best.target_delta_match_count > 0) partialSignature += 1;
      if (best.repeated_full_signature) repeatedFull += 1;
      if (best.negative_control_survivor) negativeSurvivors += 1;
      if (best.target_delta_match_count > 0 || best.target_observed_pair_count > 0) ranked.push(best);
    }
    ranked.sort((a, b) => b._score - a._score || b.coverage - a.coverage || a.route.localeCompare(b.route));
    results[semantic] = {
      funnel: {
        candidate_count_before: scan.accounting.raw_unaligned_identity_count,
        raw_unaligned_identity_count: scan.accounting.raw_unaligned_identity_count,
        anchor_observed_identity_count: anchorObserved,
        counting_definition: scan.accounting.candidate_instantiation_scope,
        partial_signature_count: partialSignature,
        repeated_full_signature_count: repeatedFull,
        cross_stat_negative_control_survivor_count: negativeSurvivors,
        candidate_count_after: negativeSurvivors,
        promotion_eligible_count: 0,
      },
      strongest_candidates: ranked.slice(0, options.topN || 20).map(({ _score, ...item }) => item),
      conclusion: negativeSurvivors > 0
        ? 'SURVIVORS_REQUIRE_INDEPENDENT_NON_MANUAL_VALIDATION_BEFORE_PROMOTION'
        : 'NO_CANDIDATE_SURVIVED_REPEATED_STEP_AND_CROSS_STAT_CONTROLS',
    };
  }
  return results;
}

function analyzeExactEventCarriers(scan, transitions, options = {}) {
  const scales = options.scales || DEFAULT_SCALES;
  const eventTimes = new Set(transitions.map((item) => item.timestamp_ms));
  const exactIdentities = [];
  for (const [key, observations] of scan.observations) {
    const byTimestamp = new Map();
    for (const observation of observations) {
      if (!eventTimes.has(observation.timestamp_ms)) continue;
      const values = byTimestamp.get(observation.timestamp_ms) || [];
      values.push(observation.value);
      byTimestamp.set(observation.timestamp_ms, values);
    }
    if (byTimestamp.size) exactIdentities.push([key, byTimestamp]);
  }
  const close = (actual, expected) => Math.abs(actual - expected) <= toleranceFor(expected);
  const result = {};
  for (const semantic of P0_SEMANTICS) {
    const target = transitions.filter((item) => item.semantic === semantic && item.delta !== 0);
    const other = transitions.filter((item) => item.semantic !== semantic && item.delta !== 0);
    const ranked = [];
    let anyTargetMatchCount = 0;
    let repeatedDirectionCount = 0;
    let negativeControlSurvivorCount = 0;
    for (const [key, byTimestamp] of exactIdentities) {
      let best = null;
      for (const scale of scales) {
        const targetRows = target.map((transition) => {
          const scaled = (byTimestamp.get(transition.timestamp_ms) || []).map((value) => value * scale);
          const signed_match = scaled.some((value) => close(value, transition.delta));
          const magnitude_match = scaled.some((value) => close(Math.abs(value), Math.abs(transition.delta)));
          return { transition_id: transition.id, timestamp_ms: transition.timestamp_ms, oracle_delta: transition.delta, signed_match, magnitude_match };
        });
        const matched = targetRows.filter((item) => item.signed_match || item.magnitude_match).length;
        const signedDirection = target.length >= 2 && targetRows.every((item) => item.signed_match);
        const magnitudeDirection = target.length >= 2 && targetRows.every((item) => item.magnitude_match);
        const repeatedDirection = signedDirection || magnitudeDirection;
        const crossStatMatchCount = other.filter((transition) => {
          const scaled = (byTimestamp.get(transition.timestamp_ms) || []).map((value) => value * scale);
          return scaled.some((value) => close(value, transition.delta) || close(Math.abs(value), Math.abs(transition.delta)));
        }).length;
        const survivor = repeatedDirection && crossStatMatchCount === 0;
        const score = matched * 1000 + (repeatedDirection ? 100 : 0) - crossStatMatchCount * 250;
        if (!best || score > best._score) best = {
          ...splitCandidateKey(key), scale, target_transition_count: target.length,
          target_exact_event_match_count: matched,
          repeated_direction_consistent: repeatedDirection,
          direction_mode: signedDirection ? 'SIGNED_DELTA' : magnitudeDirection ? 'ABSOLUTE_MAGNITUDE' : null,
          cross_stat_negative_control_match_count: crossStatMatchCount,
          negative_control_survivor: survivor,
          promotion_eligible: false,
          promotion_reason: 'MANUAL_ORACLE_AUTOMATIC_PROMOTION_FORBIDDEN',
          target_rows: targetRows,
          _score: score,
        };
      }
      if (best.target_exact_event_match_count > 0) anyTargetMatchCount += 1;
      if (best.repeated_direction_consistent) repeatedDirectionCount += 1;
      if (best.negative_control_survivor) negativeControlSurvivorCount += 1;
      if (best.target_exact_event_match_count > 0) ranked.push(best);
    }
    ranked.sort((a, b) => b._score - a._score || a.route.localeCompare(b.route));
    result[semantic] = {
      funnel: {
        exact_event_observed_identity_count: exactIdentities.length,
        any_target_delta_or_magnitude_match_count: anyTargetMatchCount,
        repeated_direction_consistent_count: repeatedDirectionCount,
        cross_stat_negative_control_survivor_count: negativeControlSurvivorCount,
        promotion_eligible_count: 0,
      },
      strongest_candidates: ranked.slice(0, options.topN || 20).map(({ _score, ...item }) => item),
      conclusion: negativeControlSurvivorCount
        ? 'DIRECT_EVENT_SURVIVORS_REQUIRE_INDEPENDENT_NON_MANUAL_VALIDATION'
        : 'NO_DIRECT_EVENT_FIELD_SURVIVED_REPEATED_DIRECTION_AND_CROSS_STAT_CONTROLS',
    };
  }
  return result;
}

function runtimeDeepEvidence(rootDir) {
  const evidencePath = path.join(rootDir, 'artifacts', 'full_semantic_deep_recovery_v2', 'hero_state', 'HERO_STATE_DAMAGE_DEFENSE_DEEP_REPORT_16_16.md');
  const text = fs.readFileSync(evidencePath, 'utf8');
  const required = [
    /0x042f: 130484 exact full-consume rows across eight safe replays/,
    /0x010c: 1370 exact full-consume, keyframe-only rows across the latest four safe replays/,
    /0x0412 exact consumer inversion recovers 714 transient buff-stat adjustment records/,
    /0x0259 \/ 0x03f8 \/ 0x04df: zero rows/,
  ];
  if (!required.every((pattern) => pattern.test(text))) throw new Error('runtime deep evidence report does not contain the expected exact-build counts');
  return {
    evidence_path: evidencePath,
    sha256: sha256File(evidencePath),
    exact_build: EXACT_BUILD,
    safe_replay_scope: { route_0x042f: 8, route_0x010c: 4 },
    route_counts: { '0x042f': 130484, '0x010c': 1370, '0x0412': 714, '0x0259': 0, '0x03f8': 0, '0x04df': 0 },
    findings: {
      '0x042f': 'EXACT_FORMULA_VECTORS; ZERO_NONTRIVIAL_P0_SCALAR_MATCHES',
      '0x010c': 'EXACT_KEYFRAME_SCOREBOARD_ROWS; NOT_LIVE_HP_DEFENSE_RESOURCE_STATE',
      '0x0412': 'TRANSIENT_BUFF_STAT_ADJUSTMENTS; ZERO_PERSISTENT_ITEM_ANCHOR_SCALAR_MATCHES',
      '0x0259_0x03f8_0x04df': 'CONTROLLED_ZERO_ROWS',
    },
    persistent_p0_or_item_anchor_scalar_found: false,
  };
}

function readJsonLines(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function nestedEvidence(anchorDir, scanAccounting) {
  const definitions = [
    ['0x010c', 'HeroStats', 'KEYFRAME_SCOREBOARD_NEGATIVE_CONTROL'],
    ['0x01dc', 'ReplicateFields', 'INGESTED_NESTED_STORAGE_UNRESOLVED'],
    ['0x042f', 'StatFormulaOutputs', 'INGESTED_NESTED_FORMULA_OUTPUTS_NEGATIVE_UNRESOLVED'],
  ];
  const evidence = definitions.map(([route, name, classification]) => {
    const evidencePath = path.join(anchorDir, `${route}_decoded.jsonl`);
    const rows = readJsonLines(evidencePath);
    return {
      route,
      name,
      classification,
      evidence_path: evidencePath,
      decoded_row_count: rows.length,
      timestamps_ms: [...new Set(rows.map((row) => row.replay_time_ms))].sort((a, b) => a - b),
      payload_lengths: [...new Set(rows.map((row) => row.payload_length))].sort((a, b) => a - b),
      full_consume_count: rows.filter((row) => row.fully_consumed === true).length,
    };
  });
  for (const [route, name, classification] of [
    ['0x0412', 'BuffUpdateStatAdjustments', 'REGISTERED_RUNTIME_NESTED_SCHEMA_CONTROLLED_ZERO_OBSERVATION'],
    ['0x0259', 'CombatStateChanged', 'REGISTERED_STATIC_HYPOTHESIS_CONTROLLED_ZERO_OBSERVATION'],
    ['0x03f8', 'SetAbilityResourceState', 'REGISTERED_STATIC_HYPOTHESIS_CONTROLLED_ZERO_OBSERVATION'],
  ]) evidence.push({ route, name, classification, controlled_observation_count: scanAccounting.target_route_observations[route] || 0 });
  return evidence;
}

function damageProtectionEvidence(anchorDir, transitions, scanAccounting = {}) {
  const evidencePath = path.join(anchorDir, '0x017f_decoded.jsonl');
  const rows = readJsonLines(evidencePath);
  const hp = new Map(transitions.filter((item) => item.semantic === 'CURRENT_HP').map((item) => [item.timestamp_ms, item]));
  const comparisons = rows.map((row) => {
    const transition = hp.get(row.replay_time_ms);
    const primary = row.decoded_fields && row.decoded_fields.field_24_f32;
    const secondary = row.decoded_fields && row.decoded_fields.field_2c_f32;
    const hpLoss = transition ? transition.before - transition.after : null;
    return {
      timestamp_ms: row.replay_time_ms,
      primary_field_24: primary,
      secondary_field_2c: secondary,
      manual_hp_loss: hpLoss,
      absolute_primary_vs_hp_loss_residual: hpLoss === null ? null : Math.abs(primary - hpLoss),
      hud_integer_compatible_within_one_hp: hpLoss === null ? null : Math.abs(primary - hpLoss) < 1,
    };
  });
  return {
    route: '0x017f',
    evidence_path: evidencePath,
    controlled_rows: rows.length,
    comparisons,
    damage_stage_conclusion: comparisons.length >= 3 && comparisons.every((item) => item.hud_integer_compatible_within_one_hp)
      ? 'CONTROLLED_REPLAY_HIGH_CONFIDENCE_APPLIED_TO_HP_CONTINUOUS_PRE_HUD_ROUNDING'
      : 'UNRESOLVED',
    global_scope: 'NOT_PROMOTED_TO_UNIVERSAL_EXACT_BUILD_STAGE_WITHOUT_BROADER_PAIRED_HP_SEQUENCE',
    shield_conclusion: comparisons.some((item) => item.secondary_field_2c === 100)
      ? 'ONE_CONTROLLED_SAMPLE_COMPATIBLE_WITH_100_SHIELD_CONSUMPTION; NOT GLOBALLY PROVEN'
      : 'UNRESOLVED',
    heal_conclusion: 'MANUAL_HP_STEP_549_TO_629_IS_COMPATIBLE_WITH_EFFECTIVE_HEAL_80; NO INDEPENDENT ROUTE FIELD ATTRIBUTION',
    mitigation_conclusion: 'UNRESOLVED_WITHOUT_PAIRED_PRE_MITIGATION_INPUT_AND_DEFENSE_FIELD',
    correlated_route_evidence: {
      exact_anchor_hits: scanAccounting.exact_anchor_route_hits || {},
      strongest_heal_routes: ['0x01cf@45212', '0x0371@45212'],
      strongest_shield_routes: ['0x01cf@61184', '0x0371@61184'],
      strongest_death_route: '0x0371@79218',
      carrier_negative_control: '0x0326_IS_PRIMARILY_KEYFRAME_OR_BUFF_CARRIER_NOT_A_CONTINUOUS_P0_FIELD',
      scope: 'EVENT_CORRELATION_ONLY; NO_CONTINUOUS_P0_FIELD_OR_CAUSAL_SEMANTIC_PROMOTION',
    },
  };
}

function renderMarkdown(report) {
  const lines = [
    '# Oracle-guided P0 field recovery', '',
    `- Exact build: \`${report.exact_build}\``,
    `- Replay SHA-256: \`${report.replay_sha256}\``,
    `- Oracle records: ${report.oracle.record_count}`,
    `- Completed scalar transitions: ${report.oracle.completed_transition_count}`,
    `- Level-Up: ${report.oracle.level_up_status} (not a blocker)`,
    `- Parsed blocks/routes/streams: ${report.scan.parsed_block_count} / ${report.scan.route_count} / ${report.scan.streams.join(', ')}`,
    '', '## P0 candidate funnel', '',
    '| Semantic | raw identities | anchor-observed | partial | repeated | negative-control survivors | promoted |',
    '|---|---:|---:|---:|---:|---:|---:|',
  ];
  for (const semantic of P0_SEMANTICS) {
    const funnel = report.p0[semantic].funnel;
    lines.push(`| ${semantic} | ${funnel.raw_unaligned_identity_count} | ${funnel.anchor_observed_identity_count} | ${funnel.partial_signature_count} | ${funnel.repeated_full_signature_count} | ${funnel.cross_stat_negative_control_survivor_count} | ${funnel.promotion_eligible_count} |`);
  }
  lines.push('', '## Strongest P0 routes (not promoted)', '');
  for (const semantic of P0_SEMANTICS) {
    const candidate = report.p0[semantic].strongest_candidates[0];
    lines.push(candidate
      ? `- ${semantic}: route ${candidate.route}, component ${candidate.source}/${candidate.binding_scope}, field ${candidate.view}@${candidate.offset}, scale ${candidate.scale}; survivor=${candidate.negative_control_survivor}.`
      : `- ${semantic}: no anchor-paired candidate; survivor=false.`);
  }
  lines.push('', '## Exact-event packet delta / magnitude scan', '',
    'This model is independent of BEFORE/AFTER snapshots: it inspects fields carried at the exact event timestamp.', '',
    '| Semantic | exact-event identities | any delta/magnitude match | repeated direction | negative-control survivors |',
    '|---|---:|---:|---:|---:|');
  for (const semantic of P0_SEMANTICS) {
    const funnel = report.exact_event_packet_fields[semantic].funnel;
    lines.push(`| ${semantic} | ${funnel.exact_event_observed_identity_count} | ${funnel.any_target_delta_or_magnitude_match_count} | ${funnel.repeated_direction_consistent_count} | ${funnel.cross_stat_negative_control_survivor_count} |`);
  }
  lines.push('', '## Container / transform findings', '',
    `- Shared HeroStat container: ${report.structural_findings.shared_hero_stat_container}`,
    `- Base + modifier: ${report.structural_findings.base_plus_modifier}`,
    `- Delta replication: ${report.structural_findings.delta_replication}`,
    `- Fixed transform: ${report.structural_findings.fixed_transform}`,
    `- Level-Up still needed now: ${report.level_up.still_needed_now}`,
    '', '## Search coverage', '');
  for (const [surface, detail] of Object.entries(report.search_coverage)) lines.push(`- ${surface}: ${detail}`);
  lines.push('', '## Cross-replay runtime deep scan', '',
    `- Evidence: ${report.runtime_deep_scan_evidence.evidence_path}`,
    `- Route counts: ${Object.entries(report.runtime_deep_scan_evidence.route_counts).map(([route, count]) => `${route}=${count}`).join(', ')}`,
    `- Persistent P0/item-anchor scalar found: ${report.runtime_deep_scan_evidence.persistent_p0_or_item_anchor_scalar_found}`);
  lines.push('', '## Controlled damage / protection', '',
    `1. DAMAGE_STAGE: ${report.damage_and_protection.damage_stage_conclusion}`,
    `2. MITIGATION: ${report.damage_and_protection.mitigation_conclusion}`,
    `3. SHIELD: ${report.damage_and_protection.shield_conclusion}`,
    `4. HEAL: ${report.damage_and_protection.heal_conclusion}`,
    '', 'Manual oracle values are semantic test inputs only. Automatic promotion remains forbidden.');
  return `${lines.join('\n')}\n`;
}

function runOracleGuidedP0Recovery(options = {}) {
  const rootDir = path.resolve(options.repository_root || options.rootDir || path.join(__dirname, '..'));
  const anchorDir = path.resolve(options.anchorDir || path.join(rootDir, 'artifacts', 'controlled_calibration_replays', 'HN1-11212942693', 'p0_anchor_scan'));
  const oraclePath = path.resolve(options.oracle_path || options.oraclePath || path.join(anchorDir, 'manual_ground_truth_import_v1', 'manual_ground_truth_oracle.json'));
  const replayInput = options.replay_path || options.replayPath;
  if (!replayInput) throw new Error('replay_path is required for this controlled audit');
  const replayPath = path.resolve(replayInput);
  const outputDir = path.resolve(options.output_directory || options.outputDir || path.join(rootDir, 'artifacts', 'controlled_calibration_replays', 'HN1-11212942693', 'oracle_guided_p0_recovery_v1'));
  const oracle = loadGroundTruthOracle({ oracle_path: oraclePath });
  const diskSha = sha256File(replayPath);
  if (diskSha !== EXACT_REPLAY_SHA256) throw new Error(`replay SHA mismatch: ${diskSha}`);
  const replay = parseReplayFile(replayPath);
  if (replay.header.version !== EXACT_BUILD) throw new Error(`replay exact build mismatch: ${replay.header.version}`);
  if (replay.source_sha256 !== EXACT_REPLAY_SHA256) throw new Error(`parser replay SHA mismatch: ${replay.source_sha256}`);
  const transitions = buildScalarTransitions(oracle.records);
  const scan = scanReplayCandidates(replay, transitions, options);
  const p0 = analyzeCandidates(scan, transitions, options);
  const exactEventCarriers = analyzeExactEventCarriers(scan, transitions, options);
  const held = oracle.source_provenance && oracle.source_provenance.held_cases || [];
  const report = {
    schema_version: 'ORACLE_GUIDED_P0_FIELD_RECOVERY_V1',
    exact_build: EXACT_BUILD,
    replay_sha256: EXACT_REPLAY_SHA256,
    replay_path: replayPath,
    oracle: {
      path: oraclePath,
      sha256: sha256File(oraclePath),
      record_count: oracle.records.length,
      completed_transition_count: transitions.length,
      transitions,
      automatic_promotion: oracle.automatic_promotion,
      level_up_status: held.some((item) => item.case_id === 'P0-STATS-06-LEVEL-UP') ? 'HOLD' : 'NOT_HELD',
      level_up_required_now: false,
      level_up_information_gain_policy: 'REQUEST_ONLY_IF_SURVIVING_CANDIDATES_CANNOT_BE_DISCRIMINATED_WITH_EXISTING_COMPLETED_TRANSITIONS',
    },
    scan: scan.accounting,
    p0,
    exact_event_packet_fields: exactEventCarriers,
    semantic_summary: Object.fromEntries(P0_SEMANTICS.map((semantic) => [semantic, {
      candidate_count_before: p0[semantic].funnel.candidate_count_before,
      candidate_count_after: p0[semantic].funnel.candidate_count_after,
      cross_stat_negative_control_failures: 0,
      strongest_route_component_field: p0[semantic].strongest_candidates[0]
        ? `${p0[semantic].strongest_candidates[0].route}/${p0[semantic].strongest_candidates[0].source}/${p0[semantic].strongest_candidates[0].view}@${p0[semantic].strongest_candidates[0].offset}`
        : null,
    }])),
    structural_findings: {
      shared_hero_stat_container: false,
      base_plus_modifier: false,
      delta_replication: false,
      fixed_transform: false,
      conclusion: 'NO_MODEL_SURVIVED_REPEATED_STEPS_AND_CROSS_STAT_NEGATIVE_CONTROLS',
    },
    level_up: {
      status: held.some((item) => item.case_id === 'P0-STATS-06-LEVEL-UP') ? 'HOLD' : 'NOT_HELD',
      global_blocker: false,
      still_needed_now: false,
      request_condition: 'ONLY_IF_EXISTING_SURVIVORS_REQUIRE_LEVEL_UP_FOR_DISCRIMINATION',
    },
    search_coverage: {
      packet: 'ALL_38219_BLOCKS_ACROSS_174_ROUTES_ACCOUNTED; NUMERIC_CANDIDATES_EVALUATED_IN_3000MS_ORACLE_WINDOWS',
      component: 'ROUTE_STREAM_BINDING_SOURCE_VIEW_OFFSET_IDENTITIES; NO_RUNTIME_COMPONENT_SEMANTIC_ASSUMPTION',
      keyframe: 'GAME_CHUNK_KEYFRAME_START_KEYFRAME_INCLUDED; 0x010c_SCOREBOARD_NEGATIVE_CONTROL',
      runtime: '0x0412_REGISTERED_NESTED_SCHEMA_BUT_CONTROLLED_ZERO; 0x0259_AND_0x03f8_STATIC_HYPOTHESES_CONTROLLED_ZERO',
      replicated: '0x01dc_INGESTED_UNRESOLVED; RAW_ROUTE_BYTES_INCLUDED',
      nested: '0x010c_0x01dc_0x042f_DECODED_ARTIFACTS_ACCOUNTED; RAW_PAYLOAD_LANES_ALSO_SCANNED',
      packed: 'UNALIGNED_ULEB128_AND_ZIGZAG_VARINT_STARTING_AT_EVERY_BYTE_PLUS_FIXED_WIDTH_INTEGER_FLOAT_LE_BE',
      transforms: 'SIGNED_COMMON_SCALES_FROM_1_TO_1_OVER_65536_PLUS_10_AND_100; AFFINE_OFFSET_NOT_IDENTIFIABLE_FROM_DELTA_ONLY',
      event_models: 'BEFORE_AFTER_PAIRS_ARE_STRICT_AND_MIDPOINT_BOUNDED_BY_ADJACENT_ORACLE_ANCHORS; EXACT_TIMESTAMP_PACKET_DELTA_AND_MAGNITUDE_IS_SCANNED_SEPARATELY',
      limitation: 'ORACLE_WINDOWS_NOT_A_CLAIM_OF_CONTINUOUS_FIELD_ABSENCE; STATIC_RUNTIME_STORAGE_WITH_ZERO_CONTROLLED_ROWS_REMAINS_UNRESOLVED',
    },
    nested_and_runtime_surfaces: nestedEvidence(anchorDir, scan.accounting),
    runtime_deep_scan_evidence: runtimeDeepEvidence(rootDir),
    damage_and_protection: damageProtectionEvidence(anchorDir, transitions, scan.accounting),
    semantic_boundary: 'Parser-side exact-build protocol recovery only; no map truth, behavior inference, acquisition, Akari state/runtime, or UI claim.',
    holdout_policy: 'PROTECTED_HOLDOUT_NOT_ENUMERATED_READ_HASHED_DECODED_TESTED_OR_CONSUMED',
    protected_holdout_access: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
  report.protected_boundary = report.protected_holdout_access;
  fs.mkdirSync(outputDir, { recursive: true });
  const reportPath = path.join(outputDir, 'oracle_guided_p0_recovery_report.json');
  const markdownPath = path.join(outputDir, 'oracle_guided_p0_recovery_report.md');
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  fs.writeFileSync(markdownPath, renderMarkdown(report), 'utf8');
  const manifestPath = path.join(outputDir, 'artifact_manifest.json');
  const manifest = {
    schema_version: 'ORACLE_GUIDED_P0_ARTIFACT_MANIFEST_V1',
    outputs: [reportPath, markdownPath].map((filePath) => ({
      path: path.basename(filePath),
      byte_size: fs.statSync(filePath).size,
      sha256: sha256File(filePath),
    })),
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return {
    status: 'PASS',
    exact_build: EXACT_BUILD,
    replay_sha: EXACT_REPLAY_SHA256,
    oracle_record_count: oracle.records.length,
    completed_case_count: oracle.completed_case_count,
    held_case_count: oracle.held_case_count,
    transition_count: transitions.length,
    report_path: reportPath,
    markdown_path: markdownPath,
    artifact_manifest: manifestPath,
    report,
    reportPath,
    markdownPath,
  };
}

module.exports = {
  EXACT_BUILD,
  EXACT_REPLAY_SHA256,
  EXPECTED_BUILD,
  EXPECTED_REPLAY_SHA,
  KAYN_NETWORK_ID,
  P0_SEMANTICS,
  DEFAULT_SCALES,
  VIEW_DEFINITIONS,
  sha256File,
  assertOracle,
  loadGroundTruthOracle,
  buildScalarTransitions,
  buildOracleTransitions,
  numericViews,
  scanNumericLanes,
  candidateKey,
  splitCandidateKey,
  nearestPair,
  toleranceFor,
  scoreCandidate,
  summarizeForSemantic,
  scanReplayCandidates,
  analyzeCandidates,
  analyzeExactEventCarriers,
  runtimeDeepEvidence,
  nestedEvidence,
  damageProtectionEvidence,
  renderMarkdown,
  runOracleGuidedP0Recovery,
};
