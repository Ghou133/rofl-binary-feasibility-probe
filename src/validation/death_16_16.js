'use strict';

const DEATH_16_16_BUILD = '16.16.805.0442';
const DEATH_16_16_PACKET_ID = 0x0112;
const PARTICIPANT_NETWORK_LOW_BYTE_BASE = 0xad;

function participantIdFromDeathParam(rawParam) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const participantId = (rawParam & 0xff) - PARTICIPANT_NETWORK_LOW_BYTE_BASE;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function collectP0DeathAnchors(anchorRows) {
  if (!Array.isArray(anchorRows)) throw new TypeError('anchorRows must be an array');
  const anchors = [];
  const seen = new Set();
  for (const row of anchorRows) {
    const timestampMs = row?.frame_boundary_evidence?.associated_death_event_timestamp_ms;
    const participantId = row?.participant_id;
    if (!Number.isInteger(timestampMs) || !Number.isInteger(participantId)) continue;
    const replaySha256 = row.replay_sha256;
    const gameId = String(row.game_id ?? '');
    const key = `${replaySha256}:${timestampMs}:${participantId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    anchors.push({
      game_id: gameId,
      replay_sha256: replaySha256,
      replay_build: row.replay_build,
      timestamp_ms: timestampMs,
      participant_id: participantId,
      champion: row.champion ?? null,
      details_event_json_path:
        row.frame_boundary_evidence.associated_death_event_json_path ?? null,
      frame_snapshot_anchor_id: row.anchor_id ?? null,
      frame_snapshot_timestamp_ms: row.timestamp_ms ?? null,
    });
  }
  return anchors.sort((left, right) => left.game_id.localeCompare(right.game_id)
    || left.timestamp_ms - right.timestamp_ms
    || left.participant_id - right.participant_id);
}

function canonicalDeathRouteRow(row, index) {
  if (row?.packet_id !== DEATH_16_16_PACKET_ID
      || !Number.isInteger(row.timestamp_ms)
      || !Number.isInteger(row.raw_param)) return null;
  const participantId = participantIdFromDeathParam(row.raw_param);
  if (participantId === null) return null;
  return {
    row_index: index,
    replay_sha256: row.replay_sha256,
    replay_build: row.replay_build,
    timestamp_ms: row.timestamp_ms,
    participant_id: participantId,
    raw_param: row.raw_param >>> 0,
    raw_param_hex: `0x${(row.raw_param >>> 0).toString(16).padStart(8, '0')}`,
    payload_length: row.payload_length,
    stream_tag: row.stream_tag ?? null,
    chunk_index: row.chunk_index ?? null,
    block_offset: row.block_offset ?? null,
    raw_payload_sha256: row.raw_payload_sha256 ?? null,
  };
}

function matchP0DeathAnchors(anchors, routeRows, options = {}) {
  const windowMs = options.windowMs ?? 2;
  if (!Number.isFinite(windowMs) || windowMs < 0) {
    throw new TypeError('windowMs must be a non-negative number');
  }
  const rows = routeRows.map(canonicalDeathRouteRow).filter(Boolean);
  const used = new Set();
  const matches = [];
  const unmatchedAnchors = [];
  for (const anchor of anchors) {
    const candidates = rows.filter((row) => !used.has(row.row_index)
      && row.replay_sha256 === anchor.replay_sha256
      && row.replay_build === anchor.replay_build
      && row.participant_id === anchor.participant_id
      && Math.abs(row.timestamp_ms - anchor.timestamp_ms) <= windowMs)
      .sort((left, right) => Math.abs(left.timestamp_ms - anchor.timestamp_ms)
        - Math.abs(right.timestamp_ms - anchor.timestamp_ms)
        || left.row_index - right.row_index);
    const selected = candidates[0];
    if (!selected) {
      unmatchedAnchors.push(anchor);
      continue;
    }
    used.add(selected.row_index);
    matches.push({
      ...anchor,
      replay_packet_timestamp_ms: selected.timestamp_ms,
      timestamp_delta_ms: selected.timestamp_ms - anchor.timestamp_ms,
      participant_mapping: {
        participant_id: selected.participant_id,
        rule: '(raw_param & 0xff) - 0xad',
        exact_build_only: true,
        upper_bytes_semantics: 'UNKNOWN_RETAINED_RAW',
      },
      raw_packet_ref: {
        replay_sha256: selected.replay_sha256,
        packet_id: DEATH_16_16_PACKET_ID,
        packet_id_hex: '0x0112',
        stream_tag: selected.stream_tag,
        chunk_index: selected.chunk_index,
        block_offset: selected.block_offset,
        payload_length: selected.payload_length,
        raw_param: selected.raw_param,
        raw_param_hex: selected.raw_param_hex,
        raw_payload_sha256: selected.raw_payload_sha256,
      },
    });
  }
  return {
    matches,
    unmatched_anchors: unmatchedAnchors,
    unmatched_route_rows: rows.filter((row) => !used.has(row.row_index)),
  };
}

function createDeathRouteAnchorValidation(input, options = {}) {
  const anchors = collectP0DeathAnchors(input.anchorRows);
  const result = matchP0DeathAnchors(anchors, input.routeRows, options);
  const replaySummaries = [];
  const replayKeys = [...new Set([
    ...anchors.map((row) => row.replay_sha256),
    ...input.routeRows.map((row) => row.replay_sha256),
  ])].sort();
  for (const replaySha256 of replayKeys) {
    const replayAnchors = anchors.filter((row) => row.replay_sha256 === replaySha256);
    const replayRows = input.routeRows.filter((row) => row.replay_sha256 === replaySha256);
    const replayMatches = result.matches.filter((row) => row.replay_sha256 === replaySha256);
    replaySummaries.push({
      replay_sha256: replaySha256,
      game_id: replayAnchors[0]?.game_id ?? null,
      details_death_anchor_count: replayAnchors.length,
      route_packet_count: replayRows.length,
      matched_count: replayMatches.length,
      payload_lengths: [...new Set(replayRows.map((row) => row.payload_length))]
        .filter(Number.isInteger).sort((left, right) => left - right),
      raw_param_variants: [...new Set(replayRows.map((row) => row.raw_param >>> 0))]
        .sort((left, right) => left - right)
        .map((value) => `0x${value.toString(16).padStart(8, '0')}`),
    });
  }
  const deltas = result.matches.map((row) => Math.abs(row.timestamp_delta_ms));
  const pass = anchors.length > 0
    && result.matches.length === anchors.length
    && result.unmatched_anchors.length === 0
    && result.unmatched_route_rows.length === 0
    && replaySummaries.every((row) => row.details_death_anchor_count === row.route_packet_count);
  return {
    schema: 'ROFL_16_16_HERO_DEATH_ROUTE_ANCHOR_VALIDATION_V1',
    schema_version: 1,
    status: pass ? 'PASS' : 'FAIL',
    exact_build: DEATH_16_16_BUILD,
    packet_id: DEATH_16_16_PACKET_ID,
    packet_id_hex: '0x0112',
    runtime_type_name: 'PKT_NPC_Hero_Die_s',
    evidence_grade: 'VERIFIED_DIRECT_ROUTE_TIME_ENTITY',
    semantic_scope: {
      verified: ['event_type=HERO_DEATH', 'timestamp_ms', 'victim_participant_id'],
      unavailable_or_unknown: [
        'killer',
        'assists',
        'kill_credit',
        'respawn_timestamp',
        'inner_payload_fields',
        'raw_param_upper_bytes',
      ],
    },
    details_role: 'INDEPENDENT_VALIDATION_ORACLE_ONLY_NOT_A_REPLAY_SEMANTIC_SOURCE',
    matching_policy: {
      replay_scope: 'exact replay SHA-256 and exact build',
      participant: '(raw_param & 0xff) - 0xad, exact build only',
      timestamp_window_ms: options.windowMs ?? 2,
      one_to_one: true,
    },
    details_death_anchor_count: anchors.length,
    route_packet_count: input.routeRows.length,
    matched_count: result.matches.length,
    unmatched_anchor_count: result.unmatched_anchors.length,
    unmatched_route_packet_count: result.unmatched_route_rows.length,
    timestamp_absolute_delta_ms: {
      min: deltas.length ? Math.min(...deltas) : null,
      max: deltas.length ? Math.max(...deltas) : null,
      exact_zero_count: deltas.filter((value) => value === 0).length,
    },
    replay_summaries: replaySummaries,
    matches: result.matches,
    unmatched_anchors: result.unmatched_anchors,
    unmatched_route_rows: result.unmatched_route_rows,
    provenance: input.provenance ?? {},
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      consumed: false,
    },
  };
}

module.exports = {
  DEATH_16_16_BUILD,
  DEATH_16_16_PACKET_ID,
  collectP0DeathAnchors,
  createDeathRouteAnchorValidation,
  matchP0DeathAnchors,
  participantIdFromDeathParam,
};
