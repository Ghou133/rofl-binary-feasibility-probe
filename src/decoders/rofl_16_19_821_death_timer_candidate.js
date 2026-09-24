'use strict';

const {
  REPLAY_VERSION_821,
  decodeHeroDeathCandidates821,
} = require('./rofl_16_19_821_7343');
const { replaySourceError } = require('./replay_source_integrity');
const { collect821Routes, rowsFor821Capability } = require('./rofl_16_19_821_scan');

// 0x0259 resolves to PKT_S2C_UpdateDeathTimer_s in the exact 821.7343 mapped
// client image. Its deserializer is RVA 0x10fa910 and consumes one float-code
// byte followed by four encoded f32 bytes for all observed KR timer packets.
const HERO_DEATH_TIMER_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-death-timer-runtime-candidate-v1',
  replay_version: REPLAY_VERSION_821,
  capability: 'hero_death_timer',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: 0x0259,
  runtime_type_name: 'PKT_S2C_UpdateDeathTimer_s',
  runtime_constructor_rva: 0xeca430,
  runtime_deserialize_rva: 0x10fa910,
  evidence_runtime_image_sha256: '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325',
  evidence_scope: 'eleven KR exact-build Replays; 657 full-consume runtime body probes and 655 matched death cores',
  known_limits: Object.freeze([
    'Exact-build runtime body transform is applied statically; no client runtime image is needed when decoding a Replay.',
    'Timer seconds are candidate packet semantics tied to matched 821 death cores and Replay tail counts, not a published death-timer capability.',
    'Two isolated 0x0259 packets in KR_8394041123 lack death-core corroboration and are excluded.',
    'A return at 0x0048 is not predicted from this value; two observed returns in KR_8394041123 occur well before the decoded timer.',
    'Victim participant identity remains a Replay-tail candidate; no live client callback or full 0x0048 runtime binding was observed.',
  ]),
});

function decodeTimerByte821(encoded) {
  let value = encoded ^ 0x94;
  value = (value + 0x21) & 0xff;
  value ^= 0x7a;
  value = (value - 0x5a) & 0xff;
  return value ^ 0xc4;
}

function decodeHeroDeathTimerPayload821(payload) {
  if (!Buffer.isBuffer(payload) || payload.length !== 5) return null;
  const first = payload[0];
  const floatCode = first & 7;
  if ((first & 0xf8) !== 0x10 || ![2, 3, 5, 6].includes(floatCode)) return null;
  const decoded = Buffer.from(payload.subarray(1).map(decodeTimerByte821));
  const seconds = decoded.readFloatBE(0);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  return {
    timer_seconds_candidate: seconds,
    timer_float_code: floatCode,
    decoded_float_bytes_hex: decoded.toString('hex'),
    decoded_float_byte_order: 'BE',
  };
}

function decodeHeroDeathTimerCandidates821(replay, precollected = null) {
  const profile = HERO_DEATH_TIMER_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_EXACT_821_RUNTIME_TRANSFORM',
    known_limits: [...profile.known_limits],
  };
  const unavailable = (status, error = null, missingInput = null) => ({
    ...base, status, event_count: null, input_count: null, events: null,
    ...(error ? { error } : {}),
    ...(missingInput ? { missing_input: missingInput } : {}),
  });
  if (replay?.header?.version !== REPLAY_VERSION_821) {
    return unavailable('UNSUPPORTED', `hero_death_timer candidate supports only ${REPLAY_VERSION_821}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return unavailable('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  }

  let scanToken = precollected;
  if (scanToken === null) {
    try {
      scanToken = collect821Routes(replay, ['hero_death_timer']);
    } catch (error) {
      return unavailable('DECODE_FAILED', `Replay framing failed: ${error.message}`);
    }
  }
  const scan = rowsFor821Capability(replay, scanToken, 'hero_death');
  if (scan.error) return unavailable('DECODE_FAILED', scan.error);
  const primary = scan.rows.filter(({ block }) => block.packet_id === profile.replay_block_packet_id);
  const common = { ...base, input_count: primary.length,
    scanned_block_count: scan.scanned_block_count };
  const fail = (error) => ({ ...common, status: 'DECODE_FAILED', event_count: null,
    events: null, error });

  const death = decodeHeroDeathCandidates821(replay, scanToken);
  if (death.status !== 'CANDIDATE') {
    return { ...common, status: death.status, event_count: null, events: null,
      ...(death.error ? { error: `hero_death_timer requires matched 821 death cores: ${death.error}` } : {}),
      ...(death.missing_input ? { missing_input: death.missing_input } : {}) };
  }
  const byLocation = new Map();
  for (const row of primary) {
    const key = `${row.chunk.index}/${row.block.offset}`;
    if (byLocation.has(key)) return fail('duplicate 0x0259 packet location');
    byLocation.set(key, row);
  }

  const events = [];
  for (const deathEvent of death.events) {
    const primaryRef = deathEvent.raw_packet_refs[0];
    const row = byLocation.get(`${primaryRef.chunk_index}/${primaryRef.decompressed_block_offset}`);
    if (!row || row.block.timestamp_ms !== primaryRef.replay_time_ms
        || (row.block.param >>> 0) !== primaryRef.raw_param
        || row.block.payload_length !== primaryRef.payload_length) {
      return fail('matched 0x0259 raw packet cannot be recovered from the source-bound Replay scan');
    }
    const timer = decodeHeroDeathTimerPayload821(row.block.payload);
    if (timer === null) return fail('matched 0x0259 payload differs from the exact 821 runtime f32 shape');
    const refs = deathEvent.raw_packet_refs.map((ref, index) => ({
      ...ref,
      role: index === 0 ? 'candidate_update_death_timer_0x0259' : `matched_death_${ref.role}`,
    }));
    events.push({
      event_type: 'HERO_DEATH_TIMER_CANDIDATE',
      game_version: REPLAY_VERSION_821,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: deathEvent.replay_time_ms,
      victim_raw_param: deathEvent.victim_raw_param,
      victim_participant_id_candidate: deathEvent.victim_participant_id,
      ...timer,
      respawn_replay_time_ms_candidate: null,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_821_EXACT_RUNTIME_FLOAT_AND_DEATH_CORE',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        victim_raw_param: 'VERIFIED_DIRECT',
        victim_participant_id_candidate: 'CANDIDATE_REPLAY_TAIL_COUNTS',
        timer_seconds_candidate: 'CANDIDATE_EXACT_821_RUNTIME_FLOAT',
        respawn_replay_time_ms_candidate: 'UNAVAILABLE',
      },
      raw_packet_ref: refs[0],
      raw_packet_refs: refs,
      known_limits: [...profile.known_limits],
    });
  }
  return {
    ...common,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_821_EXACT_RUNTIME_FLOAT_AND_DEATH_CORE',
    event_count: events.length,
    matched_death_core_count: death.matched_core_count,
    excluded_isolated_primary_count: death.unmatched_primary_count,
    excluded_isolated_primary_packet_refs: death.unmatched_primary_packet_refs,
    final_death_counts: death.final_death_counts,
    observed_death_counts: death.observed_death_counts,
    events,
  };
}

module.exports = {
  HERO_DEATH_TIMER_CANDIDATE_PROFILE_821,
  decodeHeroDeathTimerPayload821,
  decodeHeroDeathTimerCandidates821,
};
