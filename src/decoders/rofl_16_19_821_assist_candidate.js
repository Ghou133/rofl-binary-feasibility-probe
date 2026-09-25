'use strict';

const crypto = require('node:crypto');

const { REPLAY_VERSION_821, assessHeroDeathTail821,
  decodeHeroDeathCandidates821 } = require('./rofl_16_19_821_7343');
const { assessHeroStatsTail821 } = require('./rofl_16_19_821_hero_stats_candidate');
const { collect821Routes, rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { validateAssistNativeChildren821 } = require('./rofl_16_19_821_assist_native_identity');
const { RUNTIME_IMAGE_SHA256 } = require('./rofl_16_19_821_runtime_bytes');

const PACKET_ID = 0x040a;
const PAYLOAD_LENGTH = 44;
const REQUIRED_FIELDS = Object.freeze(['NUM_DEATHS', 'CHAMPIONS_KILLED', 'ASSISTS']);
const SEMANTIC_STATUS = 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT';

// 0x040a is a general packet route, so only the paired 44-byte fingerprint is
// interpreted. The exact 821 factory constructs a 0x28-byte object for this
// route; its deserializer consumed all 2476 observed 44-byte packets in the
// 11-Replay corpus. Callback semantics are still unknown.
const HERO_ASSIST_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-assist-pair-tail-candidate-v1',
  replay_version: REPLAY_VERSION_821,
  capability: 'hero_assist',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: PACKET_ID,
  payload_length: PAYLOAD_LENGTH,
  first_shape: Object.freeze({ bytes_1_to_4_hex: '35b94b3d', last_byte_hex: '14' }),
  second_shape: Object.freeze({ bytes_1_to_4_hex: '350b4bb3', last_byte_hex: 'd4' }),
  required_tail_fields: REQUIRED_FIELDS,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; 1097 paired observations, 110 participant ASSISTS tails, 3160 adjacent-keyframe participant deltas',
  known_limits: Object.freeze([
    'Experimental exact-build assist-attribution candidate, not a published assist semantic capability.',
    'The 0x040a route carries other data; even the first 44-byte shape occurs 282 times outside matched deaths in the observed corpus.',
    'A candidate assist requires both 44-byte shapes before a co-timed, matched 0x0438 Hero_Die packet, identical bytes 5..42, a killer-tail-aligned source, and all ten ASSISTS tails aligned.',
    'The exact 821 native 0x040a deserializer fully consumed 2476 observed 44-byte packets; its packet-specific callback and field name remain unconfirmed.',
    'Optional exact-image child identity checks confirm 0x0056/0x0057 packet identities, not an effective assist or actor role.',
    'The hero participant and killer labels rely on exact-build route and Replay-tail correlations; nonhero death sources do not imply an empty assist list.',
  ]),
});

function assessHeroAssistTail821(replay) {
  const base = { required_fields: [...REQUIRED_FIELDS] };
  if (replay?.header?.version !== REPLAY_VERSION_821) {
    return { ...base, status: 'UNSUPPORTED',
      error: `hero_assist candidate supports only ${REPLAY_VERSION_821}` };
  }
  const deaths = assessHeroDeathTail821(replay);
  if (deaths.status !== 'PASS') return { ...base, ...deaths };
  const kills = assessHeroStatsTail821(replay, 'CHAMPIONS_KILLED');
  if (kills.status !== 'PASS') {
    return { ...base, status: kills.status, error: kills.error,
      ...(kills.status === 'MISSING_INPUT' ? { missing_input: kills.error } : {}) };
  }
  const assists = assessHeroStatsTail821(replay, 'ASSISTS');
  if (assists.status !== 'PASS') {
    return { ...base, status: assists.status, error: assists.error,
      ...(assists.status === 'MISSING_INPUT' ? { missing_input: assists.error } : {}) };
  }
  return { ...base, status: 'PASS', death_counts: deaths.counts,
    champion_kills: kills.values, assists: assists.values };
}

function shape(block) {
  if (!Buffer.isBuffer(block.payload) || block.payload_length !== PAYLOAD_LENGTH
      || block.payload.length !== PAYLOAD_LENGTH) return null;
  const payload = block.payload;
  if (payload[1] !== 0x35 || payload[3] !== 0x4b) return null;
  if (payload[2] === 0xb9 && payload[4] === 0x3d && payload[43] === 0x14) {
    return 'first';
  }
  if (payload[2] === 0x0b && payload[4] === 0xb3 && payload[43] === 0xd4) {
    return 'second';
  }
  return null;
}

function participantFromAssistParam(rawParam, part) {
  if (!Number.isSafeInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const low = rawParam & 0xff;
  if (low < 0xae || low > 0xb7) return null;
  const expected = (0x40000000 | low) >>> 0;
  if (part === 'second' && (rawParam >>> 0) !== expected) return null;
  if (part === 'first' && ((rawParam >>> 0) & 0xfffff0ff) !== expected) return null;
  if (part === 'first' && ((rawParam >>> 8) & 0xf) > 5) return null;
  return low - 0xad;
}

function rawRef(replay, row, role, nativeChild = null) {
  const { block, chunk } = row;
  return {
    role,
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
    ...(nativeChild === null ? {} : {
      native_child_event_id: nativeChild.event_id,
      raw_child_event_id_hex: nativeChild.raw_event_id_hex,
      child_blob_sha256: nativeChild.event_blob_sha256,
      event_u32_0x04: nativeChild.event_u32_0x04,
      ...(nativeChild.event_id === 0x0057
        ? { event_u32_0x20: nativeChild.event_u32_0x20 } : {}),
    }),
  };
}

function deathKey(chunkIndex, timeMs) {
  return `${chunkIndex}/${timeMs}`;
}

function decodeHeroAssistCandidates821(replay, precollected = null, options = {}) {
  const profile = HERO_ASSIST_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    depends_on: 'hero_death',
    input_packet_id: PACKET_ID,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_used: false,
    runtime_image_status: 'EXACT_821_NATIVE_040A_44_FULL_CONSUME_EVIDENCE',
    known_limits: [...profile.known_limits],
  };
  const unavailable = (status, error = null, missingInput = null) => ({
    ...base, status, event_count: null, assist_pair_count: null,
    input_count: null, events: null,
    ...(error ? { error } : {}),
    ...(missingInput ? { missing_input: missingInput } : {}),
  });
  const tail = assessHeroAssistTail821(replay);
  if (tail.status !== 'PASS') {
    return unavailable(tail.status, tail.error ?? null, tail.missing_input ?? null);
  }

  let token = precollected;
  if (token === null) {
    try {
      token = collect821Routes(replay, ['hero_assist']);
    } catch (error) {
      return unavailable('DECODE_FAILED', `Replay framing failed: ${error.message}`);
    }
  }
  const selected = rowsFor821Capability(replay, token, 'hero_assist');
  if (selected.error) return unavailable('DECODE_FAILED', selected.error);
  const deathOutcome = decodeHeroDeathCandidates821(replay, token);
  if (deathOutcome.status !== 'CANDIDATE') {
    return unavailable(deathOutcome.status,
      deathOutcome.error ? `hero_assist requires matched 821 death cores: ${deathOutcome.error}` : null,
      deathOutcome.missing_input ?? null);
  }
  if (deathOutcome.champion_kills_tail_alignment_status !== 'CANDIDATE_ALIGNED') {
    return unavailable('DECODE_FAILED',
      `hero_assist requires aligned Hero_Die killer source: ${deathOutcome.champion_kills_tail_alignment_status}`);
  }

  const packets = selected.rows.filter(({ block }) => block.packet_id === PACKET_ID);
  const common = {
    ...base,
    input_count: packets.length,
    scanned_block_count: selected.scanned_block_count,
    matched_death_count: deathOutcome.events.length,
    final_assists: tail.assists,
  };
  const fail = (error) => ({ ...common,
    ...(native?.status === 'PASS' ? {
      runtime_image_status: native.runtime_image_status,
      runtime_image_used: native.runtime_image_used,
      runtime_image_sha256: native.runtime_image_sha256,
      native_child_identity_status: 'MATCHED_USED',
    } : {}),
    status: 'DECODE_FAILED', event_count: null,
    assist_pair_count: null, events: null, error });
  const native = options.runtimeImagePath == null ? null
    : validateAssistNativeChildren821(packets, {
      runtimeImagePath: options.runtimeImagePath,
      pythonExecutable: options.pythonExecutable,
    });
  if (native !== null && native.status !== 'PASS') {
    return { ...common, ...native, input_count: packets.length,
      native_child_identity_status: 'FAILED',
      event_count: null, assist_pair_count: null, events: null };
  }
  const nativeByRow = native === null ? null
    : new Map(packets.map((row, index) => [row, native.results[index]]));
  const deaths = new Map();
  for (const event of deathOutcome.events) {
    const die = event.die_source_raw_packet_ref;
    if (!die || die.packet_id !== 0x0438 || die.replay_sha256 !== replay.source_sha256) {
      return fail('matched Hero_Die event lacks a source-bound 0x0438 packet reference');
    }
    const key = deathKey(die.chunk_index, event.replay_time_ms);
    if (deaths.has(key)) return fail('duplicate matched death in the same chunk and millisecond');
    deaths.set(key, event);
  }

  const pairGroups = new Map();
  const nondeathFirst = [];
  for (const row of packets) {
    const { block, chunk } = row;
    if (chunk.stream_tag !== 1 || block.packet_id !== PACKET_ID
        || block.payload_length !== PAYLOAD_LENGTH) {
      return fail('0x040a route row differs from selected 821 game-stream 44-byte scope');
    }
    const fingerprintPart = shape(block);
    const nativeChild = nativeByRow?.get(row) ?? null;
    const part = nativeChild === null ? fingerprintPart
      : nativeChild.event_id === 0x0056 ? 'first' : 'second';
    if (nativeChild !== null && part !== fingerprintPart) {
      return fail('0x040a/44 raw shape and exact native child ID disagree');
    }
    if (part === null) return fail('0x040a/44 has an unrecognized exact-build payload shape');
    const assistant = participantFromAssistParam(block.param >>> 0, part);
    if (assistant === null) return fail('0x040a/44 raw param differs from observed hero family');
    const event = deaths.get(deathKey(chunk.index, block.timestamp_ms));
    if (!event) {
      if (part === 'second') return fail('second 0x040a/44 pair shape appears without matched Hero_Die');
      nondeathFirst.push(row);
      continue;
    }
    const key = `${deathKey(chunk.index, block.timestamp_ms)}/${assistant}`;
    const group = pairGroups.get(key) ?? { event, assistant, first: [], second: [] };
    group[part].push(row);
    pairGroups.set(key, group);
  }

  const pairsByDeath = new Map();
  const observedCounts = Array(10).fill(0);
  for (const group of pairGroups.values()) {
    if (group.first.length !== 1 || group.second.length !== 1) {
      return fail('0x040a/44 assist fingerprint lacks exactly one packet of each shape');
    }
    const { event, assistant } = group;
    const killer = event.killer_participant_id_candidate;
    if (killer === null || !Number.isInteger(killer) || killer < 1 || killer > 10) {
      return fail('0x040a/44 pair belongs to a death without an aligned hero killer');
    }
    if (assistant === killer || assistant === event.victim_participant_id) {
      return fail('0x040a/44 paired participant equals the killer or victim');
    }
    const first = group.first[0];
    const second = group.second[0];
    if (!first.block.payload.subarray(5, 43).equals(second.block.payload.subarray(5, 43))) {
      return fail('paired 0x040a/44 payload bytes 5..42 differ');
    }
    const dieOffset = event.die_source_raw_packet_ref.decompressed_block_offset;
    if (!(first.block.offset < second.block.offset && second.block.offset < dieOffset)) {
      return fail('paired 0x040a/44 packets do not precede Hero_Die in source order');
    }
    const current = pairsByDeath.get(event) ?? [];
    current.push({ assistant, first, second });
    pairsByDeath.set(event, current);
    observedCounts[assistant - 1]++;
  }
  if (observedCounts.some((count, index) => count !== tail.assists[index])) {
    return fail('paired 0x040a/44 assist candidates do not match all ten Replay tail ASSISTS counts');
  }

  const events = deathOutcome.events.map((death) => {
    const pairs = (pairsByDeath.get(death) ?? []).sort((a, b) => a.assistant - b.assistant);
    const mappedHeroKiller = death.killer_participant_id_candidate !== null;
    const assistRefs = pairs.map((pair) => ({
      assistant_participant_id_candidate: pair.assistant,
      first_raw_packet_ref: rawRef(replay, pair.first, 'candidate_assist_first_0x040a',
        nativeByRow?.get(pair.first) ?? null),
      second_raw_packet_ref: rawRef(replay, pair.second, 'candidate_assist_second_0x040a',
        nativeByRow?.get(pair.second) ?? null),
    }));
    return {
      event_type: 'HERO_ASSIST_ATTRIBUTION_CANDIDATE',
      game_version: REPLAY_VERSION_821,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: death.replay_time_ms,
      victim_participant_id_candidate: death.victim_participant_id,
      killer_participant_id_candidate: death.killer_participant_id_candidate,
      assisting_participant_ids_candidate: mappedHeroKiller
        ? pairs.map((pair) => pair.assistant) : null,
      assist_pair_count: mappedHeroKiller ? pairs.length : null,
      assist_observation_status: mappedHeroKiller
        ? SEMANTIC_STATUS : 'UNAVAILABLE_NONHERO_SOURCE',
      confidence: 'CANDIDATE',
      native_child_identity_status: native === null ? 'NOT_CHECKED' : 'MATCHED_USED',
      semantic_status: mappedHeroKiller
        ? SEMANTIC_STATUS : 'UNAVAILABLE_NONHERO_SOURCE',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        victim_participant_id_candidate: 'CANDIDATE_821_DEATH_TAIL_ALIGNMENT',
        killer_participant_id_candidate: mappedHeroKiller
          ? 'CANDIDATE_821_SOURCE_ID_KILL_TAIL_ALIGNMENT' : 'UNAVAILABLE',
        assisting_participant_ids_candidate: mappedHeroKiller
          ? SEMANTIC_STATUS : 'UNAVAILABLE',
      },
      matched_hero_die_raw_packet_ref: { ...death.die_source_raw_packet_ref,
        role: 'matched_hero_die_0x0438' },
      assist_pair_raw_packet_refs: assistRefs,
      raw_packet_ref: death.raw_packet_ref,
      raw_packet_refs: [
        ...death.raw_packet_refs.map((ref) => ({ ...ref, role: `matched_death_${ref.role}` })),
        ...assistRefs.flatMap((pair) => [pair.first_raw_packet_ref, pair.second_raw_packet_ref]),
      ],
      known_limits: [...profile.known_limits],
    };
  });
  return {
    ...common,
    status: 'CANDIDATE',
    evidence_status: SEMANTIC_STATUS,
    event_count: events.length,
    assist_pair_count: pairGroups.size,
    observed_assists_by_participant: observedCounts,
    nondeath_first_shape_count: nondeathFirst.length,
    nondeath_first_shape_packet_refs: nondeathFirst.map((row) =>
      rawRef(replay, row, 'nondeath_first_shape_excluded', nativeByRow?.get(row) ?? null)),
    native_child_identity_status: native === null ? 'NOT_CHECKED' : 'MATCHED_USED',
    ...(native === null ? {} : {
      runtime_image_status: native.runtime_image_status,
      runtime_image_used: native.runtime_image_used,
      runtime_image_sha256: native.runtime_image_sha256,
      native_child_first_count: native.native_child_first_count,
      native_child_second_count: native.native_child_second_count,
    }),
    events,
  };
}

module.exports = {
  HERO_ASSIST_CANDIDATE_PROFILE_821,
  assessHeroAssistTail821,
  decodeHeroAssistCandidates821,
};
