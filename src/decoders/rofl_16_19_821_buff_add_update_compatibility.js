'use strict';

// Packet-level equality and ordering of anonymous fields only. No Add row is
// paired with an Update row, and no buff identity or counter role is inferred.
const { NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE_821: ADD_PROFILE } =
  require('./rofl_16_19_821_buff_add_packet_candidate');
const { NPC_BUFF_UPDATE_NUM_COUNTER_PACKET_CANDIDATE_PROFILE_821: UPDATE_PROFILE } =
  require('./rofl_16_19_821_buff_update_num_counter_packet_candidate');

const REPLAY_VERSION = '16.19.821.7343';
const MAX_ADD_ROWS = 50_000;
const MAX_UPDATE_ROWS = 25_000;
const SHA256 = /^[0-9a-f]{64}$/;
const ADD_LENGTHS = {
  game_chunk: new Set([12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 28]),
  keyframe: new Set([13, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 32, 33, 41, 42]),
};
const UPDATE_LENGTHS = new Set([6, 7, 8, 9]);

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function u8(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xff;
}

function nonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function packetPosition(row) {
  const ref = row.raw_packet_ref;
  return [ref.chunk_index, ref.decompressed_block_offset];
}

function comparePosition(left, right) {
  return left[0] - right[0] || left[1] - right[1];
}

function countBefore(positions, position) {
  let lo = 0;
  let hi = positions.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (comparePosition(positions[mid], position) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function assertBoundRow(row, replaySha256, isAdd) {
  const profile = isAdd ? ADD_PROFILE : UPDATE_PROFILE;
  const ref = row?.raw_packet_ref;
  const validRoute = isAdd
    ? ADD_LENGTHS[ref?.chunk_stream]?.has(ref.payload_length)
    : ref?.chunk_stream === 'game_chunk' && UPDATE_LENGTHS.has(ref.payload_length);
  if (!row || row.event_type !== (isAdd ? 'NPC_BUFF_ADD_PACKET_CANDIDATE'
    : 'NPC_BUFF_UPDATE_NUM_COUNTER_PACKET_CANDIDATE')
      || row.game_version !== REPLAY_VERSION || row.patch !== '16.19'
      || row.build_profile !== profile.id || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'
      || row.replay_sha256 !== replaySha256 || ref?.replay_sha256 !== replaySha256
      || ref.packet_id !== profile.replay_block_packet_id || !validRoute
      || !nonnegativeInteger(ref.chunk_index) || !nonnegativeInteger(ref.chunk_id)
      || !nonnegativeInteger(ref.chunk_file_offset)
      || !nonnegativeInteger(ref.decompressed_block_offset)
      || !nonnegativeInteger(ref.decompressed_payload_offset)
      || !nonnegativeInteger(row.replay_time_ms)
      || row.replay_time_ms !== ref.replay_time_ms
      || !u32(row.raw_param) || row.raw_param === 0
      || row.raw_param !== ref.raw_param || !SHA256.test(ref.raw_payload_sha256)) {
    throw new TypeError('Buff packet candidate row is not bound to this exact Replay and route');
  }
  if (isAdd) {
    if (!u32(row.opaque_u32_0x10) || !u8(row.opaque_u8_0x14)
        || !/^[0-9a-f]{8}$/.test(row.raw_object_u32_bytes_hex)
        || !/^[0-9a-f]{2}$/.test(row.raw_object_u8_byte_hex)) {
      throw new TypeError('BuffAdd2 packet has invalid anonymous fields');
    }
  } else if (!u8(row.opaque_u8_0x10) || !u32(row.opaque_u32_0x14)
      || !u8(row.opaque_u8_0x18) || !u32(row.opaque_u32_0x1c)
      || !/^[0-9a-f]{2}$/.test(row.raw_object_u8_0x10_hex)
      || !/^[0-9a-f]{8}$/.test(row.raw_object_u32_0x14_hex)
      || !/^[0-9a-f]{2}$/.test(row.raw_object_u8_0x18_hex)
      || !/^[0-9a-f]{8}$/.test(row.raw_object_u32_0x1c_hex)) {
    throw new TypeError('BuffUpdateNumCounter packet has invalid anonymous fields');
  }
}

function pairFor(row, isAdd) {
  return isAdd ? `${row.opaque_u32_0x10}:${row.opaque_u8_0x14}`
    : `${row.opaque_u32_0x14}:${row.opaque_u8_0x18}`;
}

function addPosition(map, key, position) {
  let positions = map.get(key);
  if (!positions) {
    positions = [];
    map.set(key, positions);
  }
  positions.push(position);
}

function analyzeBuffAddUpdateNumCounterCompatibility821(addRows, updateRows, replaySha256) {
  if (!Array.isArray(addRows) || !Array.isArray(updateRows)
      || addRows.length > MAX_ADD_ROWS || updateRows.length > MAX_UPDATE_ROWS
      || typeof replaySha256 !== 'string' || !SHA256.test(replaySha256)) {
    throw new TypeError('821 Buff Add/Update compatibility requires bounded packet rows and Replay SHA-256');
  }
  const allPairs = new Set();
  const gamePairs = new Set();
  const keyframePairs = new Set();
  const allParamPairs = new Set();
  const gameParamPairs = new Set();
  const keyframeParamPairs = new Set();
  const gameParamPairPositions = new Map();
  const updateParamPairCounts = new Map();
  const updatePairs = new Set();
  const seenPositions = new Set();
  let gameAddPacketCount = 0;
  for (const row of addRows) {
    assertBoundRow(row, replaySha256, true);
    const position = packetPosition(row);
    const positionId = position.join(':');
    if (seenPositions.has(positionId)) throw new TypeError('Buff packet candidate position is duplicated');
    seenPositions.add(positionId);
    const pair = pairFor(row, true);
    const paramPair = `${row.raw_param}:${pair}`;
    allPairs.add(pair);
    allParamPairs.add(paramPair);
    if (row.raw_packet_ref.chunk_stream === 'game_chunk') {
      gameAddPacketCount += 1;
      gamePairs.add(pair);
      gameParamPairs.add(paramPair);
      addPosition(gameParamPairPositions, paramPair, position);
    } else {
      keyframePairs.add(pair);
      keyframeParamPairs.add(paramPair);
    }
  }
  for (const positions of gameParamPairPositions.values()) positions.sort(comparePosition);

  let updatePacketsWithPairInAdd = 0;
  let updatePacketsWithPairInGameAdd = 0;
  let updatePacketsWithPairInKeyframeAdd = 0;
  let updatePacketsWithParamPairInAdd = 0;
  let updatePacketsWithParamPairInGameAdd = 0;
  let updatePacketsWithParamPairInKeyframeAdd = 0;
  let updatePacketsWithPrecedingGameAddSameParamPair = 0;
  let updatePacketsWithMultiplePrecedingGameAddsSameParamPair = 0;
  for (const row of updateRows) {
    assertBoundRow(row, replaySha256, false);
    const position = packetPosition(row);
    const positionId = position.join(':');
    if (seenPositions.has(positionId)) throw new TypeError('Buff packet candidate position is duplicated');
    seenPositions.add(positionId);
    const pair = pairFor(row, false);
    const paramPair = `${row.raw_param}:${pair}`;
    updatePairs.add(pair);
    updateParamPairCounts.set(paramPair, (updateParamPairCounts.get(paramPair) ?? 0) + 1);
    if (allPairs.has(pair)) updatePacketsWithPairInAdd += 1;
    if (gamePairs.has(pair)) updatePacketsWithPairInGameAdd += 1;
    if (keyframePairs.has(pair)) updatePacketsWithPairInKeyframeAdd += 1;
    if (allParamPairs.has(paramPair)) updatePacketsWithParamPairInAdd += 1;
    if (gameParamPairs.has(paramPair)) updatePacketsWithParamPairInGameAdd += 1;
    if (keyframeParamPairs.has(paramPair)) updatePacketsWithParamPairInKeyframeAdd += 1;
    const preceding = countBefore(gameParamPairPositions.get(paramPair) ?? [], position);
    if (preceding > 0) updatePacketsWithPrecedingGameAddSameParamPair += 1;
    if (preceding > 1) updatePacketsWithMultiplePrecedingGameAddsSameParamPair += 1;
  }

  return {
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_OPAQUE_BUFF_ADD_UPDATE_PACKET_FIELD_COMPATIBILITY',
    game_version: REPLAY_VERSION,
    replay_sha256: replaySha256,
    add_packet_count: addRows.length,
    game_add_packet_count: gameAddPacketCount,
    keyframe_add_packet_count: addRows.length - gameAddPacketCount,
    update_packet_count: updateRows.length,
    distinct_add_pair_count: allPairs.size,
    distinct_game_add_pair_count: gamePairs.size,
    distinct_keyframe_add_pair_count: keyframePairs.size,
    distinct_update_pair_count: updatePairs.size,
    distinct_update_raw_param_pair_count: updateParamPairCounts.size,
    update_packets_with_pair_in_add: updatePacketsWithPairInAdd,
    update_packets_with_pair_in_game_add: updatePacketsWithPairInGameAdd,
    update_packets_with_pair_in_keyframe_add: updatePacketsWithPairInKeyframeAdd,
    update_packets_with_raw_param_pair_in_add: updatePacketsWithParamPairInAdd,
    update_packets_with_raw_param_pair_in_game_add: updatePacketsWithParamPairInGameAdd,
    update_packets_with_raw_param_pair_in_keyframe_add: updatePacketsWithParamPairInKeyframeAdd,
    update_packets_with_preceding_game_add_same_raw_param_pair:
      updatePacketsWithPrecedingGameAddSameParamPair,
    update_packets_with_multiple_preceding_game_adds_same_raw_param_pair:
      updatePacketsWithMultiplePrecedingGameAddsSameParamPair,
    distinct_update_raw_param_pairs_with_multiple_packets:
      [...updateParamPairCounts.values()].filter((count) => count > 1).length,
    update_packets_on_repeated_raw_param_pairs:
      [...updateParamPairCounts.values()].filter((count) => count > 1)
        .reduce((sum, count) => sum + count, 0),
    key_fields: {
      add: ['opaque_u32_0x10', 'opaque_u8_0x14'],
      update: ['opaque_u32_0x14', 'opaque_u8_0x18'],
      raw_param: 'recorded packet raw_param',
    },
    known_limits: [
      'Equality of anonymous packet fields and recorded raw_param does not establish buff identity, owner, target, effect, or counter meaning.',
      'Keyframe Add rows are snapshots, not evidence of a game-stream Add packet.',
      'Packet order and repeated field values do not establish an Add-to-Update row pairing or lifecycle.',
      'No successful Add or Update action is inferred.',
    ],
  };
}

module.exports = { analyzeBuffAddUpdateNumCounterCompatibility821 };
