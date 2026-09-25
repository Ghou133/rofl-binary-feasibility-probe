'use strict';

// This compares anonymous packet scalars only. It does not join Add and Remove
// rows or infer buff identity, owner, application, removal, or lifecycle.
const REPLAY_VERSION = '16.19.821.7343';
const ADD_PACKET_ID = 0x00ae;
const REMOVE_PACKET_ID = 0x047c;
const ADD_PROFILE = 'rofl-16.19.821.7343-kr-buff-add2-packet-runtime-candidate-v1';
const REMOVE_PROFILE = 'rofl-16.19.821.7343-kr-buff-remove2-packet-runtime-candidate-v1';

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function u8(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xff;
}

function keyFor(row) {
  if (!u32(row.opaque_u32_0x10) || !u8(row.opaque_u8_0x14)) {
    throw new TypeError('Buff packet candidate has an invalid anonymous key field');
  }
  return `${row.opaque_u32_0x10}:${row.opaque_u8_0x14}`;
}

function positionFor(row) {
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

function assertBoundRow(row, replaySha256, packetId) {
  const isAdd = packetId === ADD_PACKET_ID;
  const ref = row?.raw_packet_ref;
  const expectedStream = isAdd ? ['game_chunk', 'keyframe'] : ['game_chunk'];
  if (!row || row.game_version !== REPLAY_VERSION
      || row.build_profile !== (isAdd ? ADD_PROFILE : REMOVE_PROFILE)
      || row.event_type !== (isAdd ? 'NPC_BUFF_ADD_PACKET_CANDIDATE'
        : 'NPC_BUFF_REMOVE_PACKET_CANDIDATE')
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'
      || row.replay_sha256 !== replaySha256
      || ref?.replay_sha256 !== replaySha256 || ref.packet_id !== packetId
      || !expectedStream.includes(ref.chunk_stream)
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || row.replay_time_ms !== ref.replay_time_ms
      || !u32(row.raw_param) || row.raw_param !== ref.raw_param
      || !/^[0-9a-f]{64}$/.test(ref.raw_payload_sha256)) {
    throw new TypeError('Buff packet candidate row is not bound to this exact Replay and route');
  }
  if (!isAdd && !Number.isFinite(row.opaque_f32_0x18)) {
    throw new TypeError('BuffRemove2 packet candidate has an invalid anonymous f32 field');
  }
  keyFor(row);
}

function addPosition(map, key, position) {
  let positions = map.get(key);
  if (!positions) {
    positions = [];
    map.set(key, positions);
  }
  positions.push(position);
}

function sortPositions(map) {
  for (const positions of map.values()) positions.sort(comparePosition);
}

function analyzeBuffPacketKeyCompatibility821(addRows, removeRows, replaySha256) {
  if (!Array.isArray(addRows) || !Array.isArray(removeRows)
      || typeof replaySha256 !== 'string' || !/^[0-9a-f]{64}$/.test(replaySha256)) {
    throw new TypeError('821 Buff key compatibility requires packet rows and Replay SHA-256');
  }
  const allAdd = new Map();
  const gameAdd = new Map();
  const keyframeAdd = new Map();
  const remove = new Map();
  const seenPacketPositions = new Set();
  let gameAddPacketCount = 0;
  for (const row of addRows) {
    assertBoundRow(row, replaySha256, ADD_PACKET_ID);
    const key = keyFor(row);
    const position = positionFor(row);
    const positionId = position.join(':');
    if (seenPacketPositions.has(positionId)) {
      throw new TypeError('Buff packet candidate position is duplicated');
    }
    seenPacketPositions.add(positionId);
    addPosition(allAdd, key, position);
    if (row.raw_packet_ref.chunk_stream === 'game_chunk') {
      addPosition(gameAdd, key, position);
      gameAddPacketCount += 1;
    } else {
      addPosition(keyframeAdd, key, position);
    }
  }
  for (const row of removeRows) {
    assertBoundRow(row, replaySha256, REMOVE_PACKET_ID);
    const key = keyFor(row);
    const position = positionFor(row);
    const positionId = position.join(':');
    if (seenPacketPositions.has(positionId)) {
      throw new TypeError('Buff packet candidate position is duplicated');
    }
    seenPacketPositions.add(positionId);
    addPosition(remove, key, position);
  }
  for (const map of [allAdd, gameAdd, keyframeAdd, remove]) sortPositions(map);

  let removeKeysPresentInAdd = 0;
  let removeKeysPresentInGameAdd = 0;
  let removeKeysPresentInKeyframeAdd = 0;
  let removeKeysOnlyInKeyframeAdd = 0;
  let removePacketsWithKeyPresentInAdd = 0;
  let removePacketsWithKeyPresentInGameAdd = 0;
  let removePacketsWithKeyPresentInKeyframeAdd = 0;
  let removePacketsWithoutPrecedingGameAdd = 0;
  let removePacketsWithMultiplePrecedingGameAdds = 0;
  let removePacketsAfterPreviousRemoveWithoutInterveningGameAdd = 0;
  let distinctRemoveKeysWithMultiplePackets = 0;
  let distinctRemoveKeysWithMultipleGameAdds = 0;
  const unmatchedRemoveKeySamples = [];
  for (const [key, removePositions] of remove) {
    const allAddPositions = allAdd.get(key) || [];
    const gameAddPositions = gameAdd.get(key) || [];
    const keyframeAddPositions = keyframeAdd.get(key) || [];
    const count = removePositions.length;
    if (allAddPositions.length) {
      removeKeysPresentInAdd += 1;
      removePacketsWithKeyPresentInAdd += count;
    } else if (unmatchedRemoveKeySamples.length < 5) {
      const [opaqueU32, opaqueU8] = key.split(':').map(Number);
      unmatchedRemoveKeySamples.push({
        opaque_u32_0x10: opaqueU32, opaque_u8_0x14: opaqueU8,
        remove_packet_count: count,
      });
    }
    if (gameAddPositions.length) {
      removeKeysPresentInGameAdd += 1;
      removePacketsWithKeyPresentInGameAdd += count;
    }
    if (keyframeAddPositions.length) {
      removeKeysPresentInKeyframeAdd += 1;
      removePacketsWithKeyPresentInKeyframeAdd += count;
      if (!gameAddPositions.length) removeKeysOnlyInKeyframeAdd += 1;
    }
    if (count > 1) distinctRemoveKeysWithMultiplePackets += 1;
    if (gameAddPositions.length > 1) distinctRemoveKeysWithMultipleGameAdds += 1;
    for (let i = 0; i < count; i += 1) {
      const precedingGameAddCount = countBefore(gameAddPositions, removePositions[i]);
      if (precedingGameAddCount === 0) removePacketsWithoutPrecedingGameAdd += 1;
      if (precedingGameAddCount > 1) removePacketsWithMultiplePrecedingGameAdds += 1;
      if (i > 0 && (precedingGameAddCount === 0
          || comparePosition(removePositions[i - 1],
            gameAddPositions[precedingGameAddCount - 1]) > 0)) {
        removePacketsAfterPreviousRemoveWithoutInterveningGameAdd += 1;
      }
    }
  }
  return {
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_OPAQUE_BUFF_PACKET_KEY_COMPATIBILITY',
    game_version: REPLAY_VERSION,
    replay_sha256: replaySha256,
    add_packet_count: addRows.length,
    game_add_packet_count: gameAddPacketCount,
    keyframe_add_packet_count: addRows.length - gameAddPacketCount,
    remove_packet_count: removeRows.length,
    distinct_add_key_count: allAdd.size,
    distinct_game_add_key_count: gameAdd.size,
    distinct_keyframe_add_key_count: keyframeAdd.size,
    distinct_remove_key_count: remove.size,
    remove_keys_present_in_add: removeKeysPresentInAdd,
    remove_keys_present_in_game_add: removeKeysPresentInGameAdd,
    remove_keys_present_in_keyframe_add: removeKeysPresentInKeyframeAdd,
    remove_keys_only_in_keyframe_add: removeKeysOnlyInKeyframeAdd,
    remove_packets_with_key_present_in_add: removePacketsWithKeyPresentInAdd,
    remove_packets_with_key_present_in_game_add: removePacketsWithKeyPresentInGameAdd,
    remove_packets_with_key_present_in_keyframe_add: removePacketsWithKeyPresentInKeyframeAdd,
    remove_packets_without_preceding_game_add: removePacketsWithoutPrecedingGameAdd,
    remove_packets_with_multiple_preceding_game_adds: removePacketsWithMultiplePrecedingGameAdds,
    remove_packets_after_previous_remove_without_intervening_game_add:
      removePacketsAfterPreviousRemoveWithoutInterveningGameAdd,
    distinct_remove_keys_with_multiple_packets: distinctRemoveKeysWithMultiplePackets,
    distinct_remove_keys_with_multiple_game_adds: distinctRemoveKeysWithMultipleGameAdds,
    unmatched_remove_key_samples: unmatchedRemoveKeySamples,
    key_fields: {
      add: ['opaque_u32_0x10', 'opaque_u8_0x14'],
      remove: ['opaque_u32_0x10', 'opaque_u8_0x14'],
    },
    known_limits: [
      'Equality of anonymous exact-runtime packet fields does not establish buff identity, owner, target, or effect.',
      'Keyframe Add rows are snapshots, not evidence of a game-stream Add packet.',
      'Repeated keys and ambiguous ordering prevent a deterministic Add-to-Remove row join.',
      'No successful application, removal, duration, or lifecycle is inferred.',
    ],
  };
}

module.exports = { analyzeBuffPacketKeyCompatibility821 };
