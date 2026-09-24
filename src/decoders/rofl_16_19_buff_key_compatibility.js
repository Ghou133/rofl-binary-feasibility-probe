'use strict';

// This compares exact-runtime packet scalars only. Repeated opaque keys cannot
// establish an Add-to-Remove packet join, owner, buff identity, or lifecycle.
const REPLAY_VERSION = '16.19.820.7193';
const ADD_PACKET_ID = 0x03ed;
const REMOVE_PACKET_ID = 0x043c;

function candidateKey(token, slot) {
  if (!Number.isSafeInteger(token) || token < 0 || token > 0xffffffff
      || !Number.isSafeInteger(slot) || slot < 0 || slot > 255) {
    throw new TypeError('Buff packet candidate key has an invalid token or slot');
  }
  return `${token}:${slot}`;
}

function assertBoundRow(row, replaySha256, packetId) {
  if (!row || row.game_version !== REPLAY_VERSION
      || row.replay_sha256 !== replaySha256
      || row.raw_packet_ref?.replay_sha256 !== replaySha256
      || row.raw_packet_ref?.packet_id !== packetId) {
    throw new TypeError('Buff packet candidate row is not bound to this exact Replay and route');
  }
}

function addCount(map, key) {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function analyzeBuffPacketKeyCompatibility(addRows, removeRows, replaySha256) {
  if (!Array.isArray(addRows) || !Array.isArray(removeRows)
      || typeof replaySha256 !== 'string' || !/^[0-9a-f]{64}$/.test(replaySha256)) {
    throw new TypeError('Buff key compatibility requires packet rows and Replay SHA-256');
  }
  const allAdd = new Map();
  const gameAdd = new Map();
  const remove = new Map();
  for (const row of addRows) {
    assertBoundRow(row, replaySha256, ADD_PACKET_ID);
    if (row.stream_tag !== 1 && row.stream_tag !== 2) {
      throw new TypeError('BuffAdd2 candidate has an unsupported stream tag');
    }
    const fields = row.decoded_scalar_fields_candidate;
    const key = candidateKey(fields?.offset_0x30_u32, fields?.offset_0x28_u8);
    addCount(allAdd, key);
    if (row.stream_tag === 1) addCount(gameAdd, key);
  }
  for (const row of removeRows) {
    assertBoundRow(row, replaySha256, REMOVE_PACKET_ID);
    const key = candidateKey(row.buff_lookup_token_u32_candidate,
      row.buff_slot_index_candidate);
    addCount(remove, key);
  }
  let removeKeysInAdd = 0;
  let removeKeysInGameAdd = 0;
  let removePacketsWithAddKey = 0;
  let removePacketsWithGameAddKey = 0;
  const unmatchedKeySamples = [];
  for (const [key, count] of remove) {
    if (allAdd.has(key)) {
      removeKeysInAdd += 1;
      removePacketsWithAddKey += count;
    } else if (unmatchedKeySamples.length < 5) {
      const [token, slot] = key.split(':').map(Number);
      unmatchedKeySamples.push({ token_u32_candidate: token,
        slot_u8_candidate: slot, remove_packet_count: count });
    }
    if (gameAdd.has(key)) {
      removeKeysInGameAdd += 1;
      removePacketsWithGameAddKey += count;
    }
  }
  return {
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_OPAQUE_BUFF_PACKET_KEY_COMPATIBILITY',
    game_version: REPLAY_VERSION,
    replay_sha256: replaySha256,
    add_packet_count: addRows.length,
    game_add_packet_count: addRows.filter((row) => row.stream_tag === 1).length,
    remove_packet_count: removeRows.length,
    distinct_add_key_count: allAdd.size,
    distinct_game_add_key_count: gameAdd.size,
    distinct_remove_key_count: remove.size,
    remove_keys_present_in_add: removeKeysInAdd,
    remove_keys_present_in_game_add: removeKeysInGameAdd,
    remove_packets_with_key_present_in_add: removePacketsWithAddKey,
    remove_packets_with_key_present_in_game_add: removePacketsWithGameAddKey,
    unmatched_remove_key_samples: unmatchedKeySamples,
    key_fields: {
      add: ['decoded_scalar_fields_candidate.offset_0x30_u32',
        'decoded_scalar_fields_candidate.offset_0x28_u8'],
      remove: ['buff_lookup_token_u32_candidate', 'buff_slot_index_candidate'],
    },
    known_limits: [
      'This is equality of anonymous exact-runtime packet fields, not buff identity or owner.',
      'Keyframe Add rows are snapshots; a matching key does not prove a game Add packet.',
      'Repeated keys, missing preceding game Adds, and ambiguous ordering prevent a deterministic Add-to-Remove row join.',
      'No application, removal, duration, success, or lifecycle is inferred.',
    ],
  };
}

module.exports = { analyzeBuffPacketKeyCompatibility };
