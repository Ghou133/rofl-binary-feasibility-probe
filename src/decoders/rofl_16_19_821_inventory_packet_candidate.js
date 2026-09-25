'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { replaySourceError } = require('./replay_source_integrity');
const { collect821Routes, rowsFor821Capability } = require('./rofl_16_19_821_scan');

const REPLAY_VERSION = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const CAPABILITY = 'hero_inventory_packet';
const SNAPSHOT_APPLICATION = 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS';
const MAX_PACKETS = 256;
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MIN_PAYLOAD_BYTES = 23;
const MAX_PAYLOAD_BYTES = 159;
const FIRST_HERO_PARAM = 0x400000ae;
const LAST_HERO_PARAM = 0x400000b7;
const OBSERVED_VARIANTS = new Set([0x400001b2, 0x400001b5]);

const HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-inventory-mapview-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: 0x018d,
  packet_name: 'PKT_S2C_SetInventory_MapView_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_record_transform_table_sha256: 'ae15d606869d66dc47309b26cb489e01bf841e9dd57d540683e2dc7f5e394588',
  evidence_callback_receive_target_rva: '0x350240',
  evidence_callback_body_rva: '0x354c60',
  evidence_callback_clear_slot_rva: '0x2925f0',
  evidence_callback_zero_slot_rva: '0x5e5400',
  runtime_image_required: true,
  evidence_scope: 'exact KR runtime constructor/deserializer: 671 fully consumed packets and 5327 records across 11 exact-build Replays; exact-image callback clears client slots 0–9 before applying packet records; final ITEM0–ITEM6 tails support candidate field labels',
  known_limits: Object.freeze([
    'Each event is one observed packet. The exact-image callback resets slots 0–9 before applying its records; inventory between observed packets is unavailable.',
    'A null packet slot candidate means the slot had no record after the callback reset; it is not an observed later client state.',
    'Slot and item-definition key are exact-runtime decoded candidates, not published semantic fields.',
    'Participant mapping applies only to the ten canonical raw params and remains candidate-only.',
    'Observed raw-param variants 0x400001b2 and 0x400001b5 retain unavailable participant identity; their extra 0x100 bit has no assigned meaning.',
    'No purchase, sale, swap, per-item replacement, transaction, or inventory lifecycle is inferred.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packetRef(replay, block, chunk) {
  return {
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
    raw_payload_sha256: sha256(block.payload),
  };
}

function canonicalParticipant(rawParam) {
  return rawParam >= FIRST_HERO_PARAM && rawParam <= LAST_HERO_PARAM
    ? rawParam - 0x400000ad : null;
}

function inObservedParamFamily(rawParam) {
  return canonicalParticipant(rawParam) !== null || OBSERVED_VARIANTS.has(rawParam);
}

function decodeHeroInventoryPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `inventory packet candidate supports only ${REPLAY_VERSION}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  }
  let token;
  try {
    token = precollected ?? collect821Routes(replay, [CAPABILITY]);
  } catch (error) {
    return fail('DECODE_FAILED', `Replay framing failed: ${error.message}`);
  }
  const selected = rowsFor821Capability(replay, token, CAPABILITY);
  if (selected.error) {
    return fail('DECODE_FAILED', `Replay route source failed: ${selected.error}`);
  }
  const { rows, scanned_block_count: scannedBlockCount } = selected;
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x018d MapView route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount,
    scanned_block_count: scannedBlockCount,
    ...extra,
  });
  for (const row of rows) {
    const { block, chunk } = row;
    if (chunk.stream_tag !== 1 || block.packet_id !== profile.replay_block_packet_id
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !Number.isSafeInteger(block.timestamp_ms)) {
      return failed('DECODE_FAILED', '0x018d route framing differs from observed KR MapView scope', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (!inObservedParamFamily(block.param >>> 0)) {
      return failed('DECODE_FAILED', '0x018d raw param is outside the observed KR MapView family', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (block.payload_length < MIN_PAYLOAD_BYTES
        || block.payload_length > MAX_PAYLOAD_BYTES || block.payload[0] !== 0x1e) {
      return failed('DECODE_FAILED', '0x018d payload differs from observed KR MapView scope', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
  }
  if (inputCount > MAX_PACKETS) {
    return failed('UNSUPPORTED', `inventory runtime batch exceeds ${MAX_PACKETS} packets`);
  }
  if (typeof runtimeImagePath !== 'string' || !runtimeImagePath.trim()) {
    return failed('MISSING_INPUT', 'exact 16.19.821.7343 mapped runtime image is required', {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const imagePath = path.resolve(runtimeImagePath);
  try {
    const stat = fs.statSync(imagePath);
    if (!stat.isFile() || stat.size > MAX_IMAGE_BYTES) {
      return failed('MISSING_INPUT', 'runtime image is not a bounded file', {
        missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      });
    }
  } catch (error) {
    return failed('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const request = JSON.stringify({
    replay_version: REPLAY_VERSION,
    packets: rows.map(({ block }) => ({
      raw_param: block.param >>> 0,
      payload_hex: block.payload.toString('hex'),
    })),
  });
  if (Buffer.byteLength(request) > 2_000_000) {
    return failed('UNSUPPORTED', 'inventory runtime input exceeds its byte limit', {
      runtime_image_status: 'NOT_CHECKED',
    });
  }
  const python = pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_mapview_inventory_16_19_821.py');
  const run = childProcess.spawnSync(python, ['-B', script, '--image', imagePath], {
    input: request,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    timeout: 60000,
  });
  if (run.error || run.status !== 0) {
    const detail = String(run.error?.message || run.stderr || run.stdout
      || `Python exited ${run.status}`).trim();
    const missingPython = run.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    const wrongImage = /runtime image SHA-256 mismatch|record transform table differs/i.test(detail);
    return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `exact runtime MapView decoder failed: ${detail}`, {
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
        runtime_image_status: wrongImage ? 'HASH_MISMATCH'
          : missingPython ? 'NOT_CHECKED' : 'EXECUTION_FAILED',
      });
  }
  let decoded;
  try {
    decoded = JSON.parse(run.stdout);
  } catch (error) {
    return failed('DECODE_FAILED', `runtime MapView output is not JSON: ${error.message}`, {
      runtime_image_status: 'EXECUTION_FAILED',
    });
  }
  if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
      || !Array.isArray(decoded.results) || decoded.results.length !== inputCount) {
    return failed('DECODE_FAILED', 'runtime MapView output identity or packet count differs', {
      runtime_image_status: 'EXECUTION_FAILED',
    });
  }
  const events = [];
  let decodedRecordCount = 0;
  const variantRefs = [];
  for (let packetIndex = 0; packetIndex < inputCount; packetIndex += 1) {
    const { block, chunk } = rows[packetIndex];
    const rawRef = packetRef(replay, block, chunk);
    const result = decoded.results[packetIndex];
    if (result?.input_index !== packetIndex
        || result.raw_param !== (block.param >>> 0)
        || result.raw_payload_sha256 !== rawRef.raw_payload_sha256
        || result.status !== 'DECODED' || result.deserialize_return_al !== 1
        || result.bytes_consumed !== block.payload_length
        || !Number.isSafeInteger(result.record_count)
        || result.record_count < 2 || result.record_count > 9
        || !Array.isArray(result.records)
        || result.records.length !== result.record_count) {
      return failed('DECODE_FAILED', `runtime MapView packet ${packetIndex} did not fully decode`, {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: rawRef,
        runtime_packet_result: result ?? null,
      });
    }
    let priorSlot = -1;
    const records = [];
    for (let recordIndex = 0; recordIndex < result.records.length; recordIndex += 1) {
      const record = result.records[recordIndex];
      if (record?.record_index !== recordIndex
          || !Number.isSafeInteger(record.slot) || record.slot <= priorSlot
          || record.slot > 8 || !Number.isSafeInteger(record.item_id)
          || record.item_id < 1 || record.item_id > 0xffffffff
          || !/^[0-9a-f]{2}$/.test(record.raw_slot_byte_hex)
          || !/^[0-9a-f]{8}$/.test(record.raw_item_id_bytes_hex)) {
        return failed('DECODE_FAILED', `runtime MapView packet ${packetIndex} has an invalid record`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: rawRef,
        });
      }
      priorSlot = record.slot;
      records.push({
        record_index: recordIndex,
        slot_candidate: record.slot,
        item_id_candidate: record.item_id,
        emulated_object_slot_byte_hex: record.raw_slot_byte_hex,
        emulated_object_item_id_bytes_hex: record.raw_item_id_bytes_hex,
      });
    }
    decodedRecordCount += records.length;
    const packetSlotSnapshot = Array.from({ length: 10 }, (_, slot) => ({
      slot_candidate: slot,
      item_id_candidate: null,
      value_basis: 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
    }));
    for (const record of records) {
      packetSlotSnapshot[record.slot_candidate] = {
        slot_candidate: record.slot_candidate,
        item_id_candidate: record.item_id_candidate,
        value_basis: 'DECODED_PACKET_RECORD',
      };
    }
    const participant = canonicalParticipant(block.param >>> 0);
    if (participant === null) variantRefs.push(rawRef);
    events.push({
      event_type: 'HERO_INVENTORY_MAPVIEW_PACKET_CANDIDATE',
      game_version: REPLAY_VERSION,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: block.timestamp_ms,
      hero_raw_param: block.param >>> 0,
      participant_id_candidate: participant,
      snapshot_application: SNAPSHOT_APPLICATION,
      record_count: records.length,
      records_candidate: records,
      packet_slot_snapshot_candidate: packetSlotSnapshot,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_MAPVIEW_PACKET_FIELDS',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        hero_raw_param: 'VERIFIED_DIRECT',
        participant_id_candidate: participant === null ? 'UNAVAILABLE' : 'CANDIDATE',
        snapshot_application: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_APPLICATION',
        packet_slot_snapshot_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_APPLICATION_AND_RECORD_FIELDS',
        slot_candidate: 'CANDIDATE_EXACT_RUNTIME_FIELD',
        item_id_candidate: 'CANDIDATE_EXACT_RUNTIME_ITEM_DEFINITION_KEY',
      },
      raw_packet_ref: rawRef,
      known_limits: [...profile.known_limits],
    });
  }
  return {
    ...base,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_MAPVIEW_PACKET_FIELDS',
    input_count: inputCount,
    event_count: events.length,
    decoded_record_count: decodedRecordCount,
    unmapped_raw_param_count: variantRefs.length,
    unmapped_raw_packet_refs: variantRefs,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256,
    events,
  };
}

module.exports = {
  HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821,
  decodeHeroInventoryPacketCandidates821,
};
