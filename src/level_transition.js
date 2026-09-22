const LEVEL_MAPPING_REPLAY_VERSION = '16.15.801.3452';

const LEVEL_AFTER_BY_FIELD_10 = Object.freeze({
  197: 4,
  198: 5,
  199: 7,
  204: 6,
  207: 3,
  224: 2,
});

const LEVEL_AFTER_BY_REPLAY_VERSION = Object.freeze({
  [LEVEL_MAPPING_REPLAY_VERSION]: LEVEL_AFTER_BY_FIELD_10,
  '16.16.805.0442': require('./decoders/rofl_16_16_805_0442').LEVEL_AFTER_BY_FIELD_10,
});

function levelMapping(rawField10, gameVersion) {
  const versionMapping = LEVEL_AFTER_BY_REPLAY_VERSION[gameVersion];
  if (!versionMapping) {
    return {
      level_before: null,
      level_after: null,
      evidence: 'UNSUPPORTED_VERSION',
      qualification: `mapping is verified only for ${Object.keys(LEVEL_AFTER_BY_REPLAY_VERSION).join(', ')}`,
    };
  }
  if (!Number.isInteger(rawField10)
      || !Object.hasOwn(versionMapping, rawField10)) {
    return {
      level_before: null,
      level_after: null,
      evidence: 'UNAVAILABLE',
      qualification: 'raw field value has no verified level-after mapping in the current corpus',
    };
  }
  const levelAfter = versionMapping[rawField10];
  return {
    level_before: levelAfter - 1,
    level_after: levelAfter,
    evidence: 'VERIFIED_DERIVED',
    qualification: `PATCH_BOUND_TO_${gameVersion}`,
  };
}

function levelEventOrder(left, right) {
  return (left.timestamp_ms ?? left.replay_time_ms ?? 0)
    - (right.timestamp_ms ?? right.replay_time_ms ?? 0)
    || (left.raw_packet_ref?.chunk_index ?? 0) - (right.raw_packet_ref?.chunk_index ?? 0)
    || (left.raw_packet_ref?.decompressed_block_offset ?? 0)
      - (right.raw_packet_ref?.decompressed_block_offset ?? 0);
}

function summarizeLevelSequences(events, options = {}) {
  const includeInitialization = options.includeInitialization === true;
  const sequences = new Map();
  for (const event of events || []) {
    if (!includeInitialization && event.is_initialization === true) continue;
    if (!Number.isInteger(event.participant_id) || !Number.isInteger(event.level_after)) continue;
    let sequence = sequences.get(event.participant_id);
    if (!sequence) {
      sequence = [];
      sequences.set(event.participant_id, sequence);
    }
    sequence.push(event);
  }

  let monotonicSequenceCount = 0;
  for (const sequence of sequences.values()) {
    sequence.sort(levelEventOrder);
    const monotonic = sequence.every((event, index) => index === 0
      || (event.level_after > sequence[index - 1].level_after
        && (event.timestamp_ms ?? event.replay_time_ms)
          > (sequence[index - 1].timestamp_ms ?? sequence[index - 1].replay_time_ms)));
    if (monotonic) monotonicSequenceCount += 1;
  }
  return {
    participant_sequence_count: sequences.size,
    monotonic_participant_sequence_count: monotonicSequenceCount,
    all_monotonic: sequences.size === monotonicSequenceCount,
  };
}

function queryLevelTransitions(events, options = {}) {
  const requestedLevels = Array.isArray(options.levels)
    ? new Set(options.levels.map(Number).filter(Number.isInteger))
    : null;
  return [...(events || [])]
    .filter((event) => options.includeInitialization === true || event.is_initialization !== true)
    .filter((event) => options.includeUnmapped !== false || Number.isInteger(event.level_after))
    .filter((event) => options.participantId === undefined
      || event.participant_id === options.participantId)
    .filter((event) => options.entityNetworkId === undefined
      || event.entity_network_id === options.entityNetworkId)
    .filter((event) => options.champion === undefined
      || event.champion === options.champion)
    .filter((event) => requestedLevels === null || requestedLevels.has(event.level_after))
    .sort(levelEventOrder);
}

module.exports = {
  LEVEL_AFTER_BY_FIELD_10,
  LEVEL_AFTER_BY_REPLAY_VERSION,
  LEVEL_MAPPING_REPLAY_VERSION,
  levelEventOrder,
  levelMapping,
  queryLevelTransitions,
  summarizeLevelSequences,
};
