'use strict';

const EXACT_BUILD = '16.16.805.0442';
const PRELUDE_PACKET_ID = 0x01c2;
const ENVELOPE_PACKET_ID = 0x0473;
const IMAGE_BASE = 0x140000000n;
const EXACT_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';

const RUNTIME_LAYOUT = Object.freeze({
  packet_factory: {
    function_rva: 0x00ed97b0,
    switch_rva: 0x00ed97e0,
    maximum_direct_index: 0x04de,
    jump_table_rva: 0x00eea1bc,
  },
  route_01c2: {
    packet_id: PRELUDE_PACKET_ID,
    jump_table_entry_rva: 0x00eea8c4,
    case_rva: 0x00edfe07,
    allocation_size: 0x18,
    allocator_rva: 0x011928c0,
    constructor_call_rva: 0x00edfe1b,
    constructor_rva: 0x00e8b0a0,
    packet_object_vtable_rva: 0x01b123d0,
    vtable_entries_rva: [0x001e6780, 0x00f66dd0, 0x00284190, 0x001e81b0, 0x0021cd70, 0x00ec52a0],
    deserializer_rva: 0x00f66dd0,
    deserializer_end_rva: 0x00f66fdb,
    object_size: 0x18,
    neutral_fields: [
      { offset: 0x10, storage: 'protected_u32', tag_bits: { shift: 1, width: 3 } },
      { offset: 0x14, storage: 'protected_u8', tag_bits: { shift: 0, width: 1 } },
    ],
  },
  route_0473: {
    packet_id: ENVELOPE_PACKET_ID,
    jump_table_entry_rva: 0x00eeb388,
    case_rva: 0x00ee8831,
    allocation_size: 0x20,
    allocator_rva: 0x011928c0,
    constructor_call_rva: 0x00ee8843,
    constructor_rva: 0x00e7a930,
    packet_object_vtable_rva: 0x01b12370,
    vtable_entries_rva: [0x001e6780, 0x00f5e550, 0x00317210, 0x00eb6aa0, 0x0021cd70, 0x00ebca30],
    deserializer_rva: 0x00f5e550,
    deserializer_end_rva: 0x00f5e690,
    object_size: 0x20,
    vector_field_offset: 0x10,
    outer_count_table_rva: 0x01b1ba00,
    nested_record: {
      vtable_rva: 0x01ab9870,
      deserializer_rva: 0x00f57e30,
      deserializer_end_rva: 0x00f590a6,
      size_getter_rva: 0x004d5760,
      object_size: 0x50,
    },
  },
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function round(value, digits = 8) {
  if (!Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function formatRoute(packetId) {
  return `0x${packetId.toString(16).padStart(4, '0')}`;
}

function countRows(values, keyName, options = {}) {
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  const sort = options.sort ?? 'count';
  const rows = [...counts.entries()].map(([value, count]) => ({ [keyName]: value, count }));
  rows.sort(sort === 'value'
    ? (left, right) => Number(left[keyName]) - Number(right[keyName])
      || String(left[keyName]).localeCompare(String(right[keyName]))
    : (left, right) => right.count - left.count
      || String(left[keyName]).localeCompare(String(right[keyName])));
  return options.limit === undefined ? rows : rows.slice(0, options.limit);
}

function quantile(sorted, fraction) {
  if (!sorted.length) return null;
  const index = (sorted.length - 1) * fraction;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
}

function numericSummary(values) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return { count: 0, min: null, mean: null, p50: null, p95: null, p99: null, max: null };
  return {
    count: sorted.length,
    min: sorted[0],
    mean: round(sorted.reduce((sum, value) => sum + value, 0) / sorted.length),
    p50: round(quantile(sorted, 0.5)),
    p95: round(quantile(sorted, 0.95)),
    p99: round(quantile(sorted, 0.99)),
    max: sorted[sorted.length - 1],
  };
}

function correlation(leftValues, rightValues) {
  invariant(leftValues.length === rightValues.length, 'correlation vectors differ in length');
  const pairs = leftValues.map((left, index) => [left, rightValues[index]])
    .filter(([left, right]) => Number.isFinite(left) && Number.isFinite(right));
  if (pairs.length < 2) return { n: pairs.length, pearson_r: null, slope: null, intercept: null, r_squared: null };
  const meanX = pairs.reduce((sum, row) => sum + row[0], 0) / pairs.length;
  const meanY = pairs.reduce((sum, row) => sum + row[1], 0) / pairs.length;
  let covariance = 0;
  let varianceX = 0;
  let varianceY = 0;
  for (const [x, y] of pairs) {
    covariance += (x - meanX) * (y - meanY);
    varianceX += (x - meanX) ** 2;
    varianceY += (y - meanY) ** 2;
  }
  if (varianceX === 0 || varianceY === 0) {
    return { n: pairs.length, pearson_r: null, slope: null, intercept: null, r_squared: null };
  }
  const pearson = covariance / Math.sqrt(varianceX * varianceY);
  const slope = covariance / varianceX;
  return {
    n: pairs.length,
    pearson_r: round(pearson),
    slope: round(slope),
    intercept: round(meanY - slope * meanX),
    r_squared: round(pearson ** 2),
  };
}

function eventOrder(left, right) {
  return left.global_block_index - right.global_block_index
    || left.chunk_index - right.chunk_index
    || left.decompressed_block_offset - right.decompressed_block_offset;
}

function decodeProtectionByte(encoded, table) {
  invariant(Buffer.isBuffer(table) && table.length === 256, 'outer-count table must contain 256 bytes');
  let value = (~encoded) & 0xff;
  value = ((value >>> 4) | ((value << 4) & 0xff)) & 0xff;
  value = table[value];
  value = table[value];
  value = (value - 0x59) & 0xff;
  return table[value];
}

function decodeRoute0473OuterHeader(payload, table) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
  if (!payload.length) return { ok: false, error: 'EMPTY_PAYLOAD' };
  const tag = payload[0] & 1;
  if (tag === 0) {
    return { ok: true, outer_tag: 0, record_count: 0, count_wire_bytes: 0, header_bytes: 1 };
  }
  let value = 0;
  let shift = 0;
  for (let cursor = 1; cursor < payload.length && cursor <= 10; cursor += 1) {
    const decoded = decodeProtectionByte(payload[cursor], table);
    value += (decoded & 0x7f) * (2 ** shift);
    if (!Number.isSafeInteger(value)) return { ok: false, error: 'COUNT_OVERFLOW' };
    if ((decoded & 0x80) === 0) {
      return {
        ok: true,
        outer_tag: 1,
        record_count: value,
        count_wire_bytes: cursor,
        header_bytes: cursor + 1,
      };
    }
    shift += 7;
  }
  return { ok: false, error: 'TRUNCATED_OR_OVERSIZED_COUNT' };
}

function readRvaQwordAsRva(image, rva) {
  invariant(rva >= 0 && rva + 8 <= image.length, `qword RVA out of range: 0x${rva.toString(16)}`);
  const value = image.readBigUInt64LE(rva);
  invariant(value >= IMAGE_BASE, `qword is below image base at 0x${rva.toString(16)}`);
  return Number(value - IMAGE_BASE);
}

function validateRuntimeIdentity(image) {
  invariant(Buffer.isBuffer(image), 'runtime image must be a Buffer');
  const checks = {};
  for (const route of [RUNTIME_LAYOUT.route_01c2, RUNTIME_LAYOUT.route_0473]) {
    const key = formatRoute(route.packet_id);
    checks[`${key}_factory_jump_table_entry`] = image.readUInt32LE(route.jump_table_entry_rva) === route.case_rva;
    const constructorNeedle = Buffer.from([0x66, 0xc7, 0x41, 0x08, route.packet_id & 0xff, route.packet_id >>> 8]);
    checks[`${key}_constructor_id_write`] = image.subarray(route.constructor_rva, route.constructor_rva + 0x30).includes(constructorNeedle);
    checks[`${key}_vtable_entries`] = route.vtable_entries_rva.every((expected, slot) =>
      readRvaQwordAsRva(image, route.packet_object_vtable_rva + slot * 8) === expected);
    checks[`${key}_size_getter`] = image.readUInt32LE(route.vtable_entries_rva[2] + 1) === route.object_size;
  }
  const nested = RUNTIME_LAYOUT.route_0473.nested_record;
  checks['0x0473_nested_record_deserializer_vtable_slot'] = readRvaQwordAsRva(image, nested.vtable_rva + 8) === nested.deserializer_rva;
  checks['0x0473_nested_record_size_getter_vtable_slot'] = readRvaQwordAsRva(image, nested.vtable_rva + 0x10) === nested.size_getter_rva;
  checks['0x0473_nested_record_size_getter'] = image.readUInt32LE(nested.size_getter_rva + 1) === nested.object_size;
  return {
    status: Object.values(checks).every(Boolean) ? 'VERIFIED_EXACT_FACTORY_CONSTRUCTOR_VTABLE_DESERIALIZER_CHAIN' : 'VALIDATION_FAILED',
    all_checks_pass: Object.values(checks).every(Boolean),
    checks,
    layout: RUNTIME_LAYOUT,
    static_callback_surface: {
      status: 'UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE',
      interpretation: 'Static negative only for that registration surface; the packet factory identity above is independently closed.',
    },
    full_plaintext_decode_failure_surface: {
      status: 'BLOCKED_BY_PROCESS_RUNTIME_PROTECTION_STATE',
      first_missing_virtual_address_hex: '0x25cc4670',
      route_01c2_dynamic_helper_rva_hex: '0x00f51410',
      route_0473_nested_deserializer_rva_hex: '0x00f57e30',
      reason: 'Exact offline execution reaches protected storage helpers that dereference process-populated state outside the captured image.',
    },
  };
}

function groupEvents(events) {
  const groups = new Map();
  for (const event of events) {
    const exactTime = event.replay_time_seconds_exact ?? (event.replay_time_ms / 1000);
    const key = `${event.replay_sha256}:${exactTime}`;
    if (!groups.has(key)) groups.set(key, {
      replay_sha256: event.replay_sha256,
      replay_label: event.replay_label ?? null,
      replay_time_ms: event.replay_time_ms,
      replay_time_seconds_exact: exactTime,
      prelude: [],
      envelope: [],
    });
    groups.get(key)[event.packet_id === PRELUDE_PACKET_ID ? 'prelude' : 'envelope'].push(event);
  }
  for (const group of groups.values()) {
    group.prelude.sort(eventOrder);
    group.envelope.sort(eventOrder);
  }
  return [...groups.values()].sort((left, right) =>
    String(left.replay_sha256).localeCompare(String(right.replay_sha256))
    || left.replay_time_ms - right.replay_time_ms);
}

function witness(group) {
  return {
    replay_sha256: group.replay_sha256,
    replay_label: group.replay_label,
    replay_time_ms: group.replay_time_ms,
    replay_time_seconds_exact: group.replay_time_seconds_exact,
    route_01c2_count: group.prelude.length,
    route_0473_count: group.envelope.length,
    route_01c2_first_payload_hex: group.prelude[0]?.raw_payload_hex ?? null,
    route_0473_first_payload_prefix_hex: group.envelope[0]?.raw_payload_hex.slice(0, 32) ?? null,
  };
}

function bytePositionProfiles(events, maximumLength) {
  const profiles = [];
  for (let offset = 0; offset < maximumLength; offset += 1) {
    const bytes = events.filter((event) => event.payload_buffer.length > offset)
      .map((event) => event.payload_buffer[offset]);
    profiles.push({
      offset,
      observed_count: bytes.length,
      distinct_count: new Set(bytes).size,
      values: countRows(bytes.map((byte) => `0x${byte.toString(16).padStart(2, '0')}`), 'byte_hex'),
    });
  }
  return profiles;
}

function analyzeRoutePair(events, options = {}) {
  const selected = events.filter((event) => [PRELUDE_PACKET_ID, ENVELOPE_PACKET_ID].includes(event.packet_id));
  for (const event of selected) {
    invariant(event.replay_version === EXACT_BUILD, `wrong build ${event.replay_version}`);
    event.payload_buffer = event.payload_buffer ?? Buffer.from(event.raw_payload_hex, 'hex');
    invariant(event.payload_buffer.length === event.payload_length, 'payload length mismatch');
  }
  const table = options.outerCountTable;
  invariant(Buffer.isBuffer(table) && table.length === 256, 'exact outer-count table is required');
  const preludeEvents = selected.filter((event) => event.packet_id === PRELUDE_PACKET_ID);
  const envelopeEvents = selected.filter((event) => event.packet_id === ENVELOPE_PACKET_ID);
  const groups = groupEvents(selected);
  const preludeGroups = groups.filter((group) => group.prelude.length);
  const envelopeGroups = groups.filter((group) => group.envelope.length);
  const sharedGroups = groups.filter((group) => group.prelude.length && group.envelope.length);
  const preludeOnlyGroups = groups.filter((group) => group.prelude.length && !group.envelope.length);
  const envelopeOnlyGroups = groups.filter((group) => !group.prelude.length && group.envelope.length);
  const shapeViolations = [];
  let sharedPreludeRows = 0;
  let uniqueEnvelopeGroups = 0;
  let orderedGroups = 0;
  let sameChunkGroups = 0;
  let finalImmediateGroups = 0;
  let contiguousPreludeRunGroups = 0;
  let directContainmentRows = 0;
  let reverseImmediateGroups = 0;
  const sharedRows = [];
  const globalAdjacencyCounterexamples = [];
  for (const group of sharedGroups) {
    sharedPreludeRows += group.prelude.length;
    const envelope = group.envelope[0];
    const lastPrelude = group.prelude[group.prelude.length - 1];
    const uniqueEnvelope = group.envelope.length === 1;
    const ordered = uniqueEnvelope && group.prelude.every((event) => eventOrder(event, envelope) < 0);
    const sameChunk = uniqueEnvelope && group.prelude.every((event) => event.chunk_index === envelope.chunk_index);
    const finalImmediate = uniqueEnvelope && lastPrelude.global_block_index + 1 === envelope.global_block_index;
    const contiguousRun = finalImmediate && group.prelude.every((event, index) =>
      index === 0 || event.global_block_index === group.prelude[index - 1].global_block_index + 1);
    const reverseImmediate = uniqueEnvelope && envelope.next_global_packet_id === PRELUDE_PACKET_ID
      && (envelope.next_global_timestamp_seconds_exact ?? envelope.next_global_timestamp_ms / 1000)
        === group.replay_time_seconds_exact;
    if (uniqueEnvelope) uniqueEnvelopeGroups += 1;
    if (ordered) orderedGroups += 1;
    if (sameChunk) sameChunkGroups += 1;
    if (finalImmediate) finalImmediateGroups += 1;
    if (contiguousRun) contiguousPreludeRunGroups += 1;
    else if (uniqueEnvelope && ordered && sameChunk) {
      globalAdjacencyCounterexamples.push({
        ...witness(group),
        last_01c2_global_block_index: lastPrelude.global_block_index,
        route_0473_global_block_index: envelope.global_block_index,
        intervening_global_block_count: envelope.global_block_index - lastPrelude.global_block_index - 1,
      });
    }
    if (reverseImmediate) reverseImmediateGroups += 1;
    const envelopeBuffer = envelope.payload_buffer;
    for (const event of group.prelude) {
      if (envelopeBuffer.includes(event.payload_buffer)) directContainmentRows += 1;
    }
    const outer = decodeRoute0473OuterHeader(envelopeBuffer, table);
    sharedRows.push({
      batch_size: group.prelude.length,
      envelope_payload_length: envelope.payload_length,
      outer_record_count: outer.ok ? outer.record_count : null,
      outer_decode_ok: outer.ok,
    });
    if (!(uniqueEnvelope && ordered && sameChunk)) {
      shapeViolations.push({ ...witness(group), unique_envelope: uniqueEnvelope, ordered, same_chunk: sameChunk, final_immediate: finalImmediate, contiguous_prelude_run: contiguousRun });
    }
  }

  const outerHeaders = envelopeEvents.map((event) => decodeRoute0473OuterHeader(event.payload_buffer, table));
  const outerFailures = outerHeaders.filter((header) => !header.ok);
  const expectedCounts = options.expectedCounts ?? null;
  const inventoryMatch = expectedCounts === null || (
    expectedCounts[PRELUDE_PACKET_ID] === preludeEvents.length
    && expectedCounts[ENVELOPE_PACKET_ID] === envelopeEvents.length
  );
  const rawParamAllZero = selected.length > 0 && selected.every((event) => event.raw_param === 0);
  const sharedShapePass = sharedGroups.length > 0
    && uniqueEnvelopeGroups === sharedGroups.length
    && orderedGroups === sharedGroups.length
    && sameChunkGroups === sharedGroups.length
    && reverseImmediateGroups === 0;
  const outerDecodePass = envelopeEvents.length > 0 && outerFailures.length === 0;
  const runtimePass = options.runtimeIdentity?.all_checks_pass === true;
  const repurposePass = inventoryMatch && rawParamAllZero && sharedShapePass && outerDecodePass && runtimePass;
  const replayKeys = [...new Set(selected.map((event) => event.replay_sha256))].sort();
  const perReplay = replayKeys.map((replaySha256) => {
    const replayPrelude = preludeEvents.filter((event) => event.replay_sha256 === replaySha256);
    const replayEnvelope = envelopeEvents.filter((event) => event.replay_sha256 === replaySha256);
    const replayGroups = groups.filter((group) => group.replay_sha256 === replaySha256);
    const replayShared = replayGroups.filter((group) => group.prelude.length && group.envelope.length);
    return {
      replay_sha256: replaySha256,
      replay_label: replayGroups[0]?.replay_label ?? null,
      route_01c2_event_count: replayPrelude.length,
      route_0473_event_count: replayEnvelope.length,
      route_01c2_timestamp_group_count: replayGroups.filter((group) => group.prelude.length).length,
      route_0473_timestamp_group_count: replayGroups.filter((group) => group.envelope.length).length,
      shared_timestamp_group_count: replayShared.length,
      shared_route_01c2_row_count: replayShared.reduce((sum, group) => sum + group.prelude.length, 0),
    };
  });

  const preludeTagRows = preludeEvents.map((event) => ({
    prefix: event.payload_buffer[0],
    field_10_tag: (event.payload_buffer[0] >>> 1) & 0x07,
    field_14_tag: event.payload_buffer[0] & 0x01,
    payload_length: event.payload_length,
  }));
  const branchName = (row) => {
    const field10 = row.field_10_tag === 1 ? 'CONSTANT_MINUS_ONE'
      : row.field_10_tag === 5 ? 'CONSTANT_ZERO' : 'DYNAMIC_PROTECTED_U32';
    const field14 = row.field_14_tag === 0 ? 'STATIC_DEFAULT_PROTECTED_U8' : 'DYNAMIC_PROTECTED_U8';
    return `${field10}+${field14}`;
  };
  const bucketMap = new Map();
  for (const row of sharedRows) {
    if (!bucketMap.has(row.batch_size)) bucketMap.set(row.batch_size, []);
    bucketMap.get(row.batch_size).push(row);
  }
  const batchBuckets = [...bucketMap.entries()].sort((a, b) => a[0] - b[0]).map(([batchSize, rows]) => ({
    route_01c2_batch_size: batchSize,
    group_count: rows.length,
    route_0473_payload_length: numericSummary(rows.map((row) => row.envelope_payload_length)),
    route_0473_outer_record_count: numericSummary(rows.map((row) => row.outer_record_count)),
  }));
  const nextRequiredEvidence = [
    'Capture the process-populated protection state rooted at virtual address 0x25cc4670, or hook plaintext immediately before protected in-object storage, to close 0x01c2 values and 0x0473 nested record fields.',
    'Obtain a callback/consumer read-site or controlled gameplay perturbation that independently anchors any nested field before assigning a gameplay semantic.',
    'Add a new exact-build replay only through the governed safe-evidence process to test the optional-prelude counterexample population out of sample.',
  ];

  return {
    schema: 'ROUTE_PAIR_01C2_0473_BATCH_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    audit_scope: {
      project_context_loaded: true,
      architecture_gate: 'PASS',
      architecture_gate_reason: 'Parser-owned, offline, exact-build structural recovery in dedicated research files; no map truth, behavior inference, acquisition, UI, public API, manifest, or canonical schema mutation.',
      evidence_scope: 'EXPLICIT_SAFE_LATEST_FOUR_REPLAYS_PLUS_PINNED_EXACT_RUNTIME_IMAGE_AND_SIDECARS',
    },
    pair: {
      prelude_route: formatRoute(PRELUDE_PACKET_ID),
      envelope_route: formatRoute(ENVELOPE_PACKET_ID),
      timestamp_group_key: 'REPLAY_SHA256_PLUS_EXACT_PARSED_TIMESTAMP_SECONDS_UNROUNDED',
      timestamp_rounding_policy: 'replay_time_ms is presentation-only and is never used to merge groups',
      structural_identity: 'OPTIONAL_PROTECTED_TWO_FIELD_PRELUDE_RUN_IMMEDIATELY_BEFORE_PROTECTED_VECTOR_RECORD_BATCH_ENVELOPE',
      gameplay_semantic_claim: null,
    },
    counts: {
      route_01c2_event_count: preludeEvents.length,
      route_0473_event_count: envelopeEvents.length,
      route_01c2_timestamp_group_count: preludeGroups.length,
      route_0473_timestamp_group_count: envelopeGroups.length,
      shared_timestamp_group_count: sharedGroups.length,
      shared_route_01c2_row_count: sharedPreludeRows,
      route_01c2_only_timestamp_group_count: preludeOnlyGroups.length,
      route_01c2_only_row_count: preludeOnlyGroups.reduce((sum, group) => sum + group.prelude.length, 0),
      route_0473_only_timestamp_group_count: envelopeOnlyGroups.length,
      route_0473_only_row_count: envelopeOnlyGroups.reduce((sum, group) => sum + group.envelope.length, 0),
    },
    relationship: {
      route_01c2_timestamp_group_shared_rate: round(sharedGroups.length / preludeGroups.length),
      route_01c2_row_shared_rate: round(sharedPreludeRows / preludeEvents.length),
      route_0473_timestamp_group_with_prelude_rate: round(sharedGroups.length / envelopeGroups.length),
      shared_group_unique_0473_count: uniqueEnvelopeGroups,
      shared_group_01c2_before_0473_count: orderedGroups,
      shared_group_same_chunk_count: sameChunkGroups,
      shared_group_01c2_to_0473_selected_pair_immediate_count: orderedGroups,
      shared_group_01c2_to_0473_global_immediate_count: finalImmediateGroups,
      shared_group_01c2_to_0473_global_immediate_rate: round(finalImmediateGroups / sharedGroups.length),
      shared_group_contiguous_full_01c2_run_count: contiguousPreludeRunGroups,
      shared_group_0473_to_01c2_reverse_immediate_count: reverseImmediateGroups,
      direct_01c2_payload_contained_in_0473_row_count: directContainmentRows,
      direct_01c2_payload_containment_rate: round(directContainmentRows / sharedPreludeRows),
      correlations: {
        route_01c2_batch_size_vs_route_0473_payload_length: correlation(sharedRows.map((row) => row.batch_size), sharedRows.map((row) => row.envelope_payload_length)),
        route_01c2_batch_size_vs_route_0473_outer_record_count: correlation(sharedRows.map((row) => row.batch_size), sharedRows.map((row) => row.outer_record_count)),
        route_0473_outer_record_count_vs_payload_length: correlation(sharedRows.map((row) => row.outer_record_count), sharedRows.map((row) => row.envelope_payload_length)),
      },
    },
    route_01c2_codec: {
      object_layout: RUNTIME_LAYOUT.route_01c2,
      raw_param: {
        zero_count: preludeEvents.filter((event) => event.raw_param === 0).length,
        nonzero_count: preludeEvents.filter((event) => event.raw_param !== 0).length,
        distinct_count: new Set(preludeEvents.map((event) => event.raw_param)).size,
      },
      payload_length_distribution: countRows(preludeEvents.map((event) => event.payload_length), 'payload_length', { sort: 'value' }),
      prefix_distribution: countRows(preludeTagRows.map((row) => `0x${row.prefix.toString(16).padStart(2, '0')}`), 'prefix_hex'),
      field_10_tag_distribution: countRows(preludeTagRows.map((row) => row.field_10_tag), 'tag', { sort: 'value' }),
      field_14_tag_distribution: countRows(preludeTagRows.map((row) => row.field_14_tag), 'tag', { sort: 'value' }),
      codec_branch_distribution: countRows(preludeTagRows.map(branchName), 'branch'),
      tag_pair_and_length_distribution: countRows(preludeTagRows.map((row) => `${row.field_10_tag}/${row.field_14_tag}/${row.payload_length}`), 'tag_pair_length'),
      byte_position_profiles: bytePositionProfiles(preludeEvents, 5),
      distinct_payload_count: new Set(preludeEvents.map((event) => event.raw_payload_hex)).size,
      full_plaintext_status: 'UNAVAILABLE_REQUIRES_PROCESS_RUNTIME_PROTECTION_STATE',
    },
    route_0473_codec: {
      object_layout: RUNTIME_LAYOUT.route_0473,
      raw_param: {
        zero_count: envelopeEvents.filter((event) => event.raw_param === 0).length,
        nonzero_count: envelopeEvents.filter((event) => event.raw_param !== 0).length,
        distinct_count: new Set(envelopeEvents.map((event) => event.raw_param)).size,
      },
      payload_length: numericSummary(envelopeEvents.map((event) => event.payload_length)),
      payload_length_distribution: countRows(envelopeEvents.map((event) => event.payload_length), 'payload_length', { sort: 'value' }),
      prefix_distribution: countRows(envelopeEvents.map((event) => `0x${event.payload_buffer[0].toString(16).padStart(2, '0')}`), 'prefix_hex'),
      outer_tag_distribution: countRows(outerHeaders.filter((header) => header.ok).map((header) => header.outer_tag), 'outer_tag', { sort: 'value' }),
      outer_record_count: numericSummary(outerHeaders.filter((header) => header.ok).map((header) => header.record_count)),
      outer_record_count_distribution: countRows(outerHeaders.filter((header) => header.ok).map((header) => header.record_count), 'record_count', { sort: 'value' }),
      outer_count_wire_bytes_distribution: countRows(outerHeaders.filter((header) => header.ok).map((header) => header.count_wire_bytes), 'wire_bytes', { sort: 'value' }),
      outer_decode_failure_count: outerFailures.length,
      outer_decode_failure_distribution: countRows(outerFailures.map((header) => header.error), 'error'),
      recovered_outer_decoder: {
        status: outerDecodePass ? 'VERIFIED_FULL_CORPUS' : 'FAILED',
        table_rva_hex: '0x01b1ba00',
        byte_transform: 'x=~encoded; nibble_swap(x); x=table[x]; x=table[x]; x=(x-0x59)&255; x=table[x]; standard lower-7/continuation varuint',
        vector_record_size_in_memory: 0x50,
      },
      nested_plaintext_status: 'UNAVAILABLE_REQUIRES_PROCESS_RUNTIME_PROTECTION_STATE',
    },
    shared_batch_size_distribution: countRows(sharedRows.map((row) => row.batch_size), 'route_01c2_batch_size', { sort: 'value' }),
    shared_batch_buckets: batchBuckets,
    per_replay: perReplay,
    counterexamples: {
      interpretation: 'The prelude is optional, not universally required. These unpaired groups constrain the claim to a co-scheduled family and rule out payload containment/equality.',
      route_01c2_only_group_witnesses: preludeOnlyGroups.slice(0, 8).map(witness),
      route_0473_only_group_witnesses: envelopeOnlyGroups.slice(0, 8).map(witness),
      shared_shape_violation_count: shapeViolations.length,
      shared_shape_violation_witnesses: shapeViolations.slice(0, 8),
      global_immediate_adjacency_counterexample_count: globalAdjacencyCounterexamples.length,
      global_immediate_adjacency_counterexample_witnesses: globalAdjacencyCounterexamples.slice(0, 8),
    },
    runtime_identity: options.runtimeIdentity ?? null,
    static_sidecar_crosscheck: options.staticSidecarCrosscheck ?? null,
    raw_profiler_crosscheck: options.rawProfilerCrosscheck ?? null,
    validations: {
      exact_registry_inventory_match: inventoryMatch,
      raw_param_is_zero_for_both_routes: rawParamAllZero,
      every_shared_exact_timestamp_group_is_unique_0473_after_01c2_in_same_chunk: sharedShapePass,
      selected_pair_sequence_is_immediate_in_every_shared_group: orderedGroups === sharedGroups.length,
      global_stream_immediate_adjacency_counterexamples_are_count_conserved:
        globalAdjacencyCounterexamples.length === sharedGroups.length - finalImmediateGroups,
      every_0473_outer_count_decodes: outerDecodePass,
      exact_factory_constructor_vtable_deserializer_identity_closed: runtimePass,
      direct_payload_containment_is_zero: directContainmentRows === 0,
      all_structural_repurpose_checks_pass: repurposePass && directContainmentRows === 0,
    },
    negative_evidence: {
      rejected_hypotheses: repurposePass ? [
        'DIRECT_DAMAGE_EVENT',
        'DIRECT_CURRENT_HP_SCALAR',
        'DIRECT_MAX_HP_SCALAR',
        'DIRECT_ARMOR_SCALAR',
        'DIRECT_MAGIC_RESIST_SCALAR',
        'DIRECT_RESOURCE_SCALAR',
        'DIRECT_ENTITY_SCALAR_UPDATE',
        '0x01c2_PAYLOADS_ARE_DIRECTLY_EMBEDDED_0x0473_RECORDS',
        '0x01c2_IS_REQUIRED_FOR_EVERY_0x0473_ENVELOPE',
      ] : [],
      reason: repurposePass
        ? 'Both routes have raw_param=0, 0x0473 is a runtime-verified vector-of-0x50-byte-record envelope, and 0x01c2 is a protected two-field packet that forms an optional immediate prelude run without byte containment. This is incompatible with an independently addressable plaintext hero/combat scalar.'
        : 'Structural repurpose thresholds did not all pass.',
      semantic_claim: null,
    },
    route_decisions: [
      {
        packet_id: PRELUDE_PACKET_ID,
        packet_discriminator: formatRoute(PRELUDE_PACKET_ID),
        decision: repurposePass ? 'REPURPOSE' : 'KEEP_CANDIDATE',
        hypothesis: 'OPTIONAL_PROTECTED_TWO_FIELD_PRELUDE_RUN_BEFORE_0x0473_VECTOR_BATCH',
        evidence_grade: repurposePass ? 'VERIFIED_STRUCTURAL_EXACT_BUILD' : 'CANDIDATE',
        evidence_scope: 'EXACT_FULL_FOUR_REPLAY_CORPUS_PLUS_FACTORY_RUNTIME_IDENTITY',
        semantic_claim: null,
        positive_anchor_count: sharedPreludeRows,
        counterexample_count: preludeOnlyGroups.reduce((sum, group) => sum + group.prelude.length, 0),
        evidence_exhausted: true,
        evidence_exhausted_scope: 'PINNED_OFFLINE_IMAGE_SIDECARS_AND_EXPLICIT_SAFE_FOUR_REPLAY_CORPUS',
        next_required_evidence: nextRequiredEvidence,
      },
      {
        packet_id: ENVELOPE_PACKET_ID,
        packet_discriminator: formatRoute(ENVELOPE_PACKET_ID),
        decision: repurposePass ? 'REPURPOSE' : 'KEEP_CANDIDATE',
        hypothesis: 'PROTECTED_VARIABLE_VECTOR_RECORD_BATCH_ENVELOPE_WITH_OPTIONAL_0x01c2_PRELUDE',
        evidence_grade: repurposePass ? 'VERIFIED_STRUCTURAL_EXACT_BUILD' : 'CANDIDATE',
        evidence_scope: 'EXACT_FULL_FOUR_REPLAY_CORPUS_PLUS_FACTORY_RUNTIME_IDENTITY',
        semantic_claim: null,
        positive_anchor_count: envelopeEvents.length,
        counterexample_count: envelopeOnlyGroups.length,
        evidence_exhausted: true,
        evidence_exhausted_scope: 'PINNED_OFFLINE_IMAGE_SIDECARS_AND_EXPLICIT_SAFE_FOUR_REPLAY_CORPUS',
        next_required_evidence: nextRequiredEvidence,
      },
    ],
    capability_decisions: [
      {
        capability: 'EXACT_BUILD_ROUTE_0x0473_OUTER_VECTOR_COUNT_DECODER',
        decision: outerDecodePass && runtimePass ? 'PROMOTE' : 'KEEP_CANDIDATE',
        scope: 'RESEARCH_ARTIFACT_EXACT_BUILD_ONLY',
        semantic_claim: null,
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        capability: 'EXACT_BUILD_ROUTE_PAIR_01C2_0473_FULL_PLAINTEXT_NESTED_DECODER',
        decision: 'KEEP_CANDIDATE',
        scope: 'NOT_PUBLISHED',
        semantic_claim: null,
        evidence_exhausted: true,
        evidence_exhausted_scope: 'OFFLINE_IMAGE_WITHOUT_PROCESS_PROTECTION_STATE',
        next_required_evidence: nextRequiredEvidence.slice(0, 2),
      },
      {
        capability: 'ROUTE_PAIR_01C2_0473_GAMEPLAY_SEMANTIC',
        decision: 'REJECT',
        scope: 'CURRENT_EVIDENCE',
        semantic_claim: null,
        evidence_exhausted: true,
        next_required_evidence: nextRequiredEvidence.slice(1),
      },
    ],
    domain_decisions: [
      {
        domain: 'OPAQUE_REPLICATION_OR_BITSTREAM_BATCH_FAMILY',
        decision: repurposePass ? 'REPURPOSE' : 'KEEP_CANDIDATE',
        semantic_claim: null,
        evidence_exhausted: true,
        next_required_evidence: nextRequiredEvidence,
      },
      {
        domain: 'HERO_PERSISTENT_STATE_OR_DIRECT_DAMAGE_DEFENSE_RESOURCE_SCALAR',
        decision: repurposePass ? 'REJECT' : 'KEEP_CANDIDATE',
        semantic_claim: null,
        evidence_exhausted: true,
        next_required_evidence: nextRequiredEvidence.slice(1),
      },
    ],
    saturation: {
      current_local_evidence_saturated: true,
      closed_surfaces: [
        'FOUR_REPLAY_INVENTORY_AND_TIMESTAMP_SEQUENCE',
        '0x01c2_PREFIX_TAG_AND_LENGTH_BRANCH_SHAPE',
        '0x0473_OUTER_VECTOR_COUNT_AND_NESTED_RECORD_RUNTIME_LAYOUT',
        'FACTORY_CASE_CONSTRUCTOR_VTABLE_DESERIALIZER_IDENTITY',
        'DIRECT_PAYLOAD_CONTAINMENT_COUNTERCHECK',
      ],
      blocked_surface: 'PROTECTED_PLAINTEXT_AND_GAMEPLAY_CONSUMER_IDENTITY',
      next_required_evidence: nextRequiredEvidence,
    },
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

module.exports = {
  EXACT_BUILD,
  EXACT_IMAGE_SHA256,
  PRELUDE_PACKET_ID,
  ENVELOPE_PACKET_ID,
  RUNTIME_LAYOUT,
  analyzeRoutePair,
  decodeProtectionByte,
  decodeRoute0473OuterHeader,
  validateRuntimeIdentity,
};
