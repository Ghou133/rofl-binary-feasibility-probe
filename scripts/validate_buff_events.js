#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_RUNTIME_DIR = path.join(ROOT, 'artifacts', 'runtime_probe');
const PROFILE_INPUTS = Object.freeze({
  add: {
    path: 'buff_add_decoded_all10.jsonl',
    packetId: 0x0406,
    operation: 'ADD',
  },
  remove: {
    path: 'buff_remove_decoded_all10.jsonl',
    packetId: 0x0031,
    operation: 'REMOVE',
  },
  update: {
    path: 'buff_update_count_decoded_all10.jsonl',
    packetId: 0x0256,
    operation: 'UPDATE_COUNT',
  },
});
const DURATION_TOLERANCE_SECONDS = 0.25;

function parseArgs(argv) {
  const options = {
    add: path.join(DEFAULT_RUNTIME_DIR, PROFILE_INPUTS.add.path),
    remove: path.join(DEFAULT_RUNTIME_DIR, PROFILE_INPUTS.remove.path),
    update: path.join(DEFAULT_RUNTIME_DIR, PROFILE_INPUTS.update.path),
    outputDir: DEFAULT_RUNTIME_DIR,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--add') options.add = path.resolve(argv[++index]);
    else if (token === '--remove') options.remove = path.resolve(argv[++index]);
    else if (token === '--update') options.update = path.resolve(argv[++index]);
    else if (token === '--output-dir') options.outputDir = path.resolve(argv[++index]);
    else throw new Error(`unknown argument: ${token}`);
  }
  return options;
}

function compactRow(row, profile) {
  const fields = row.decoded_fields || {};
  return {
    operation: profile.operation,
    replay_path: row.replay_path,
    replay_sha256: row.replay_sha256,
    replay_time_ms: row.replay_time_ms,
    chunk_index: row.chunk_index,
    decompressed_block_offset: row.decompressed_block_offset,
    packet_id: row.packet_id,
    payload_length: row.payload_length,
    raw_payload_sha256: row.raw_payload_sha256,
    target_network_id: fields.raw_param,
    buff_slot: fields.buff_slot,
    buff_name_hash: fields.buff_name_hash ?? null,
    caster_network_id: fields.caster_network_id ?? null,
    count: fields.count ?? null,
    duration_seconds: fields.duration_seconds ?? fields.time_10_seconds ?? null,
    running_time_seconds: fields.running_time_seconds ?? fields.time_18_seconds ?? null,
    removal_time_seconds: fields.removal_time_seconds ?? null,
    structural_valid: row.packet_id === profile.packetId
      && row.decoded_opcode === profile.packetId
      && row.opcode_matches_profile === true
      && row.deserialize_return_al !== 0
      && row.fully_consumed === true
      && fields.raw_param === row.raw_param
      && Number.isInteger(fields.buff_slot),
  };
}

async function readProfile(filePath, profile, replays) {
  const input = readline.createInterface({
    input: fs.createReadStream(filePath),
    crlfDelay: Infinity,
  });
  for await (const line of input) {
    if (!line.trim()) continue;
    const event = compactRow(JSON.parse(line), profile);
    let replay = replays.get(event.replay_sha256);
    if (!replay) {
      replay = { path: event.replay_path, events: [] };
      replays.set(event.replay_sha256, replay);
    }
    replay.events.push(event);
  }
}

function emptyMetrics(replayPath, replaySha256) {
  return {
    replay_path: replayPath,
    replay_sha256: replaySha256,
    game_id: /(?:^|[-_])([0-9]+)\.rofl$/i.exec(path.basename(replayPath))?.[1] ?? null,
    add_count: 0,
    remove_count: 0,
    update_count: 0,
    structural_valid_count: 0,
    target_slot_remove_test_count: 0,
    active_add_hash_match_count: 0,
    shifted_slot_negative_test_count: 0,
    shifted_slot_negative_hash_match_count: 0,
    target_slot_update_test_count: 0,
    update_caster_match_count: 0,
    update_duration_sum_test_count: 0,
    update_duration_sum_match_count: 0,
    nonzero_removal_time_count: 0,
    removal_clock_match_count: 0,
    champion_target_add_count: 0,
    champion_caster_add_count: 0,
  };
}

function isChampionNetworkId(value) {
  return Number.isInteger(value) && value >= 0x400000ae && value <= 0x400000b7;
}

function rawRef(event) {
  return {
    replay_path: event.replay_path,
    replay_sha256: event.replay_sha256,
    replay_time_ms: event.replay_time_ms,
    chunk_index: event.chunk_index,
    decompressed_block_offset: event.decompressed_block_offset,
    packet_id: event.packet_id,
    payload_length: event.payload_length,
    raw_payload_sha256: event.raw_payload_sha256,
  };
}

function validateReplay(replayPath, replaySha256, events, anchors) {
  const metrics = emptyMetrics(replayPath, replaySha256);
  const active = new Map();
  events.sort((left, right) => left.chunk_index - right.chunk_index
    || left.decompressed_block_offset - right.decompressed_block_offset);
  for (const event of events) {
    metrics.structural_valid_count += Number(event.structural_valid);
    const key = `${event.target_network_id}:${event.buff_slot}`;
    if (event.operation === 'ADD') {
      metrics.add_count += 1;
      metrics.champion_target_add_count += Number(isChampionNetworkId(event.target_network_id));
      metrics.champion_caster_add_count += Number(isChampionNetworkId(event.caster_network_id));
      active.set(key, event);
      continue;
    }
    if (event.operation === 'REMOVE') {
      metrics.remove_count += 1;
      if (event.removal_time_seconds > 0) {
        metrics.nonzero_removal_time_count += 1;
        metrics.removal_clock_match_count += Number(
          Math.abs(event.removal_time_seconds * 1000 - event.replay_time_ms) <= 2,
        );
      }
      const add = active.get(key);
      if (add) {
        metrics.target_slot_remove_test_count += 1;
        const hashMatches = add.buff_name_hash === event.buff_name_hash;
        metrics.active_add_hash_match_count += Number(hashMatches);
        if (hashMatches && anchors.length < 24) {
          anchors.push({
            anchor_kind: 'BUFF_ADD_REMOVE_LIFECYCLE',
            target_network_id: event.target_network_id,
            buff_slot: event.buff_slot,
            buff_name_hash: event.buff_name_hash,
            add: rawRef(add),
            remove: rawRef(event),
          });
        }
        if (hashMatches) active.delete(key);
      }
      const shiftedSlot = (event.buff_slot + 1) & 0xff;
      const shifted = active.get(`${event.target_network_id}:${shiftedSlot}`);
      if (shifted) {
        metrics.shifted_slot_negative_test_count += 1;
        metrics.shifted_slot_negative_hash_match_count += Number(
          shifted.buff_name_hash === event.buff_name_hash,
        );
      }
      continue;
    }

    metrics.update_count += 1;
    const add = active.get(key);
    if (!add) continue;
    metrics.target_slot_update_test_count += 1;
    const casterMatches = add.caster_network_id === event.caster_network_id;
    metrics.update_caster_match_count += Number(casterMatches);
    const durationDelta = Math.abs(
      event.duration_seconds + event.running_time_seconds - add.duration_seconds,
    );
    metrics.update_duration_sum_test_count += 1;
    metrics.update_duration_sum_match_count += Number(
      durationDelta <= DURATION_TOLERANCE_SECONDS,
    );
    if (casterMatches && durationDelta <= DURATION_TOLERANCE_SECONDS && anchors.length < 24) {
      anchors.push({
        anchor_kind: 'BUFF_ADD_UPDATE_LIFECYCLE',
        target_network_id: event.target_network_id,
        caster_network_id: event.caster_network_id,
        buff_slot: event.buff_slot,
        buff_name_hash: add.buff_name_hash,
        add_duration_seconds: add.duration_seconds,
        update_duration_seconds: event.duration_seconds,
        update_running_time_seconds: event.running_time_seconds,
        duration_sum_delta_seconds: durationDelta,
        add: rawRef(add),
        update: rawRef(event),
      });
    }
  }
  const eventCount = metrics.add_count + metrics.remove_count + metrics.update_count;
  return {
    ...metrics,
    event_count: eventCount,
    structural_valid_rate: ratio(metrics.structural_valid_count, eventCount),
    active_add_hash_match_rate: ratio(
      metrics.active_add_hash_match_count,
      metrics.target_slot_remove_test_count,
    ),
    shifted_slot_negative_hash_match_rate: ratio(
      metrics.shifted_slot_negative_hash_match_count,
      metrics.shifted_slot_negative_test_count,
    ),
    update_caster_match_rate: ratio(
      metrics.update_caster_match_count,
      metrics.target_slot_update_test_count,
    ),
    update_duration_sum_match_rate: ratio(
      metrics.update_duration_sum_match_count,
      metrics.update_duration_sum_test_count,
    ),
    removal_clock_match_rate: ratio(
      metrics.removal_clock_match_count,
      metrics.nonzero_removal_time_count,
    ),
  };
}

function ratio(numerator, denominator) {
  return denominator === 0 ? null : numerator / denominator;
}

function sum(rows, field) {
  return rows.reduce((total, row) => total + row[field], 0);
}

function aggregate(rows) {
  const fields = [
    'add_count',
    'remove_count',
    'update_count',
    'event_count',
    'structural_valid_count',
    'target_slot_remove_test_count',
    'active_add_hash_match_count',
    'shifted_slot_negative_test_count',
    'shifted_slot_negative_hash_match_count',
    'target_slot_update_test_count',
    'update_caster_match_count',
    'update_duration_sum_test_count',
    'update_duration_sum_match_count',
    'nonzero_removal_time_count',
    'removal_clock_match_count',
    'champion_target_add_count',
    'champion_caster_add_count',
  ];
  const result = Object.fromEntries(fields.map((field) => [field, sum(rows, field)]));
  return {
    ...result,
    replay_count: rows.length,
    structural_valid_rate: ratio(result.structural_valid_count, result.event_count),
    active_add_hash_match_rate: ratio(
      result.active_add_hash_match_count,
      result.target_slot_remove_test_count,
    ),
    shifted_slot_negative_hash_match_rate: ratio(
      result.shifted_slot_negative_hash_match_count,
      result.shifted_slot_negative_test_count,
    ),
    update_caster_match_rate: ratio(
      result.update_caster_match_count,
      result.target_slot_update_test_count,
    ),
    update_duration_sum_match_rate: ratio(
      result.update_duration_sum_match_count,
      result.update_duration_sum_test_count,
    ),
    removal_clock_match_rate: ratio(
      result.removal_clock_match_count,
      result.nonzero_removal_time_count,
    ),
  };
}

function csvValue(value) {
  if (value === null || value === undefined) return '';
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(filePath, rows) {
  const columns = Object.keys(rows[0] || {});
  const lines = [columns.join(',')];
  for (const row of rows) lines.push(columns.map((column) => csvValue(row[column])).join(','));
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const replays = new Map();
  await Promise.all(Object.entries(PROFILE_INPUTS).map(([name, profile]) => (
    readProfile(options[name], profile, replays)
  )));
  const anchors = [];
  const rows = [...replays.entries()]
    .map(([sha256, replay]) => validateReplay(replay.path, sha256, replay.events, anchors))
    .sort((left, right) => left.game_id.localeCompare(right.game_id));
  const totals = aggregate(rows);
  const gates = {
    all_packets_structurally_valid: totals.structural_valid_rate === 1,
    add_remove_active_hash_consistency: totals.active_add_hash_match_rate >= 0.95,
    update_caster_consistency: totals.update_caster_match_rate >= 0.9,
    update_duration_sum_consistency: totals.update_duration_sum_match_rate >= 0.85,
    removal_internal_clock_consistency: totals.removal_clock_match_rate >= 0.99,
    shifted_slot_negative_control: totals.shifted_slot_negative_hash_match_rate < 0.25,
  };
  const summary = {
    schema_version: 1,
    status: Object.values(gates).every(Boolean) ? 'PASS' : 'FAIL',
    capability_status: 'VERIFIED_DIRECT',
    target_replay_version: '16.15.801.3452',
    details_or_oracle_input: false,
    method: 'Exact client deserializer plus cross-packet lifecycle and shifted-slot negative control',
    runtime_image_sha256: '7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb',
    public_contract_references: [
      {
        repository: 'LeagueSandbox/LeaguePackets',
        commit: '207baab80dc4cd203dd2d41ce9d98f1aae7a1544',
      },
      {
        repository: 'LeagueSandbox/GameServer',
        commit: 'b37c75483abf66048af7c914e7fab700efaa5e21',
      },
    ],
    exact_profiles: {
      add: { opcode: '0x0406', constructor_rva: '0x00e80970', deserialize_rva: '0x010b53f0' },
      remove: { opcode: '0x0031', constructor_rva: '0x00e80f90', deserialize_rva: '0x010b8500' },
      update_count: { opcode: '0x0256', constructor_rva: '0x00e81440', deserialize_rva: '0x010ba590' },
    },
    duration_tolerance_seconds: DURATION_TOLERANCE_SECONDS,
    totals,
    gates,
    replay_rows: rows,
    anchor_count: anchors.length,
  };
  fs.mkdirSync(options.outputDir, { recursive: true });
  const csvPath = path.join(options.outputDir, 'buff_validation_all.csv');
  const summaryPath = path.join(options.outputDir, 'buff_validation_summary.json');
  const anchorsPath = path.join(options.outputDir, 'buff_lifecycle_anchors.json');
  writeCsv(csvPath, rows);
  fs.writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  fs.writeFileSync(anchorsPath, `${JSON.stringify({ schema_version: 1, anchors }, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    status: summary.status,
    totals,
    gates,
    outputs: { csvPath, summaryPath, anchorsPath },
  }, null, 2)}\n`);
  return summary.status === 'PASS' ? 0 : 2;
}

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  aggregate,
  compactRow,
  main,
  parseArgs,
  validateReplay,
};
