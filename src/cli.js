#!/usr/bin/env node

const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const {
  TOOL_VERSION,
  analyzeReplay,
} = require('./analysis');
const {
  RoflError,
  parseReplayFile,
  sha256,
} = require('./rofl');
const {
  buildAdcDeathRecords,
  decodeSemanticReplay,
  DEFAULT_DECODER_IMAGE,
} = require('./semantic_pipeline');
const { buildWardOutputs } = require('./ward_pipeline_v2');
const { buildPathOutputs } = require('./path_pipeline_v2');
const { buildReplayPacketIndex } = require('./provenance_v2');
const {
  analyzeWardEvents,
  readWardDocument,
  writeWardAnalysis,
} = require('./ward_analysis_v2');
const {
  DEFAULT_UPSTREAM_PATHS,
  compareHashSnapshots,
} = require('./integrity');
const {
  ensureDir,
  hashFiles,
  outputHashes,
  safeStem,
  writeCsv,
  writeJson,
  writeJsonl,
} = require('./io');

const REPOSITORY_ROOT = path.resolve(__dirname, '..');
const TEST_COMMAND = 'node --test test/*.test.js';
const COMMANDS = new Set(['inspect', 'decode', 'analyze', 'batch', 'validate', 'ward-events']);

function enumerateRepositoryTestFiles() {
  const testRoot = path.join(REPOSITORY_ROOT, 'test');
  return fs.readdirSync(testRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.test.js'))
    .map((entry) => path.join('test', entry.name))
    .sort();
}

function usage() {
  return `ROFL Analyzer ${TOOL_VERSION}

Usage:
  node src/cli.js inspect <file.rofl> [--out-dir artifacts]
  node src/cli.js decode <file.rofl> [--out-dir artifacts]
  node src/cli.js analyze <file.rofl> [--out-dir artifacts]
  node src/cli.js batch <directory> [directory ...] [--out-dir artifacts]
  node src/cli.js validate [file.rofl|directory ...] [--out-dir artifacts]
  node src/cli.js ward-events <rows.json|rows.jsonl|file.rofl> [--out-dir artifacts]

Options:
  --out-dir <path>              Independent output directory (default: artifacts)
  --timeline-limit <number>     Maximum packet timeline sample rows (default: 250)
  --sample-stride <number>      Add one raw packet every N blocks (default: 10000)
  --include-private-metadata     Include Riot ID/PUUID fields in roster output
  --strict                       Stop at the first framing error
  --decoder-image <path>        Exact 16.15 runtime image (default: bundled probe image)
  --python <command>            Python command with Unicorn installed (default: python)
  --details-dir <path>          Validation-only directory for same-game Details matching
  --ward-spawns <jsonl>         Verified current-build WardSpawn decoder rows
  --ward-lifecycles <jsonl>     Derived current-build Ward corpse lifecycle rows
  --hero-positions <jsonl>      Verified one-second PathPacket position rows
  Ward event filters (ward-events):
  --output <path>               Write filtered rows (extension selects jsonl/json/csv)
  --format <jsonl|json|csv>     Output format (default: jsonl)
  --team <100|200[, ...]>       Filter by raw team ID
  --viewer-team <100|200>       Explicit viewer team for ally/enemy perspective
  --ally-team <100|200>         Explicit ally team for ally/enemy perspective
  --perspective <ally|enemy>    Filter relative to viewer/ally team
  --side <blue|red|ally|enemy>  Filter map side or relative side
  --champion <name[, ...]>      Filter owner/caster champion
  --role <role[, ...]>          Filter top/jungle/mid/adc/support
  --ward-type <type[, ...]>     Filter Ward type
  --from-ms/--to-ms <number>    Inclusive Replay millisecond bounds
  --from-minute/--to-minute <n> Inclusive minute bucket bounds
  --collection <key>             Input array key (ward_events, candidates, rows)
  --help                        Show this help
`;
}

function parseArgs(argv) {
  const args = [...argv];
  const first = args.shift();
  const command = !first || first === '--help' || first === '-h' ? 'help' : first;
  const positionals = [];
  const options = {
    outDir: 'artifacts',
    timelineLimit: 250,
    sampleStride: 10000,
    includePrivateMetadata: false,
    strict: false,
    detailsDir: null,
    decoderImage: DEFAULT_DECODER_IMAGE,
    python: null,
    wardSpawns: null,
    wardLifecycles: null,
    heroPositions: null,
    output: null,
    format: null,
    collection: null,
    rowsOnly: false,
    team: null,
    viewerTeam: null,
    allyTeam: null,
    perspective: null,
    side: null,
    champion: null,
    role: null,
    wardType: null,
    fromMs: null,
    toMs: null,
    fromMinute: null,
    toMinute: null,
    inputs: [],
  };
  if (command === 'help' && first && first !== '--help' && first !== '-h') {
    args.unshift(first);
  }
  while (args.length > 0) {
    const token = args.shift();
    if (token === '--help' || token === '-h') {
      options.help = true;
      continue;
    }
    if (token === '--include-private-metadata') {
      options.includePrivateMetadata = true;
      continue;
    }
    if (token === '--strict') {
      options.strict = true;
      continue;
    }
    if (command === 'ward-events' && token === '--ally') {
      options.perspective = 'ally';
      continue;
    }
    if (command === 'ward-events' && token === '--enemy') {
      options.perspective = 'enemy';
      continue;
    }
    if (command === 'ward-events' && token === '--rows-only') {
      options.rowsOnly = true;
      continue;
    }
    if (command === 'ward-events' && token === '--stdout') {
      options.output = '-';
      continue;
    }
    if (command === 'ward-events' && token === '--json') {
      options.format = 'json';
      continue;
    }
    if (command === 'ward-events' && token === '--jsonl') {
      options.format = 'jsonl';
      continue;
    }
    if (command === 'ward-events' && token === '--csv') {
      options.format = 'csv';
      continue;
    }
    const match = token.match(/^--([^=]+)(?:=(.*))?$/);
    if (match) {
      const key = match[1];
      const inlineValue = match[2];
      const value = inlineValue !== undefined ? inlineValue : args.shift();
      if (value === undefined) throw new Error(`Missing value for --${key}`);
      if (key === 'out-dir') options.outDir = value;
      else if (key === 'timeline-limit') options.timelineLimit = positiveInteger(value, key);
      else if (key === 'sample-stride') options.sampleStride = positiveInteger(value, key);
      else if (key === 'details-dir') options.detailsDir = value;
      else if (key === 'decoder-image') options.decoderImage = value;
      else if (key === 'python') options.python = value;
      else if (key === 'ward-spawns') options.wardSpawns = value;
      else if (key === 'ward-lifecycles') options.wardLifecycles = value;
      else if (key === 'hero-positions') options.heroPositions = value;
      else if (command === 'ward-events' && key === 'output') options.output = value;
      else if (command === 'ward-events' && key === 'format') options.format = String(value).toLowerCase();
      else if (command === 'ward-events' && key === 'collection') options.collection = value;
      else if (command === 'ward-events' && key === 'input') options.inputs.push(value);
      else if (command === 'ward-events' && key === 'team') options.team = value;
      else if (command === 'ward-events' && (key === 'viewer-team' || key === 'viewer_team')) options.viewerTeam = value;
      else if (command === 'ward-events' && (key === 'ally-team' || key === 'ally_team')) options.allyTeam = value;
      else if (command === 'ward-events' && (key === 'perspective' || key === 'relation')) options.perspective = value;
      else if (command === 'ward-events' && key === 'side') options.side = value;
      else if (command === 'ward-events' && key === 'champion') options.champion = value;
      else if (command === 'ward-events' && key === 'role') options.role = value;
      else if (command === 'ward-events' && (key === 'ward-type' || key === 'ward_type')) options.wardType = value;
      else if (command === 'ward-events' && (key === 'from-ms' || key === 'start-ms' || key === 'min-ms')) options.fromMs = value;
      else if (command === 'ward-events' && (key === 'to-ms' || key === 'end-ms' || key === 'max-ms')) options.toMs = value;
      else if (command === 'ward-events' && (key === 'from-minute' || key === 'start-minute' || key === 'min-minute')) options.fromMinute = value;
      else if (command === 'ward-events' && (key === 'to-minute' || key === 'end-minute' || key === 'max-minute')) options.toMinute = value;
      else if (command === 'ward-events' && key === 'minutes') options.minutes = value;
      else throw new Error(`Unknown option: --${key}`);
      continue;
    }
    if (command === 'ward-events') options.inputs.push(token);
    else positionals.push(token);
  }
  if (options.detailsDir && command !== 'validate') {
    throw new Error('--details-dir is only valid with validate; decode commands never read Match Details');
  }
  if (command === 'ward-events') {
    positionals.push(...options.inputs);
  }
  return { command, positionals, options };
}

function positiveInteger(value, label) {
  const number = Number.parseInt(value, 10);
  if (!Number.isInteger(number) || number <= 0) throw new Error(`--${label} must be a positive integer`);
  return number;
}

function stripAnsi(value) {
  return String(value || '').replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '');
}

function parseTestSummary(output, exitCode) {
  const clean = stripAnsi(output);
  const readNumber = (label) => {
    const matches = [...clean.matchAll(new RegExp(`(?:^|\\n)\\s*(?:[#ℹi]\\s*)?${label}\\s+(\\d+)`, 'gi'))];
    return matches.length > 0 ? Number(matches[matches.length - 1][1]) : null;
  };
  return {
    command: TEST_COMMAND,
    exit_code: exitCode,
    total: readNumber('tests'),
    passed: readNumber('pass'),
    failed: readNumber('fail'),
    cancelled: readNumber('cancelled'),
    skipped: readNumber('skipped'),
    todo: readNumber('todo'),
    output_tail: clean.slice(-4000),
  };
}

function runTestSuite() {
  let result;
  try {
    result = childProcess.spawnSync(process.execPath, ['--test', ...enumerateRepositoryTestFiles()], {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    return {
      command: TEST_COMMAND,
      exit_code: null,
      total: null,
      passed: null,
      failed: null,
      cancelled: null,
      skipped: null,
      todo: null,
      output_tail: error.message,
      error: errorToObject(error),
    };
  }
  const output = `${result.stdout || ''}\n${result.stderr || ''}`;
  const summary = parseTestSummary(output, result.status);
  if (result.error) summary.error = errorToObject(result.error);
  return summary;
}

function quoteCommandArg(value) {
  return `"${String(value).replaceAll('"', '\\\"')}"`;
}

function discoverReplayFiles(inputs) {
  const files = [];
  const seen = new Set();
  const visit = (input) => {
    const resolved = path.resolve(input);
    if (!fs.existsSync(resolved)) throw new Error(`Input does not exist: ${resolved}`);
    const stat = fs.statSync(resolved);
    if (stat.isFile()) {
      if (!resolved.toLowerCase().endsWith('.rofl')) throw new Error(`Input is not a .rofl file: ${resolved}`);
      if (!seen.has(resolved)) {
        seen.add(resolved);
        files.push(resolved);
      }
      return;
    }
    for (const entry of fs.readdirSync(resolved, { withFileTypes: true })) {
      const full = path.join(resolved, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.rofl') && !seen.has(full)) {
        seen.add(full);
        files.push(full);
      }
    }
  };
  for (const input of inputs) visit(input);
  return files.sort((a, b) => a.localeCompare(b));
}

function gitCommit() {
  try {
    return childProcess.execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || null;
  } catch {
    return null;
  }
}

const jsonlInputCache = new Map();

function readJsonlRowsCached(filePath, label) {
  if (!filePath) return { rows: [], sha256: null };
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    throw new Error(`${label} input does not exist: ${resolved}`);
  }
  const stat = fs.statSync(resolved);
  const cacheKey = `${resolved}:${stat.size}:${stat.mtimeMs}`;
  if (jsonlInputCache.has(cacheKey)) return jsonlInputCache.get(cacheKey);
  const bytes = fs.readFileSync(resolved);
  const rows = bytes.toString('utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`${label} has invalid JSON on line ${index + 1}: ${error.message}`);
      }
    });
  const input = { rows, sha256: sha256(bytes), path: resolved };
  jsonlInputCache.set(cacheKey, input);
  return input;
}

function rowReplaySha256(row) {
  return row?.replay_sha256
    ?? row?.raw_packet_ref?.replay_sha256
    ?? row?.spawn_raw_packet_ref?.replay_sha256
    ?? row?.remove_raw_packet_ref?.replay_sha256
    ?? null;
}

function v2InputsForReplay(replay, options = {}) {
  const select = (filePath, label) => {
    const input = readJsonlRowsCached(filePath, label);
    return {
      ...input,
      rows: input.rows.filter((row) => rowReplaySha256(row) === replay.source_sha256),
    };
  };
  const wardSpawns = select(options.wardSpawns, 'WardSpawn');
  const wardLifecycles = select(options.wardLifecycles, 'Ward lifecycle');
  const heroPositions = select(options.heroPositions, 'Hero position');
  return {
    wardSpawns: wardSpawns.rows,
    wardSpawnInputSha256: wardSpawns.sha256,
    wardLifecycles: wardLifecycles.rows,
    wardLifecycleInputSha256: wardLifecycles.sha256,
    heroPositions: heroPositions.rows,
    heroPositionInputSha256: heroPositions.sha256,
  };
}

function parseOne(filePath, options) {
  const started = process.hrtime.bigint();
  try {
    const replay = parseReplayFile(filePath);
    const v2Inputs = v2InputsForReplay(replay, options);
    const v2PacketIds = [
      ...(options.wardSpawns || options.wardLifecycles ? [0x0353] : []),
      ...(options.heroPositions ? [0x02d1] : []),
    ];
    const packetProvenanceIndex = v2PacketIds.length > 0
      ? buildReplayPacketIndex(replay, v2PacketIds)
      : null;
    const analysis = analyzeReplay(replay, {
      timelineLimit: options.timelineLimit,
      sampleStride: options.sampleStride,
      includePrivateMetadata: options.includePrivateMetadata,
      strict: options.strict,
    });
    // Ward V2 is an additive surface. Unsupported replay versions remain explicit
    // and never alter the existing V1/semantic event analysis.
    try {
      const ward = buildWardOutputs(replay, {
        strict: options.strict,
        ward_spawn_events: v2Inputs.wardSpawns,
        ward_lifecycles: v2Inputs.wardLifecycles,
        ward_spawn_input_sha256: v2Inputs.wardSpawnInputSha256,
        ward_lifecycle_input_sha256: v2Inputs.wardLifecycleInputSha256,
        packet_provenance_index: packetProvenanceIndex,
      });
      analysis.ward_pipeline = ward;
      analysis.ward_cast_candidates = ward.ward_cast_candidates;
      analysis.ward_events = ward.ward_events;
      analysis.ward_lifecycles = ward.ward_lifecycles;
      analysis.ward_cast_spawn_matches = ward.ward_cast_spawn_matches;
      analysis.ward_heatmap_input = ward.ward_heatmap_input;
    } catch (error) {
      analysis.ward_pipeline = {
        schema_version: 2,
        pipeline: 'ward-p0-v2',
        status: 'UNAVAILABLE',
        ward_event_status: 'UNAVAILABLE',
        ward_lifecycle_status: 'UNAVAILABLE',
        ward_cast_spawn_match_status: 'UNAVAILABLE',
        ward_heatmap_status: 'UNAVAILABLE',
        ward_cast_candidates: [],
        ward_events: [],
        ward_lifecycles: [],
        ward_cast_spawn_matches: [],
        ward_heatmap_input: [],
        provenance: {
          fact_source: 'ROFL_REPLAY_PACKET_BYTES',
          candidate_profile: 'rofl-16.15.801.3452-ward-cast-candidate-v2-p0',
          unsupported_reason: error.message,
        },
      };
      analysis.ward_cast_candidates = [];
      analysis.ward_events = [];
      analysis.ward_lifecycles = [];
      analysis.ward_cast_spawn_matches = [];
      analysis.ward_heatmap_input = [];
    }
    if (options.semantic !== false) {
      const semantic = decodeSemanticReplay(replay, {
        decoderImage: options.decoderImage,
        python: options.python,
      });
      if (semantic.events) {
        analysis.events = semantic.events;
        analysis.event_counts = Object.fromEntries(
          Object.entries(semantic.events).map(([name, rows]) => [name, rows.length]),
        );
        analysis.adc_deaths = semantic.adc_deaths;
        analysis.decoded_packet_count = semantic.decoded_packet_count;
        analysis.unknown_packet_count = Math.max(0, analysis.packet_count - semantic.decoded_packet_count);
        analysis.capabilities = semantic.capabilities;
        analysis.game_id = semantic.adc_deaths[0]?.game_id ?? gameIdFromFilePath(replay.source_path);
        analysis.game_id_status = analysis.game_id ? 'INFERRED_FROM_FILENAME' : 'UNAVAILABLE';
      }
      analysis.decoder = {
        profile: semantic.profile,
        status: semantic.status,
        note: semantic.note
          ?? 'Patch-matched HeroDeath, UnitApplyDamage, CastSpell, Buff, and Protection OnEvent profiles executed.',
      };
      analysis.semantic = {
        status: semantic.status,
        profile: semantic.profile,
        decoded_packet_count: semantic.decoded_packet_count,
        damage_decode: semantic.damage_decode,
        cast_spell_decode: semantic.cast_spell_decode,
        buff_decode: semantic.buff_decode,
        protection_decode: semantic.protection_decode,
        protection_status: semantic.protection_status,
        death_decode: semantic.death_decode,
        combat_rule: semantic.combat_rule,
      };
      // Rebuild the additive ward surface from verified CastSpell rows when the
      // semantic decoder supplied them; raw P0 candidates remain the fallback.
      if (Array.isArray(analysis.events?.spell_events)) {
        try {
          const ward = buildWardOutputs(replay, {
            strict: options.strict,
            spell_events: analysis.events.spell_events,
            ward_spawn_events: v2Inputs.wardSpawns,
            ward_lifecycles: v2Inputs.wardLifecycles,
            ward_spawn_input_sha256: v2Inputs.wardSpawnInputSha256,
            ward_lifecycle_input_sha256: v2Inputs.wardLifecycleInputSha256,
            packet_provenance_index: packetProvenanceIndex,
          });
          analysis.ward_pipeline = ward;
          analysis.ward_cast_candidates = ward.ward_cast_candidates;
          analysis.ward_events = ward.ward_events;
          analysis.ward_lifecycles = ward.ward_lifecycles;
          analysis.ward_cast_spawn_matches = ward.ward_cast_spawn_matches;
          analysis.ward_heatmap_input = ward.ward_heatmap_input;
        } catch (wardError) {
          analysis.ward_pipeline.provenance.semantic_input_error = wardError.message;
        }
      }
      if (options.heroPositions) {
        const pathLayer = buildPathOutputs(replay, v2Inputs.heroPositions, {
          inputSha256: v2Inputs.heroPositionInputSha256,
          packetIndex: packetProvenanceIndex,
        });
        analysis.path_pipeline = pathLayer;
        analysis.events.position_events = pathLayer.position_events;
        analysis.event_counts.position_events = pathLayer.position_events.length;
        analysis.adc_deaths = buildAdcDeathRecords(
          replay,
          analysis.events.death_events,
          analysis.events.damage_events,
          analysis.events.spell_events,
          analysis.events.position_events,
          analysis.events.buff_events,
          analysis.events.protection_events,
        );
        const positionCapability = analysis.capabilities?.find(
          (row) => row.capability === 'position',
        );
        if (positionCapability && pathLayer.accepted_count > 0) {
          positionCapability.status = 'VERIFIED_DERIVED';
          positionCapability.evidence = 'One-second positions interpolated from verified current-build PathPacket waypoints.';
        }
        analysis.semantic.path_decode = {
          status: pathLayer.status,
          input_count: pathLayer.input_count,
          accepted_count: pathLayer.accepted_count,
          rejected_count: pathLayer.rejected_count,
          profile: pathLayer.profile,
        };
      }
      const hasWardSpawn = analysis.ward_pipeline?.ward_spawn_position_status === 'VERIFIED_DIRECT';
      const hasHeroPosition = analysis.path_pipeline?.accepted_count > 0;
      analysis.v2_status = hasWardSpawn && hasHeroPosition
        ? 'RESEARCH_READY_V2_COMPLETE'
        : (hasWardSpawn ? 'WARD_SPAWN_POSITION_VERIFIED_DIRECT' : 'V2_INPUTS_INCOMPLETE');
    }
    analysis.input_parse_elapsed_ms = Number((Number(process.hrtime.bigint() - started) / 1e6).toFixed(3));
    return { ok: true, analysis };
  } catch (error) {
    return {
      ok: false,
      source_path: path.resolve(filePath),
      error: errorToObject(error),
    };
  }
}

function gameIdFromFilePath(filePath) {
  return /(?:^|[-_])([0-9]+)\.rofl$/i.exec(path.basename(filePath))?.[1] ?? null;
}

function readWardRowsFromReplay(filePath, options = {}) {
  const replay = parseReplayFile(filePath);
  const v2Inputs = v2InputsForReplay(replay, options);
  const base = analyzeReplay(replay, {
    includePrivateMetadata: false,
    timelineLimit: 1,
    sampleStride: 1,
    strict: options.strict,
  });
  let outputs;
  try {
    outputs = buildWardOutputs(replay, {
      strict: options.strict,
      ward_spawn_events: v2Inputs.wardSpawns,
      ward_lifecycles: v2Inputs.wardLifecycles,
      ward_spawn_input_sha256: v2Inputs.wardSpawnInputSha256,
      ward_lifecycle_input_sha256: v2Inputs.wardLifecycleInputSha256,
    });
  } catch (error) {
    // Keep the command replay-only and explicit when a profile cannot open the
    // input.  The caller can still use a JSON/JSONL V2 artifact as input.
    error.code = error.code || 'WARD_REPLAY_INPUT_UNAVAILABLE';
    throw error;
  }
  const rows = outputs.ward_events?.length > 0
    ? outputs.ward_events
    : outputs.ward_cast_candidates ?? [];
  return { rows, players: base.metadata?.players ?? [], source_path: filePath };
}

function runWardEventsCommand(parsed) {
  const { options } = parsed;
  let inputs = parsed.positionals.length > 0
    ? parsed.positionals
    : (options.inputs || []);
  if (inputs.length === 0) {
    const defaultWardInput = path.resolve(
      REPOSITORY_ROOT,
      'artifacts', 'v2_research', 'ward_dataset', 'ward_events.jsonl',
    );
    if (fs.existsSync(defaultWardInput)) inputs = [defaultWardInput];
  }
  if (inputs.length === 0) {
    throw new Error('ward-events requires at least one JSON/JSONL Ward input or .rofl file');
  }
  const rows = [];
  const players = [];
  for (const input of inputs) {
    const resolved = input === '-' ? '-' : path.resolve(input);
    if (resolved !== '-' && !fs.existsSync(resolved)) {
      throw new Error(`Input does not exist: ${resolved}`);
    }
    if (resolved !== '-' && resolved.toLowerCase().endsWith('.rofl')) {
      const loaded = readWardRowsFromReplay(resolved, options);
      rows.push(...loaded.rows);
      players.push(...loaded.players);
    } else {
      const loaded = readWardDocument(resolved, { collection: options.collection });
      rows.push(...loaded.rows);
      if (Array.isArray(loaded.players)) players.push(...loaded.players);
    }
  }
  const analysis = analyzeWardEvents(rows, {
    ...options,
    players: players.length > 0 ? players : options.players,
  });
  const format = String(options.format || 'jsonl').toLowerCase();
  if (!['jsonl', 'json', 'csv'].includes(format)) {
    throw new Error('--format must be jsonl, json, or csv');
  }
  let outputPath = options.output;
  if (!outputPath) {
    ensureDir(path.resolve(options.outDir || 'artifacts'));
    outputPath = path.join(path.resolve(options.outDir || 'artifacts'), 'ward_events.jsonl');
  }
  const output = writeWardAnalysis(outputPath, analysis, {
    format,
    rowsOnly: options.rowsOnly,
  });
  if (outputPath === '-') {
    process.stdout.write(output);
    process.stderr.write(`Ward rows: ${analysis.row_count}/${analysis.input_row_count}\n`);
  } else {
    // Keep a machine-readable envelope beside the default JSONL output.  An
    // explicitly requested output path is never overwritten with a sidecar.
    if (!options.output) {
      writeWardAnalysis(path.join(path.dirname(outputPath), 'ward_analysis.json'), analysis, {
        format: 'json',
        rowsOnly: false,
      });
    }
    process.stdout.write(`Ward rows: ${analysis.row_count}/${analysis.input_row_count}\n`);
    process.stdout.write(`Output: ${path.resolve(outputPath)}\n`);
  }
  return 0;
}

function errorToObject(error) {
  return {
    code: error.code || 'UNHANDLED_ERROR',
    message: error.message || String(error),
    details: error.details || null,
    name: error.name || 'Error',
  };
}

function writePerReplayArtifacts(analysis, rootDir) {
  const replayDir = path.join(rootDir, 'replays', safeStem(analysis.source_path));
  ensureDir(replayDir);
  writeJson(path.join(replayDir, 'replay_analysis.json'), analysis);
  writeJson(path.join(replayDir, 'rofl_inventory.json'), inventoryFromAnalysis(analysis));
  writeCsv(path.join(replayDir, 'packet_type_inventory.csv'), analysis.packet_type_inventory, [
    'packet_id',
    'packet_type',
    'count',
    'average_payload_length',
    'min_payload_length',
    'max_payload_length',
    'min_timestamp_ms',
    'max_timestamp_ms',
    'streams',
    'decoder_status',
  ]);
  writeJsonl(path.join(replayDir, 'packet_timeline_sample.jsonl'), analysis.packet_timeline_sample);
  writeJson(path.join(replayDir, 'raw_packet_anchors.json'), analysis.raw_anchors);
  writeJson(path.join(replayDir, 'events.json'), analysis.events);
  for (const [name, rows] of Object.entries(analysis.events)) {
    writeJsonl(path.join(replayDir, `${name}.jsonl`), rows);
  }
  writeJsonl(path.join(replayDir, 'adc_deaths.jsonl'), analysis.adc_deaths);
  const ward = analysis.ward_pipeline;
  if (ward) {
    writeJson(path.join(replayDir, 'ward_provenance.json'), ward.provenance);
    writeJsonl(path.join(replayDir, 'ward_cast_candidates.jsonl'), ward.ward_cast_candidates);
    writeJsonl(path.join(replayDir, 'ward_events.jsonl'), ward.ward_events);
    writeCsv(path.join(replayDir, 'ward_events.csv'), ward.ward_events, [
      'schema_version', 'event_type', 'event_status', 'game_id', 'replay_sha256',
      'timestamp', 'timestamp_ms', 'owner_entity', 'owner_participant',
      'owner_champion', 'owner_team', 'ward_type', 'ward_network_id',
      'spawn_timestamp_ms', 'actual_x', 'actual_y', 'actual_z',
      'cast_target_x', 'cast_target_y', 'cast_target_z', 'position_source',
      'coordinate_system', 'map_id', 'map_name', 'patch', 'normalized_x',
      'normalized_y', 'perspective_team', 'perspective_participant', 'role',
      'side', 'lifecycle_status', 'confidence',
    ]);
    writeJsonl(path.join(replayDir, 'ward_lifecycles.jsonl'), ward.ward_lifecycles);
    writeJsonl(path.join(replayDir, 'ward_cast_spawn_matches.jsonl'), ward.ward_cast_spawn_matches);
    writeJsonl(path.join(replayDir, 'ward_heatmap_input.jsonl'), ward.ward_heatmap_input);
    writeCsv(path.join(replayDir, 'ward_heatmap_input.csv'), ward.ward_heatmap_input, [
      'schema_version', 'game_id', 'replay_sha256', 'timestamp', 'minute',
      'team', 'participant', 'champion', 'ward_type', 'x', 'y', 'cast_target_y',
      'position_source', 'coordinate_system', 'map_id', 'map_name', 'patch',
      'normalized_x', 'normalized_y', 'perspective_team', 'perspective_participant',
      'role', 'side', 'confidence', 'is_spawn_position',
    ]);
  }
  return replayDir;
}

function inventoryFromAnalysis(analysis) {
  return {
    source_path: analysis.source_path,
    sha256: analysis.replay_sha256,
    file_size: analysis.file_size,
    game_id: analysis.game_id,
    game_id_status: analysis.game_id_status,
    game_version: analysis.replay_version,
    replay_version: analysis.replay_version,
    duration: analysis.metadata.game_length_ms,
    metadata: {
      game_length_ms: analysis.metadata.game_length_ms,
      last_game_chunk_id: analysis.metadata.last_game_chunk_id,
      last_key_frame_id: analysis.metadata.last_key_frame_id,
      stats_player_count: analysis.metadata.stats_player_count,
      metadata_keys: analysis.metadata.metadata_keys,
      players: analysis.metadata.players,
    },
    chunk_count: analysis.container.chunk_count,
    keyframe_count: analysis.container.keyframe_count,
    parser_version: analysis.parser_version,
    block_count: analysis.packet_count,
    block_error_count: analysis.block_errors.length,
  };
}

function flattenPacketRows(results) {
  return results.flatMap((result) => result.ok
    ? result.analysis.packet_type_inventory.map((row) => ({ source_path: result.analysis.source_path, replay_sha256: result.analysis.replay_sha256, ...row }))
    : []);
}

function flattenTimeline(results) {
  return results.flatMap((result) => result.ok
    ? result.analysis.packet_timeline_sample.map((row) => ({ source_path: result.analysis.source_path, ...row }))
    : []);
}

function detailsValidationRows(results, detailsDir) {
  const detailsIndex = detailsDir && fs.existsSync(detailsDir)
    ? indexDetailsFiles(detailsDir)
    : new Map();
  return results.map((result) => {
    const sourcePath = result.ok ? result.analysis.source_path : result.source_path;
    const filename = path.basename(sourcePath);
    const match = filename.match(/HN1-(\d+)/i);
    const candidateGameId = match ? match[1] : null;
    let detailsPath = null;
    if (candidateGameId) detailsPath = detailsIndex.get(candidateGameId) ?? null;
    return {
      source_path: sourcePath,
      replay_sha256: result.ok ? result.analysis.replay_sha256 : null,
      candidate_game_id: candidateGameId,
      candidate_game_id_status: candidateGameId ? 'INFERRED_FROM_FILENAME' : 'UNAVAILABLE',
      details_path: detailsPath,
      validation_status: detailsPath ? 'DETAILS_FOUND_VALIDATION_ONLY' : 'NO_MATCHING_DETAILS',
      replay_death_count: result.ok ? result.analysis.event_counts.death_events : null,
      details_death_count: null,
      replay_damage_count: result.ok ? result.analysis.event_counts.damage_events : null,
      details_damage_rows: null,
      mismatch_notes: detailsPath
        ? 'Replay semantic events were decoded without Details; use the dedicated validators for cross-source comparison.'
        : 'Replay semantic events were decoded without Details; no cross-source claim was made for this row.',
    };
  });
}

function gameIdsFromDetailsDocument(document) {
  const candidates = [
    document?.metadata?.match_id,
    document?.metadata?.matchId,
    document?.match_id,
    document?.matchId,
    document?.gameId,
    document?.json?.gameId,
    document?.json?.metadata?.matchId,
  ];
  return candidates
    .map((value) => /(?:^|_)(\d+)$/.exec(String(value ?? ''))?.[1] ?? null)
    .filter(Boolean);
}

function indexDetailsFiles(directory) {
  const index = new Map();
  const queue = [path.resolve(directory)];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) queue.push(full);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) {
        const filenameGameId = /(?:^|[-_])(\d{8,})(?:[-_.]|$)/.exec(entry.name)?.[1] ?? null;
        if (filenameGameId && !index.has(filenameGameId)) index.set(filenameGameId, full);
        try {
          const document = JSON.parse(fs.readFileSync(full, 'utf8'));
          for (const gameId of gameIdsFromDetailsDocument(document)) {
            if (!index.has(gameId)) index.set(gameId, full);
          }
        } catch {
          // Non-JSON and malformed validation artifacts are ignored.
        }
      }
    }
  }
  return index;
}

function buildAcceptanceSummary(results, beforeHashes, afterHashes, testSummary, args) {
  const successful = results.filter((result) => result.ok);
  const failed = results.filter((result) => !result.ok);
  const sum = (selector) => successful.reduce((total, result) => total + (selector(result.analysis) || 0), 0);
  const sumMetadataStat = (selector) => {
    let total = 0;
    let found = false;
    for (const result of successful) {
      for (const player of result.analysis.metadata.players || []) {
        const value = selector(player);
        if (Number.isFinite(value)) {
          total += value;
          found = true;
        }
      }
    }
    return found ? total : null;
  };
  const replaySha256 = successful.map((result) => ({ path: result.analysis.source_path, sha256: result.analysis.replay_sha256 }));
  const versions = [...new Set(successful.map((result) => result.analysis.replay_version))].sort();
  const blockErrorCount = sum((analysis) => analysis.block_errors.length);
  const testRunFailed = Boolean(testSummary && (
    testSummary.exit_code !== 0
    || (testSummary.failed !== null && testSummary.failed > 0)
    || (testSummary.total === null && !testSummary.error)
  ));
  const warnings = [];
  if (successful.some((result) => result.analysis.decoder.status === 'UNSUPPORTED_REPLAY_VERSION')) {
    warnings.push('Semantic decoder profile is unavailable for one or more real Replay versions.');
  }
  if (successful.some((result) => result.analysis.game_id_status !== 'VERIFIED')) {
    warnings.push('Game ID was not recovered from the ROFL container; filename candidates remain explicitly inferred.');
  }
  if (blockErrorCount > 0) {
    warnings.push(`The parser recorded ${blockErrorCount} block framing/decompression error(s); semantic output is not promoted.`);
  }
  if (!testSummary) {
    warnings.push('The test suite was not run by this command; use validate for the acceptance gate.');
  } else if (testRunFailed) {
    warnings.push('The node test suite did not pass; this run cannot be accepted as a clean validation.');
  }
  const upstream = compareHashSnapshots(beforeHashes, afterHashes);
  if (!upstream.unchanged) {
    warnings.push('An upstream research/collector file changed during the run; investigate before trusting outputs.');
  }
  const allSemanticReady = successful.length > 0 && successful.every(
    (result) => result.analysis.decoder.status === 'RESEARCH_READY_COMPLETE',
  );
  const allV2Ready = successful.length > 0 && successful.every(
    (result) => result.analysis.v2_status === 'RESEARCH_READY_V2_COMPLETE',
  );
  const validationClean = failed.length === 0
    && blockErrorCount === 0
    && !testRunFailed
    && upstream.unchanged;
  const status = successful.length === 0
    ? 'NEED_USER_FILE'
    : validationClean && allSemanticReady && allV2Ready
      ? 'RESEARCH_READY_V2_COMPLETE'
      : validationClean && allSemanticReady
      ? 'RESEARCH_READY_COMPLETE'
      : failed.length > 0 || blockErrorCount > 0 || testRunFailed || !upstream.unchanged
        ? 'VALIDATION_FAILED'
        : 'UNSUPPORTED_REPLAY_VERSION';
  return {
    status,
    milestone: status,
    tool_version: TOOL_VERSION,
    parser_version: successful[0]?.analysis.parser_version || null,
    generated_at_utc: new Date().toISOString(),
    command_args: args,
    replay_versions: versions,
    replay_file_count: successful.length,
    replay_files_tested: replaySha256,
    replay_sha256: replaySha256,
    tests_total: testSummary?.total ?? null,
    tests_passed: testSummary?.passed ?? null,
    tests_failed: testSummary?.failed ?? null,
    test_summary: testSummary,
    parquet_output_status: 'UNAVAILABLE',
    parquet_output_note: 'JSON/JSONL/CSV are emitted without an external dependency; Parquet is intentionally not synthesized in this build.',
    packet_count: sum((analysis) => analysis.packet_count),
    decoded_packet_count: sum((analysis) => analysis.decoded_packet_count),
    unknown_packet_count: sum((analysis) => analysis.unknown_packet_count),
    metadata_aggregate: {
      champion_kills: sumMetadataStat((player) => player.aggregate_stats.kills),
      deaths: sumMetadataStat((player) => player.aggregate_stats.deaths),
      assists: sumMetadataStat((player) => player.aggregate_stats.assists),
      damage_to_champions: sumMetadataStat((player) => player.aggregate_stats.total_damage_to_champions),
      heal: sumMetadataStat((player) => player.aggregate_stats.total_heal),
      items_purchased: sumMetadataStat((player) => player.aggregate_stats.items_purchased),
    },
    death_event_count: sum((analysis) => analysis.event_counts.death_events),
    damage_event_count: sum((analysis) => analysis.event_counts.damage_events),
    spell_event_count: sum((analysis) => analysis.event_counts.spell_events),
    buff_event_count: sum((analysis) => analysis.event_counts.buff_events),
    adc_death_count: sum((analysis) => analysis.adc_deaths.length),
    position_event_count: sum((analysis) => analysis.event_counts.position_events),
    ward_event_count: sum((analysis) => analysis.ward_events?.length),
    ward_direct_spawn_event_count: sum((analysis) => analysis.ward_events?.filter(
      (row) => row.position_source === 'ENTITY_SPAWN_DIRECT',
    ).length),
    ward_cast_spawn_match_count: sum((analysis) => analysis.ward_cast_spawn_matches?.length),
    ward_lifecycle_count: sum((analysis) => analysis.ward_lifecycles?.length),
    item_event_count: sum((analysis) => analysis.event_counts.item_events),
    shield_event_count: sum((analysis) => analysis.event_counts.shield_events),
    heal_event_count: sum((analysis) => analysis.event_counts.heal_events),
    unsupported_event_count: sum((analysis) => analysis.unknown_packet_count),
    errors: failed.map((result) => ({ source_path: result.source_path, ...result.error })),
    warnings,
    upstream_hash_before: beforeHashes,
    upstream_hash_after: afterHashes,
    upstream_unchanged: upstream.unchanged,
    upstream_changes: upstream.changes,
    real_replay_validation: {
      container_opened: successful.length > 0,
      packet_count_positive: successful.every((result) => result.analysis.packet_count > 0),
      block_framing_errors: blockErrorCount,
      semantic_events_verified: allSemanticReady,
      v2_complete: allV2Ready,
      ward_spawn_position_verified_direct: successful.every(
        (result) => result.analysis.ward_pipeline?.ward_spawn_position_status === 'VERIFIED_DIRECT',
      ),
      hero_position_verified_derived: successful.every(
        (result) => result.analysis.path_pipeline?.accepted_count > 0,
      ),
      replay_only_decoder: true,
      details_or_oracle_input_to_decoder: false,
      adc_combat_timeline_generated: successful.every(
        (result) => Array.isArray(result.analysis.adc_deaths)
          && result.analysis.adc_deaths.length > 0,
      ),
      all_replays_completed_without_errors: failed.length === 0 && blockErrorCount === 0,
    },
    decoder_summaries: successful.map((result) => ({
      source_path: result.analysis.source_path,
      replay_sha256: result.analysis.replay_sha256,
      status: result.analysis.decoder.status,
      death_decode: result.analysis.semantic?.death_decode ?? null,
      damage_decode: result.analysis.semantic?.damage_decode ?? null,
      cast_spell_decode: result.analysis.semantic?.cast_spell_decode ?? null,
      buff_decode: result.analysis.semantic?.buff_decode ?? null,
      ward_decode: result.analysis.ward_pipeline ? {
        status: result.analysis.ward_pipeline.status,
        direct_spawn_matches: result.analysis.ward_cast_spawn_matches?.length ?? 0,
        lifecycles: result.analysis.ward_lifecycles?.length ?? 0,
      } : null,
      path_decode: result.analysis.semantic?.path_decode ?? null,
      v2_status: result.analysis.v2_status ?? null,
    })),
    capabilities: successful[0]?.analysis.capabilities ?? [],
  };
}

function buildAcceptanceReport(summary, results, artifactRoot) {
  const lines = [
    '# ROFL Analyzer Acceptance Report',
    '',
    `- Status: **${summary.status}**`,
    `- Milestone: **${summary.milestone}**`,
    `- Real Replay files: ${summary.replay_files_tested.length}`,
    `- Replay versions: ${summary.replay_versions.join(', ') || 'none'}`,
    `- Total parsed blocks: ${summary.packet_count}`,
    `- Block framing errors: ${summary.real_replay_validation.block_framing_errors}`,
    `- Tests: ${summary.tests_total === null ? 'NOT RUN' : `${summary.tests_passed}/${summary.tests_total} passed; ${summary.tests_failed} failed`}`,
    `- Parquet output: **${summary.parquet_output_status}** (JSON/JSONL/CSV are emitted)`,
    `- Upstream data unchanged: **${summary.upstream_unchanged ? 'YES' : 'NO'}**`,
    '',
    '## Verified Replay Semantics',
    '',
    `- Hero Death events: ${summary.death_event_count} (VERIFIED_DIRECT).`,
    `- Damage events: ${summary.damage_event_count} with Replay timestamp, source, target, and amount (VERIFIED_DIRECT).`,
    `- CastSpell events: ${summary.spell_event_count} with caster, spell key, targets, and dictionary-derived slot/name where available.`,
    `- Buff Add/Remove/UpdateCount events: ${summary.buff_event_count} (VERIFIED_DIRECT core fields plus lifecycle derivations).`,
    `- Ward events: ${summary.ward_direct_spawn_event_count}/${summary.ward_event_count} use independently decoded entity spawn coordinates (VERIFIED_DIRECT).`,
    `- Ward cast-to-spawn matches: ${summary.ward_cast_spawn_match_count}; corpse-derived lifecycle rows: ${summary.ward_lifecycle_count}.`,
    `- Hero positions: ${summary.position_event_count} one-second rows derived from verified current-build PathPacket waypoints.`,
    '- Champion entity mapping uses the exact-build network-ID range and rejects non-champion entities.',
    '- ADC death records contain Replay-only damage sequences, attacker totals, combat duration, support casts, and support-to-ADC Buff adds.',
    '- Decode does not read Match Details; Details remain validation-only.',
    '- Every semantic row retains Replay SHA-256, chunk, decompressed offset, packet ID, payload length, and payload SHA-256.',
    '',
    '## Remaining Limits',
    '',
    '- Per-hit physical/magic/true type and basic-attack attribution are unavailable from the verified Damage fields.',
    summary.position_event_count > 0
      ? '- Position/movement is available; support distance and nearby-unit metrics are not yet derived from it and remain `NULL`.'
      : '- Position/movement is unavailable, so support distance and nearby-unit counts remain `NULL`.',
    '- Shield generated/application amount and direct reported heal amount are Replay-observed. Shield remaining/absorbed/unused and heal raw/effective/overheal remain unavailable.',
    '- Buff names are emitted as verified hashes unless a separately pinned dictionary can resolve them.',
    '',
    '## Independent Review',
    '',
    `- Per-Replay evidence is under ${path.resolve(artifactRoot, 'replays')}.`,
    '- Select a row from `damage_events.jsonl`, `death_events.jsonl`, `spell_events.jsonl`, `buff_events.jsonl`, `shield_events.jsonl`, or `heal_events.jsonl` and follow `raw_packet_ref` into the source Replay.',
    '- Recompute the Replay and payload SHA-256 values before checking semantic fields.',
    `- Re-run \`${TEST_COMMAND}\` and the validation command recorded in \`reviewer_manifest.json\` from the repository root.`,
    '',
    'The report itself is not evidence. Re-run the commands in `reviewer_manifest.json` and inspect the raw Replay bytes independently.',
    '',
  ];
  return lines.join('\n');
}

function buildReviewerManifest(summary, rootDir, results, args) {
  const absoluteRoot = path.resolve(rootDir);
  const successful = results.filter((result) => result.ok);
  const reviewReplay = successful[0]?.analysis.source_path || results[0]?.source_path || null;
  const reviewerRerunRoot = path.resolve(absoluteRoot, 'reviewer-rerun');
  const replayCommand = reviewReplay
    ? `node src/cli.js analyze ${quoteCommandArg(reviewReplay)} --out-dir ${quoteCommandArg(reviewerRerunRoot)}`
    : null;
  const validationInputs = [...new Set(results.map((result) => result.ok ? result.analysis.source_path : result.source_path))];
  const validationCommand = validationInputs.length > 0
    ? `node src/cli.js validate ${validationInputs.map(quoteCommandArg).join(' ')} --out-dir ${quoteCommandArg(absoluteRoot)}`
    : null;
  return {
    generated_at_utc: new Date().toISOString(),
    status: summary.status,
    repository_root: REPOSITORY_ROOT,
    key_source_files: [
      path.resolve(__dirname, 'rofl.js'),
      path.resolve(__dirname, 'semantic_pipeline.js'),
      path.resolve(__dirname, 'decoders', 'rofl_16_15_801_3452.js'),
      path.resolve(__dirname, 'cli.js'),
      path.resolve(REPOSITORY_ROOT, 'scripts', 'emulate_exact_packet_decoder.py'),
      path.resolve(REPOSITORY_ROOT, 'scripts', 'validate_buff_events.js'),
      path.resolve(__dirname, '..', 'test'),
    ],
    replay_samples: results.filter((result) => result.ok).map((result) => ({
      path: result.analysis.source_path,
      sha256: result.analysis.replay_sha256,
      version: result.analysis.replay_version,
      patch: result.analysis.patch,
    })),
    output_root: absoluteRoot,
    acceptance_summary: path.resolve(absoluteRoot, 'acceptance_summary.json'),
    acceptance_report: path.resolve(absoluteRoot, 'ACCEPTANCE_REPORT.md'),
    capability_matrix: path.resolve(REPOSITORY_ROOT, 'docs', 'PROTECTION_V4_CAPABILITY_MATRIX.md'),
    format_documentation: path.resolve(REPOSITORY_ROOT, 'docs', 'ROFL_FORMAT.md'),
    protocol_report: path.resolve(REPOSITORY_ROOT, 'docs', 'PROTECTION_V4_COMPLETION_REPORT.md'),
    test_command: TEST_COMMAND,
    npm_test_command: 'npm test',
    replay_command: replayCommand,
    validation_command: validationCommand,
    raw_anchor_command: `node scripts/verify_raw_anchor.js ${quoteCommandArg(path.resolve(absoluteRoot, 'raw_packet_anchors.json'))} 0 --output-root ${quoteCommandArg(absoluteRoot)}`,
    source_command_args: args,
    key_artifacts: {
      inventory: path.resolve(absoluteRoot, 'rofl_inventory.json'),
      packet_type_inventory: path.resolve(absoluteRoot, 'packet_type_inventory.csv'),
      packet_timeline: path.resolve(absoluteRoot, 'packet_timeline_sample.jsonl'),
      raw_packet_anchors: path.resolve(absoluteRoot, 'raw_packet_anchors.json'),
      replay_vs_details: path.resolve(absoluteRoot, 'replay_vs_details_validation.csv'),
      damage_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'semantic_probe', 'damage_validation_summary.json'),
      death_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'semantic_probe', 'death_validation.json'),
      spell_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'semantic_probe', 'spell_validation_summary.json'),
      buff_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'runtime_probe', 'buff_validation_summary.json'),
    },
    raw_anchor_guidance: [
      'Use raw_packet_anchors.json to select a real chunk/block.',
      'Verify replay_sha256 before reading the recorded offsets.',
      'Check chunk_file_offset and decompressed_block_offset against the source Replay.',
      'Open the matching semantic JSONL row and verify its raw_packet_ref and payload_sha256.',
      'Follow source Replay bytes → chunk → decompressed block → exact-build decoder → semantic event → ADC output.',
    ],
    raw_anchor_chain_status: {
      raw_packet: 'VERIFIED',
      decoded_event: 'VERIFIED_DIRECT',
      entity_attribution: 'VERIFIED_DERIVED',
      final_semantic_output: 'VERIFIED_DERIVED',
    },
    details_comparison: {
      status: 'VALIDATION_ONLY',
      validation_csv: path.resolve(absoluteRoot, 'replay_vs_details_validation.csv'),
      database: null,
      database_access: 'read_only_only',
      note: 'No external database path is embedded in portable artifacts.',
    },
    independent_reviewer_message: '请按 reviewer_manifest 重新执行测试，并抽查 RAW Replay packet → decoded event → final output 链路。',
  };
}

async function writeRunArtifacts(results, rootDir, beforeHashes, afterHashes, args, testSummary = null, detailsDir = null) {
  ensureDir(rootDir);
  const successful = results.filter((result) => result.ok);
  for (const result of successful) writePerReplayArtifacts(result.analysis, rootDir);

  const inventories = successful.map((result) => inventoryFromAnalysis(result.analysis));
  writeJson(path.join(rootDir, 'rofl_inventory.json'), inventories);
  writeCsv(path.join(rootDir, 'packet_type_inventory.csv'), flattenPacketRows(results), [
    'source_path',
    'replay_sha256',
    'packet_id',
    'packet_type',
    'count',
    'average_payload_length',
    'min_payload_length',
    'max_payload_length',
    'min_timestamp_ms',
    'max_timestamp_ms',
    'streams',
    'decoder_status',
  ]);
  writeJsonl(path.join(rootDir, 'packet_timeline_sample.jsonl'), flattenTimeline(results));
  writeJson(path.join(rootDir, 'raw_packet_anchors.json'), successful.flatMap((result) => result.analysis.raw_anchors));
  writeCsv(path.join(rootDir, 'replay_vs_details_validation.csv'), detailsValidationRows(results, detailsDir), [
    'source_path',
    'replay_sha256',
    'candidate_game_id',
    'candidate_game_id_status',
    'details_path',
    'validation_status',
    'replay_death_count',
    'details_death_count',
    'replay_damage_count',
    'details_damage_rows',
    'mismatch_notes',
  ]);
  const summary = buildAcceptanceSummary(results, beforeHashes, afterHashes, testSummary, args);
  writeJson(path.join(rootDir, 'acceptance_summary.json'), summary);
  fs.writeFileSync(path.join(rootDir, 'ACCEPTANCE_REPORT.md'), `${buildAcceptanceReport(summary, results, rootDir)}\n`, 'utf8');
  const reviewerManifest = buildReviewerManifest(summary, rootDir, results, args);
  writeJson(path.join(rootDir, 'reviewer_manifest.json'), reviewerManifest);
  const outputHashExclusions = ['manifest.json', 'single-run', 'post-fix-single'];
  const hashes = await outputHashes(rootDir, { exclude: outputHashExclusions });
  writeJson(path.join(rootDir, 'manifest.json'), {
    tool_version: TOOL_VERSION,
    parser_version: successful[0]?.analysis.parser_version || null,
    git_commit: gitCommit(),
    generated_at_utc: new Date().toISOString(),
    command_args: args,
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    dependencies: {
      zstd_native: typeof require('node:zlib').zstdDecompressSync === 'function',
      external_runtime_dependencies: [],
    },
    replay_inputs: successful.map((result) => ({
      path: result.analysis.source_path,
      sha256: result.analysis.replay_sha256,
      version: result.analysis.replay_version,
      decoder_profile: result.analysis.decoder.profile,
      decoder_status: result.analysis.decoder.status,
    })),
    decoder_profiles: successful.map((result) => ({
      replay_version: result.analysis.replay_version,
      profile: result.analysis.decoder.profile,
      status: result.analysis.decoder.status,
    })),
    test_summary: testSummary,
    upstream_hash_before: beforeHashes,
    upstream_hash_after: afterHashes,
    upstream_unchanged: compareHashSnapshots(beforeHashes, afterHashes).unchanged,
    output_hash_exclusions: outputHashExclusions,
    output_hashes_excluding_manifest: hashes,
  });
  return summary;
}

async function main(argv = process.argv.slice(2)) {
  const parsed = parseArgs(argv);
  if (parsed.options.help || parsed.command === 'help') {
    process.stdout.write(usage());
    return 0;
  }
  if (!COMMANDS.has(parsed.command)) throw new Error(`Unknown command: ${parsed.command}`);
  if (parsed.command === 'ward-events') return runWardEventsCommand(parsed);
  const inputs = parsed.positionals.length > 0 ? parsed.positionals : ['replay'];
  const files = discoverReplayFiles(inputs);
  if (files.length === 0) throw new Error('No .rofl files found in the supplied input.');
  const outDir = path.resolve(parsed.options.outDir);
  const beforeHashes = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const parseOptions = { ...parsed.options, semantic: parsed.command !== 'inspect' };
  const results = files.map((filePath) => parseOne(filePath, parseOptions));
  const testSummary = parsed.command === 'validate' ? runTestSuite() : null;
  const afterHashes = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const validationDetailsDir = parsed.command === 'validate' && parsed.options.detailsDir
    ? path.resolve(parsed.options.detailsDir)
    : null;
  const summary = await writeRunArtifacts(
    results,
    outDir,
    beforeHashes,
    afterHashes,
    argv,
    testSummary,
    validationDetailsDir,
  );
  for (const result of results) {
    if (result.ok) {
      process.stdout.write(`${result.analysis.source_path}\t${result.analysis.replay_version}\t${result.analysis.packet_count} blocks\t${result.analysis.block_errors.length} errors\n`);
    } else {
      process.stderr.write(`${result.source_path}\t${result.error.code}\t${result.error.message}\n`);
    }
  }
  process.stdout.write(`Status: ${summary.status}\nOutput: ${outDir}\n`);
  return results.some((result) => !result.ok) || (testSummary && testSummary.exit_code !== 0) ? 2 : 0;
}

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(`${error.message || error}\n`);
    process.stderr.write(usage());
    process.exitCode = 1;
  });
}

module.exports = {
  parseArgs,
  parseTestSummary,
  runTestSuite,
  discoverReplayFiles,
  runWardEventsCommand,
  readWardRowsFromReplay,
  parseOne,
  v2InputsForReplay,
  inventoryFromAnalysis,
  buildAcceptanceSummary,
  main,
};
