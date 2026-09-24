#!/usr/bin/env node

const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { rawAnchorChainStatus, renderAcceptanceReport } = require('./cli_report');
const { resolveBuildProfile } = require('./build_registry');
const { candidateTailStatAssessment } = require('./decoders/rofl_16_19_820_7193');
const {
  assessHeroMinionsKilledSnapshotTail,
  assessHeroExperienceSnapshotTail,
  assessHeroGoldEarnedSnapshotTail,
  assessHeroGoldSpentSnapshotTail,
  assessHeroChampionKillsSnapshotTail,
  assessHeroDeathsSnapshotTail,
} = require('./decoders/rofl_16_19_hero_stats_candidate');

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
  DEFAULT_SPELL_DICTIONARY,
} = require('./semantic_pipeline');
const {
  decodeSemanticReplay: decodeExactBuildReplay,
  DEFAULT_16_16_RUNTIME_IMAGE,
} = require('./semantic_api');
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
const COMMANDS = new Set(['inspect', 'decode', 'analyze', 'batch', 'validate', 'ward-events', 'capabilities']);

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
  node src/cli.js capabilities <file.rofl> [--json]
  node src/cli.js decode <file.rofl> [--out-dir artifacts]
  node src/cli.js analyze <file.rofl> [--out-dir artifacts]
  node src/cli.js batch <file.rofl|directory> [more inputs ...] [--out-dir artifacts]
  node src/cli.js validate [file.rofl|directory ...] [--out-dir artifacts]
  node src/cli.js ward-events <rows.json|rows.jsonl|file.rofl> [--out-dir artifacts]

Runtime: Node >=22.15.0 with native Zstd.
Legacy semantic CLI scope: exact 16.15.801.3452. The separate 16.16 public API
is not dispatched by this CLI; see docs/PUBLIC_DEVELOPMENT.md.
16.19 decode and batch use the exact-build semantic API when --events is selected.
Inspect reads the container and packet framing without a runtime image.
Capabilities reads the container/build registry without packet framing or semantic decode.

Options:
  --out-dir <path>              Independent output directory (default: artifacts)
  --timeline-limit <number>     First N packet timeline rows (default: 250)
  --sample-stride <number>      Deprecated compatibility option; prefix samples are unchanged
  --include-private-metadata     Include Riot ID/PUUID fields in roster output
  --strict                       Stop at the first framing error
  --decoder-image <path>        Exact 16.15 runtime image (external input; not bundled)
  --runtime-image <path>        External image path; 16.19 candidate does not use it
  --events <name[,name...]>     Select 16.19 semantic capabilities to decode
  --json                        Emit only machine-readable JSON (capabilities)
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
    runtimeImage: null,
    events: null,
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
    if ((command === 'ward-events' || command === 'capabilities') && token === '--json') {
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
      else if (key === 'runtime-image') options.runtimeImage = value;
      else if (key === 'events') options.events = parseEventNames(value);
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

function parseEventNames(value) {
  const names = String(value).split(',').map((name) => name.trim());
  if (names.length === 0 || names.some((name) => !/^[a-z][a-z0-9_]*$/.test(name))) {
    throw new Error('--events requires a comma-separated list of capability names');
  }
  return [...new Set(names)];
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

function summarizeCapabilityResults(requested, decoded) {
  const source = decoded?.capability_results ?? {};
  const fallbackStatus = decoded?.status === 'UNSUPPORTED_VERSION' ? 'UNSUPPORTED'
    : decoded?.status === 'BLOCKED' || decoded?.status === 'MISSING_INPUT'
      ? 'MISSING_INPUT' : 'DECODE_FAILED';
  const capabilityResults = {};
  for (const capability of requested) {
    const row = source[capability];
    if (!row || typeof row !== 'object' || typeof row.status !== 'string') {
      capabilityResults[capability] = {
        status: fallbackStatus,
        input_count: null,
        event_count: null,
        error: decoded?.note ?? `Decoder did not report ${capability}.`,
      };
      continue;
    }
    if ((row.status === 'PASS' || row.status === 'CANDIDATE')
        && (!Number.isSafeInteger(row.input_count)
        || row.input_count < 0 || !Number.isSafeInteger(row.event_count)
        || row.event_count < 0)) {
      capabilityResults[capability] = {
        status: 'DECODE_FAILED',
        input_count: null,
        event_count: null,
        error: `Decoder returned ${row.status} without valid counts for ${capability}.`,
      };
      continue;
    }
    capabilityResults[capability] = row;
  }
  const statuses = Object.values(capabilityResults).map((row) => row.status);
  const completed = statuses.filter((status) => status === 'PASS' || status === 'CANDIDATE').length;
  const status = completed === requested.length
    ? statuses.includes('CANDIDATE') ? 'CANDIDATE' : 'PASS'
    : completed > 0 ? 'PARTIAL'
      : statuses.every((item) => item === statuses[0]) ? statuses[0]
        : 'DECODE_FAILED';
  return { status, capabilityResults };
}

function parseOne1619(replay, options, started) {
  const analysis = analyzeReplay(replay, {
    timelineLimit: options.timelineLimit,
    includePrivateMetadata: options.includePrivateMetadata,
    strict: options.strict,
  });
  // The raw analyzer initializes legacy event arrays. For a 16.19 run, only
  // arrays returned by an executed exact-build decoder may appear here.
  analysis.events = {};
  analysis.event_counts = {};
  analysis.capabilities = [];
  analysis.adc_deaths = [];
  analysis.decoder = {
    profile: null,
    status: analysis.block_errors.length === 0 ? 'CONTAINER_INSPECTED' : 'FRAMING_FAILED',
    note: analysis.block_errors.length === 0
      ? 'Container and packet framing inspected; no semantic decoder was requested.'
      : `${analysis.block_errors.length} packet framing/decompression error(s) prevent semantic decoding.`,
  };
  if (options.semantic !== false) {
    const requested = options.events ?? [];
    let decoded = null;
    if (analysis.block_errors.length > 0) {
      analysis.decoder.status = 'FRAMING_FAILED';
      analysis.semantic = {
        status: 'FRAMING_FAILED',
        requested_capabilities: requested,
        capability_results: Object.fromEntries(requested.map((capability) => [capability, {
          status: 'DECODE_FAILED', input_count: null, event_count: null,
          error: 'Replay packet framing/decompression failed.',
        }])),
      };
    } else if (!resolveBuildProfile(replay).profile) {
      analysis.decoder.status = 'UNSUPPORTED_VERSION';
      analysis.decoder.note = `No exact build profile is registered for ${replay.header.version}.`;
      analysis.semantic = {
        status: 'UNSUPPORTED_VERSION',
        requested_capabilities: requested,
        capability_results: Object.fromEntries(requested.map((capability) => [capability, {
          status: 'UNSUPPORTED', input_count: null, event_count: null,
          error: analysis.decoder.note,
        }])),
      };
    } else if (requested.length === 0) {
      analysis.decoder.status = 'MISSING_CAPABILITY_SELECTION';
      analysis.decoder.note = 'Specify --events with the 16.19 capability to decode.';
      analysis.semantic = {
        status: 'MISSING_CAPABILITY_SELECTION',
        requested_capabilities: [],
        capability_results: {},
      };
    } else {
      try {
        decoded = decodeExactBuildReplay(replay, {
          capabilities: requested,
          runtimeImagePath: options.runtimeImage ?? undefined,
          pythonExecutable: options.python ?? undefined,
        });
      } catch (error) {
        decoded = {
          status: 'DECODE_FAILED',
          note: error.message || String(error),
          capability_results: Object.fromEntries(requested.map((capability) => [capability, {
            status: 'DECODE_FAILED', input_count: null, event_count: null,
            error: error.message || String(error),
          }])),
        };
      }
      const capabilitySummary = summarizeCapabilityResults(requested, decoded);
      const runtimeStatuses = Object.values(capabilitySummary.capabilityResults)
        .map((row) => row.runtime_image_status);
      const runtimeImageUsed = typeof decoded.runtime_image_used === 'boolean'
        ? decoded.runtime_image_used
        : runtimeStatuses.length > 0 && runtimeStatuses.every((status) => [
          'PROVIDED_NOT_USED', 'NOT_REQUIRED',
        ].includes(status)) ? false : null;
      analysis.decoder = {
        profile: decoded.profile ?? null,
        status: capabilitySummary.status,
        note: decoded.note ?? (capabilitySummary.status === 'CANDIDATE'
          ? 'Experimental candidate output; it is not a confirmed semantic event.' : null),
      };
      analysis.semantic = {
        status: capabilitySummary.status,
        api_status: decoded.status ?? null,
        note: decoded.note ?? null,
        requested_capabilities: requested,
        capability_results: capabilitySummary.capabilityResults,
        runtime_image_requested: options.runtimeImage ? path.resolve(options.runtimeImage) : null,
        runtime_image_used: runtimeImageUsed,
        runtime_image_sha256: decoded.runtime_image_sha256 ?? null,
      };
      analysis.events = Object.fromEntries(Object.entries(decoded.events ?? {})
        .filter(([, rows]) => Array.isArray(rows)));
      analysis.event_counts = Object.fromEntries(Object.entries(analysis.events)
        .map(([name, rows]) => [name, rows.length]));
      if (Number.isSafeInteger(decoded.decoded_packet_count)
          && decoded.decoded_packet_count >= 0) {
        analysis.decoded_packet_count = decoded.decoded_packet_count;
        analysis.unknown_packet_count = Math.max(0,
          analysis.packet_count - decoded.decoded_packet_count);
      }
    }
  }
  analysis.input_parse_elapsed_ms = Number((Number(process.hrtime.bigint() - started) / 1e6).toFixed(3));
  return { ok: true, analysis };
}

function parseOne(filePath, options) {
  const started = process.hrtime.bigint();
  try {
    const replay = parseReplayFile(filePath);
    if (replay.header.patch === '16.19') {
      return parseOne1619(replay, options, started);
    }
    if (options.events || options.runtimeImage) {
      const analysis = analyzeReplay(replay, {
        timelineLimit: options.timelineLimit,
        includePrivateMetadata: options.includePrivateMetadata,
        strict: options.strict,
      });
      analysis.events = {};
      analysis.event_counts = {};
      analysis.capabilities = [];
      analysis.decoder = {
        profile: null,
        status: 'UNSUPPORTED_REPLAY_VERSION',
        note: `--events and --runtime-image select the 16.19 path; received ${replay.header.version}.`,
      };
      analysis.input_parse_elapsed_ms = Number((Number(process.hrtime.bigint() - started) / 1e6).toFixed(3));
      return { ok: true, analysis };
    }
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
        note: semantic.status === 'UNSUPPORTED_REPLAY_VERSION'
          ? `Legacy CLI semantics support only 16.15.801.3452; received ${replay.header.version}. `
            + 'The separate 16.16 public API is not dispatched by this command. See docs/PUBLIC_DEVELOPMENT.md.'
          : semantic.note
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

function replayDirectoryNames(analyses) {
  const stems = analyses.map((analysis) => safeStem(analysis.source_path));
  const stemCounts = new Map();
  for (const stem of stems) stemCounts.set(stem, (stemCounts.get(stem) ?? 0) + 1);
  const candidates = analyses.map((analysis, index) => {
    const stem = stems[index];
    const sourcePath = path.resolve(analysis.source_path);
    const identity = process.platform === 'win32' ? sourcePath.toLowerCase() : sourcePath;
    const pathHash = sha256(Buffer.from(identity, 'utf8'));
    return {
      stem,
      pathHash,
      name: stemCounts.get(stem) > 1 ? `${stem}-${pathHash.slice(0, 12)}` : stem,
    };
  });
  const candidateCounts = new Map();
  for (const row of candidates) {
    candidateCounts.set(row.name, (candidateCounts.get(row.name) ?? 0) + 1);
  }
  const names = candidates.map((row) => candidateCounts.get(row.name) > 1
    ? `${row.stem}-${row.pathHash}` : row.name);
  if (new Set(names).size !== names.length) {
    throw new Error('Replay output directory identities are not unique');
  }
  return names;
}

function writePerReplayArtifacts(analysis, rootDir, replayDirName) {
  const replayDir = path.join(rootDir, 'replays', replayDirName);
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
  if (analysis.patch === '16.19' && analysis.semantic) {
    writeJson(path.join(replayDir, 'semantic_run.json'), {
      replay_version: analysis.replay_version,
      replay_sha256: analysis.replay_sha256,
      container_status: analysis.block_errors.length === 0 ? 'PASS' : 'FRAMING_FAILED',
      ...analysis.semantic,
    });
  }
  writeJson(path.join(replayDir, 'events.json'), analysis.events);
  for (const [name, rows] of Object.entries(analysis.events)) {
    writeJsonl(path.join(replayDir, `${name}.jsonl`), rows);
  }
  if (analysis.patch !== '16.19') {
    writeJsonl(path.join(replayDir, 'adc_deaths.jsonl'), analysis.adc_deaths);
  }
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
      mismatch_notes: result.ok && result.analysis.patch === '16.19'
        ? '16.19 capability execution is recorded separately in semantic_run.json; Match Details are validation-only and were not used for decoding.'
        : detailsPath
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
  let status = successful.length === 0
    ? 'NEED_USER_FILE'
    : validationClean && allSemanticReady && allV2Ready
      ? 'RESEARCH_READY_V2_COMPLETE'
      : validationClean && allSemanticReady
      ? 'RESEARCH_READY_COMPLETE'
      : failed.length > 0 || blockErrorCount > 0 || testRunFailed || !upstream.unchanged
        ? 'VALIDATION_FAILED'
        : 'UNSUPPORTED_REPLAY_VERSION';
  const has1619 = successful.some((result) => result.analysis.patch === '16.19');
  if (has1619 && successful.length > 0) {
    const statuses = successful.map((result) => result.analysis.decoder.status);
    const completed = new Set(['PASS', 'CANDIDATE', 'RESEARCH_READY_COMPLETE']);
    if (!validationClean) status = 'VALIDATION_FAILED';
    else if (args[0] === 'inspect' || statuses.every((item) => item === 'CONTAINER_INSPECTED')) {
      status = 'CONTAINER_INSPECTED';
    } else if (statuses.every((item) => item === 'PASS' || item === 'RESEARCH_READY_COMPLETE')) {
      status = 'PASS';
    } else if (statuses.every((item) => completed.has(item))) {
      status = 'CANDIDATE';
    } else if (statuses.some((item) => completed.has(item))) {
      status = 'PARTIAL';
    } else if (statuses.every((item) => item === statuses[0])) {
      status = statuses[0];
    } else {
      status = 'DECODE_FAILED';
    }
  }
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
    replay_artifacts: successful.map((result) => ({
      source_path: result.analysis.source_path,
      replay_sha256: result.analysis.replay_sha256,
      artifact_directory: result.analysis.artifact_directory ?? null,
    })),
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
    death_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.death_events),
    damage_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.damage_events),
    spell_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.spell_events),
    buff_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.buff_events),
    adc_death_count: has1619 ? null : sum((analysis) => analysis.adc_deaths.length),
    position_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.position_events),
    ward_event_count: has1619 ? null : sum((analysis) => analysis.ward_events?.length),
    ward_direct_spawn_event_count: has1619 ? null : sum((analysis) => analysis.ward_events?.filter(
      (row) => row.position_source === 'ENTITY_SPAWN_DIRECT',
    ).length),
    ward_cast_spawn_match_count: has1619 ? null : sum((analysis) => analysis.ward_cast_spawn_matches?.length),
    ward_lifecycle_count: has1619 ? null : sum((analysis) => analysis.ward_lifecycles?.length),
    item_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.item_events),
    shield_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.shield_events),
    heal_event_count: has1619 ? null : sum((analysis) => analysis.event_counts.heal_events),
    unsupported_event_count: has1619 ? null : sum((analysis) => analysis.unknown_packet_count),
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
    capability_runs: successful.filter((result) => result.analysis.patch === '16.19')
      .map((result) => ({
        source_path: result.analysis.source_path,
        replay_sha256: result.analysis.replay_sha256,
        replay_version: result.analysis.replay_version,
        status: result.analysis.decoder.status,
        requested_capabilities: result.analysis.semantic?.requested_capabilities ?? [],
        capability_results: result.analysis.semantic?.capability_results ?? {},
      })),
    capabilities: successful[0]?.analysis.capabilities ?? [],
  };
}

function buildAcceptanceReport(summary, results, artifactRoot) {
  if (results.some((result) => result.ok && result.analysis.patch === '16.19')) {
    const lines = [
      '# ROFL Analyzer Run Report', '',
      `- Run status: **${summary.status}**`,
      `- Output: ${path.resolve(artifactRoot)}`,
      `- Parsed Replays: ${summary.replay_file_count}`,
      `- Packet framing errors: ${summary.real_replay_validation.block_framing_errors}`, '',
      '## Per-Replay execution', '',
    ];
    for (const result of results) {
      if (!result.ok) {
        lines.push(`- ${result.source_path}: INPUT_FAILED — ${result.error.message}`);
        continue;
      }
      const analysis = result.analysis;
      lines.push(`- ${analysis.source_path}: ${analysis.replay_version}; ${analysis.packet_count} blocks; ${analysis.decoder.status}`);
      for (const [name, capability] of Object.entries(
        analysis.semantic?.capability_results ?? {},
      )) {
        const count = capability.event_count === null || capability.event_count === undefined
          ? 'unavailable' : capability.event_count;
        const missing = capability.missing_input == null ? null
          : typeof capability.missing_input === 'string'
            ? capability.missing_input : JSON.stringify(capability.missing_input);
        lines.push(`  - ${name}: ${capability.status}; ${count} events; ${capability.input_count ?? 'unavailable'} inputs${capability.profile_id ? `; profile ${capability.profile_id}` : ''}${missing ? `; missing input: ${missing}` : ''}${capability.error ? `; ${capability.error}` : ''}`);
      }
    }
    lines.push('', '## Interpretation', '',
      'PASS with zero events means the requested capability executed and found no matching events.',
      'CANDIDATE marks experimental output and is not a confirmed semantic event.',
      'MISSING_INPUT, UNSUPPORTED, PROFILE_UNAVAILABLE, DECODE_FAILED and FRAMING_FAILED do not mean zero events.',
      'Per-Replay semantic_run.json records requested capability results and Replay identity.', '');
    return lines.join('\n');
  }
  return renderAcceptanceReport(summary, results, artifactRoot, TEST_COMMAND);
}

function buildReviewerManifest(summary, rootDir, results, args) {
  const absoluteRoot = path.resolve(rootDir);
  const successful = results.filter((result) => result.ok);
  const first1619 = successful.find((result) => result.analysis.patch === '16.19')?.analysis;
  const reviewReplay = first1619?.source_path
    || successful[0]?.analysis.source_path || results[0]?.source_path || null;
  const reviewerRerunRoot = path.resolve(absoluteRoot, 'reviewer-rerun');
  const selected1619 = first1619?.semantic?.requested_capabilities ?? [];
  const selectedArg = selected1619.length > 0
    ? ` --events ${quoteCommandArg(selected1619.join(','))}` : '';
  const runtimeArg = first1619?.semantic?.runtime_image_requested
    ? ` --runtime-image ${quoteCommandArg(first1619.semantic.runtime_image_requested)}` : '';
  const replayCommand = reviewReplay ? first1619
    ? `node src/cli.js ${selected1619.length > 0 ? 'decode' : 'inspect'} ${quoteCommandArg(reviewReplay)}${selectedArg}${runtimeArg} --out-dir ${quoteCommandArg(reviewerRerunRoot)}`
    : `node src/cli.js analyze ${quoteCommandArg(reviewReplay)} --out-dir ${quoteCommandArg(reviewerRerunRoot)}`
    : null;
  const validationInputs = [...new Set(results.map((result) => result.ok ? result.analysis.source_path : result.source_path))];
  const validationCommand = validationInputs.length > 0 && !first1619
    ? `node src/cli.js validate ${validationInputs.map(quoteCommandArg).join(' ')} --out-dir ${quoteCommandArg(absoluteRoot)}`
    : null;
  return {
    generated_at_utc: new Date().toISOString(),
    status: summary.status,
    repository_root: REPOSITORY_ROOT,
    key_source_files: first1619 ? [
      path.resolve(__dirname, 'rofl.js'),
      path.resolve(__dirname, 'build_registry.js'),
      path.resolve(__dirname, 'semantic_api.js'),
      path.resolve(__dirname, 'cli.js'),
      path.resolve(__dirname, '..', 'test'),
    ] : [
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
    capability_matrix: first1619 ? null
      : path.resolve(REPOSITORY_ROOT, 'docs', 'PROTECTION_V4_CAPABILITY_MATRIX.md'),
    format_documentation: path.resolve(REPOSITORY_ROOT, 'docs', 'ROFL_FORMAT.md'),
    protocol_report: first1619 ? null
      : path.resolve(REPOSITORY_ROOT, 'docs', 'PROTECTION_V4_COMPLETION_REPORT.md'),
    test_command: TEST_COMMAND,
    npm_test_command: 'npm run test:all',
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
      ...(first1619 ? {} : {
        damage_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'semantic_probe', 'damage_validation_summary.json'),
        death_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'semantic_probe', 'death_validation.json'),
        spell_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'semantic_probe', 'spell_validation_summary.json'),
        buff_validation: path.resolve(REPOSITORY_ROOT, 'artifacts', 'runtime_probe', 'buff_validation_summary.json'),
      }),
    },
    raw_anchor_guidance: [
      'Use raw_packet_anchors.json to select a real chunk/block.',
      'Verify replay_sha256 before reading the recorded offsets.',
      'Check chunk_file_offset and decompressed_block_offset against the source Replay.',
      'Open the matching semantic JSONL row and verify its raw_packet_ref and payload_sha256.',
      first1619
        ? 'Follow source Replay bytes through the exact-build candidate profile; CANDIDATE is not a confirmed semantic event.'
        : 'Follow source Replay bytes → chunk → decompressed block → exact-build decoder → semantic event → ADC output.',
    ],
    raw_anchor_chain_status: rawAnchorChainStatus(summary),
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
  const replayDirNames = replayDirectoryNames(successful.map((result) => result.analysis));
  for (const [index, result] of successful.entries()) {
    result.analysis.artifact_directory = path.posix.join('replays', replayDirNames[index]);
    writePerReplayArtifacts(result.analysis, rootDir, replayDirNames[index]);
  }

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
  summary.output_root = path.resolve(rootDir);
  writeJson(path.join(rootDir, 'acceptance_summary.json'), summary);
  fs.writeFileSync(path.join(rootDir, 'ACCEPTANCE_REPORT.md'), `${buildAcceptanceReport(summary, results, rootDir)}\n`, 'utf8');
  const reviewerManifest = buildReviewerManifest(summary, rootDir, results, args);
  writeJson(path.join(rootDir, 'reviewer_manifest.json'), reviewerManifest);
  const outputHashExclusions = ['manifest.json', 'single-run', 'post-fix-single'];
  const hashes = await outputHashes(rootDir, { exclude: outputHashExclusions });
  writeJson(path.join(rootDir, 'manifest.json'), {
    tool_version: TOOL_VERSION,
    output_root: path.resolve(rootDir),
    parser_version: successful[0]?.analysis.parser_version || null,
    git_commit: gitCommit(),
    generated_at_utc: new Date().toISOString(),
    command_args: args,
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    dependencies: {
      zstd_native: typeof require('node:zlib').zstdDecompressSync === 'function',
      external_runtime_dependencies: [...new Set(successful
        .filter((result) => result.analysis.semantic?.runtime_image_used === true)
        .map((result) => result.analysis.semantic?.runtime_image_requested)
        .filter(Boolean))],
      requested_runtime_images: [...new Set(successful
        .map((result) => result.analysis.semantic?.runtime_image_requested)
        .filter(Boolean))],
    },
    replay_inputs: successful.map((result) => ({
      path: result.analysis.source_path,
      sha256: result.analysis.replay_sha256,
      version: result.analysis.replay_version,
      decoder_profile: result.analysis.decoder.profile,
      decoder_status: result.analysis.decoder.status,
      requested_capabilities: result.analysis.semantic?.requested_capabilities ?? null,
      artifact_directory: result.analysis.artifact_directory ?? null,
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

function isIgnoredRepositoryOutputRoot(resolved, repositoryRoot = REPOSITORY_ROOT) {
  const normalized = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  return ['artifacts', 'work', 'dist', 'evidence'].some((name) => {
    const candidate = path.resolve(repositoryRoot, name);
    return normalized === (process.platform === 'win32' ? candidate.toLowerCase() : candidate);
  });
}

function reserveOutputDirectory(requested, repositoryRoot = REPOSITORY_ROOT) {
  const resolved = path.resolve(requested);
  ensureDir(path.dirname(resolved));
  try {
    fs.mkdirSync(resolved);
    return resolved;
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory()) throw new Error(`Output path is not a directory: ${resolved}`);
  if (fs.readdirSync(resolved).length === 0) return resolved;
  const timestamp = new Date().toISOString().replace(/[^0-9A-Za-z]/g, '');
  if (isIgnoredRepositoryOutputRoot(resolved, repositoryRoot)) {
    return fs.mkdtempSync(path.join(resolved, `run-${timestamp}-`));
  }
  return fs.mkdtempSync(`${resolved}-run-${timestamp}-`);
}

function fileInputDependency(name, filePath) {
  if (!filePath) return { name, status: 'NOT_ASSESSED', path: null };
  const resolved = path.resolve(filePath);
  try {
    return {
      name,
      status: fs.statSync(resolved).isFile() ? 'PRESENT_UNVERIFIED' : 'MISSING',
      path: resolved,
    };
  } catch (error) {
    return {
      name,
      status: error.code === 'ENOENT' ? 'MISSING' : 'NOT_ASSESSED',
      path: resolved,
    };
  }
}

function capabilityQuery(replay, options = {}) {
  const resolved = resolveBuildProfile(replay);
  const profile = resolved.profile;
  const document = {
    schema_version: 1,
    command: 'capabilities',
    source_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    game_version: replay.header.version,
    status: profile ? 'PROFILE_RESOLVED' : 'UNSUPPORTED_VERSION',
    profile_release_status: profile?.release_status ?? null,
    inspection_scope: 'CONTAINER_HEADER_TAIL_AND_CHUNK_DESCRIPTORS',
    packet_framing_inspected: false,
    semantic_decode_performed: false,
    runtime_image_used: false,
    runtime_image_requested: options.runtimeImage ? path.resolve(options.runtimeImage) : null,
    input_assessment_scope: replay.header.version === '16.19.820.7193'
      ? 'CONTAINER_TAIL_FIELD_PREFLIGHT' : 'PRESENCE_ONLY',
    runtime_profile_status: profile?.runtime_profile?.status
      ?? (profile?.runtime_profile?.image_sha256 ? 'EXACT_IMAGE_HASH_REGISTERED' : null),
    capabilities: [],
    unlisted_capability_status: 'NOT_REGISTERED_FOR_EXACT_BUILD',
  };
  if (!profile) return document;

  let dependencies;
  let entrypoint;
  let pendingChecks;
  if (profile.game_version === '16.19.820.7193') {
    const statsJson = replay.tail?.metadata?.statsJson;
    const tailStatus = Array.isArray(replay.tail?.stats) ? 'PRESENT_UNVALIDATED'
      : typeof statsJson === 'string' && replay.tail?.stats_parse_error
        ? 'INVALID' : 'MISSING';
    dependencies = [
      { name: 'replay', status: 'PRESENT', path: replay.source_path },
      { name: 'replay_tail_statsJson', status: tailStatus, path: replay.source_path },
    ];
    entrypoint = 'SELECTED_CLI_AND_EXACT_BUILD_API';
    pendingChecks = ['packet framing'];
  } else if (profile.game_version === '16.16.805.0442') {
    dependencies = [
      { name: 'replay', status: 'PRESENT', path: replay.source_path },
      fileInputDependency('exact_runtime_image',
        options.runtimeImage ?? DEFAULT_16_16_RUNTIME_IMAGE),
    ];
    entrypoint = 'EXACT_BUILD_API_ONLY';
    pendingChecks = ['packet framing', 'runtime image SHA-256', 'runtime decoder execution'];
  } else {
    dependencies = [
      { name: 'replay', status: 'PRESENT', path: replay.source_path },
      fileInputDependency('exact_runtime_image', options.decoderImage ?? DEFAULT_DECODER_IMAGE),
      fileInputDependency('spell_dictionary', DEFAULT_SPELL_DICTIONARY),
    ];
    entrypoint = 'LEGACY_CLI_FULL_PIPELINE_AND_API';
    pendingChecks = [
      'packet framing', 'runtime image and spell dictionary SHA-256',
      'legacy full-pipeline execution',
    ];
  }
  if (profile.game_version !== '16.19.820.7193') {
    document.entrypoint_input_precheck = {
      entrypoint,
      scope: 'WHOLE_PIPELINE_FILE_PRESENCE_ONLY',
      inputs: dependencies,
      missing_inputs: dependencies.filter((input) => input.status === 'MISSING')
        .map((input) => input.name),
    };
  }

  const classifications = [
    ['verified_capabilities', 'RELEASED_VERIFIED'],
    ['partial_capabilities', 'RELEASED_PARTIAL'],
    ['candidate_capabilities', 'CANDIDATE'],
    ['unverified_capabilities', 'UNVERIFIED'],
    ['unsupported_capabilities', 'UNSUPPORTED'],
  ];
  for (const [profileKey, status] of classifications) {
    for (const capability of profile[profileKey] ?? []) {
      const applicable = status !== 'UNSUPPORTED' && status !== 'UNVERIFIED';
      const perCapabilityInputsAssessed = applicable
        && profile.game_version === '16.19.820.7193';
      const tailStat = perCapabilityInputsAssessed
        ? capability === 'hero_minions_killed_snapshot'
          ? assessHeroMinionsKilledSnapshotTail(replay)
          : capability === 'hero_experience_snapshot'
            ? assessHeroExperienceSnapshotTail(replay)
            : capability === 'hero_gold_earned_snapshot'
              ? assessHeroGoldEarnedSnapshotTail(replay)
              : capability === 'hero_gold_spent_snapshot'
                ? assessHeroGoldSpentSnapshotTail(replay)
                : capability === 'hero_champion_kills_snapshot'
                  ? assessHeroChampionKillsSnapshotTail(replay)
                  : capability === 'hero_deaths_snapshot'
                    ? assessHeroDeathsSnapshotTail(replay)
                  : candidateTailStatAssessment(replay, capability)
        : null;
      const tailStatInput = tailStat ? [{
        name: `replay_tail_${tailStat.field}`,
        status: !Array.isArray(replay.tail?.stats) ? 'NOT_ASSESSED'
          : tailStat.status === 'PASS' ? 'PRESENT_UNVALIDATED'
          : tailStat.status === 'MISSING_INPUT' ? 'MISSING' : 'INVALID',
        path: replay.source_path,
        error: tailStat.status === 'PASS' ? null : tailStat.error,
      }] : [];
      const inputs = perCapabilityInputsAssessed ? [...dependencies, ...tailStatInput] : [{
        name: 'replay', status: 'PRESENT', path: replay.source_path,
      }];
      const validationPending = applicable ? [...pendingChecks] : [];
      if (applicable && !perCapabilityInputsAssessed) {
        validationPending.push('capability-specific input dependencies');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_death') {
        validationPending.push('matching 16.19 route fingerprint',
          'ten-participant NUM_DEATHS presence and equality');
      }
      if (profile.game_version === '16.19.820.7193'
          && (capability === 'hero_death_timer' || capability === 'hero_respawn')) {
        validationPending.push('ten-participant NUM_DEATHS presence and equality',
          'HN route, timer field, and death-to-respawn invariants',
          'Replay tail gameLength if a timer has no observed reincarnation');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_respawn') {
        validationPending.push('unique observed reincarnation packet per matched death timer');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_level_state') {
        validationPending.push('ten-participant LEVEL presence and value range',
          'HN level route, payload, and observed sequence against final LEVEL');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_minions_killed_snapshot') {
        validationPending.push('ten-participant MINIONS_KILLED tail values',
          'HN keyframe 0x0276 route, field transform, and per-participant sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_experience_snapshot') {
        validationPending.push('ten-participant EXP tail values',
          'HN keyframe 0x0276 route, offset 0x28 candidate, and per-participant sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_gold_earned_snapshot') {
        validationPending.push('ten-participant GOLD_EARNED tail values',
          'HN keyframe 0x0276 route, offset 0x38 candidate, and per-participant sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_gold_spent_snapshot') {
        validationPending.push('ten-participant GOLD_SPENT tail values',
          'HN keyframe 0x0276 route, offset 0x34 candidate, and observed declines');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_champion_kills_snapshot') {
        validationPending.push('ten-participant CHAMPIONS_KILLED tail values',
          'HN keyframe 0x0276 mirrored offsets 0x4c/0x33c and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_deaths_snapshot') {
        validationPending.push('ten-participant NUM_DEATHS tail values',
          'HN keyframe 0x0276 offset 0x50 and observed sequences');
      }
      const gameLength = replay.tail?.metadata?.gameLength;
      const conditionalInputs = ['hero_death_timer', 'hero_respawn'].includes(capability)
        && profile.game_version === '16.19.820.7193'
        ? [{
          name: 'replay_tail_gameLength',
          required_if: 'a death timer has no observed reincarnation',
          status: Number.isSafeInteger(gameLength) && gameLength >= 0
            ? 'PRESENT_UNVALIDATED' : gameLength === undefined ? 'MISSING' : 'INVALID',
          path: replay.source_path,
        }] : [];
      document.capabilities.push({
        capability,
        status,
        published: status.startsWith('RELEASED_'),
        entrypoint: applicable ? entrypoint : null,
        required_inputs: inputs,
        runtime_image_requirement: applicable
          ? perCapabilityInputsAssessed ? 'NOT_REQUIRED' : 'NOT_ASSESSED_PER_CAPABILITY'
          : null,
        missing_inputs: perCapabilityInputsAssessed
          ? inputs.filter((input) => input.status === 'MISSING').map((input) => input.name)
          : null,
        invalid_inputs: perCapabilityInputsAssessed
          ? inputs.filter((input) => input.status === 'INVALID').map((input) => input.name)
          : null,
        conditional_inputs: conditionalInputs,
        input_assessment_complete: perCapabilityInputsAssessed
          && !inputs.some((input) => input.status === 'NOT_ASSESSED'),
        validation_pending: validationPending,
        output: profile.game_version === '16.19.820.7193'
          ? ({
            hero_death: 'hero_death_candidates',
            hero_death_timer: 'hero_death_timer_candidates',
            hero_respawn: 'hero_respawn_candidates',
            hero_level_state: 'hero_level_state_candidates',
            hero_minions_killed_snapshot: 'hero_minions_killed_snapshot_candidates',
            hero_experience_snapshot: 'hero_experience_snapshot_candidates',
            hero_gold_earned_snapshot: 'hero_gold_earned_snapshot_candidates',
            hero_gold_spent_snapshot: 'hero_gold_spent_snapshot_candidates',
            hero_champion_kills_snapshot: 'hero_champion_kills_snapshot_candidates',
            hero_deaths_snapshot: 'hero_deaths_snapshot_candidates',
          })[capability] ?? null
          : null,
      });
    }
  }
  return document;
}

function runCapabilitiesCommand(parsed) {
  if (parsed.positionals.length !== 1) {
    throw new Error('capabilities requires exactly one .rofl file');
  }
  const filePath = path.resolve(parsed.positionals[0]);
  if (path.extname(filePath).toLowerCase() !== '.rofl') {
    throw new Error(`capabilities requires a .rofl file: ${filePath}`);
  }
  const replay = parseReplayFile(filePath);
  const result = capabilityQuery(replay, parsed.options);
  if (parsed.options.format === 'json') {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(`Replay: ${result.source_path}\nBuild: ${result.game_version}\n`);
    process.stdout.write(`Profile: ${result.profile_release_status ?? result.status}\n`);
    process.stdout.write('Scope: container and registry only; packet framing and semantic decode not run.\n');
    for (const row of result.capabilities) {
      const missing = row.missing_inputs === null ? 'not assessed per capability'
        : row.missing_inputs.length ? row.missing_inputs.join(', ') : 'none detected';
      const invalid = row.invalid_inputs?.length
        ? `; invalid inputs: ${row.invalid_inputs.join(', ')}` : '';
      process.stdout.write(`${row.capability}: ${row.status}; missing inputs: ${missing}`
        + invalid + `${row.input_assessment_complete ? '' : ' (some inputs not assessed)'}\n`);
      if (row.validation_pending.length > 0) {
        process.stdout.write(`  Pending: ${row.validation_pending.join(', ')}\n`);
      }
      for (const input of row.conditional_inputs.filter((item) =>
        item.status === 'MISSING' || item.status === 'INVALID')) {
        process.stdout.write(`  Conditional input: ${input.name} ${input.status}; ${input.required_if}.\n`);
      }
    }
    if (result.entrypoint_input_precheck) {
      const missing = result.entrypoint_input_precheck.missing_inputs;
      process.stdout.write(`Whole-pipeline file precheck: ${missing.length
        ? `missing ${missing.join(', ')}` : 'no missing files detected; hashes not checked'}.\n`);
    }
    if (result.profile_release_status === 'EXPERIMENTAL_CANDIDATE') {
      process.stdout.write('Other semantic capabilities: not registered for this exact build.\n');
    }
    if (result.status === 'UNSUPPORTED_VERSION') {
      process.stdout.write(`No exact build profile is registered for ${result.game_version}.\n`);
    }
  }
  return result.status === 'UNSUPPORTED_VERSION' ? 2 : 0;
}

async function main(argv = process.argv.slice(2)) {
  const parsed = parseArgs(argv);
  if (parsed.options.help || parsed.command === 'help') {
    process.stdout.write(usage());
    return 0;
  }
  if (!COMMANDS.has(parsed.command)) throw new Error(`Unknown command: ${parsed.command}`);
  if (parsed.command === 'ward-events') return runWardEventsCommand(parsed);
  if (parsed.command === 'capabilities') return runCapabilitiesCommand(parsed);
  const inputs = parsed.positionals.length > 0 ? parsed.positionals : ['replay'];
  const files = discoverReplayFiles(inputs);
  if (files.length === 0) throw new Error('No .rofl files found in the supplied input.');
  const beforeHashes = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const parseOptions = { ...parsed.options, semantic: parsed.command !== 'inspect' };
  const results = files.map((filePath) => parseOne(filePath, parseOptions));
  const testSummary = parsed.command === 'validate' ? runTestSuite() : null;
  const afterHashes = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const validationDetailsDir = parsed.command === 'validate' && parsed.options.detailsDir
    ? path.resolve(parsed.options.detailsDir)
    : null;
  const outDir = reserveOutputDirectory(parsed.options.outDir);
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
      process.stdout.write(`${result.analysis.source_path}\t${result.analysis.replay_version}\t${result.analysis.packet_count} blocks\t${result.analysis.block_errors.length} errors\t${result.analysis.decoder.status}\n`);
    } else {
      process.stderr.write(`${result.source_path}\t${result.error.code}\t${result.error.message}\n`);
    }
  }
  process.stdout.write(`Status: ${summary.status}\nOutput: ${outDir}\n`);
  const includes1619 = results.some((result) => result.ok && result.analysis.patch === '16.19');
  const semanticRunFailed = includes1619 && parsed.command !== 'inspect'
    && results.some((result) => result.ok && (
      result.analysis.block_errors.length > 0
      || !['PASS', 'CANDIDATE', 'RESEARCH_READY_COMPLETE'].includes(result.analysis.decoder.status)
    ));
  const framingRunFailed = results.some((result) => result.ok
    && result.analysis.block_errors.length > 0);
  return results.some((result) => !result.ok) || semanticRunFailed || framingRunFailed
    || (testSummary && testSummary.exit_code !== 0) ? 2 : 0;
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
  reserveOutputDirectory,
  capabilityQuery,
  runCapabilitiesCommand,
  main,
};
