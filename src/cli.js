#!/usr/bin/env node

const childProcess = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { finished } = require('node:stream/promises');
const { Worker } = require('node:worker_threads');
const { rawAnchorChainStatus, renderAcceptanceReport } = require('./cli_report');
const { resolveBuildProfile } = require('./build_registry');
const {
  analyzeReplayWithCandidateRoutes,
  candidateTailStatAssessment,
} = require('./decoders/rofl_16_19_820_7193');
const { assessHeroDeathTail821 } = require('./decoders/rofl_16_19_821_7343');
const { assessHeroRespawnDeadTimeTail821 } =
  require('./decoders/rofl_16_19_821_respawn_candidate');
const {
  assessHeroStatsTail821,
  assessHeroDeathsSnapshotTail821,
  assessHeroChampionKillsSnapshotTail821,
  assessHeroAssistsSnapshotTail821,
  assessHeroMissionsMinionsKilledSnapshotTail821,
} =
  require('./decoders/rofl_16_19_821_hero_stats_candidate');
const { assessHeroLevelTail821 } =
  require('./decoders/rofl_16_19_821_level_candidate');
const { assessHeroWardStatsTail821, assessHeroMissionsCannonMinionsTail821 } =
  require('./decoders/rofl_16_19_821_aux_counts_candidate');
const { assessHeroFloatSnapshotTail821, assessHeroJungleMinionsTail821 } =
  require('./decoders/rofl_16_19_821_float_stats_candidate');
const { assessHeroKillStatsTail821 } =
  require('./decoders/rofl_16_19_821_kill_stats_candidate');
const { PROFILES: DAMAGE_PROFILES_821 } =
  require('./decoders/rofl_16_19_821_damage_float_candidate');
const { PROFILES: TIME_PROFILES_821 } =
  require('./decoders/rofl_16_19_821_time_stats_candidate');
const { PROFILES: HEAL_PROFILES_821 } =
  require('./decoders/rofl_16_19_821_heal_stats_candidate');
const { PROFILES: EPIC_CC_PROFILES_821 } =
  require('./decoders/rofl_16_19_821_epic_cc_candidate');
const EXTRA_STATS_PROFILES_821 = Object.freeze({
  ...TIME_PROFILES_821, ...HEAL_PROFILES_821, ...EPIC_CC_PROFILES_821,
});
const { analyzeReplayWith821Routes } = require('./decoders/rofl_16_19_821_scan');
const {
  assessHeroMinionsKilledSnapshotTail,
  assessHeroJungleMinionsKilledSnapshotTail,
  assessHeroExperienceSnapshotTail,
  assessHeroGoldEarnedSnapshotTail,
  assessHeroGoldSpentSnapshotTail,
  assessHeroChampionKillsSnapshotTail,
  assessHeroDeathsSnapshotTail,
  assessHeroAssistsSnapshotTail,
  assessHeroKillStatsSnapshotTail,
  assessHeroWardStatsSnapshotTail,
  assessHeroDamageTotalsSnapshotTail,
  assessHeroDamageTakenFromChampionsSnapshotTail,
  assessHeroDamageSelfMitigatedSnapshotTail,
  assessHeroLongestLivingTimeSnapshotTail,
  assessHeroTotalTimeSpentDeadSnapshotTail,
  assessHeroTotalHealSnapshotTail,
  assessHeroTotalUnitsHealedSnapshotTail,
  assessHeroVisionScoreSnapshotTail,
  assessHeroEpicMonsterDamageSnapshotTail,
  assessHeroCrowdControlTimeSnapshotTail,
  assessHeroStructureObjectiveDamageSnapshotTail,
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  analyzeReplayWithHeroStats,
} = require('./decoders/rofl_16_19_hero_stats_candidate');

const {
  TOOL_VERSION,
  analyzeReplay,
} = require('./analysis');
const {
  HEADER_PREFIX_SIZE,
  RoflError,
  parseHeader,
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
const { EventQueryError, prepareEventQuery, prepareBatchEventQuery,
  streamEventQuery, streamBatchEventQuery, listSavedEvents } = require('./event_query');

const REPOSITORY_ROOT = path.resolve(__dirname, '..');
const BATCH_JOBS_BUILD = '16.19.821.7343';
const TEST_COMMAND = 'node --test test/*.test.js';
const COMMANDS = new Set(['inspect', 'decode', 'analyze', 'batch', 'validate', 'ward-events', 'capabilities', 'query-events']);
const INVENTORY_GAME_COMPARISON_LABELS_821 = Object.freeze([
  'SAME_AS_BOTH_ENDPOINTS', 'DIFFERS_FROM_EQUAL_ENDPOINTS',
  'SAME_AS_PREVIOUS_ENDPOINT', 'SAME_AS_NEXT_ENDPOINT',
  'DIFFERS_FROM_BOTH_ENDPOINTS',
]);

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
  node src/cli.js query-events <replay-or-batch-artifact-directory> --list-events
  node src/cli.js query-events <replay-or-batch-artifact-directory> --event <exact-event-key> [filters]

Runtime: Node >=22.15.0 with native Zstd.
Legacy semantic CLI scope: exact 16.15.801.3452. The separate 16.16 public API
is not dispatched by this CLI; see docs/PUBLIC_DEVELOPMENT.md.
16.19 decode and batch use the exact-build semantic API when --events is selected.
For 821, hero_death with champion_die_event_packet emits a candidate packet pair;
adding champion_kill_event_packet, champion_multiple_kill_event_packet, or
on_shutdown_event_packet emits the corresponding candidate three-route packet group.
hero_assist,hero_death_timer,hero_respawn together emit candidate death episodes.
hero_ward_stats_snapshot,hero_inventory_broadcast_packet together emit same-keyframe candidate observations.
hero_inventory_broadcast_packet also emits adjacent keyframe slot-difference candidates;
these are observed packet differences, not purchases, sales, swaps, or persistent inventory state.
champion_double_kill_event_packet emits a separate packet-local named child marker.
champion_triple_quadra_event_packet emits exact-image 0x000c/0x000d packet markers.
resurrect_event_packet emits a separate packet-local OnResurrect candidate.
revive_ally_event_packet emits a separate packet-local OnReviveAlly candidate.
first_blood_assist_event_packet emits a packet-local OnFirstBloodAssist marker candidate.
objective_steal_event_packet emits exact-image OnKillDragonSteal/OnKillWormSteal packet markers.
turret_die_event_packet emits a separate packet-local OnTurretDie candidate.
dampener_die_event_packet emits a separate packet-local OnDampenerDie candidate.
turret_first_blood_event_packet emits a separate packet-local OnTurretFirstBlood candidate.
Selecting both also emits a candidate OnTurretDie/OnTurretFirstBlood packet-order pair.
hq_kill_event_packet emits a separate packet-local OnHQKill candidate.
turret_plate_event_packet emits a separate packet-local OnTurretPlateDestroyed candidate.
  objective_bounty_claimed_packet emits a separate packet-local OnObjectiveBountyClaimed candidate.
  Selecting it with turret_plate_event_packet and turret_die_event_packet emits
  a candidate same-chunk packet triple when anonymous native words agree.
npc_buff_update_num_counter_packet emits an exact-821 packet-local opaque candidate.
npc_buff_update_count_packet emits an exact-821 packet-local opaque candidate.
npc_buff_replace_packet emits an exact-821 packet-local opaque candidate.
--cast-packet-v5 opts CastSpellAns into the exact-821 nested anonymous u32
candidate; the default CastSpellAns packet profile remains v4.
--cast-packet-v6 also records a second exact-821 nested anonymous u32;
--cast-packet-v7 also records an exact-821 nested anonymous f32;
--cast-packet-v8 also records a packet-local anonymous callback lookup key;
--cast-packet-v9 adds an ordered native-output digest for those packet fields;
all newer CastSpellAns packet profiles require explicit selection.
set_spell_timer_from_buff_packet emits an exact-821 packet-local opaque candidate.
--spell-timer-packet-v2 adds an exact-821 native callback receiver-slot
candidate while preserving the default packet profile.
set_spell_level_packet emits an exact-821 packet-local opaque candidate.
--spell-level-packet-v2 adds exact-821 native callback receiver selection
and clamped scalar candidates while preserving the default packet profile.
increment_minion_kills_packet emits an exact-821 packet-local lookup-key candidate.
Selecting it with hero_minions_killed_snapshot also emits packet-to-keyframe bracket candidates;
the endpoint difference does not establish a per-packet CS effect or last hit.
Selecting hero_level_state with hero_experience_snapshot emits level-packet/EXP-keyframe
time brackets; their sampled endpoint differences do not establish XP gain or thresholds.
face_direction_packet emits exact-821 packet-local direction-vector candidates;
its raw param does not identify an actor, and the packet does not establish position or path.
circular_movement_restriction_packet emits exact-821 packet-local anonymous fields;
it does not establish an actor, world position, hero path, or effective restriction.
notify_contextual_situation_packet emits an exact-821 packet-local UTF-8 string candidate;
it does not establish an actor, Recall action, or gameplay effect.
item_group_data_broadcast_packet emits an exact-821 keyframe callback lookup key;
it does not establish an item, group identity, owner, slot, or inventory state.
--item-group-packet-v2 adds the protected +0x1c byte and a conditional native
callback byte witnessed with a synthetic lookup hit; actual receiver state is unknown.
cooldown_broadcast_packet emits an exact-821 game/keyframe callback lookup key;
it does not establish cooldown state, slot identity, actor, target, or effect.
item_charges_packet emits exact-821 packet-local callback arguments before receiver state;
it does not establish item identity, charge state, slot, owner, or effect.
target_hero_packet emits an exact-821 game packet callback u32 before a
receiver-dependent call; resolved target object, actor, state and effect are unknown.
force_create_missile_packet emits an exact-821 game packet-local callback
comparison u32 witnessed before a synthetic receiver comparison; live receiver,
missile identity, owner, target, creation, effect and causality are unknown.
change_missile_target_packet emits an exact-821 game packet-local callback
comparison u32 before consulting live receiver state; receiver match, missile
identity, owner, resolved target, target change and effect are unknown.
set_dimension_missile_packet emits an exact-821 game packet-local callback u8
before the receiver method; receiver state, missile identity, owner, target,
dimension change, effect and causality are unknown.
unit_apply_damage_packet requires the exact-821 runtime image and Python+Unicorn
to witness full native consumption of every selected packet before emitting
packet-local selectors or a bounded anonymous float candidate; these do not
establish damage amount or attribution.
--damage-packet-v6 opts a decode/batch run into the exact-821 anonymous +0x1c
u32 callback candidate and preserves the default v5 packet profile otherwise.
show_health_bar_packet requires the exact-821 runtime image and Python+Unicorn
to witness full native consumption of every selected packet before emitting
packet-local callback flag candidates; these do not establish health or display effects.
unit_apply_damage_roster_key_pair additionally requires complete exact-821
HeroStats keyframes; full raw-key equality gives a candidate roster label,
without actor, source, target, or effective damage attribution.
unit_apply_damage_lookup_roster_key_pair matches the native +0x24 lookup key
against that complete roster, retaining +0x100 raw-key aliases as candidates;
lookup success, actor, source, target, and effect remain unknown.
unit_apply_damage_lookup2c_roster_key_pair matches the independent native +0x2c
lookup key against that complete roster by full equality; lookup success, actor,
source, target, and effect remain unknown.
hero_death_damage_lookup_key_cooccurrence preserves all same-chunk, same-ms
native 0x005f packets whose +0x24 key equals the death candidate victim roster
key, and compares +0x2c to the decoded die-source key. It does not select a
fatal packet or establish damage actor, source, target, or effect.
face_direction_keyframe_roster_pair pairs canonical keyframe FaceDirection packets
with same-keyframe HeroStats roster candidates; the roster label does not identify the packet actor.
Inspect reads the container and packet framing without a runtime image.
Capabilities reads the container/build registry and checks selected dependencies
without packet framing or semantic decode.

Options:
  --out-dir <path>              Independent output directory (default: artifacts)
  --timeline-limit <number>     First N packet timeline rows (default: 250)
  --sample-stride <number>      Deprecated compatibility option; prefix samples are unchanged
  --include-private-metadata     Include Riot ID/PUUID fields in roster output
  --strict                       Stop at the first framing error
  --decoder-image <path>        Exact 16.15 runtime image (external input; not bundled)
  --runtime-image <path>        Exact-build runtime image for selected native packet candidates
  --events <name[,name...]>     Select 16.19 semantic capabilities to decode
  --cast-packet-v5              Opt into exact 821 CastSpellAns nested anonymous u32 candidates (decode/batch)
  --cast-packet-v6              Opt into exact 821 CastSpellAns two nested anonymous u32 candidates (decode/batch)
  --cast-packet-v7              Opt into exact 821 CastSpellAns nested anonymous f32 candidate (decode/batch)
  --cast-packet-v8              Opt into exact 821 CastSpellAns anonymous callback lookup key (decode/batch)
  --cast-packet-v9              Opt into exact 821 CastSpellAns ordered native-output witness (decode/batch)
  --spell-timer-packet-v2       Opt into exact 821 SetSpellTimerFromBuff native receiver callback candidates (decode/batch)
  --spell-level-packet-v2       Opt into exact 821 SetSpellLevel callback receiver/scalar candidates (decode/batch)
  --item-group-packet-v2        Opt into exact 821 item-group conditional callback byte candidate (decode/batch)
  --damage-packet-v6            Opt into exact 821 UnitApplyDamage +0x1c u32 packet/association candidates (decode/batch)
  --event-jsonl-only            Store 16.19 event rows only in JSONL (decode/batch with --events)
  --jobs <1|2>                  Exact-821 batch with --events and --event-jsonl-only (default: 1)
  --event <key>                 Exact 16.19 candidate JSONL key (query-events)
  --list-events                 List saved 16.19 candidate keys and declared counts (query-events)
  --verify-source               Check supported exact-821 packet rows against the original ROFL
  --source-replay <path>        Original ROFL override for one Replay with --verify-source
  --json                        Emit only machine-readable JSON (capabilities)
  --python <command>            Python command with Unicorn installed (default: python)
  --details-dir <path>          Validation-only directory for same-game Details matching
  --ward-spawns <jsonl>         Verified current-build WardSpawn decoder rows
  --ward-lifecycles <jsonl>     Derived current-build Ward corpse lifecycle rows
  --hero-positions <jsonl>      Verified one-second PathPacket position rows
  Query event filters (query-events, 16.19 default or --event-jsonl-only artifacts):
  --from-ms/--to-ms <number>    Inclusive Replay millisecond bounds
  --participant <1..10>        Candidate subject participant; unknown rows do not match
  --killer-participant <1..10>  Candidate killer in exact-821 death, assist or episode rows
  --assisting-participant <1..10>  Member of exact-821 assist or episode candidate list
  --raw-param <uint32|0xhex>   Exact recorded raw packet parameter; no identity inference
  --contextual-situation <text>  Exact UTF-8 contextual situation string on an 821 packet candidate
  --item-id <uint32|0xhex>     Exact 821 inventory record item ID, including saved associations
  --previous-item-id <uint32|0xhex>  Previous endpoint item ID in an exact-821 keyframe interval difference
  --slot <0..9>                Exact observed 821 inventory record slot, including saved associations
  Interval differences: --item-id is the CURRENT item ID on a changed slot (zero valid).
                        Previous/current item IDs and --slot must match the SAME changed slot.
  --opaque-u32 <uint32|0xhex>  Exact decoded anonymous 821 packet/group u32 field
  --item-group-callback-u8 <0..255|0xhex>  Exact 821 item-group V2 conditional callback byte candidate
  --item-charges-selector-u8 <0..255|0xhex>  Exact 821 0x0437 callback selector argument
  --item-charges-value-u16 <0..65535|0xhex>  Exact 821 0x0437 callback value argument
  --opaque-pair <u32:u8>      Exact anonymous 821 Buff Add/Remove/Update pair
  --opaque-i32 <int32>         Exact decoded 821 CastSpellAns opaque_i32_0x14c (decimal)
  --cast-nested-bits <0..255|0xhex>  Exact decoded 821 CastSpellAns nested callback bits
  --cast-nested-u32 <uint32|0xhex>   Exact decoded 821 CastSpellAns V5 nested anonymous u32
  --cast-nested-u32-0x4c <uint32|0xhex>  Exact decoded 821 CastSpellAns V6 second nested anonymous u32
  --cast-nested-f32-0xa0 <finite decimal>  Exact decoded 821 CastSpellAns V7 nested anonymous f32 (rounded to f32)
  --cast-nested-u32-0x28 <uint32|0xhex>  Exact decoded 821 CastSpellAns V8 packet-local lookup key
  --spell-timer-receiver-slot <0..5|63|0xhex>  Exact 821 SetSpellTimerFromBuff V2 native receiver table slot candidate
  --spell-level-receiver-index <0..63|0xhex>  Exact 821 SetSpellLevel V2 native receiver table index candidate
  --spell-level-clamped-scalar <0..6|0xhex>  Exact 821 SetSpellLevel V2 native clamped scalar candidate
  --damage-callback-f32-available  Exact 821 UnitApplyDamage rows with a native-matched anonymous +0x20 f32
                                Checks saved witness metadata and raw bytes; does not rerun the native parser.
  --damage-callback-u32-0x10 <uint32|0xhex>  Exact 821 v4-v6 anonymous native +0x10 u32 (zero is valid)
  --damage-callback-f32-0x18-raw  Exact 821 v5/v6 anonymous native +0x18 f32 RAW_READER rows
  --damage-callback-u32-0x1c <uint32|0xhex>  Exact 821 v6 anonymous native +0x1c u32 (zero is valid)
  --damage-lookup-key24 <uint32|0xhex>  Exact 821 UnitApplyDamage v3-v6 native +0x24 lookup key
  --damage-lookup-key2c <uint32|0xhex>  Exact 821 UnitApplyDamage v3-v6 native +0x2c lookup key
                                These anonymous object keys do not establish actor or damage roles.
  --die-source-key2c-match <has|none|unavailable>  Exact 821 death/damage
                                cooccurrence status for the candidate source key
  --show-health-zero-flag <0|1>  Exact 821 ShowHealthBar callback zero-flag candidate
                                Checks saved witness metadata and raw bytes; does not infer display effect.
  --packet-record-count <0|1>  Exact 821 circular movement restriction packet record count
  --level-after <1..20>        Exact-821 level packet within adjacent EXP keyframes
  --child-event-id <uint32|0xhex>  Exact 821 named child ID (including objective steal markers)
  --latest-per-participant    Last matching observed row per participant and Replay
                                For interval differences: last matching observed difference.
  --endpoint-reversed-pair    Exact-821 interval rows with two unique nonzero item keys
                               observed in reversed slots at adjacent keyframe endpoints
  --comparison-to-endpoints <label>  Exact-821 game Broadcast bracket record label:
                                SAME_AS_BOTH_ENDPOINTS, DIFFERS_FROM_EQUAL_ENDPOINTS,
                                SAME_AS_PREVIOUS_ENDPOINT, SAME_AS_NEXT_ENDPOINT,
                                DIFFERS_FROM_BOTH_ENDPOINTS
  --limit <number>              Maximum rows emitted; all rows are still checked and counted
  --output <path|->            Write unmodified JSONL rows (default: stdout)
                                Query summary is JSON on stderr when output is stdout
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
    event: null,
    listEvents: false,
    verifySource: false,
    sourceReplay: null,
    eventJsonlOnly: false,
    jobs: null,
    participant: null,
    killerParticipant: null,
    assistingParticipant: null,
    rawParam: null,
    contextualSituation: null,
    itemId: null,
    previousItemId: null,
    slot: null,
    opaqueU32: null,
    itemGroupCallbackU8: null,
    itemChargesSelectorU8: null,
    itemChargesValueU16: null,
    opaquePair: null,
    opaqueI32: null,
    castNestedBits: null,
    castNestedU32: null,
    castNestedU32At4c: null,
    castNestedF32AtA0: null,
    castNestedU32At28: null,
    spellTimerReceiverSlot: null,
    spellLevelReceiverIndex: null,
    spellLevelClampedScalar: null,
    damageCallbackF32Available: false,
    damageCallbackU32At10: null,
    damageCallbackU32At1c: null,
    damageCallbackF32At18Raw: false,
    castPacketV5: false,
    castPacketV6: false,
    castPacketV7: false,
    castPacketV8: false,
    castPacketV9: false,
    spellTimerPacketV2: false,
    spellLevelPacketV2: false,
    itemGroupPacketV2: false,
    damagePacketV6: false,
    damageLookupKey24: null,
    damageLookupKey2c: null,
    dieSourceKey2cMatch: null,
    showHealthZeroFlag: null,
    packetRecordCount: null,
    levelAfter: null,
    childEventId: null,
    latestPerParticipant: false,
    endpointReversedPair: false,
    comparisonToEndpoints: null,
    limit: null,
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
    if (token === '--event-jsonl-only') {
      options.eventJsonlOnly = true;
      continue;
    }
    if (token === '--damage-packet-v6') {
      options.damagePacketV6 = true;
      continue;
    }
    if (token === '--cast-packet-v5') {
      options.castPacketV5 = true;
      continue;
    }
    if (token === '--cast-packet-v6') {
      options.castPacketV6 = true;
      continue;
    }
    if (token === '--cast-packet-v7') {
      options.castPacketV7 = true;
      continue;
    }
    if (token === '--cast-packet-v8') {
      options.castPacketV8 = true;
      continue;
    }
    if (token === '--cast-packet-v9') {
      options.castPacketV9 = true;
      continue;
    }
    if (token === '--spell-level-packet-v2') {
      options.spellLevelPacketV2 = true;
      continue;
    }
    if (token === '--item-group-packet-v2') {
      options.itemGroupPacketV2 = true;
      continue;
    }
    if (token === '--spell-timer-packet-v2') {
      options.spellTimerPacketV2 = true;
      continue;
    }
    if (command === 'query-events' && token === '--latest-per-participant') {
      options.latestPerParticipant = true;
      continue;
    }
    if (command === 'query-events' && token === '--list-events') {
      options.listEvents = true;
      continue;
    }
    if (command === 'query-events' && token === '--verify-source') {
      options.verifySource = true;
      continue;
    }
    if (command === 'query-events' && token === '--endpoint-reversed-pair') {
      options.endpointReversedPair = true;
      continue;
    }
    if (command === 'query-events' && token === '--damage-callback-f32-available') {
      options.damageCallbackF32Available = true;
      continue;
    }
    if (command === 'query-events' && token === '--damage-callback-f32-0x18-raw') {
      options.damageCallbackF32At18Raw = true;
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
      else if (key === 'jobs') {
        if (!/^[12]$/.test(value)) throw new Error('--jobs must be 1 or 2');
        options.jobs = Number(value);
      }
      else if (command === 'query-events' && key === 'event') options.event = value;
      else if (command === 'query-events' && key === 'source-replay') options.sourceReplay = value;
      else if (key === 'python') options.python = value;
      else if (key === 'ward-spawns') options.wardSpawns = value;
      else if (key === 'ward-lifecycles') options.wardLifecycles = value;
      else if (key === 'hero-positions') options.heroPositions = value;
      else if (command === 'ward-events' && key === 'output') options.output = value;
      else if (command === 'query-events' && key === 'output') options.output = value;
      else if (command === 'query-events' && key === 'from-ms') options.fromMs = queryInteger(value, key, true);
      else if (command === 'query-events' && key === 'to-ms') options.toMs = queryInteger(value, key, true);
      else if (command === 'query-events' && key === 'participant') options.participant = queryInteger(value, key);
      else if (command === 'query-events' && key === 'killer-participant') options.killerParticipant = queryInteger(value, key);
      else if (command === 'query-events' && key === 'assisting-participant') options.assistingParticipant = queryInteger(value, key);
      else if (command === 'query-events' && key === 'raw-param') options.rawParam = queryRawParam(value);
      else if (command === 'query-events' && key === 'contextual-situation') options.contextualSituation = value;
      else if (command === 'query-events' && key === 'item-id') options.itemId = queryUint32(value, key);
      else if (command === 'query-events' && key === 'previous-item-id') options.previousItemId = queryUint32(value, key);
      else if (command === 'query-events' && key === 'slot') options.slot = queryInteger(value, key, true);
      else if (command === 'query-events' && key === 'comparison-to-endpoints') options.comparisonToEndpoints = value;
      else if (command === 'query-events' && key === 'opaque-u32') options.opaqueU32 = queryUint32(value, key);
      else if (command === 'query-events' && key === 'item-group-callback-u8') options.itemGroupCallbackU8 = queryByte(value, key);
      else if (command === 'query-events' && key === 'item-charges-selector-u8') options.itemChargesSelectorU8 = queryByte(value, key);
      else if (command === 'query-events' && key === 'item-charges-value-u16') options.itemChargesValueU16 = queryWord(value, key);
      else if (command === 'query-events' && key === 'opaque-pair') options.opaquePair = queryOpaquePair(value);
      else if (command === 'query-events' && key === 'opaque-i32') options.opaqueI32 = queryInt32(value, key);
      else if (command === 'query-events' && key === 'cast-nested-bits') options.castNestedBits = queryByte(value, key);
      else if (command === 'query-events' && key === 'cast-nested-u32') options.castNestedU32 = queryUint32(value, key);
      else if (command === 'query-events' && key === 'cast-nested-u32-0x4c') options.castNestedU32At4c = queryUint32(value, key);
      else if (command === 'query-events' && key === 'cast-nested-f32-0xa0') options.castNestedF32AtA0 = queryFiniteFloat(value, key);
      else if (command === 'query-events' && key === 'cast-nested-u32-0x28') options.castNestedU32At28 = queryUint32(value, key);
      else if (command === 'query-events' && key === 'spell-timer-receiver-slot') options.spellTimerReceiverSlot = queryUint32(value, key);
      else if (command === 'query-events' && key === 'spell-level-receiver-index') options.spellLevelReceiverIndex = queryUint32(value, key);
      else if (command === 'query-events' && key === 'spell-level-clamped-scalar') options.spellLevelClampedScalar = queryUint32(value, key);
      else if (command === 'query-events' && key === 'damage-callback-u32-0x10') options.damageCallbackU32At10 = queryUint32(value, key);
      else if (command === 'query-events' && key === 'damage-callback-u32-0x1c') options.damageCallbackU32At1c = queryUint32(value, key);
      else if (command === 'query-events' && key === 'damage-lookup-key24') options.damageLookupKey24 = queryUint32(value, key);
      else if (command === 'query-events' && key === 'damage-lookup-key2c') options.damageLookupKey2c = queryUint32(value, key);
      else if (command === 'query-events' && key === 'die-source-key2c-match') options.dieSourceKey2cMatch = value;
      else if (command === 'query-events' && key === 'show-health-zero-flag') options.showHealthZeroFlag = queryInteger(value, key, true);
      else if (command === 'query-events' && key === 'packet-record-count') options.packetRecordCount = queryInteger(value, key, true);
      else if (command === 'query-events' && key === 'level-after') options.levelAfter = queryInteger(value, key);
      else if (command === 'query-events' && key === 'child-event-id') options.childEventId = queryUint32(value, key);
      else if (command === 'query-events' && key === 'limit') options.limit = queryInteger(value, key);
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
  if (options.eventJsonlOnly && (!['decode', 'batch'].includes(command) || !options.events)) {
    throw new Error('--event-jsonl-only requires decode or batch with --events');
  }
  if (options.jobs !== null && (command !== 'batch' || !options.events
      || !options.eventJsonlOnly)) {
    throw new Error('--jobs requires batch with --events and --event-jsonl-only');
  }
  if (options.damagePacketV6 && (!['decode', 'batch'].includes(command)
      || !options.events?.some((capability) => [
        'unit_apply_damage_packet', 'unit_apply_damage_roster_key_pair',
        'unit_apply_damage_lookup_roster_key_pair',
        'unit_apply_damage_lookup2c_roster_key_pair',
        'hero_death_damage_lookup_key_cooccurrence',
      ].includes(capability)))) {
    throw new Error('--damage-packet-v6 requires decode or batch with an exact-821 UnitApplyDamage packet or association capability in --events');
  }
  if (options.castPacketV5 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('cast_spell_ans_packet'))) {
    throw new Error('--cast-packet-v5 requires decode or batch with exact-821 cast_spell_ans_packet in --events');
  }
  if (options.castPacketV6 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('cast_spell_ans_packet'))) {
    throw new Error('--cast-packet-v6 requires decode or batch with exact-821 cast_spell_ans_packet in --events');
  }
  if (options.castPacketV7 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('cast_spell_ans_packet'))) {
    throw new Error('--cast-packet-v7 requires decode or batch with exact-821 cast_spell_ans_packet in --events');
  }
  if (options.castPacketV8 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('cast_spell_ans_packet'))) {
    throw new Error('--cast-packet-v8 requires decode or batch with exact-821 cast_spell_ans_packet in --events');
  }
  if (options.castPacketV9 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('cast_spell_ans_packet'))) {
    throw new Error('--cast-packet-v9 requires decode or batch with exact-821 cast_spell_ans_packet in --events');
  }
  if ([options.castPacketV5, options.castPacketV6, options.castPacketV7,
    options.castPacketV8, options.castPacketV9]
    .filter(Boolean).length > 1) {
    throw new Error('--cast-packet-v5 through --cast-packet-v9 are mutually exclusive');
  }
  if (options.spellLevelPacketV2 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('set_spell_level_packet'))) {
    throw new Error('--spell-level-packet-v2 requires decode or batch with exact-821 set_spell_level_packet in --events');
  }
  if (options.itemGroupPacketV2 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('item_group_data_broadcast_packet'))) {
    throw new Error('--item-group-packet-v2 requires decode or batch with exact-821 item_group_data_broadcast_packet in --events');
  }
  if (options.spellTimerPacketV2 && (!['decode', 'batch'].includes(command)
      || !options.events?.includes('set_spell_timer_from_buff_packet'))) {
    throw new Error('--spell-timer-packet-v2 requires decode or batch with exact-821 set_spell_timer_from_buff_packet in --events');
  }
  if (command === 'ward-events') {
    positionals.push(...options.inputs);
  }
  if (command === 'query-events') {
    if (positionals.length !== 1 || (!options.event && !options.listEvents)) {
      throw new Error('query-events requires one Replay or batch artifact directory and --event or --list-events');
    }
    if (options.listEvents) {
      const filterKeys = ['fromMs', 'toMs', 'participant', 'killerParticipant',
        'assistingParticipant', 'rawParam', 'contextualSituation', 'itemId', 'previousItemId', 'slot',
        'opaqueU32', 'itemGroupCallbackU8', 'itemChargesSelectorU8', 'itemChargesValueU16',
        'opaquePair', 'opaqueI32', 'castNestedBits', 'castNestedU32',
        'castNestedU32At4c', 'castNestedF32AtA0', 'castNestedU32At28',
        'spellTimerReceiverSlot',
        'spellLevelReceiverIndex',
        'spellLevelClampedScalar', 'damageCallbackF32Available',
        'damageCallbackU32At10', 'damageCallbackU32At1c',
        'damageCallbackF32At18Raw', 'damageLookupKey24', 'damageLookupKey2c',
        'dieSourceKey2cMatch', 'showHealthZeroFlag', 'packetRecordCount',
        'levelAfter', 'childEventId', 'latestPerParticipant',
        'endpointReversedPair', 'comparisonToEndpoints', 'limit'];
      if (options.event || options.output || options.verifySource
          || options.sourceReplay || filterKeys.some((key) =>
        options[key] !== null && options[key] !== false)) {
        throw new Error('--list-events cannot be combined with --event, --output, source verification or query filters');
      }
    }
    if (options.participant !== null && options.participant > 10) {
      throw new Error('--participant must be in 1..10');
    }
    if (options.killerParticipant !== null
        && (options.killerParticipant > 10
          || !['hero_death_candidates', 'hero_assist_candidates',
            'hero_death_episode_candidates'].includes(options.event))) {
      throw new Error('--killer-participant requires hero_death_candidates, hero_assist_candidates or hero_death_episode_candidates and 1..10');
    }
    if (options.assistingParticipant !== null
        && (options.assistingParticipant > 10
          || !['hero_assist_candidates', 'hero_death_episode_candidates']
            .includes(options.event))) {
      throw new Error('--assisting-participant requires hero_assist_candidates or hero_death_episode_candidates and 1..10');
    }
    if (options.contextualSituation !== null
        && options.event !== 'notify_contextual_situation_packet_candidates') {
      throw new Error('--contextual-situation requires notify_contextual_situation_packet_candidates');
    }
    if (options.dieSourceKey2cMatch !== null
        && !['has', 'none', 'unavailable'].includes(options.dieSourceKey2cMatch)) {
      throw new Error('--die-source-key2c-match requires has, none or unavailable');
    }
    if (options.dieSourceKey2cMatch !== null
        && options.event !== 'hero_death_damage_lookup_key_cooccurrence_candidates') {
      throw new Error('--die-source-key2c-match requires hero_death_damage_lookup_key_cooccurrence_candidates');
    }
    if (options.fromMs !== null && options.toMs !== null && options.fromMs > options.toMs) {
      throw new Error('--from-ms must not exceed --to-ms');
    }
    const inventoryQueryEvent = [
      'hero_inventory_packet_candidates',
      'hero_inventory_broadcast_packet_candidates',
      'hero_inventory_set_item_packet_candidates',
      'ward_inventory_keyframe_pair_candidates',
      'inventory_keyframe_interval_difference_candidates',
      'inventory_game_broadcast_keyframe_bracket_candidates',
    ].includes(options.event);
    if (options.itemId !== null && !inventoryQueryEvent) {
      throw new Error('--item-id requires an 821 inventory packet event, ward/inventory keyframe pair event, inventory keyframe interval difference event, or game Broadcast bracket event');
    }
    if (options.previousItemId !== null
        && options.event !== 'inventory_keyframe_interval_difference_candidates') {
      throw new Error('--previous-item-id requires inventory_keyframe_interval_difference_candidates');
    }
    if (options.endpointReversedPair
        && options.event !== 'inventory_keyframe_interval_difference_candidates') {
      throw new Error('--endpoint-reversed-pair requires inventory_keyframe_interval_difference_candidates');
    }
    if (options.comparisonToEndpoints !== null
        && !INVENTORY_GAME_COMPARISON_LABELS_821.includes(options.comparisonToEndpoints)) {
      throw new Error('--comparison-to-endpoints requires one of the five exact uppercase bracket comparison labels');
    }
    if (options.comparisonToEndpoints !== null
        && options.event !== 'inventory_game_broadcast_keyframe_bracket_candidates') {
      throw new Error('--comparison-to-endpoints requires inventory_game_broadcast_keyframe_bracket_candidates');
    }
    if (options.slot !== null && !inventoryQueryEvent) {
      throw new Error('--slot requires an 821 inventory packet event, ward/inventory keyframe pair event, inventory keyframe interval difference event, or game Broadcast bracket event');
    }
    if (options.slot !== null && options.slot > 9) {
      throw new Error('--slot must be in 0..9');
    }
    if (options.opaqueU32 !== null && ![
      'params_heal_packet_candidates',
      'shielding_params_packet_pair_candidates',
      'stealth_event_packet_candidates',
      'npc_buff_add_packet_candidates',
      'npc_buff_remove_packet_candidates',
      'npc_buff_update_num_counter_packet_candidates',
      'npc_buff_update_count_packet_candidates',
      'npc_buff_replace_packet_candidates',
      'set_spell_timer_from_buff_packet_candidates',
      'set_spell_level_packet_candidates',
      'item_group_data_broadcast_packet_candidates',
      'cooldown_broadcast_packet_candidates',
      'target_hero_packet_candidates',
      'force_create_missile_packet_candidates',
      'change_missile_target_packet_candidates',
      'set_dimension_missile_packet_candidates',
      'champion_die_event_packet_candidates',
      'champion_kill_event_packet_candidates',
      'champion_multiple_kill_event_packet_candidates',
      'on_shutdown_event_packet_candidates',
      'resurrect_event_packet_candidates',
      'revive_ally_event_packet_candidates',
      'turret_plate_event_packet_candidates',
      'objective_bounty_claimed_packet_candidates',
      'objective_bounty_turret_pair_candidates',
      'champion_die_hero_death_pair_candidates',
      'champion_kill_die_hero_death_pair_candidates',
      'champion_multiple_kill_die_hero_death_pair_candidates',
      'champion_double_kill_multi_group_candidates',
      'champion_triple_quadra_multi_group_candidates',
      'on_shutdown_die_hero_death_pair_candidates',
    ].includes(options.event)) {
      throw new Error('--opaque-u32 requires a supported 821 packet or packet-group candidate event');
    }
    if (options.opaquePair !== null && ![
      'npc_buff_add_packet_candidates',
      'npc_buff_remove_packet_candidates',
      'npc_buff_update_num_counter_packet_candidates',
    ].includes(options.event)) {
      throw new Error('--opaque-pair requires an 821 Buff Add, Remove, or UpdateNumCounter packet event');
    }
    if (options.opaqueI32 !== null && options.event !== 'cast_spell_ans_packet_candidates') {
      throw new Error('--opaque-i32 requires an 821 cast_spell_ans_packet_candidates event');
    }
    if (options.castNestedBits !== null
        && options.event !== 'cast_spell_ans_packet_candidates') {
      throw new Error('--cast-nested-bits requires an 821 cast_spell_ans_packet_candidates event');
    }
    if (options.castNestedU32 !== null
        && options.event !== 'cast_spell_ans_packet_candidates') {
      throw new Error('--cast-nested-u32 requires an 821 cast_spell_ans_packet_candidates event');
    }
    if (options.castNestedU32At4c !== null
        && options.event !== 'cast_spell_ans_packet_candidates') {
      throw new Error('--cast-nested-u32-0x4c requires an 821 cast_spell_ans_packet_candidates event');
    }
    if (options.castNestedF32AtA0 !== null
        && options.event !== 'cast_spell_ans_packet_candidates') {
      throw new Error('--cast-nested-f32-0xa0 requires an 821 cast_spell_ans_packet_candidates event');
    }
    if (options.castNestedU32At28 !== null
        && options.event !== 'cast_spell_ans_packet_candidates') {
      throw new Error('--cast-nested-u32-0x28 requires an 821 cast_spell_ans_packet_candidates event');
    }
    if ((options.spellLevelReceiverIndex !== null
        || options.spellLevelClampedScalar !== null)
        && options.event !== 'set_spell_level_packet_candidates') {
      throw new Error('--spell-level-receiver-index and --spell-level-clamped-scalar require an 821 set_spell_level_packet_candidates event');
    }
    if (options.spellTimerReceiverSlot !== null
        && options.event !== 'set_spell_timer_from_buff_packet_candidates') {
      throw new Error('--spell-timer-receiver-slot requires an 821 set_spell_timer_from_buff_packet_candidates event');
    }
    if (options.damageCallbackF32Available
        && options.event !== 'unit_apply_damage_packet_candidates') {
      throw new Error('--damage-callback-f32-available requires an 821 unit_apply_damage_packet_candidates event');
    }
    if (options.damageCallbackU32At10 !== null
        && options.event !== 'unit_apply_damage_packet_candidates') {
      throw new Error('--damage-callback-u32-0x10 requires an 821 unit_apply_damage_packet_candidates event');
    }
    if (options.damageCallbackU32At1c !== null
        && options.event !== 'unit_apply_damage_packet_candidates') {
      throw new Error('--damage-callback-u32-0x1c requires an 821 unit_apply_damage_packet_candidates event');
    }
    if (options.damageCallbackF32At18Raw
        && options.event !== 'unit_apply_damage_packet_candidates') {
      throw new Error('--damage-callback-f32-0x18-raw requires an 821 unit_apply_damage_packet_candidates event');
    }
    if ((options.damageLookupKey24 !== null || options.damageLookupKey2c !== null)
        && options.event !== 'unit_apply_damage_packet_candidates') {
      throw new Error('--damage-lookup-key24 and --damage-lookup-key2c require an 821 unit_apply_damage_packet_candidates event');
    }
    if (options.showHealthZeroFlag !== null
        && (options.event !== 'show_health_bar_packet_candidates'
          || options.showHealthZeroFlag > 1)) {
      throw new Error('--show-health-zero-flag requires show_health_bar_packet_candidates and 0..1');
    }
    if (options.packetRecordCount !== null
        && (options.event !== 'circular_movement_restriction_packet_candidates'
          || options.packetRecordCount > 1)) {
      throw new Error('--packet-record-count requires circular_movement_restriction_packet_candidates and 0..1');
    }
    if (options.levelAfter !== null
        && (options.event !== 'level_experience_keyframe_bracket_candidates'
          || options.levelAfter > 20)) {
      throw new Error('--level-after requires level_experience_keyframe_bracket_candidates and 1..20');
    }
    if (options.childEventId !== null) {
      const ids = options.event === 'stealth_event_packet_candidates'
        ? [0x0101, 0x0102]
        : options.event === 'first_blood_assist_event_packet_candidates'
          ? [0x0017]
        : options.event === 'objective_steal_event_packet_candidates'
          ? [0x00be, 0x00d6]
        : options.event === 'hq_kill_event_packet_candidates'
          ? [0x0046]
        : options.event === 'objective_bounty_claimed_packet_candidates'
          ? [0x0113]
        : ['champion_double_kill_event_packet_candidates',
          'champion_double_kill_multi_group_candidates'].includes(options.event)
          ? [0x000b]
          : ['champion_triple_quadra_event_packet_candidates',
            'champion_triple_quadra_multi_group_candidates'].includes(options.event)
            ? [0x000c, 0x000d] : null;
      if (!ids) {
        throw new Error('--child-event-id requires a supported 821 named child candidate event');
      }
      if (!ids.includes(options.childEventId)) {
        throw new Error(options.event === 'stealth_event_packet_candidates'
          ? '--child-event-id must be 0x0101 (OnEnterStealth) or 0x0102 (OnExitStealth)'
          : options.event === 'first_blood_assist_event_packet_candidates'
            ? '--child-event-id must be 0x0017 (OnFirstBloodAssist)'
          : options.event === 'objective_steal_event_packet_candidates'
            ? '--child-event-id must be 0x00be (OnKillDragonSteal) or 0x00d6 (OnKillWormSteal)'
          : options.event === 'hq_kill_event_packet_candidates'
            ? '--child-event-id must be 0x0046 (OnHQKill)'
          : options.event === 'objective_bounty_claimed_packet_candidates'
            ? '--child-event-id must be 0x0113 (OnObjectiveBountyClaimed)'
          : ids[0] === 0x000b
            ? '--child-event-id must be 0x000b (OnChampionDoubleKill)'
            : '--child-event-id must be 0x000c (OnChampionTripleKill) or 0x000d (OnChampionQuadraKill)');
      }
    }
    if (options.output === '') throw new Error('--output must be a path or -');
  }
  return { command, positionals, options };
}

function queryInteger(value, label, allowZero = false) {
  const literal = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(literal)) {
    throw new Error(`--${label} must be a ${allowZero ? 'nonnegative' : 'positive'} integer`);
  }
  const number = Number(literal);
  if (!Number.isSafeInteger(number) || (!allowZero && number === 0)) {
    throw new Error(`--${label} must be a ${allowZero ? 'nonnegative' : 'positive'} safe integer`);
  }
  return number;
}

function queryInt32(value, label) {
  const literal = String(value);
  if (!/^(?:0|-?[1-9][0-9]*)$/.test(literal)) {
    throw new Error(`--${label} must be a decimal signed int32`);
  }
  const number = Number(literal);
  if (!Number.isInteger(number) || number < -0x80000000 || number > 0x7fffffff) {
    throw new Error(`--${label} must be a decimal signed int32`);
  }
  return number;
}

function queryFiniteFloat(value, label) {
  const literal = String(value);
  if (!/^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/.test(literal)) {
    throw new Error(`--${label} must be a finite decimal number`);
  }
  const number = Number(literal);
  const f32 = Math.fround(number);
  if (!Number.isFinite(number) || !Number.isFinite(f32)) {
    throw new Error(`--${label} must be a finite decimal number`);
  }
  return f32;
}

function queryRawParam(value) {
  return queryUint32(value, 'raw-param');
}

function queryByte(value, label) {
  const number = queryUint32(value, label);
  if (number > 0xff) throw new Error(`--${label} must be in 0..255`);
  return number;
}

function queryWord(value, label) {
  const number = queryUint32(value, label);
  if (number > 0xffff) throw new Error(`--${label} must be in 0..65535`);
  return number;
}

function queryUint32(value, label) {
  const literal = String(value);
  if (!/^(?:0|[1-9][0-9]*|0[xX][0-9a-fA-F]{1,8})$/.test(literal)) {
    throw new Error(`--${label} must be a decimal or 0x hexadecimal uint32`);
  }
  const number = Number(literal);
  if (!Number.isSafeInteger(number) || number > 0xffffffff) {
    throw new Error(`--${label} must be a decimal or 0x hexadecimal uint32`);
  }
  return number;
}

function queryOpaquePair(value) {
  const parts = String(value).split(':');
  if (parts.length !== 2) throw new Error('--opaque-pair must be uint32:uint8');
  const u32 = queryUint32(parts[0], 'opaque-pair');
  const u8 = queryUint32(parts[1], 'opaque-pair');
  if (u8 > 0xff) throw new Error('--opaque-pair byte must be in 0..255');
  return { u32, u8 };
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
  const addFile = (filePath, stat = null) => {
    let identity = filePath;
    if (process.platform === 'win32') {
      const fileStat = stat ?? fs.statSync(filePath, { bigint: true });
      identity = fileStat.ino !== 0n
        ? `${fileStat.dev}:${fileStat.ino}` : filePath.toLowerCase();
    }
    if (!seen.has(identity)) {
      seen.add(identity);
      files.push(filePath);
    }
  };
  const visit = (input) => {
    const resolved = path.resolve(input);
    if (!fs.existsSync(resolved)) throw new Error(`Input does not exist: ${resolved}`);
    const stat = fs.statSync(resolved, { bigint: true });
    if (stat.isFile()) {
      if (!resolved.toLowerCase().endsWith('.rofl')) throw new Error(`Input is not a .rofl file: ${resolved}`);
      addFile(resolved, stat);
      return;
    }
    for (const entry of fs.readdirSync(resolved, { withFileTypes: true })) {
      const full = path.join(resolved, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.rofl')) addFile(full);
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
  const is820 = replay.header.version === '16.19.820.7193';
  const is821 = replay.header.version === '16.19.821.7343';
  const selected821 = is821 && options.semantic !== false && Array.isArray(options.events)
    ? [...new Set(options.events.filter((name) => [
      'hero_death', 'hero_assist', 'hero_death_timer', 'hero_respawn', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_missions_minions_killed_snapshot',
      'hero_ward_stats_snapshot', 'hero_missions_cannon_minions_killed_snapshot',
      'hero_minions_killed_snapshot', 'hero_jungle_minions_killed_snapshot',
      'hero_kill_stats_snapshot',
      'hero_experience_snapshot', 'hero_vision_score_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
      'hero_damage_totals_snapshot', 'hero_damage_taken_from_champions_snapshot',
      'hero_damage_self_mitigated_snapshot',
      'hero_structure_objective_damage_snapshot',
      'hero_longest_living_time_snapshot', 'hero_total_time_spent_dead_snapshot',
      'hero_total_heal_snapshot', 'hero_total_units_healed_snapshot',
      'hero_epic_monster_damage_snapshot', 'hero_crowd_control_time_snapshot',
      'hero_level_state', 'hero_inventory_packet', 'hero_inventory_broadcast_packet',
      'hero_inventory_set_item_packet',
      'params_heal_packet',
      'shielding_params_packet_pair',
      'stealth_event_packet',
      'champion_die_event_packet',
      'champion_kill_event_packet',
      'champion_multiple_kill_event_packet',
      'champion_double_kill_event_packet',
      'champion_triple_quadra_event_packet',
      'on_shutdown_event_packet',
      'resurrect_event_packet',
      'revive_ally_event_packet',
      'first_blood_assist_event_packet',
      'objective_steal_event_packet',
      'turret_die_event_packet',
      'dampener_die_event_packet',
      'turret_first_blood_event_packet',
      'hq_kill_event_packet',
      'turret_plate_event_packet',
      'objective_bounty_claimed_packet',
      'cast_spell_ans_packet', 'npc_buff_remove_packet', 'npc_buff_add_packet',
      'npc_buff_update_num_counter_packet',
      'npc_buff_update_count_packet',
      'npc_buff_replace_packet',
      'set_spell_timer_from_buff_packet',
      'set_spell_level_packet',
      'direct_input_movement_turn_packet',
      'set_movement_driver_packet',
      'increment_minion_kills_packet',
      'face_direction_packet',
      'circular_movement_restriction_packet',
      'notify_contextual_situation_packet',
      'item_group_data_broadcast_packet',
      'cooldown_broadcast_packet',
      'item_charges_packet',
      'target_hero_packet',
      'force_create_missile_packet',
      'change_missile_target_packet',
      'set_dimension_missile_packet',
      'unit_apply_damage_packet',
      'show_health_bar_packet',
    ].includes(name)))] : [];
  if (options.semantic !== false && Array.isArray(options.events)
      && options.events.includes('face_direction_keyframe_roster_pair')) {
    for (const source of ['face_direction_packet', 'hero_minions_killed_snapshot']) {
      if (!selected821.includes(source)) selected821.push(source);
    }
  }
  if (options.semantic !== false && Array.isArray(options.events)
      && options.events.some((name) => [
        'unit_apply_damage_roster_key_pair',
        'unit_apply_damage_lookup_roster_key_pair',
        'unit_apply_damage_lookup2c_roster_key_pair',
        'hero_death_damage_lookup_key_cooccurrence',
      ].includes(name))) {
    for (const source of ['unit_apply_damage_packet', 'hero_minions_killed_snapshot',
      ...(options.events.includes('hero_death_damage_lookup_key_cooccurrence')
        ? ['hero_death'] : [])]) {
      if (!selected821.includes(source)) selected821.push(source);
    }
  }
  const selectsBuffAdd = options.semantic !== false
    && Array.isArray(options.events) && options.events.includes('npc_buff_add_packet');
  const selectsBuffRemove = options.semantic !== false
    && Array.isArray(options.events) && options.events.includes('npc_buff_remove_packet');
  const selectsGameRoutes = options.semantic !== false
    && Array.isArray(options.events)
    && (selectsBuffAdd || selectsBuffRemove || options.events.some((name) => [
      'hero_death', 'hero_death_timer', 'hero_respawn', 'hero_level_state',
      'hero_inventory_mapview', 'hero_inventory_set_item', 'hero_inventory_broadcast',
    ].includes(name)));
  const selectsHeroStats = is820 && options.semantic !== false
    && Array.isArray(options.events)
    && options.events.some((name) => HERO_STATS_SNAPSHOT_CAPABILITIES.includes(name));
  const analysisOptions = {
    timelineLimit: options.timelineLimit,
    includePrivateMetadata: options.includePrivateMetadata,
    strict: options.strict,
  };
  const { analysis, heroStatsScan, candidateRouteScan, candidate821Scan } = is820 && selectsGameRoutes
    ? analyzeReplayWithCandidateRoutes(replay, analysisOptions, selectsHeroStats,
      { includeBuffAdd: selectsBuffAdd, includeBuffRemove: selectsBuffRemove })
    : selectsHeroStats ? analyzeReplayWithHeroStats(replay, analysisOptions)
      : selected821.length > 0
        ? analyzeReplayWith821Routes(replay, analysisOptions, selected821)
      : { analysis: analyzeReplay(replay, analysisOptions), heroStatsScan: null,
        candidateRouteScan: null, candidate821Scan: null };
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
          heroStatsScan: heroStatsScan ?? undefined,
          candidateRouteScan: candidateRouteScan ?? undefined,
          candidate821Scan: candidate821Scan ?? undefined,
          runtimeImagePath: options.runtimeImage ?? undefined,
          pythonExecutable: options.python ?? undefined,
          castPacketProfile: options.castPacketV9 ? 'v9'
            : options.castPacketV8 ? 'v8'
            : options.castPacketV7 ? 'v7'
            : options.castPacketV6 ? 'v6'
              : options.castPacketV5 ? 'v5' : undefined,
          setSpellTimerProfile: options.spellTimerPacketV2 ? 'v2' : undefined,
          setSpellLevelProfile: options.spellLevelPacketV2 ? 'v2' : undefined,
          itemGroupPacketProfile: options.itemGroupPacketV2 ? 'v2' : undefined,
          damagePacketProfile: options.damagePacketV6 ? 'v6' : undefined,
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
      const associationDecodeFailed = Object.values(decoded.candidate_associations ?? {})
        .some((association) => ['DECODE_FAILED', 'INCONSISTENT'].includes(association?.status));
      const semanticStatus = associationDecodeFailed
          && ['PASS', 'CANDIDATE'].includes(capabilitySummary.status)
        ? 'PARTIAL' : capabilitySummary.status;
      const semanticNote = decoded.note ?? (associationDecodeFailed
        ? 'A candidate association failed; inspect candidate_associations for its error.'
        : semanticStatus === 'CANDIDATE'
          ? 'Experimental candidate output; it is not a confirmed semantic event.' : null);
      const runtimeStatuses = Object.values(capabilitySummary.capabilityResults)
        .map((row) => row.runtime_image_status);
      const runtimeImageUsed = typeof decoded.runtime_image_used === 'boolean'
        ? decoded.runtime_image_used
        : runtimeStatuses.length > 0 && runtimeStatuses.every((status) => [
          'PROVIDED_NOT_USED', 'NOT_REQUIRED',
        ].includes(status)) ? false : null;
      analysis.decoder = {
        profile: decoded.profile ?? null,
        status: semanticStatus,
        note: semanticNote,
      };
      analysis.semantic = {
        status: semanticStatus,
        api_status: decoded.status ?? null,
        note: decoded.note ?? (associationDecodeFailed ? semanticNote : null),
        requested_capabilities: requested,
        capability_results: capabilitySummary.capabilityResults,
        ...(decoded.candidate_associations
          && Object.keys(decoded.candidate_associations).length > 0
          ? { candidate_associations: decoded.candidate_associations } : {}),
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
    if (options.eventJsonlOnly && replay.header.patch !== '16.19') {
      const error = new Error('--event-jsonl-only supports only 16.19 Replays');
      error.code = 'UNSUPPORTED_OUTPUT_MODE';
      throw error;
    }
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

function quickReplayVersion(filePath) {
  const bytes = Buffer.alloc(HEADER_PREFIX_SIZE + 64);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, 'r');
    const length = fs.readSync(descriptor, bytes, 0, bytes.length, 0);
    return parseHeader(bytes.subarray(0, length)).version;
  } catch {
    // The ordinary parser retains the precise missing-file or malformed-header error.
    return null;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseOneExact821Batch(filePath, options) {
  const version = quickReplayVersion(filePath);
  if (version !== null && version !== BATCH_JOBS_BUILD) {
    return {
      ok: false,
      source_path: path.resolve(filePath),
      error: {
        code: 'UNSUPPORTED_OUTPUT_MODE',
        message: `--jobs supports only exact ${BATCH_JOBS_BUILD}; received ${version}.`,
        details: { replay_version: version },
        name: 'Error',
      },
    };
  }
  return parseOne(filePath, options);
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

const MAX_REPLAY_DIRECTORY_COMPONENT = 255;

function replayDirectoryNameWithSuffix(stem, suffix) {
  return `${stem.slice(0, MAX_REPLAY_DIRECTORY_COMPONENT - suffix.length - 1)}-${suffix}`;
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
      name: stemCounts.get(stem) > 1
        ? replayDirectoryNameWithSuffix(stem, pathHash.slice(0, 12)) : stem,
    };
  });
  const candidateCounts = new Map();
  for (const row of candidates) {
    candidateCounts.set(row.name, (candidateCounts.get(row.name) ?? 0) + 1);
  }
  const names = candidates.map((row) => candidateCounts.get(row.name) > 1
    ? replayDirectoryNameWithSuffix(row.stem, row.pathHash) : row.name);
  const outputKey = (name) => process.platform === 'win32' ? name.toLowerCase() : name;
  const foldedCounts = new Map();
  for (const name of names) {
    const key = outputKey(name);
    foldedCounts.set(key, (foldedCounts.get(key) ?? 0) + 1);
  }
  const isolated = names.map((name, index) => foldedCounts.get(outputKey(name)) > 1
    ? replayDirectoryNameWithSuffix(stems[index],
      sha256(Buffer.from(path.resolve(analyses[index].source_path))))
    : name);
  if (new Set(isolated.map(outputKey)).size !== isolated.length) {
    throw new Error('Replay output directory identities are not unique');
  }
  return isolated;
}

function writePerReplayArtifacts(analysis, rootDir, replayDirName, options = {}) {
  const replayDir = path.join(rootDir, 'replays', replayDirName);
  ensureDir(replayDir);
  const eventJsonlOnly = options.eventJsonlOnly === true && analysis.patch === '16.19';
  const replayAnalysis = eventJsonlOnly ? {
    ...analysis,
    events: null,
    event_storage: 'JSONL_ONLY',
    event_jsonl_files: Object.fromEntries(Object.keys(analysis.events)
      .map((name) => [name, `${name}.jsonl`])),
  } : analysis;
  writeJson(path.join(replayDir, 'replay_analysis.json'), replayAnalysis);
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
  if (!eventJsonlOnly) writeJson(path.join(replayDir, 'events.json'), analysis.events);
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
    ? failed.some((result) => result.error.code === 'WORKER_FAILED')
      ? 'VALIDATION_FAILED'
      : failed.some((result) => result.error.code === 'UNSUPPORTED_OUTPUT_MODE')
        ? 'UNSUPPORTED_OUTPUT_MODE' : 'NEED_USER_FILE'
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

function buildReviewerManifest(summary, rootDir, results, args, options = {}) {
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
  const eventOutputArg = first1619 && options.eventJsonlOnly ? ' --event-jsonl-only' : '';
  const replayCommand = reviewReplay ? first1619
    ? `node src/cli.js ${selected1619.length > 0 ? 'decode' : 'inspect'} ${quoteCommandArg(reviewReplay)}${selectedArg}${runtimeArg}${eventOutputArg} --out-dir ${quoteCommandArg(reviewerRerunRoot)}`
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

async function writeRunArtifacts(results, rootDir, beforeHashes, afterHashes, args, testSummary = null, detailsDir = null, options = {}) {
  ensureDir(rootDir);
  const successful = results.filter((result) => result.ok);
  if (options.prewrittenReplayArtifacts) {
    const replayRoot = path.resolve(rootDir, 'replays');
    for (const result of successful) {
      const relative = result.analysis.artifact_directory;
      const replayDir = path.resolve(rootDir, relative ?? '');
      if (path.dirname(replayDir) !== replayRoot) {
        throw new Error('Worker reported a Replay artifact directory outside this run');
      }
      const saved = JSON.parse(fs.readFileSync(path.join(replayDir, 'replay_analysis.json'), 'utf8'));
      if (saved.replay_sha256 !== result.analysis.replay_sha256
          || saved.source_path !== result.analysis.source_path
          || saved.replay_version !== BATCH_JOBS_BUILD
          || saved.event_storage !== 'JSONL_ONLY'
          || saved.events !== null) {
        throw new Error('Worker Replay artifact identity or JSONL storage differs');
      }
      if (!fs.statSync(path.join(replayDir, 'semantic_run.json')).isFile()
          || !saved.event_jsonl_files || typeof saved.event_jsonl_files !== 'object') {
        throw new Error('Worker Replay artifact is missing semantic or event metadata');
      }
      for (const [name, filename] of Object.entries(saved.event_jsonl_files)) {
        if (filename !== `${name}.jsonl`
            || !fs.statSync(path.join(replayDir, filename)).isFile()) {
          throw new Error(`Worker Replay event artifact is missing: ${name}`);
        }
      }
    }
  } else {
    const replayDirNames = replayDirectoryNames(successful.map((result) => result.analysis));
    for (const [index, result] of successful.entries()) {
      result.analysis.artifact_directory = path.posix.join('replays', replayDirNames[index]);
      writePerReplayArtifacts(result.analysis, rootDir, replayDirNames[index], options);
    }
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
  const reviewerManifest = buildReviewerManifest(summary, rootDir, results, args, options);
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
      ...(options.eventJsonlOnly && result.analysis.patch === '16.19'
        ? { event_storage: 'JSONL_ONLY' } : {}),
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

function pythonUnicornDependency(command) {
  const python = command || process.env.PYTHON || 'python';
  const checked = childProcess.spawnSync(python, ['-B', '-c', 'import unicorn'], {
    encoding: 'utf8', timeout: 5000, maxBuffer: 8192, windowsHide: true,
  });
  const detail = String(checked.error?.message || checked.stderr || '').trim();
  const missing = checked.error?.code === 'ENOENT'
    || /No module named ['"]unicorn['"]/.test(detail);
  return {
    name: 'python_unicorn',
    status: checked.status === 0 && !checked.error ? 'PRESENT_UNVERIFIED'
      : missing ? 'MISSING' : 'INVALID',
    path: null,
    command: python,
    ...(checked.status === 0 && !checked.error ? {}
      : { error: detail.slice(0, 300) || `exit ${checked.status}` }),
  };
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
    input_assessment_scope: ['16.19.820.7193', '16.19.821.7343'].includes(replay.header.version)
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
  if (['16.19.820.7193', '16.19.821.7343'].includes(profile.game_version)) {
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
  if (!['16.19.820.7193', '16.19.821.7343'].includes(profile.game_version)) {
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
        && ['16.19.820.7193', '16.19.821.7343'].includes(profile.game_version);
      const needs1619RuntimeImage = capability === 'hero_inventory_mapview'
        || capability === 'hero_inventory_set_item'
        || capability === 'hero_inventory_broadcast'
        || (profile.game_version === '16.19.821.7343'
          && (capability === 'hero_inventory_packet'
            || capability === 'hero_inventory_broadcast_packet'
            || capability === 'hero_inventory_set_item_packet'
            || capability === 'params_heal_packet'
            || capability === 'shielding_params_packet_pair'
            || capability === 'stealth_event_packet'
            || capability === 'champion_die_event_packet'
            || capability === 'champion_kill_event_packet'
            || capability === 'champion_multiple_kill_event_packet'
            || capability === 'champion_double_kill_event_packet'
            || capability === 'champion_triple_quadra_event_packet'
            || capability === 'on_shutdown_event_packet'
            || capability === 'resurrect_event_packet'
            || capability === 'revive_ally_event_packet'
            || capability === 'first_blood_assist_event_packet'
            || capability === 'objective_steal_event_packet'
            || capability === 'turret_die_event_packet'
            || capability === 'dampener_die_event_packet'
            || capability === 'turret_first_blood_event_packet'
            || capability === 'hq_kill_event_packet'
            || capability === 'turret_plate_event_packet'
            || capability === 'objective_bounty_claimed_packet'
            || capability === 'cast_spell_ans_packet'))
        || capability === 'npc_buff_remove_packet'
        || capability === 'npc_buff_add_packet'
        || (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_update_num_counter_packet')
        || (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_update_count_packet')
        || (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_replace_packet')
        || (profile.game_version === '16.19.821.7343'
          && capability === 'set_spell_timer_from_buff_packet')
        || (profile.game_version === '16.19.821.7343'
          && capability === 'set_spell_level_packet')
        || (profile.game_version === '16.19.821.7343'
          && (capability === 'direct_input_movement_turn_packet'
            || capability === 'set_movement_driver_packet'
            || capability === 'increment_minion_kills_packet'
            || capability === 'face_direction_packet'
            || capability === 'circular_movement_restriction_packet'
            || capability === 'notify_contextual_situation_packet'
             || capability === 'item_group_data_broadcast_packet'
             || capability === 'cooldown_broadcast_packet'
             || capability === 'item_charges_packet'
             || capability === 'target_hero_packet'
             || capability === 'force_create_missile_packet'
             || capability === 'change_missile_target_packet'
             || capability === 'set_dimension_missile_packet'
            || capability === 'unit_apply_damage_packet'
            || capability === 'show_health_bar_packet'
            || capability === 'unit_apply_damage_roster_key_pair'
            || capability === 'unit_apply_damage_lookup_roster_key_pair'
            || capability === 'unit_apply_damage_lookup2c_roster_key_pair'
            || capability === 'hero_death_damage_lookup_key_cooccurrence'
            || capability === 'face_direction_keyframe_roster_pair'));
      const tailStat = perCapabilityInputsAssessed
        ? profile.game_version === '16.19.821.7343'
          && capability === 'hero_respawn'
          ? (() => {
            const death = assessHeroDeathTail821(replay);
            const deadTime = assessHeroRespawnDeadTimeTail821(replay);
            return { required_fields: [
              { field: 'NUM_DEATHS', status: death.status,
                error: death.error ?? death.missing_input ?? null },
              { field: 'TOTAL_TIME_SPENT_DEAD', status: deadTime.status,
                error: deadTime.error ?? deadTime.missing_input ?? null },
            ] };
          })()
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_death_damage_lookup_key_cooccurrence'
          ? (() => {
            const death = assessHeroDeathTail821(replay);
            const minions = assessHeroFloatSnapshotTail821(replay,
              'hero_minions_killed_snapshot');
            return { required_fields: [
              { field: 'NUM_DEATHS', status: death.status,
                error: death.error ?? death.missing_input ?? null },
              { field: 'MINIONS_KILLED', status: minions.status,
                error: minions.error ?? minions.missing_input ?? null },
            ] };
          })()
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_assist'
          ? { required_fields: [
            ['NUM_DEATHS', assessHeroDeathTail821(replay)],
            ['CHAMPIONS_KILLED', assessHeroChampionKillsSnapshotTail821(replay)],
            ['ASSISTS', assessHeroAssistsSnapshotTail821(replay)],
          ].map(([field, assessment]) => ({ field, status: assessment.status,
            error: assessment.error ?? assessment.missing_input ?? null })) }
        : profile.game_version === '16.19.821.7343'
          && Object.hasOwn(DAMAGE_PROFILES_821, capability)
          ? { required_fields: [
            ...DAMAGE_PROFILES_821[capability].fields.map((field) => field.replay_tail_field),
            ...(DAMAGE_PROFILES_821[capability].mirror_replay_tail_field
              ? [DAMAGE_PROFILES_821[capability].mirror_replay_tail_field] : []),
          ].map((field) => {
            const assessment = assessHeroStatsTail821(replay, field);
            return { field, status: assessment.status,
              error: assessment.error ?? assessment.missing_input ?? null };
          }) }
        : profile.game_version === '16.19.821.7343'
          && Object.hasOwn(EXTRA_STATS_PROFILES_821, capability)
          ? (() => {
            const field = EXTRA_STATS_PROFILES_821[capability].replay_tail_field;
            const assessment = assessHeroStatsTail821(replay, field);
            return { field, status: assessment.status,
              error: assessment.error ?? assessment.missing_input ?? null };
          })()
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_level_state'
          ? (() => {
            const assessment = assessHeroLevelTail821(replay);
            return { field: 'LEVEL', status: assessment.status,
              error: assessment.error ?? assessment.missing_input ?? null };
          })()
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_deaths_snapshot'
          ? assessHeroDeathsSnapshotTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_champion_kills_snapshot'
          ? assessHeroChampionKillsSnapshotTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_assists_snapshot'
          ? assessHeroAssistsSnapshotTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_missions_minions_killed_snapshot'
          ? assessHeroMissionsMinionsKilledSnapshotTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_ward_stats_snapshot'
          ? assessHeroWardStatsTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_missions_cannon_minions_killed_snapshot'
          ? assessHeroMissionsCannonMinionsTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_jungle_minions_killed_snapshot'
          ? assessHeroJungleMinionsTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && capability === 'hero_kill_stats_snapshot'
          ? assessHeroKillStatsTail821(replay)
        : profile.game_version === '16.19.821.7343'
          && ['hero_minions_killed_snapshot', 'face_direction_keyframe_roster_pair',
            'unit_apply_damage_roster_key_pair',
            'unit_apply_damage_lookup_roster_key_pair',
            'unit_apply_damage_lookup2c_roster_key_pair',
            'hero_experience_snapshot', 'hero_vision_score_snapshot',
            'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot'].includes(capability)
          ? assessHeroFloatSnapshotTail821(replay,
            ['face_direction_keyframe_roster_pair',
              'unit_apply_damage_roster_key_pair',
              'unit_apply_damage_lookup_roster_key_pair',
              'unit_apply_damage_lookup2c_roster_key_pair'].includes(capability)
              ? 'hero_minions_killed_snapshot' : capability)
        : profile.game_version === '16.19.821.7343'
          && (capability === 'hero_death' || capability === 'hero_death_timer')
          ? (() => {
            const assessment = assessHeroDeathTail821(replay);
            return { required_fields: [{ field: 'NUM_DEATHS',
              status: assessment.status,
              error: assessment.error ?? assessment.missing_input ?? null }] };
          })()
        : capability === 'hero_minions_killed_snapshot'
          ? assessHeroMinionsKilledSnapshotTail(replay)
          : capability === 'hero_jungle_minions_killed_snapshot'
            ? assessHeroJungleMinionsKilledSnapshotTail(replay)
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
                    : capability === 'hero_assists_snapshot'
                      ? assessHeroAssistsSnapshotTail(replay)
                    : capability === 'hero_kill_stats_snapshot'
                      ? assessHeroKillStatsSnapshotTail(replay)
                    : capability === 'hero_ward_stats_snapshot'
                      ? assessHeroWardStatsSnapshotTail(replay)
                    : capability === 'hero_damage_totals_snapshot'
                      ? assessHeroDamageTotalsSnapshotTail(replay)
                    : capability === 'hero_damage_taken_from_champions_snapshot'
                      ? assessHeroDamageTakenFromChampionsSnapshotTail(replay)
                    : capability === 'hero_damage_self_mitigated_snapshot'
                      ? assessHeroDamageSelfMitigatedSnapshotTail(replay)
                    : capability === 'hero_longest_living_time_snapshot'
                      ? assessHeroLongestLivingTimeSnapshotTail(replay)
                    : capability === 'hero_total_time_spent_dead_snapshot'
                      ? assessHeroTotalTimeSpentDeadSnapshotTail(replay)
                    : capability === 'hero_total_heal_snapshot'
                      ? assessHeroTotalHealSnapshotTail(replay)
                    : capability === 'hero_total_units_healed_snapshot'
                      ? assessHeroTotalUnitsHealedSnapshotTail(replay)
                    : capability === 'hero_vision_score_snapshot'
                      ? assessHeroVisionScoreSnapshotTail(replay)
                    : capability === 'hero_epic_monster_damage_snapshot'
                      ? assessHeroEpicMonsterDamageSnapshotTail(replay)
                    : capability === 'hero_crowd_control_time_snapshot'
                      ? assessHeroCrowdControlTimeSnapshotTail(replay)
                    : capability === 'hero_structure_objective_damage_snapshot'
                      ? assessHeroStructureObjectiveDamageSnapshotTail(replay)
                  : candidateTailStatAssessment(replay, capability)
        : null;
      const tailStatInput = (tailStat?.required_fields ?? (tailStat ? [tailStat] : []))
        .map((assessment) => ({
          name: `replay_tail_${assessment.field}`,
          status: !Array.isArray(replay.tail?.stats) ? 'NOT_ASSESSED'
            : assessment.status === 'PASS' ? 'PRESENT_UNVALIDATED'
              : assessment.status === 'MISSING_INPUT' ? 'MISSING' : 'INVALID',
          path: replay.source_path,
          error: assessment.status === 'PASS' ? null : assessment.error,
        }));
      const inputs = perCapabilityInputsAssessed
        ? needs1619RuntimeImage
          ? [dependencies[0], options.runtimeImage
            ? fileInputDependency('exact_runtime_image', options.runtimeImage)
            : { name: 'exact_runtime_image', status: 'MISSING', path: null },
          ...(['unit_apply_damage_packet', 'show_health_bar_packet',
            'unit_apply_damage_roster_key_pair',
            'unit_apply_damage_lookup_roster_key_pair',
            'unit_apply_damage_lookup2c_roster_key_pair'].includes(capability)
            || capability === 'hero_death_damage_lookup_key_cooccurrence'
            ? [pythonUnicornDependency(options.python ?? options.pythonExecutable)] : []),
          ...(['face_direction_keyframe_roster_pair',
            'unit_apply_damage_roster_key_pair',
            'unit_apply_damage_lookup_roster_key_pair',
            'unit_apply_damage_lookup2c_roster_key_pair'].includes(capability)
            || capability === 'hero_death_damage_lookup_key_cooccurrence'
            ? tailStatInput : [])]
          : [...dependencies, ...tailStatInput,
            ...(profile.game_version === '16.19.821.7343' && capability === 'hero_respawn'
              ? [{ name: 'replay_tail_gameLength',
                status: Number.isSafeInteger(replay.tail?.metadata?.gameLength)
                    && replay.tail.metadata.gameLength >= 0
                  ? 'PRESENT_UNVALIDATED'
                  : replay.tail?.metadata?.gameLength == null ? 'MISSING' : 'INVALID',
                path: replay.source_path }]
              : [])]
        : [{ name: 'replay', status: 'PRESENT', path: replay.source_path }];
      const validationPending = applicable ? [...pendingChecks] : [];
      if (applicable && !perCapabilityInputsAssessed) {
        validationPending.push('capability-specific input dependencies');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_death') {
        validationPending.push('matching 16.19 route fingerprint',
          'ten-participant NUM_DEATHS presence and equality');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_death') {
        validationPending.push('KR 0x0259/0x0438/0x031b co-timed core and optional 0x03d4',
          'ten-participant NUM_DEATHS presence and equality',
          '0x0438 source ID runtime wire decode and optional CHAMPIONS_KILLED tail alignment for killer participant');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_assist') {
        validationPending.push('KR death core and 0x0438 killer-tail alignment',
          'paired 0x040a/44 shapes with matching payload bytes and participant',
          'ten-participant ASSISTS tail equality and killer/victim exclusion');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_death_timer') {
        validationPending.push('KR matched 0x0259 death core and exact 821 five-byte runtime float transform',
          'ten-participant NUM_DEATHS equality; isolated timer packets remain excluded',
          'two observed early return exceptions prohibit respawn-time prediction');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_respawn') {
        validationPending.push('matched 821 death cores and exact 0x0048 ReincarnateAlive route/f32 decode',
          'co-timed 0x018d inventory MapView packet as structural fingerprint only',
          'ten-participant TOTAL_TIME_SPENT_DEAD aggregate equality and final-death censoring');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_deaths_snapshot') {
        validationPending.push('KR keyframe 0x0089 length, prefix, param, and pinned 821 runtime byte transform',
          'ten-participant NUM_DEATHS final gap 0..1 and monotone snapshots');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_champion_kills_snapshot') {
        validationPending.push('KR keyframe 0x0089 structure, mirrored bytes 434/1186, and pinned 821 runtime byte transform',
          'monotone snapshots and ten CHAMPIONS_KILLED tails');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_assists_snapshot') {
        validationPending.push('KR keyframe 0x0089 structure, raw byte 1178, and pinned 821 runtime byte transform',
          'monotone snapshots and ten ASSISTS tails');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_missions_minions_killed_snapshot') {
        validationPending.push('KR keyframe 0x0089 structure, raw bytes 374/373, upper-zero scope, and pinned 821 runtime byte transform',
          'monotone snapshots and ten Missions_MinionsKilled tails; distinct from MINIONS_KILLED');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_ward_stats_snapshot') {
        validationPending.push('KR keyframe 0x0089 structure, raw bytes 834/838/842, upper-zero scope, and pinned 821 runtime byte transform',
          'monotone snapshots and ten WARD_PLACED_DETECTOR, WARD_KILLED, and WARD_PLACED tails');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_missions_cannon_minions_killed_snapshot') {
        validationPending.push('KR keyframe 0x0089 structure, raw byte 450, upper-zero scope, and pinned 821 runtime byte transform',
          'monotone snapshots and ten Missions_CannonMinionsKilled tails');
      }
      if (profile.game_version === '16.19.821.7343'
          && ['hero_minions_killed_snapshot', 'hero_experience_snapshot', 'hero_vision_score_snapshot',
            'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot'].includes(capability)) {
        validationPending.push('KR keyframe 0x0089 structure and pinned 821 reversed-byte f32 transform',
          'ten numeric Replay tails, first-value scope, and per-participant snapshots');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_jungle_minions_killed_snapshot') {
        validationPending.push('KR keyframe 0x0089 structure and pinned 821 reversed-byte f32 transform',
          'three distinct numeric neutral-minion tails, first-value scope, and per-participant snapshots');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_kill_stats_snapshot') {
        validationPending.push('KR keyframe 0x0089 structure and pinned 821 byte transform',
          'six numeric kill-stat Replay tails, zero starts, monotone snapshots, and retained gaps; QUADRA remains sparse');
      }
      if (profile.game_version === '16.19.821.7343'
          && Object.hasOwn(DAMAGE_PROFILES_821, capability)) {
        validationPending.push('KR keyframe 0x0089 native vector and reversed-byte f32 transform',
          'selected numeric damage Replay tails, zero starts, monotone snapshots and retained final gaps');
      }
      if (profile.game_version === '16.19.821.7343'
          && Object.hasOwn(EXTRA_STATS_PROFILES_821, capability)) {
        validationPending.push('KR keyframe 0x0089 native vector and exact 821 byte transform',
          'selected numeric Replay tail, zero start, monotone snapshots and retained final gap');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_level_state') {
        validationPending.push('exact 821 LevelUp route, observed payload shapes, and pinned runtime byte transform',
          'ten-participant LEVEL sequence and tail equality; out-of-range values fail closed');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_inventory_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x018d MapView packet consumption',
          'per-packet slot/item record transform, exact-image callback reset/apply action, and raw-param provenance; no transaction or between-packet inventory-state inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_inventory_broadcast_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x0357 Broadcast packet consumption',
          'per-packet slot/item record transform and shared callback reset/apply action; no transaction or between-packet inventory-state inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_inventory_set_item_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x002d SetItem packet consumption',
          'nested slot/item transform and raw packet provenance; no transaction or between-packet inventory-state inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'params_heal_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x004b ParamsHeal packet consumption',
          'handler-read reported float and anonymous u32 fields; no effective-heal, caster, or target inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'shielding_params_packet_pair') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x00ef/0x00f0 packet consumption',
          'paired ShieldingParams blobs and anonymous fields; no shield generation, absorption, actor, or target inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'stealth_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0101/0x0102 packet consumption',
          'registered event names and anonymous u32 field; no participant, visibility, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'champion_die_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0004 packet consumption',
          'OnChampionDie image label and anonymous u32 field; no effective death, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'champion_kill_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0007 packet consumption',
          'OnChampionKill image label and anonymous u32 fields; no effective kill, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'champion_multiple_kill_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0009 packet consumption',
          'OnChampionMultipleKill image label and anonymous u32 fields; no effective multikill, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'champion_double_kill_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x000b packet consumption',
          'OnChampionDoubleKill image label only; no callback-backed field, effective double kill, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'champion_triple_quadra_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x000c/0x000d packet consumption',
          'OnChampionTripleKill/OnChampionQuadraKill image labels only; no effective kill streak, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'on_shutdown_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x00e8 packet consumption',
          'OnShutdown image label and anonymous u32 fields; no gameplay shutdown effect, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'resurrect_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x002d packet consumption',
          'OnResurrect image label and anonymous u32 fields; no resurrection, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'revive_ally_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x002c packet consumption',
          'OnReviveAlly image label and anonymous +0x04 u32; no revive effect, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'first_blood_assist_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0017 packet consumption',
          'OnFirstBloodAssist image label and opaque child blob; no first-blood, assist, actor, or effect inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'objective_steal_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a children 0x00be/0x00d6 packet consumption',
          'OnKillDragonSteal/OnKillWormSteal image labels and opaque child blobs; no actual steal, objective state, actor, or gameplay effect inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'turret_die_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x003b packet consumption',
          'OnTurretDie image label and anonymous child blob; no actual turret death, structure, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'dampener_die_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0035 packet consumption',
          'OnDampenerDie image label and anonymous child blob; no actual dampener death, structure, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'turret_first_blood_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x003d packet consumption',
          'OnTurretFirstBlood image label and anonymous child blob; no actual first turret death, structure, actor, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hq_kill_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0046 packet consumption',
          'OnHQKill image label and anonymous child blob; no HQ destruction, winner, actor, or state transition inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'turret_plate_event_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0107 packet consumption',
          'OnTurretPlateDestroyed image label and anonymous +0x04 u32; no callback-field, structure, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'objective_bounty_claimed_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x040a child 0x0113 packet consumption',
          'OnObjectiveBountyClaimed image label and anonymous eight-byte blob; no payout, actor, object, or state-change inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'cast_spell_ans_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x01da full packet consumption',
          'callback-transformed opaque fields and raw packet provenance; no successful-cast or spell identity inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'circular_movement_restriction_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native-observed 0x0464 packet shapes',
          'anonymous scalar and vector packet fields; no actor, world position, path, or effective restriction inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'unit_apply_damage_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and Python+Unicorn full native consumption of every selected 0x005f packet',
          'packet selectors and one bounded anonymous callback float; no damage amount, source, target, or effect inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'show_health_bar_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and Python+Unicorn full native consumption of every selected 0x0165 packet',
          'two observed one-byte packet shapes and callback flag candidates; no health amount, actor, or display-effect inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'unit_apply_damage_roster_key_pair') {
        validationPending.push('native-gated 0x005f packet source and complete ten-hero 0x0089 keyframe roster',
          'full raw-key equality and both source references; no actor, source, target, or applied-damage inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'unit_apply_damage_lookup_roster_key_pair') {
        validationPending.push('v3 native-gated 0x005f callback +0x24 lookup key and complete ten-hero 0x0089 keyframe roster',
          'full lookup-key equality and both source references; no proven lookup success, actor, source, target, or applied-damage inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'unit_apply_damage_lookup2c_roster_key_pair') {
        validationPending.push('v3 native-gated 0x005f callback +0x2c lookup key and complete ten-hero 0x0089 keyframe roster',
          'full lookup-key equality and both source references; no proven lookup success, actor, source, target, or applied-damage inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'hero_death_damage_lookup_key_cooccurrence') {
        validationPending.push('exact 821 death route, complete ten-hero roster and every native-gated v3 0x005f packet',
          'same-chunk and same-ms +0x24 victim-key co-occurrence with all packets and +0x2c die-source comparisons; no fatal packet, actor, source, target or applied-damage inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_remove_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x047c full packet consumption',
          'callback-transformed opaque fields and raw packet provenance; no buff identity or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_add_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x00ae full packet consumption',
          'callback-transformed opaque fields and raw packet provenance; no buff identity or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_update_num_counter_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x0194 full packet consumption',
          'callback-transformed anonymous fields and raw packet provenance; no owner, buff identity, counter meaning, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_update_count_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x02d9 full packet consumption',
          'callback-transformed anonymous fields and raw packet provenance; no owner, buff identity, counter meaning, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'npc_buff_replace_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x01ad full packet consumption',
          'callback-transformed anonymous fields and raw packet provenance; no owner, buff identity, replacement effect, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'set_spell_timer_from_buff_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x00fd full packet consumption',
          'callback-transformed anonymous fields and raw packet provenance; no owner, buff identity, spell identity, timer effect, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'set_spell_level_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x025d full packet consumption',
          'callback-transformed anonymous fields and raw packet provenance; no owner, spell identity, level change, or lifecycle inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'direct_input_movement_turn_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x00ba full packet consumption',
          'three callback-transformed opaque f32 fields and raw packet provenance; no world-position, general hero-path or participant inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'set_movement_driver_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x0335 full packet consumption',
          'one callback-transformed opaque dispatch byte and raw packet provenance; no driver-state transition, position, path or participant inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'increment_minion_kills_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native 0x03a7 full packet consumption',
          'callback-transformed packet-local lookup key and raw packet provenance; no proven lookup success, participant, minion, last hit, or CS delta');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'notify_contextual_situation_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full packet consumption',
          'packet-local UTF-8 contextual situation string and raw packet provenance; no actor, Recall action, or gameplay-effect inference');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'item_group_data_broadcast_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full packet consumption',
          'packet-local callback lookup key; live receiver lookup, group identity and inventory effect remain unknown');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'cooldown_broadcast_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full 0x039d packet consumption',
          'packet-local callback lookup key; receiver lookup, cooldown state, slot, actor, target and effect remain unknown');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'item_charges_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full 0x0437 packet consumption',
          'packet-local callback selector/value before receiver method; item identity, charges, slot, owner and effect remain unknown');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'target_hero_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full 0x0265 packet consumption',
          'packet-local callback u32; resolved target object, source actor, receiver state and effect remain unknown');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'force_create_missile_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full 0x0087 packet consumption',
          'packet-local comparison u32 under synthetic receiver; live receiver, missile identity, owner, target, creation, effect and causality remain unknown');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'change_missile_target_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full 0x040c packet consumption',
          'packet-local comparison u32 before live receiver comparison; receiver match, missile identity, owner, resolved target, target change and effect remain unknown');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'set_dimension_missile_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and native full 0x008a packet consumption',
          'packet-local callback u8 before receiver method; receiver state, missile identity, owner, target, dimension change, effect and causality remain unknown');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'face_direction_packet') {
        validationPending.push('exact 821 runtime image SHA-256 and bounded 0x038e packet shape validation',
          'packet-local unit-vector and optional scalar candidates with raw provenance; no actor, world position, path or direction effect');
      }
      if (profile.game_version === '16.19.821.7343'
          && capability === 'face_direction_keyframe_roster_pair') {
        validationPending.push('exact 821 FaceDirection image and complete 0x0089 ten-participant MINIONS_KILLED keyframe source',
          'same chunk, time, full raw parameter and Stats-before-Face ordering; roster participant label does not identify the Face packet actor');
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
          && capability === 'hero_jungle_minions_killed_snapshot') {
        validationPending.push('ten-participant total, own-jungle, and enemy-jungle neutral-minion tails',
          'HN keyframe 0x0276 offsets 0x40/0x44/0x48 and observed sequences');
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
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_assists_snapshot') {
        validationPending.push('ten-participant ASSISTS tail values',
          'HN keyframe 0x0276 offset 0x54 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_kill_stats_snapshot') {
        validationPending.push('ten-participant killing-spree and multi-kill tail values',
          'HN keyframe 0x0276 offsets 0x58 through 0x6c and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_ward_stats_snapshot') {
        validationPending.push('ten-participant ward placed, killed, and detector tail values',
          'HN keyframe 0x0276 offsets 0x1a4 through 0x1ac and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_damage_totals_snapshot') {
        validationPending.push('ten-participant TOTAL_DAMAGE_DEALT_TO_CHAMPIONS, TOTAL_DAMAGE_DEALT, and TOTAL_DAMAGE_TAKEN tail values',
          'HN keyframe 0x0276 f32 offsets 0x1e0/0x1d0/0x1f0 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_damage_taken_from_champions_snapshot') {
        validationPending.push('ten-participant TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS tail values',
          'HN keyframe 0x0276 f32 offset 0x200 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_damage_self_mitigated_snapshot') {
        validationPending.push('ten-participant TOTAL_DAMAGE_SELF_MITIGATED tail values',
          'HN keyframe 0x0276 f32 offset 0x208 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_longest_living_time_snapshot') {
        validationPending.push('ten-participant LONGEST_TIME_SPENT_LIVING tail values',
          'HN keyframe 0x0276 f32 offset 0x244 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_total_time_spent_dead_snapshot') {
        validationPending.push('ten-participant TOTAL_TIME_SPENT_DEAD tail values',
          'HN keyframe 0x0276 f32 offset 0x248 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_total_heal_snapshot') {
        validationPending.push('ten-participant TOTAL_HEAL tail values',
          'HN keyframe 0x0276 u32 offset 0x234 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_total_units_healed_snapshot') {
        validationPending.push('ten-participant TOTAL_UNITS_HEALED tail values',
          'HN keyframe 0x0276 u32 offset 0x23c and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_vision_score_snapshot') {
        validationPending.push('ten-participant VISION_SCORE tail values',
          'HN keyframe 0x0276 f32 offset 0x1b0 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_epic_monster_damage_snapshot') {
        validationPending.push('ten-participant TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS tail values',
          'HN keyframe 0x0276 f32 offset 0x21c and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_crowd_control_time_snapshot') {
        validationPending.push('ten-participant TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS tail values',
          'HN keyframe 0x0276 f32 offset 0x230 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && capability === 'hero_structure_objective_damage_snapshot') {
        validationPending.push('ten-participant TOTAL_DAMAGE_DEALT_TO_BUILDINGS and TOTAL_DAMAGE_DEALT_TO_OBJECTIVES tail values',
          'HN keyframe 0x0276 f32 offsets 0x210/0x214/0x218 and observed sequences');
      }
      if (profile.game_version === '16.19.820.7193'
          && needs1619RuntimeImage) {
        validationPending.push('exact runtime image SHA-256 and decoder execution',
          capability === 'hero_inventory_mapview'
            ? 'HN 0x0420 MapView route, full packet consumption, and slot record provenance'
            : capability === 'hero_inventory_set_item'
              ? 'HN 0x03b7 SetItem route, full packet consumption, and slot/item field provenance'
              : capability === 'hero_inventory_broadcast'
                ? 'HN 0x03ef Broadcast route, full packet consumption, and record provenance'
                : capability === 'npc_buff_remove_packet'
                  ? 'HN 0x043c BuffRemove2 route, full packet consumption, and raw field provenance'
                  : 'HN 0x03ed BuffAdd2 game/keyframe route, full packet consumption, and scalar field provenance');
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
          ? perCapabilityInputsAssessed
            ? needs1619RuntimeImage ? 'EXACT_IMAGE_REQUIRED' : 'NOT_REQUIRED'
            : 'NOT_ASSESSED_PER_CAPABILITY'
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
        output: profile.game_version === '16.19.821.7343'
          ? ({ hero_death: 'hero_death_candidates',
            hero_assist: 'hero_assist_candidates',
            hero_death_timer: 'hero_death_timer_candidates',
            hero_respawn: 'hero_respawn_candidates',
            hero_deaths_snapshot: 'hero_deaths_snapshot_candidates',
            hero_champion_kills_snapshot: 'hero_champion_kills_snapshot_candidates',
            hero_assists_snapshot: 'hero_assists_snapshot_candidates',
            hero_missions_minions_killed_snapshot:
              'hero_missions_minions_killed_snapshot_candidates',
            hero_ward_stats_snapshot: 'hero_ward_stats_snapshot_candidates',
            hero_missions_cannon_minions_killed_snapshot:
              'hero_missions_cannon_minions_killed_snapshot_candidates',
            hero_minions_killed_snapshot: 'hero_minions_killed_snapshot_candidates',
            hero_jungle_minions_killed_snapshot:
              'hero_jungle_minions_killed_snapshot_candidates',
            hero_kill_stats_snapshot: 'hero_kill_stats_snapshot_candidates',
            hero_experience_snapshot: 'hero_experience_snapshot_candidates',
            hero_vision_score_snapshot: 'hero_vision_score_snapshot_candidates',
            hero_gold_earned_snapshot: 'hero_gold_earned_snapshot_candidates',
            hero_gold_spent_snapshot: 'hero_gold_spent_snapshot_candidates',
            hero_level_state: 'hero_level_state_candidates',
            hero_inventory_packet: 'hero_inventory_packet_candidates',
            hero_inventory_broadcast_packet: 'hero_inventory_broadcast_packet_candidates',
            hero_inventory_set_item_packet: 'hero_inventory_set_item_packet_candidates',
            params_heal_packet: 'params_heal_packet_candidates',
            shielding_params_packet_pair: 'shielding_params_packet_pair_candidates',
            stealth_event_packet: 'stealth_event_packet_candidates',
            champion_die_event_packet: 'champion_die_event_packet_candidates',
            champion_kill_event_packet: 'champion_kill_event_packet_candidates',
            champion_multiple_kill_event_packet: 'champion_multiple_kill_event_packet_candidates',
            champion_double_kill_event_packet: 'champion_double_kill_event_packet_candidates',
            champion_triple_quadra_event_packet: 'champion_triple_quadra_event_packet_candidates',
            on_shutdown_event_packet: 'on_shutdown_event_packet_candidates',
            resurrect_event_packet: 'resurrect_event_packet_candidates',
            revive_ally_event_packet: 'revive_ally_event_packet_candidates',
            first_blood_assist_event_packet: 'first_blood_assist_event_packet_candidates',
            objective_steal_event_packet: 'objective_steal_event_packet_candidates',
            turret_die_event_packet: 'turret_die_event_packet_candidates',
            dampener_die_event_packet: 'dampener_die_event_packet_candidates',
            turret_first_blood_event_packet: 'turret_first_blood_event_packet_candidates',
            hq_kill_event_packet: 'hq_kill_event_packet_candidates',
            turret_plate_event_packet: 'turret_plate_event_packet_candidates',
            objective_bounty_claimed_packet: 'objective_bounty_claimed_packet_candidates',
            cast_spell_ans_packet: 'cast_spell_ans_packet_candidates',
            npc_buff_remove_packet: 'npc_buff_remove_packet_candidates',
            npc_buff_add_packet: 'npc_buff_add_packet_candidates',
            npc_buff_update_num_counter_packet:
              'npc_buff_update_num_counter_packet_candidates',
            npc_buff_update_count_packet:
              'npc_buff_update_count_packet_candidates',
            npc_buff_replace_packet: 'npc_buff_replace_packet_candidates',
            set_spell_timer_from_buff_packet:
              'set_spell_timer_from_buff_packet_candidates',
            set_spell_level_packet: 'set_spell_level_packet_candidates',
            direct_input_movement_turn_packet:
              'direct_input_movement_turn_packet_candidates',
            set_movement_driver_packet: 'set_movement_driver_packet_candidates',
            increment_minion_kills_packet: 'increment_minion_kills_packet_candidates',
            face_direction_packet: 'face_direction_packet_candidates',
            circular_movement_restriction_packet:
              'circular_movement_restriction_packet_candidates',
            notify_contextual_situation_packet:
              'notify_contextual_situation_packet_candidates',
            item_group_data_broadcast_packet:
              'item_group_data_broadcast_packet_candidates',
            cooldown_broadcast_packet:
              'cooldown_broadcast_packet_candidates',
            item_charges_packet: 'item_charges_packet_candidates',
            target_hero_packet:
              'target_hero_packet_candidates',
            force_create_missile_packet:
              'force_create_missile_packet_candidates',
            change_missile_target_packet:
              'change_missile_target_packet_candidates',
            set_dimension_missile_packet:
              'set_dimension_missile_packet_candidates',
            unit_apply_damage_packet: 'unit_apply_damage_packet_candidates',
            show_health_bar_packet: 'show_health_bar_packet_candidates',
            unit_apply_damage_roster_key_pair: 'unit_apply_damage_roster_key_candidates',
            unit_apply_damage_lookup_roster_key_pair:
              'unit_apply_damage_lookup_roster_key_candidates',
            unit_apply_damage_lookup2c_roster_key_pair:
              'unit_apply_damage_lookup2c_roster_key_candidates',
            hero_death_damage_lookup_key_cooccurrence:
              'hero_death_damage_lookup_key_cooccurrence_candidates',
            face_direction_keyframe_roster_pair:
              'face_direction_keyframe_roster_pair_candidates',
            hero_damage_totals_snapshot: 'hero_damage_totals_snapshot_candidates',
            hero_damage_taken_from_champions_snapshot:
              'hero_damage_taken_from_champions_snapshot_candidates',
            hero_damage_self_mitigated_snapshot:
              'hero_damage_self_mitigated_snapshot_candidates',
            hero_structure_objective_damage_snapshot:
              'hero_structure_objective_damage_snapshot_candidates',
            hero_longest_living_time_snapshot:
              'hero_longest_living_time_snapshot_candidates',
            hero_total_time_spent_dead_snapshot:
              'hero_total_time_spent_dead_snapshot_candidates',
            hero_total_heal_snapshot: 'hero_total_heal_snapshot_candidates',
            hero_total_units_healed_snapshot: 'hero_total_units_healed_snapshot_candidates',
            hero_epic_monster_damage_snapshot:
              'hero_epic_monster_damage_snapshot_candidates',
            hero_crowd_control_time_snapshot:
              'hero_crowd_control_time_snapshot_candidates' })[capability] ?? null
          : profile.game_version === '16.19.820.7193'
          ? ({
            hero_death: 'hero_death_candidates',
            hero_death_timer: 'hero_death_timer_candidates',
            hero_respawn: 'hero_respawn_candidates',
            hero_level_state: 'hero_level_state_candidates',
            hero_minions_killed_snapshot: 'hero_minions_killed_snapshot_candidates',
            hero_jungle_minions_killed_snapshot: 'hero_jungle_minions_killed_snapshot_candidates',
            hero_experience_snapshot: 'hero_experience_snapshot_candidates',
            hero_gold_earned_snapshot: 'hero_gold_earned_snapshot_candidates',
            hero_gold_spent_snapshot: 'hero_gold_spent_snapshot_candidates',
            hero_champion_kills_snapshot: 'hero_champion_kills_snapshot_candidates',
            hero_deaths_snapshot: 'hero_deaths_snapshot_candidates',
            hero_assists_snapshot: 'hero_assists_snapshot_candidates',
            hero_kill_stats_snapshot: 'hero_kill_stats_snapshot_candidates',
            hero_ward_stats_snapshot: 'hero_ward_stats_snapshot_candidates',
            hero_damage_totals_snapshot: 'hero_damage_totals_snapshot_candidates',
            hero_damage_taken_from_champions_snapshot:
              'hero_damage_taken_from_champions_snapshot_candidates',
            hero_damage_self_mitigated_snapshot:
              'hero_damage_self_mitigated_snapshot_candidates',
            hero_longest_living_time_snapshot:
              'hero_longest_living_time_snapshot_candidates',
            hero_total_time_spent_dead_snapshot:
              'hero_total_time_spent_dead_snapshot_candidates',
            hero_total_heal_snapshot: 'hero_total_heal_snapshot_candidates',
            hero_total_units_healed_snapshot:
              'hero_total_units_healed_snapshot_candidates',
            hero_vision_score_snapshot: 'hero_vision_score_snapshot_candidates',
            hero_epic_monster_damage_snapshot: 'hero_epic_monster_damage_snapshot_candidates',
            hero_crowd_control_time_snapshot: 'hero_crowd_control_time_snapshot_candidates',
            hero_structure_objective_damage_snapshot:
              'hero_structure_objective_damage_snapshot_candidates',
            hero_inventory_mapview: 'hero_inventory_mapview_candidates',
            hero_inventory_set_item: 'hero_inventory_set_item_candidates',
            hero_inventory_broadcast: 'hero_inventory_broadcast_candidates',
            npc_buff_remove_packet: 'npc_buff_remove_packet_candidates',
            npc_buff_add_packet: 'npc_buff_add_packet_candidates',
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
    process.stdout.write('Scope: container, registry, and selected dependency checks; packet framing and semantic decode not run.\n');
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

async function runQueryEventsCommand(parsed) {
  const { options, positionals } = parsed;
  let outputPath = null;
  let writer = process.stdout;
  let createdOutput = false;
  let stagedStdoutDirectory = null;
  let stagedStdoutPath = null;
  let createdStaging = false;
  try {
    const artifactDirectory = path.resolve(positionals[0]);
    const batch = fs.existsSync(path.join(artifactDirectory, 'manifest.json'));
    if (options.listEvents) {
      process.stdout.write(`${JSON.stringify(listSavedEvents(artifactDirectory, batch))}\n`);
      return 0;
    }
    if (options.output && options.output !== '-') {
      outputPath = path.resolve(options.output);
      const relative = path.relative(artifactDirectory, outputPath);
      const outsideArtifacts = relative === '..'
        || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
      // Keep paths inside the artifact tree on the input-alias check below.
      // An existing external output can be rejected before hashing batch events.
      if (outsideArtifacts && fs.existsSync(outputPath)) {
        throw new EventQueryError('OUTPUT_EXISTS',
          `Query output already exists: ${outputPath}`);
      }
    }
    const prepared = batch
      ? prepareBatchEventQuery(artifactDirectory, options.event)
      : prepareEventQuery(artifactDirectory, options.event);
    if (options.output && options.output !== '-') {
      const replayInputs = batch ? prepared.replays
        .flatMap((replay) => [replay.prepared?.inputPath,
          path.join(replay.replayDirectory, 'semantic_run.json'),
          path.join(replay.replayDirectory, 'replay_analysis.json')]).filter(Boolean)
        : [prepared.inputPath,
          path.join(prepared.artifactDirectory, 'semantic_run.json'),
          path.join(prepared.artifactDirectory, 'replay_analysis.json')];
      const protectedPaths = batch
        ? [path.join(prepared.artifactDirectory, 'manifest.json'), ...replayInputs]
        : replayInputs;
      const normalize = (filename) => process.platform === 'win32'
        ? filename.toLowerCase() : filename;
      if (protectedPaths.some((filename) => normalize(filename) === normalize(outputPath))) {
        throw new EventQueryError('UNSAFE_OUTPUT',
          'Query output must not replace its event JSONL or Replay metadata.');
      }
      await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
      let handle;
      try {
        handle = await fs.promises.open(outputPath, 'wx');
      } catch (error) {
        if (error.code === 'EEXIST') {
          throw new EventQueryError('OUTPUT_EXISTS',
            `Query output already exists: ${outputPath}`);
        }
        throw error;
      }
      writer = handle.createWriteStream();
      createdOutput = true;
    } else {
      // A later invalid JSONL row or digest must not leave a partial stdout
      // result. Spool only selected rows, then publish them after validation.
      stagedStdoutDirectory = await fs.promises.mkdtemp(
        path.join(os.tmpdir(), 'rofl-query-'));
      stagedStdoutPath = path.join(stagedStdoutDirectory, 'selected.jsonl');
      const handle = await fs.promises.open(stagedStdoutPath, 'wx');
      writer = handle.createWriteStream();
      createdStaging = true;
    }
    const filters = {
      fromMs: options.fromMs,
      toMs: options.toMs,
      participant: options.participant,
      killerParticipant: options.killerParticipant,
      assistingParticipant: options.assistingParticipant,
      rawParam: options.rawParam,
      contextualSituation: options.contextualSituation,
      itemId: options.itemId,
      previousItemId: options.previousItemId,
      slot: options.slot,
      opaqueU32: options.opaqueU32,
      itemGroupCallbackU8: options.itemGroupCallbackU8,
      itemChargesSelectorU8: options.itemChargesSelectorU8,
      itemChargesValueU16: options.itemChargesValueU16,
      opaquePair: options.opaquePair,
      opaqueI32: options.opaqueI32,
      castNestedBits: options.castNestedBits,
      castNestedU32: options.castNestedU32,
      castNestedU32At4c: options.castNestedU32At4c,
      castNestedF32AtA0: options.castNestedF32AtA0,
      castNestedU32At28: options.castNestedU32At28,
      spellTimerReceiverSlot: options.spellTimerReceiverSlot,
      spellLevelReceiverIndex: options.spellLevelReceiverIndex,
      spellLevelClampedScalar: options.spellLevelClampedScalar,
      damageCallbackF32Available: options.damageCallbackF32Available,
      damageCallbackU32At10: options.damageCallbackU32At10,
      damageCallbackU32At1c: options.damageCallbackU32At1c,
      damageCallbackF32At18Raw: options.damageCallbackF32At18Raw,
      damageLookupKey24: options.damageLookupKey24,
      damageLookupKey2c: options.damageLookupKey2c,
      dieSourceKey2cMatch: options.dieSourceKey2cMatch,
      showHealthZeroFlag: options.showHealthZeroFlag,
      packetRecordCount: options.packetRecordCount,
      levelAfter: options.levelAfter,
      childEventId: options.childEventId,
      latestPerParticipant: options.latestPerParticipant,
      endpointReversedPair: options.endpointReversedPair,
      comparisonToEndpoints: options.comparisonToEndpoints,
      limit: options.limit,
      verifySource: options.verifySource,
      sourceReplay: options.sourceReplay,
    };
    const emitLine = async (line) => {
      if (!writer.write(line)) await once(writer, 'drain');
    };
    const summary = batch
      ? await streamBatchEventQuery(prepared, filters, emitLine)
      : await streamEventQuery(prepared, filters, emitLine);
    if (createdOutput || createdStaging) {
      writer.end();
      await finished(writer);
    }
    if (createdStaging) {
      for await (const chunk of fs.createReadStream(stagedStdoutPath)) {
        if (!process.stdout.write(chunk)) await once(process.stdout, 'drain');
      }
    }
    summary.output = outputPath ?? '-';
    (outputPath ? process.stdout : process.stderr).write(`${JSON.stringify(summary)}\n`);
    return 0;
  } catch (error) {
    if (createdOutput || createdStaging) {
      writer.destroy();
      await finished(writer).catch(() => {});
    }
    if (createdOutput) {
      await fs.promises.rm(outputPath, { force: true });
    }
    if (error instanceof EventQueryError) {
      process.stderr.write(`${JSON.stringify({ query_status: 'FAILED', code: error.code,
        error: error.message, ...error.details })}\n`);
      return 2;
    }
    throw error;
  } finally {
    if (stagedStdoutPath) {
      await fs.promises.rm(stagedStdoutPath, { force: true });
    }
    if (stagedStdoutDirectory) {
      await fs.promises.rmdir(stagedStdoutDirectory);
    }
  }
}

function failedBatchWorker(filePath, message, details = null) {
  return {
    ok: false,
    source_path: path.resolve(filePath),
    error: { code: 'WORKER_FAILED', message, details, name: 'Error' },
  };
}

function runOneBatchWorker(filePath, options, rootDir, replayDirName, workerScript) {
  return new Promise((resolve) => {
    let worker;
    try {
      worker = new Worker(workerScript, {
        workerData: { filePath, options, rootDir, replayDirName },
      });
    } catch (error) {
      resolve(failedBatchWorker(filePath, `Replay worker could not start: ${error.message}`));
      return;
    }
    let reported = null;
    let workerError = null;
    worker.on('message', (value) => { reported = value; });
    worker.on('error', (error) => { workerError = error; });
    worker.on('exit', (code) => {
      if (code !== 0 || workerError) {
        resolve(failedBatchWorker(filePath,
          `Replay worker exited ${code}: ${workerError?.message ?? 'no completed result'}`,
          { worker_exit_code: code }));
      } else if (!reported || typeof reported !== 'object'
          || typeof reported.ok !== 'boolean'
          || (reported.ok && (reported.analysis?.events !== null
            || reported.analysis?.artifact_directory !== path.posix.join('replays', replayDirName)))
          || (!reported.ok && (!reported.error || reported.source_path !== path.resolve(filePath)))) {
        resolve(failedBatchWorker(filePath, 'Replay worker returned an invalid compact result'));
      } else {
        resolve(reported);
      }
    });
  });
}

async function runBatchWorkers(files, options, rootDir, jobs = 2,
  workerScript = path.join(__dirname, 'batch_worker.js')) {
  const replayDirNames = replayDirectoryNames(files.map((source_path) => ({ source_path })));
  const results = new Array(files.length);
  let next = 0;
  async function runLane() {
    while (next < files.length) {
      const index = next++;
      const name = replayDirNames[index];
      const result = await runOneBatchWorker(files[index], options, rootDir, name, workerScript);
      if (!result.ok) {
        const replayDir = path.join(rootDir, 'replays', name);
        if (fs.existsSync(replayDir)) {
          const relative = path.posix.join('failed_replays', `${index + 1}-${name}`);
          const preserved = path.join(rootDir, relative);
          ensureDir(path.dirname(preserved));
          fs.renameSync(replayDir, preserved);
          result.error.details = {
            ...(result.error.details ?? {}), partial_artifact_directory: relative,
          };
        }
      }
      results[index] = result;
    }
  }
  await Promise.all(Array.from({ length: Math.min(jobs, files.length) }, runLane));
  return results;
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
  if (parsed.command === 'query-events') return runQueryEventsCommand(parsed);
  const inputs = parsed.positionals.length > 0 ? parsed.positionals : ['replay'];
  const files = discoverReplayFiles(inputs);
  if (files.length === 0) throw new Error('No .rofl files found in the supplied input.');
  const beforeHashes = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const parseOptions = { ...parsed.options, semantic: parsed.command !== 'inspect' };
  const parallel = parsed.options.jobs === 2;
  const workerOutputRoot = parallel ? reserveOutputDirectory(parsed.options.outDir) : null;
  const results = parallel
    ? await runBatchWorkers(files, parseOptions, workerOutputRoot)
    : files.map((filePath) => parsed.options.jobs === 1
      ? parseOneExact821Batch(filePath, parseOptions) : parseOne(filePath, parseOptions));
  const testSummary = parsed.command === 'validate' ? runTestSuite() : null;
  const afterHashes = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const validationDetailsDir = parsed.command === 'validate' && parsed.options.detailsDir
    ? path.resolve(parsed.options.detailsDir)
    : null;
  const outDir = workerOutputRoot ?? reserveOutputDirectory(parsed.options.outDir);
  const summary = await writeRunArtifacts(
    results,
    outDir,
    beforeHashes,
    afterHashes,
    argv,
    testSummary,
    validationDetailsDir,
    { ...parsed.options, prewrittenReplayArtifacts: parallel },
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
  parseOneExact821Batch,
  writePerReplayArtifacts,
  runBatchWorkers,
  v2InputsForReplay,
  inventoryFromAnalysis,
  buildAcceptanceSummary,
  reserveOutputDirectory,
  capabilityQuery,
  runCapabilitiesCommand,
  runQueryEventsCommand,
  main,
};
