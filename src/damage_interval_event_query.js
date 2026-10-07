'use strict';

const fs = require('node:fs');
const readline = require('node:readline');
const {isDeepStrictEqual} = require('node:util');
const {parseReplayFile} = require('./rofl');
const {decodeSemanticReplay} = require('./semantic_api');
const {DAMAGE_KEYFRAME_INTERVALS_821_PROFILE: PROFILE} =
  require('./decoders/rofl_16_19_821_damage_keyframe_intervals_candidate');
const {decodeHeroDamageFieldBytes821} =
  require('./decoders/rofl_16_19_821_damage_float_candidate');

const EVENT = 'hero_damage_keyframe_interval_candidates';
const supports = key => key === EVENT;
const count = value => Number.isSafeInteger(value) && value >= 0;
const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const shape = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
const FIELDS = PROFILE.fields.map(field => field.replay_tail_field);
const ROW_KEYS = ['event_type','game_version','patch','build_profile','replay_sha256','replay_time_ms',
  'participant_id_candidate','hero_raw_param','confidence','semantic_status','observation_scope',
  'change_time_status','previous_observation_time_ms','current_observation_time_ms','interval_duration_ms',
  'any_counter_changed','counters','previous_raw_payload_field_bytes_hex','current_raw_payload_field_bytes_hex',
  'previous_raw_packet_ref','current_raw_packet_ref','raw_packet_ref','raw_packet_refs'];
const REF_KEYS = ['source_path','replay_sha256','chunk_index','chunk_id','chunk_stream','chunk_file_offset',
  'decompressed_block_offset','decompressed_payload_offset','packet_id','replay_time_ms','payload_length',
  'raw_param','raw_payload_sha256'];
const COUNTER_KEYS = ['previous_raw_f32_candidate','current_raw_f32_candidate',
  'endpoint_delta_f32_candidate','endpoint_floor_difference_candidate'];
const GAP_KEYS = ['replay_tail_field','participant_id_candidate','last_snapshot_replay_time_ms',
  'last_snapshot_raw_f32_candidate','last_snapshot_floor_candidate','final_replay_tail','unobserved_tail_gap',
  'unobserved_tail_time_ms','last_raw_packet_ref'];
const RESULT_KEYS = ['profile_id','input_packet_id','depends_on','evidence_runtime_image_sha256',
  'lookup_table_sha256','runtime_image_used','runtime_image_status','known_limits','status','evidence_status',
  'dependency_statuses','input_count','keyframe_count','observed_participant_count','observed_interval_count',
  'changed_interval_count','unchanged_interval_count','changed_interval_counts_by_field','tail_gaps','event_count'];

function createDamageIntervalQuery({EventQueryError,normalizeReplaySourcePaths}) {
  const fail = (code,message) => {throw new EventQueryError(code,message);};
  function prepare(prepared,semantic,analysis) {
    if (!supports(prepared.eventKey)) return;
    const result = prepared.capabilityResult;
    if (prepared.replayVersion !== PROFILE.replay_version) {
      fail('UNSUPPORTED_EVENT_BUILD','Damage intervals require exact KR 16.19.821.7343.');
    }
    if (!shape(result,RESULT_KEYS) || result.status !== 'CANDIDATE' || result.profile_id !== PROFILE.id
        || result.evidence_status !== 'CANDIDATE_821_SAMPLED_DAMAGE_COUNTER_ENDPOINT_DIFFERENCE'
        || result.input_packet_id !== 0x0089
        || result.evidence_runtime_image_sha256 !== PROFILE.evidence_runtime_image_sha256
        || result.lookup_table_sha256 !== PROFILE.lookup_table_sha256
        || result.runtime_image_used !== false
        || result.runtime_image_status !== 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED'
        || !isDeepStrictEqual(result.depends_on,[...PROFILE.depends_on])
        || !isDeepStrictEqual(result.known_limits,[...PROFILE.known_limits])
        || !isDeepStrictEqual(result.dependency_statuses,Object.fromEntries(PROFILE.depends_on.map(name=>[name,'CANDIDATE'])))
        || !count(result.keyframe_count) || result.keyframe_count < 1
        || result.input_count !== result.keyframe_count*10 || result.observed_participant_count !== 10
        || result.event_count !== (result.keyframe_count-1)*10
        || result.observed_interval_count !== result.event_count
        || !count(result.changed_interval_count) || !count(result.unchanged_interval_count)
        || result.changed_interval_count+result.unchanged_interval_count !== result.event_count
        || !shape(result.changed_interval_counts_by_field,FIELDS)
        || FIELDS.some(field=>!count(result.changed_interval_counts_by_field[field])
          || result.changed_interval_counts_by_field[field]>result.changed_interval_count)
        || !Array.isArray(result.tail_gaps) || result.tail_gaps.length !== 40
        || !isDeepStrictEqual(analysis.semantic?.capability_results?.[PROFILE.capability],result)) {
      fail('CAPABILITY_METADATA_MISMATCH','Damage interval profile, dependencies or complete counts differ.');
    }
    if (prepared.eventStorage === 'EMBEDDED_AND_JSONL') {
      prepared.damageIntervalEmbeddedRows = analysis.events[EVENT];
    }
  }

  function checkRef(ref,prepared,time,param) {
    return shape(ref,REF_KEYS) && ref.source_path === (prepared.sourcePath ?? null)
      && ref.replay_sha256 === prepared.replaySha && ref.packet_id === 0x0089
      && ref.chunk_stream === 'keyframe' && ref.payload_length === 1263
      && ref.replay_time_ms === time && ref.raw_param === param
      && ['chunk_index','chunk_id','chunk_file_offset','decompressed_block_offset',
        'decompressed_payload_offset'].every(key=>count(ref[key]))
      && ref.decompressed_payload_offset > ref.decompressed_block_offset && sha(ref.raw_payload_sha256);
  }

  function rememberRef(ref,state) {
    const position = ref.chunk_index+'/'+ref.decompressed_block_offset;
    const previous = state.refs.get(position);
    if (previous && !isDeepStrictEqual(previous,ref)) {
      fail('INVALID_EVENT_ROW','A damage endpoint position refers to inconsistent packets.');
    }
    state.refs.set(position,ref);
  }

  function validate(row,prepared,index,state) {
    const participant = (index-1)%10+1, param = 0x400000ad+participant;
    const previous = state.last.get(participant);
    const start = row.previous_observation_time_ms, end = row.current_observation_time_ms;
    if (!shape(row,ROW_KEYS) || row.event_type !== 'HERO_DAMAGE_KEYFRAME_INTERVAL_CANDIDATE'
        || row.game_version !== PROFILE.replay_version || row.patch !== '16.19' || row.build_profile !== PROFILE.id
        || row.replay_sha256 !== prepared.replaySha || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_821_SAMPLED_DAMAGE_COUNTER_ENDPOINT_DIFFERENCE'
        || row.observation_scope !== 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY'
        || row.change_time_status !== 'UNRESOLVED_WITHIN_INTERVAL'
        || row.participant_id_candidate !== participant || row.hero_raw_param !== param
        || !count(start) || !count(end) || end <= start || row.replay_time_ms !== end
        || row.interval_duration_ms !== end-start || !shape(row.counters,FIELDS)
        || !shape(row.previous_raw_payload_field_bytes_hex,FIELDS)
        || !shape(row.current_raw_payload_field_bytes_hex,FIELDS)
        || !checkRef(row.previous_raw_packet_ref,prepared,start,param)
        || !checkRef(row.current_raw_packet_ref,prepared,end,param)
        || row.current_raw_packet_ref.chunk_index <= row.previous_raw_packet_ref.chunk_index
        || !isDeepStrictEqual(row.raw_packet_ref,row.current_raw_packet_ref)
        || !isDeepStrictEqual(row.raw_packet_refs,[row.previous_raw_packet_ref,row.current_raw_packet_ref])
        || (previous && (!isDeepStrictEqual(row.previous_raw_packet_ref,previous.current_raw_packet_ref)
          || !isDeepStrictEqual(row.previous_raw_payload_field_bytes_hex,previous.current_raw_payload_field_bytes_hex)))) {
      fail('INVALID_EVENT_ROW','Invalid complete damage interval at line '+index+'.');
    }
    rememberRef(row.previous_raw_packet_ref,state);
    rememberRef(row.current_raw_packet_ref,state);
    const frameIdentity = [start,end,...[row.previous_raw_packet_ref,row.current_raw_packet_ref]
      .flatMap(ref=>[ref.chunk_index,ref.chunk_id,ref.chunk_file_offset])];
    if (participant === 1) state.frameIdentity = frameIdentity;
    else if (!isDeepStrictEqual(frameIdentity,state.frameIdentity)) {
      fail('INVALID_EVENT_ROW','Damage interval frame endpoints differ at line '+index+'.');
    }
    let changed = false;
    for (const field of FIELDS) {
      const a = decodeHeroDamageFieldBytes821(row.previous_raw_payload_field_bytes_hex[field]);
      const b = decodeHeroDamageFieldBytes821(row.current_raw_payload_field_bytes_hex[field]);
      const delta = b-a, counter = row.counters[field];
      if (!Number.isFinite(a) || !Number.isFinite(b) || a < 0 || b < a
          || !Number.isSafeInteger(Math.floor(b)) || (!previous && a !== 0)
          || !shape(counter,COUNTER_KEYS) || counter.previous_raw_f32_candidate !== a
          || counter.current_raw_f32_candidate !== b || counter.endpoint_delta_f32_candidate !== delta
          || counter.endpoint_floor_difference_candidate !== Math.floor(b)-Math.floor(a)) {
        fail('INVALID_EVENT_ROW','Protected damage endpoint/counter differs at line '+index+'.');
      }
      if (delta > 0) {changed = true;state.changedFields[field]++;}
    }
    if (row.any_counter_changed !== changed) fail('INVALID_EVENT_ROW','Damage changed marker differs at line '+index+'.');
    if (changed) state.changed++;
    state.last.set(participant,row);
  }

  function validateGaps(prepared,state) {
    const seen = new Set();
    for (const gap of prepared.capabilityResult.tail_gaps) {
      if (!shape(gap,GAP_KEYS)) fail('CAPABILITY_METADATA_MISMATCH','Invalid damage tail gap schema.');
      const participant = gap.participant_id_candidate, field = gap.replay_tail_field;
      const last = state.last.get(participant), value = last?.counters[field]?.current_raw_f32_candidate ?? 0;
      const key = participant+'/'+field;
      if (!shape(gap,GAP_KEYS) || !count(participant) || participant<1 || participant>10 || !FIELDS.includes(field)
          || seen.has(key) || !count(gap.last_snapshot_replay_time_ms)
          || gap.last_snapshot_raw_f32_candidate !== value || gap.last_snapshot_floor_candidate !== Math.floor(value)
          || !count(gap.final_replay_tail) || gap.final_replay_tail < Math.floor(value)
          || gap.unobserved_tail_gap !== gap.final_replay_tail-Math.floor(value)
          || (gap.unobserved_tail_time_ms !== null && !count(gap.unobserved_tail_time_ms))
          || !checkRef(gap.last_raw_packet_ref,prepared,gap.last_snapshot_replay_time_ms,0x400000ad+participant)
          || (last && (!isDeepStrictEqual(gap.last_raw_packet_ref,last.current_raw_packet_ref)
            || gap.last_snapshot_replay_time_ms !== last.current_observation_time_ms))) {
        fail('CAPABILITY_METADATA_MISMATCH','Damage final sampled endpoints or unobserved tail gaps differ.');
      }
      rememberRef(gap.last_raw_packet_ref,state);
      seen.add(key);
    }
  }

  function physical(prepared,options) {
    if (!options.verifySource) return null;
    const source = options.sourceReplay ?? prepared.sourcePath;
    if (typeof source !== 'string' || !source.trim()) fail('MISSING_SOURCE_REPLAY','No original Replay path is available.');
    let replay;
    try {replay=parseReplayFile(source);} catch(error) {
      fail(error.code==='INPUT_READ_ERROR'?'SOURCE_REPLAY_READ_FAILED':'SOURCE_REPLAY_INVALID',error.message);
    }
    if (replay.source_sha256 !== prepared.replaySha || replay.header.version !== prepared.replayVersion) {
      fail('SOURCE_REPLAY_IDENTITY_MISMATCH','Original Replay hash/build differs.');
    }
    let decoded;
    try {decoded=decodeSemanticReplay(replay,{capabilities:[PROFILE.capability]});}
    catch(error) {fail('SOURCE_REPLAY_DECODE_FAILED',error.message);}
    const result = decoded.capability_results?.[PROFILE.capability];
    if (result?.status !== 'CANDIDATE') fail('SOURCE_REPLAY_DECODE_FAILED','Original damage interval decoding is unavailable.');
    if (!isDeepStrictEqual(normalizeReplaySourcePaths(result,prepared.sourcePath ?? null),prepared.capabilityResult)) {
      fail('SOURCE_PROVENANCE_MISMATCH','Complete damage interval metadata differs from original Replay decoding.');
    }
    return {rows:decoded.events[EVENT],source:replay.source_path};
  }

  async function stream(prepared,options,emitLine) {
    const allowed = new Set(['fromMs','toMs','participant','rawParam','limit','verifySource','sourceReplay']);
    for (const [key,value] of Object.entries(options)) {
      if (!allowed.has(key) && value != null && value !== false) fail('UNSUPPORTED_FILTER',key+' is not supported on sampled damage intervals.');
    }
    if (options.sourceReplay != null && !options.verifySource) fail('INVALID_FILTER','--source-replay requires --verify-source.');
    const verified = physical(prepared,options);
    const state = {last:new Map(),refs:new Map(),changed:0,changedFields:Object.fromEntries(FIELDS.map(field=>[field,0]))};
    let scanned=0,matched=0,emitted=0;
    const input = fs.createReadStream(prepared.inputPath,{encoding:'utf8'});
    const lines = readline.createInterface({input,crlfDelay:Infinity});
    try {
      for await (const line of lines) {
        if (++scanned > prepared.declaredCount) fail('EVENT_COUNT_MISMATCH','Extra damage interval rows.');
        let row;
        try {row=JSON.parse(line);} catch {fail('INVALID_EVENT_ROW','Invalid JSON at damage interval line '+scanned+'.');}
        if (!row || typeof row !== 'object' || Array.isArray(row)) fail('INVALID_EVENT_ROW','Damage interval must be an object.');
        if (prepared.damageIntervalEmbeddedRows
            && !isDeepStrictEqual(row,prepared.damageIntervalEmbeddedRows[scanned-1])) {
          fail('INVALID_EVENT_ROW','Embedded and JSONL damage intervals differ.');
        }
        validate(row,prepared,scanned,state);
        if (verified && !isDeepStrictEqual(row,normalizeReplaySourcePaths(verified.rows[scanned-1],prepared.sourcePath ?? null))) {
          fail('SOURCE_PROVENANCE_MISMATCH','Damage interval line '+scanned+' differs from the complete original Replay.');
        }
        if ((options.fromMs != null && row.replay_time_ms < options.fromMs)
            || (options.toMs != null && row.replay_time_ms > options.toMs)
            || (options.participant != null && row.participant_id_candidate !== options.participant)
            || (options.rawParam != null && row.hero_raw_param !== options.rawParam)) continue;
        matched++;
        if (options.limit == null || emitted < options.limit) {await emitLine(line+'\n');emitted++;}
      }
    } finally {lines.close();input.destroy();}
    if (scanned !== prepared.declaredCount) fail('EVENT_COUNT_MISMATCH','Incomplete damage interval rows.');
    const result = prepared.capabilityResult;
    if (state.changed !== result.changed_interval_count
        || !isDeepStrictEqual(state.changedFields,result.changed_interval_counts_by_field)) {
      fail('EVENT_COUNT_MISMATCH','Complete damage changed/unchanged counts differ.');
    }
    validateGaps(prepared,state);
    return {schema_version:1,command:'query-events',query_status:'COMPLETE',
      artifact_directory:prepared.artifactDirectory,event_key:EVENT,replay_version:prepared.replayVersion,
      replay_sha256:prepared.replaySha,capability_status:'CANDIDATE',declared_event_count:prepared.declaredCount,
      scanned_count:scanned,matched_count:matched,emitted_count:emitted,rows_unmodified:true,
      observation_scope:'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY',
      source_provenance_status:verified?'SOURCE_REPLAY_VERIFIED':'SAVED_ONLY_UNVERIFIED',
      ...(verified?{source_replay:verified.source}:{}),
      filters:{from_ms:options.fromMs??null,to_ms:options.toMs??null,participant:options.participant??null,
        raw_param:options.rawParam??null,limit:options.limit??null}};
  }
  return {supports,prepare,stream};
}
module.exports = {createDamageIntervalQuery};
