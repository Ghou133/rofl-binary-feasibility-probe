'use strict';

const fs = require('node:fs');
const readline = require('node:readline');
const {isDeepStrictEqual} = require('node:util');
const {parseReplayFile} = require('./rofl');
const {decodeSemanticReplay} = require('./semantic_api');
const damageFilters = require('./damage_query_filters');
const {DAMAGE_PACKET_KEYFRAME_WINDOW_PROFILE_821: PROFILE,compareDamagePacketKeyframeWindows821: compare} =
  require('./decoders/rofl_16_19_821_damage_window_reconciliation_candidate');
const {UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: PACKET,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821: PACKET_V6} =
  require('./decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const EVENT = 'hero_damage_packet_keyframe_window_candidates';
const SOURCE_EVENTS = {unit_apply_damage_packet:'unit_apply_damage_packet_candidates',
  hero_damage_keyframe_intervals:'hero_damage_keyframe_interval_candidates'};
const RESULT_KEYS = ['profile_id','replay_sha256','required_capabilities','known_limits','status',
  'native_packet_count','sampled_counter_window_count','exact_endpoint_time_packets_excluded',
  'packets_outside_sampled_windows','positive_counter_comparisons','event_count'];
const count = value => Number.isSafeInteger(value) && value >= 0;
const shape = (value,keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key=>Object.hasOwn(value,key));
const supports = key => key === EVENT;

function createDamageWindowQuery({EventQueryError,prepareEventQueryFromDocuments,
  streamEventQuery,normalizeReplaySourcePaths}) {
  const fail = (code,message,details) => {throw new EventQueryError(code,message,details);};
  function association(semantic,analysis) {
    if (semantic.replay_version !== PROFILE.replay_version) fail('UNSUPPORTED_EVENT_BUILD','Damage packet/window queries require exact KR 821.');
    const result = semantic.candidate_associations?.[PROFILE.capability];
    if (!result || result.status !== 'CANDIDATE') return result;
    if (!shape(result,RESULT_KEYS) || result.profile_id !== PROFILE.id
        || result.replay_sha256 !== semantic.replay_sha256
        || !isDeepStrictEqual(result.required_capabilities,[...PROFILE.required_capabilities])
        || !isDeepStrictEqual(result.known_limits,[...PROFILE.known_limits])
        || !['native_packet_count','sampled_counter_window_count','exact_endpoint_time_packets_excluded',
          'packets_outside_sampled_windows','event_count'].every(field=>count(result[field]))
        || result.event_count !== result.sampled_counter_window_count
        || result.exact_endpoint_time_packets_excluded+result.packets_outside_sampled_windows > result.native_packet_count
        || !isDeepStrictEqual(analysis.semantic?.candidate_associations?.[PROFILE.capability],result)) {
      fail('ASSOCIATION_METADATA_MISMATCH','Complete damage packet/window profile or mirrored metadata differs.');
    }
    for (const capability of PROFILE.required_capabilities) {
      if (!semantic.requested_capabilities?.includes(capability)) fail('CAPABILITY_NOT_REQUESTED','Missing damage comparison dependency '+capability+'.');
      if (semantic.capability_results?.[capability]?.status !== 'CANDIDATE') fail('CAPABILITY_UNAVAILABLE','Unavailable damage comparison dependency '+capability+'.');
    }
    return result;
  }

  function prepare(prepared,semantic,analysis) {
    if (!supports(prepared.eventKey)) return;
    prepared.damageWindowSources = Object.fromEntries(Object.entries(SOURCE_EVENTS).map(([capability,event])=>[
      capability,prepareEventQueryFromDocuments(prepared.artifactDirectory,event,semantic,analysis)]));
    const sources = prepared.damageWindowSources, result = prepared.capabilityResult;
    const packet = sources.unit_apply_damage_packet.capabilityResult;
    if (![PACKET.id,PACKET_V6.id].includes(packet.profile_id)
        || packet.runtime_image_used !== true || packet.runtime_image_status !== 'MATCHED_USED'
        || packet.runtime_image_sha256 !== PACKET.evidence_runtime_image_sha256
        || packet.native_full_success_count !== packet.event_count
        || packet.native_callback_f32_available_count !== packet.event_count
        || packet.native_callback_lookup_full_write_count !== packet.event_count
        || result.native_packet_count !== sources.unit_apply_damage_packet.declaredCount
        || result.sampled_counter_window_count !== sources.hero_damage_keyframe_intervals.declaredCount) {
      fail('ASSOCIATION_METADATA_MISMATCH','Native damage or sampled window dependencies are incomplete.');
    }
    if (prepared.eventStorage === 'EMBEDDED_AND_JSONL') prepared.damageWindowEmbeddedRows = analysis.events[EVENT];
  }

  function physical(prepared,options) {
    if (!options.verifySource) return null;
    if (typeof options.runtimeImage !== 'string' || !options.runtimeImage.trim()) {
      fail('MISSING_RUNTIME_IMAGE','Damage packet/window source verification requires the exact runtime image.');
    }
    const source = options.sourceReplay ?? prepared.sourcePath;
    if (typeof source !== 'string' || !source.trim()) fail('MISSING_SOURCE_REPLAY','No original Replay path is available.');
    let replay;
    try {replay=parseReplayFile(source);} catch(error) {
      fail(error.code==='INPUT_READ_ERROR'?'SOURCE_REPLAY_READ_FAILED':'SOURCE_REPLAY_INVALID',error.message);
    }
    if (replay.source_sha256 !== prepared.replaySha || replay.header.version !== prepared.replayVersion) {
      fail('SOURCE_REPLAY_IDENTITY_MISMATCH','Original damage comparison Replay SHA/build differs.');
    }
    const packetProfile = prepared.damageWindowSources.unit_apply_damage_packet.capabilityResult.profile_id;
    let decoded;
    try {decoded=decodeSemanticReplay(replay,{capabilities:[...PROFILE.required_capabilities],
      runtimeImagePath:options.runtimeImage,pythonExecutable:options.pythonExecutable,
      ...(packetProfile === PACKET_V6.id?{damagePacketProfile:'v6'}:{})});}
    catch(error) {fail('SOURCE_REPLAY_DECODE_FAILED',error.message);}
    if (PROFILE.required_capabilities.some(capability=>decoded.capability_results?.[capability]?.status !== 'CANDIDATE')
        || decoded.candidate_associations?.[PROFILE.capability]?.status !== 'CANDIDATE') {
      fail('SOURCE_REPLAY_DECODE_FAILED','Complete native damage/window source decode is unavailable.',
        {dependency_statuses:Object.fromEntries(PROFILE.required_capabilities.map(capability=>
          [capability,decoded.capability_results?.[capability]?.status??null]))});
    }
    for (const capability of PROFILE.required_capabilities) {
      if (!isDeepStrictEqual(normalizeReplaySourcePaths(decoded.capability_results[capability],prepared.sourcePath??null),
          prepared.damageWindowSources[capability].capabilityResult)) {
        fail('SOURCE_PROVENANCE_MISMATCH','Complete source dependency metadata differs: '+capability+'.');
      }
    }
    if (!isDeepStrictEqual(normalizeReplaySourcePaths(decoded.candidate_associations[PROFILE.capability],prepared.sourcePath??null),
        prepared.capabilityResult)) fail('SOURCE_PROVENANCE_MISMATCH','Complete source comparison metadata differs.');
    return decoded;
  }

  async function stream(prepared,options,emitLine) {
    const allowed = new Set(['fromMs','toMs','participant','rawParam','limit','verifySource','sourceReplay','runtimeImage','pythonExecutable',...damageFilters.FILTER_KEYS]);
    for (const [key,value] of Object.entries(options)) {
      if (!allowed.has(key) && value != null && value !== false) fail('UNSUPPORTED_FILTER',key+' is not supported on damage packet/window comparisons.');
    }
    if (options.sourceReplay != null && !options.verifySource) fail('INVALID_FILTER','--source-replay requires --verify-source.');
    if ((options.runtimeImage != null || options.pythonExecutable != null) && !options.verifySource) {
      fail('INVALID_FILTER','Native query inputs require --verify-source.');
    }
    const fresh = physical(prepared,options), rowsByCapability = {};
    for (const capability of PROFILE.required_capabilities) {
      const source = prepared.damageWindowSources[capability], rows = [];
      await streamEventQuery(source,{},line=>{
        const row = JSON.parse(line);
        if (fresh && !isDeepStrictEqual(row,normalizeReplaySourcePaths(fresh.events[SOURCE_EVENTS[capability]][rows.length],prepared.sourcePath??null))) {
          fail('SOURCE_PROVENANCE_MISMATCH','Complete source dependency row differs: '+capability+' line '+(rows.length+1)+'.');
        }
        rows.push(row);
      });
      rowsByCapability[capability] = {...source.capabilityResult,events:rows};
    }
    const replay = {header:{version:prepared.replayVersion},source_sha256:prepared.replaySha};
    let computed;
    try {computed=compare(replay,rowsByCapability.unit_apply_damage_packet,rowsByCapability.hero_damage_keyframe_intervals);}
    catch(error) {fail('INVALID_EVENT_ROW',error.message);}
    const {events:expected,...metadata} = computed;
    if (computed.status !== 'CANDIDATE' || !isDeepStrictEqual(metadata,prepared.capabilityResult)) {
      fail('ASSOCIATION_METADATA_MISMATCH','Complete saved dependency reconciliation differs from the comparison metadata.');
    }
    let scanned=0,matched=0,emitted=0;
    const input=fs.createReadStream(prepared.inputPath,{encoding:'utf8'});
    const lines=readline.createInterface({input,crlfDelay:Infinity});
    try {
      for await(const line of lines) {
        if (++scanned > prepared.declaredCount) fail('EVENT_COUNT_MISMATCH','Extra damage comparison rows.');
        let row;
        try {row=JSON.parse(line);} catch {fail('INVALID_EVENT_ROW','Invalid damage comparison JSON at line '+scanned+'.');}
        if (!isDeepStrictEqual(row,expected[scanned-1])
            || (prepared.damageWindowEmbeddedRows && !isDeepStrictEqual(row,prepared.damageWindowEmbeddedRows[scanned-1]))) {
          fail('INVALID_EVENT_ROW','Damage comparison line '+scanned+' differs from complete dependencies.');
        }
        if (fresh && !isDeepStrictEqual(row,normalizeReplaySourcePaths(fresh.events[EVENT][scanned-1],prepared.sourcePath??null))) {
          fail('SOURCE_PROVENANCE_MISMATCH','Damage comparison differs from the original native source.');
        }
        const rawParam=0x400000ad+row.participant_id_candidate;
        if ((options.fromMs!=null && row.replay_time_ms<options.fromMs)
            || (options.toMs!=null && row.replay_time_ms>options.toMs)
            || (options.participant!=null && row.participant_id_candidate!==options.participant)
            || (options.rawParam!=null && rawParam!==options.rawParam)
            || !damageFilters.matches(row,options)) continue;
        matched++;
        if (options.limit==null || emitted<options.limit) {await emitLine(line+'\n');emitted++;}
      }
    } finally {lines.close();input.destroy();}
    if (scanned!==prepared.declaredCount) fail('EVENT_COUNT_MISMATCH','Incomplete damage comparison rows.');
    return {schema_version:1,command:'query-events',query_status:'COMPLETE',event_key:EVENT,
      artifact_directory:prepared.artifactDirectory,replay_version:prepared.replayVersion,replay_sha256:prepared.replaySha,
      capability_status:'CANDIDATE',declared_event_count:prepared.declaredCount,
      source_provenance_status:fresh?'SOURCE_REPLAY_VERIFIED':'SAVED_ONLY_UNVERIFIED',
      native_witness_check:fresh?'FRESH_EXACT_IMAGE_REDECODE':'COMPLETE_SAVED_DEPENDENCY_RECONCILIATION',
      dependency_event_counts:Object.fromEntries(PROFILE.required_capabilities.map(capability=>[capability,rowsByCapability[capability].event_count])),
      scanned_count:scanned,matched_count:matched,emitted_count:emitted,rows_unmodified:true,
      packet_time_window:'STRICT_OPEN_ENDPOINTS',semantic_effect_status:'UNKNOWN',
      filters:{from_ms:options.fromMs??null,to_ms:options.toMs??null,participant:options.participant??null,
        raw_param:options.rawParam??null,limit:options.limit??null,...damageFilters.summary(options)}};
  }
  return {supports,association,prepare,stream};
}
module.exports = {createDamageWindowQuery};
