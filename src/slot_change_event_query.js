'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const {isDeepStrictEqual} = require('node:util');
const {parseReplayFile} = require('./rofl');
const {decodeSemanticReplay} = require('./semantic_api');
const {ANONYMOUS_049C_PACKET_821_PROFILE: REGULAR, SPELL_SLOT_CHANGE_REQUEST_821_PROFILE: REQUEST,
  callbackRequestError, isObservedSlotChangeShape821} =
  require('./decoders/rofl_16_19_821_anonymous_049c_packet_candidate');
const {SPELL_SLOT_CHANGE_ROSTER_KEY_PAIR_821_PROFILE: PAIR, spellSlotChangeRosterKeyPairRow821} =
  require('./decoders/rofl_16_19_821_spell_slot_change_roster_key_pair_candidate');

const PROFILES = Object.freeze({anonymous_049c_packet_candidates:REGULAR,
  spell_slot_change_request_candidates:REQUEST, spell_slot_change_roster_key_pair_candidates:PAIR});
const supports = key => Object.hasOwn(PROFILES, key);
const count = n => Number.isSafeInteger(n) && n >= 0;
const sha = text => typeof text === 'string' && /^[0-9a-f]{64}$/.test(text);
const fields = (object, names) => object && typeof object === 'object' && !Array.isArray(object)
  && Object.keys(object).length === names.length && names.every(key => Object.hasOwn(object,key));
const ROW_FIELDS = ['event_type','game_version','patch','build_profile','replay_sha256','replay_time_ms',
  'raw_param','stream_tag','confidence','semantic_status','semantic_effect_status','deserialize_return_al',
  'native_packet_id','bytes_consumed','native_nested_field_bytes_hex','native_byte_vector_length',
  'native_byte_vector_hex','native_byte_vector_ascii_candidate','native_byte_vector_text_status',
  'native_byte_vector_terminal_nul','callback_request_candidate','raw_packet_ref'];
const REF_FIELDS = ['source_path','replay_sha256','chunk_index','chunk_id','chunk_stream','chunk_file_offset',
  'decompressed_block_offset','decompressed_payload_offset','packet_id','replay_time_ms','raw_param',
  'payload_length','raw_payload_sha256'];
const CALLBACK_FIELDS = ['status','registered_packet_class','registered_receiver_class','operation_selector',
  'slot_index','value_decode_witness','callback_stop_rva','receiver_entity_status','application_status','operation_kind'];
const OP_FIELDS = {1:['requested_u8','receiver_field_offset','receiver_field_meaning','native_lookup_index'],
  2:['requested_name_bytes_hex','requested_name_ascii','native_name_comparison_hash_u32','anonymous_control_bytes'],
  6:['requested_u8','receiver_field_offset','receiver_field_meaning','callee_has_state_gate'],
  7:['requested_word_count','requested_words_u32','word_decode_witness','nested_holder_vector_offset','word_meaning','callee_has_state_gate']};

function createSlotChangeQuery(context) {
  const {EventQueryError,readArtifactJson,checkBatchHash,prepareEventQueryFromDocuments,
    streamEventQuery,normalizeReplaySourcePaths} = context;
  const fail = (code,message,details) => { throw new EventQueryError(code,message,details); };

  function prepare(prepared,semantic,analysis) {
    if (!supports(prepared.eventKey)) return;
    const profile=PROFILES[prepared.eventKey], result=prepared.capabilityResult;
    if (prepared.eventStorage==='EMBEDDED_AND_JSONL') prepared.slotChangeEmbeddedRows=analysis.events[prepared.eventKey];
    if (prepared.replayVersion !== profile.replay_version) fail('UNSUPPORTED_EVENT_BUILD','Slot queries require exact KR 16.19.821.7343.');
    if (result.profile_id !== profile.id || result.evidence_status !== profile.evidence_status
        || result.runtime_image_used !== true || result.runtime_image_status !== 'MATCHED_USED'
        || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
        || result.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
        || !count(result.input_count) || result.input_count > 30_000
        || !isDeepStrictEqual(result.known_limits,[...profile.known_limits])
        || !isDeepStrictEqual(analysis.semantic?.capability_results?.[profile.capability],result)) {
      fail('CAPABILITY_METADATA_MISMATCH','Saved slot profile, native binding or mirrored metadata differs.');
    }
    if (profile !== PAIR && (result.input_count !== prepared.declaredCount
        || result.native_full_success_count !== result.input_count
        || !count(result.native_printable_ascii_count) || !count(result.native_opaque_vector_count)
        || result.native_printable_ascii_count+result.native_opaque_vector_count !== result.input_count
        || !sha(result.ordered_native_input_sha256)
        || result.memory_compatibility_operation !== profile.memory_compatibility_operation
        || result.memory_compatibility_leaf_rva !== profile.memory_compatibility_leaf_rva
        || result.memory_compatibility_prefix_sha256 !== profile.memory_compatibility_prefix_sha256
        || result.native_callback_rva !== profile.native_callback_rva
        || result.registered_receiver_class !== profile.registered_receiver_class
        || (profile === REGULAR ? result.input_packet_id !== 0x049c
          : !isDeepStrictEqual(result.input_packet_ids,[0x049c,0x028e,0x0375])))) {
      fail('CAPABILITY_METADATA_MISMATCH','Complete native slot request counts or receive binding differs.');
    }
    if (path.basename(path.dirname(prepared.artifactDirectory)) !== 'replays') {
      fail('MISSING_METADATA','Slot queries require their manifest-hashed Replay artifact directory.');
    }
    const root=path.dirname(path.dirname(prepared.artifactDirectory)), manifest=readArtifactJson(root,'manifest.json');
    const relative=`replays/${path.basename(prepared.artifactDirectory)}`;
    const entry=manifest.replay_inputs?.find(row=>row.artifact_directory===relative);
    if (entry?.sha256 !== prepared.replaySha || entry?.version !== prepared.replayVersion) {
      fail('ARTIFACT_IDENTITY_MISMATCH','Slot manifest and Replay identity differ.');
    }
    for (const name of ['semantic_run.json','replay_analysis.json',`${prepared.eventKey}.jsonl`]) {
      checkBatchHash(manifest.output_hashes_excluding_manifest??{},`${relative}/${name}`,path.join(prepared.artifactDirectory,name));
    }
    if (profile === PAIR) {
      prepared.slotChangeSources={request:prepareEventQueryFromDocuments(prepared.artifactDirectory,
        'spell_slot_change_request_candidates',semantic,analysis),
      roster:prepareEventQueryFromDocuments(prepared.artifactDirectory,'hero_roster_metadata_bridge_candidates',semantic,analysis)};
      const source=prepared.slotChangeSources.request;
      if (result.input_count !== source.declaredCount || result.event_count !== result.matched_header_count
          || !count(result.nonroster_header_count) || result.event_count+result.nonroster_header_count !== result.input_count
          || !count(result.plus_0x100_alias_excluded_count) || !count(result.low_byte_alias_excluded_count)
          || result.plus_0x100_alias_excluded_count > result.nonroster_header_count
          || result.low_byte_alias_excluded_count > result.nonroster_header_count
          || !isDeepStrictEqual(result.input_packet_ids,[0x049c,0x028e,0x0375])
          || !isDeepStrictEqual(result.dependency_statuses,{spell_slot_change_request:'CANDIDATE',hero_roster_metadata_bridge:'CANDIDATE'})) {
        fail('CAPABILITY_METADATA_MISMATCH','Slot association dependencies or complete match counts differ.');
      }
    }
  }

  function validateRequest(row,prepared,index,positions) {
    const profile=PROFILES[prepared.eventKey], ref=row.raw_packet_ref, request=row.callback_request_candidate;
    const op=request?.operation_selector;
    let callbackError;
    try { callbackError=callbackRequestError(row); } catch { callbackError='invalid callback field types'; }
    if (!fields(row,ROW_FIELDS) || !fields(ref,REF_FIELDS)
        || !fields(request,[...CALLBACK_FIELDS,...(OP_FIELDS[op]??[])]) || callbackError
        || request.status !== 'CANDIDATE_STATIC_RECEIVE_DATAFLOW'
        || row.event_type !== (profile===REGULAR?'ANONYMOUS_049C_PACKET_CANDIDATE':'SPELL_SLOT_CHANGE_REQUEST_CANDIDATE')
        || row.game_version !== profile.replay_version || row.patch !== '16.19' || row.build_profile !== profile.id
        || row.replay_sha256 !== prepared.replaySha || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== profile.evidence_status || row.semantic_effect_status !== 'UNKNOWN'
        || row.deserialize_return_al !== 1 || row.bytes_consumed !== ref.payload_length
        || !count(row.replay_time_ms) || !count(row.raw_param) || row.raw_param===0 || row.raw_param>0xffffffff
        || (profile===REGULAR && row.native_packet_id!==0x049c)
        || !isObservedSlotChangeShape821(row.native_packet_id,row.stream_tag,ref.payload_length)
        || ref.source_path !== prepared.sourcePath || ref.replay_sha256 !== prepared.replaySha
        || ref.packet_id !== row.native_packet_id || ref.raw_param !== row.raw_param || ref.replay_time_ms !== row.replay_time_ms
        || ref.chunk_stream !== (row.stream_tag===1?'game_chunk':'keyframe')
        || !['chunk_index','chunk_id','chunk_file_offset','decompressed_block_offset','decompressed_payload_offset'].every(key=>count(ref[key]))
        || ref.decompressed_payload_offset <= ref.decompressed_block_offset || !sha(ref.raw_payload_sha256)
        || !fields(row.native_nested_field_bytes_hex,['0x18','0x1c','0x20'])
        || ![['0x18',2],['0x1c',8],['0x20',6]].every(([key,length])=>
          typeof row.native_nested_field_bytes_hex[key]==='string'
          && row.native_nested_field_bytes_hex[key].length===length
          && /^[0-9a-f]+$/.test(row.native_nested_field_bytes_hex[key]))
        || !count(row.native_byte_vector_length) || row.native_byte_vector_length>256
        || typeof row.native_byte_vector_hex !== 'string'
        || !/^(?:[0-9a-f]{2})*$/.test(row.native_byte_vector_hex)
        || row.native_byte_vector_hex.length!==row.native_byte_vector_length*2) {
      fail('INVALID_EVENT_ROW',`Invalid complete slot request at line ${index}.`);
    }
    const vector=Buffer.from(row.native_byte_vector_hex,'hex'), nul=vector.length>0&&vector.at(-1)===0;
    const visible=nul?vector.subarray(0,-1):vector;
    const printable=visible.length>0&&visible.every(byte=>byte>=32&&byte<=126);
    if (row.native_byte_vector_terminal_nul!==nul || row.native_byte_vector_ascii_candidate!==(printable?visible.toString('ascii'):null)
        || row.native_byte_vector_text_status!==(printable?'PRINTABLE_ASCII_CANDIDATE':'OPAQUE_BYTES')) {
      fail('INVALID_EVENT_ROW',`Slot text presentation differs at line ${index}.`);
    }
    const position=`${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (positions.has(position)) fail('INVALID_EVENT_ROW',`Duplicate slot packet position at line ${index}.`);
    positions.add(position);
    return printable;
  }

  async function readRows(prepared,visit) {
    let total=0;
    const input=fs.createReadStream(prepared.inputPath,{encoding:'utf8'});
    const lines=readline.createInterface({input,crlfDelay:Infinity});
    try {
      for await(const line of lines) {
        if (++total>prepared.declaredCount) fail('EVENT_COUNT_MISMATCH','Extra slot JSONL rows.');
        let row;try { row=JSON.parse(line); } catch { fail('INVALID_EVENT_ROW',`Invalid slot JSON at line ${total}.`); }
        if (!row || typeof row!=='object' || Array.isArray(row)) fail('INVALID_EVENT_ROW',`Slot line ${total} must be an object.`);
        if (prepared.slotChangeEmbeddedRows && !isDeepStrictEqual(row,prepared.slotChangeEmbeddedRows[total-1])) {
          fail('INVALID_EVENT_ROW',`Slot JSONL and embedded saved row ${total} differ.`);
        }
        await visit(row,total,line);
      }
    } finally { lines.close();input.destroy(); }
    if (total!==prepared.declaredCount) fail('EVENT_COUNT_MISMATCH','Incomplete slot JSONL rows.');
    return total;
  }

  function filters(prepared,options) {
    const allowed=new Set(['fromMs','toMs','participant','rawParam','limit','verifySource','sourceReplay',
      'runtimeImage','pythonExecutable','slotChangeIndex','slotChangeOperation']);
    for (const [key,value] of Object.entries(options)) {
      if (!allowed.has(key) && value!==null && value!==undefined && value!==false) {
        fail('UNSUPPORTED_FILTER',`${key} is not supported on slot request queries.`);
      }
    }
    if (options.participant!=null && PROFILES[prepared.eventKey]!==PAIR) {
      fail('UNSUPPORTED_FILTER','--participant applies only to the candidate slot roster association.');
    }
    if (options.slotChangeIndex!=null && (!count(options.slotChangeIndex)||options.slotChangeIndex>255)) fail('INVALID_FILTER','--slot-change-index must be 0..255.');
    if (options.slotChangeOperation!=null && ![1,2,6,7].includes(options.slotChangeOperation)) fail('INVALID_FILTER','--slot-change-operation must be 1, 2, 6 or 7.');
    if (options.runtimeImage!=null && !options.verifySource) fail('INVALID_FILTER','--runtime-image on slot queries requires --verify-source.');
  }

  function physical(prepared,options) {
    if (!options.verifySource) return null;
    if (typeof options.runtimeImage!=='string'||!options.runtimeImage.trim()) fail('MISSING_RUNTIME_IMAGE','Slot source verification requires the exact --runtime-image.');
    const source=options.sourceReplay??prepared.sourcePath;
    if (typeof source!=='string'||!source.trim()) fail('MISSING_SOURCE_REPLAY','No original Replay path is available.');
    let replay;
    try { replay=parseReplayFile(source); } catch(error) {
      fail(error.code==='INPUT_READ_ERROR'?'SOURCE_REPLAY_READ_FAILED':'SOURCE_REPLAY_INVALID',error.message);
    }
    if (replay.source_sha256!==prepared.replaySha||replay.header.version!==prepared.replayVersion) fail('SOURCE_REPLAY_IDENTITY_MISMATCH','Original Replay hash/build differs.');
    let decoded;
    try { decoded=decodeSemanticReplay(replay,{capabilities:[prepared.capability],runtimeImagePath:options.runtimeImage,
      pythonExecutable:options.pythonExecutable}); } catch(error) { fail('SOURCE_REPLAY_DECODE_FAILED',error.message); }
    const result=decoded.capability_results?.[prepared.capability];
    if (result?.status!=='CANDIDATE') {
      fail('SOURCE_REPLAY_DECODE_FAILED','Fresh exact-image decoding could not run within the saved candidate scope.',
        {source_status:result?.status??null,source_error:result?.error??null,
          runtime_image_status:result?.runtime_image_status??null,missing_input:result?.missing_input??null});
    }
    if (!isDeepStrictEqual(result,prepared.capabilityResult)) {
      fail('SOURCE_PROVENANCE_MISMATCH','Fresh exact-image native result differs from saved metadata.',{source_status:result?.status??null});
    }
    return {decoded,source:path.resolve(source)};
  }

  async function stream(prepared,options,emitLine) {
    filters(prepared,options);
    const verified=physical(prepared,options), isPair=PROFILES[prepared.eventKey]===PAIR;
    let expected=null;
    if (isPair) {
      const roster=new Map(), sources=prepared.slotChangeSources;
      await streamEventQuery(sources.roster,{},async line=>{
        const row=JSON.parse(line);
        if (verified && !isDeepStrictEqual(row,normalizeReplaySourcePaths(
          verified.decoded.events.hero_roster_metadata_bridge_candidates[roster.size],prepared.sourcePath))) {
          fail('SOURCE_PROVENANCE_MISMATCH','Complete roster dependency differs from fresh Replay decoding.');
        }
        roster.set(row.hero_raw_param,row);
      });
      expected=[];let nonroster=0,plus100=0,lowByte=0,printable=0;
      const positions=new Set();
      await readRows(sources.request,(row,index)=>{
        printable+=validateRequest(row,sources.request,index,positions)?1:0;
        const matched=roster.get(row.raw_param);
        if (matched) expected.push(spellSlotChangeRosterKeyPairRow821(row,matched));
        else {nonroster++;if(roster.has(row.raw_param-0x100))plus100++;
          if([...roster.keys()].some(key=>(key&255)===(row.raw_param&255)))lowByte++;}
        if (verified && !isDeepStrictEqual(row,normalizeReplaySourcePaths(
          verified.decoded.events.spell_slot_change_request_candidates[index-1],prepared.sourcePath))) {
          fail('SOURCE_PROVENANCE_MISMATCH',`Complete slot dependency differs from native re-decode at line ${index}.`);
        }
      });
      const result=prepared.capabilityResult;
      if (expected.length!==prepared.declaredCount || result.nonroster_header_count!==nonroster
          || result.plus_0x100_alias_excluded_count!==plus100 || result.low_byte_alias_excluded_count!==lowByte
          || printable!==sources.request.capabilityResult.native_printable_ascii_count) {
        fail('EVENT_COUNT_MISMATCH','Complete saved slot source/association counts differ.');
      }
    }
    let matched=0,emitted=0,printable=0;
    const positions=new Set();
    const scanned=await readRows(prepared,async(row,index,line)=>{
      if (isPair) {
        if (!isDeepStrictEqual(row,expected[index-1])) fail('INVALID_EVENT_ROW',`Slot association differs from complete sources at line ${index}.`);
      } else printable+=validateRequest(row,prepared,index,positions)?1:0;
      if (verified && !isDeepStrictEqual(row,normalizeReplaySourcePaths(
        verified.decoded.events[prepared.eventKey][index-1],prepared.sourcePath))) {
        fail('SOURCE_PROVENANCE_MISMATCH',`Slot row differs from fresh exact-image native decode at line ${index}.`);
      }
      const request=isPair?row.request_candidate:row.callback_request_candidate;
      if ((options.fromMs!=null&&row.replay_time_ms<options.fromMs)||(options.toMs!=null&&row.replay_time_ms>options.toMs)
          ||(options.participant!=null&&row.participant_id_candidate!==options.participant)
          ||(options.rawParam!=null&&row.raw_param!==options.rawParam)
          ||(options.slotChangeIndex!=null&&request.slot_index!==options.slotChangeIndex)
          ||(options.slotChangeOperation!=null&&request.operation_selector!==options.slotChangeOperation)) return;
      matched++;if(options.limit==null||emitted<options.limit){await emitLine(`${line}\n`);emitted++;}
    });
    if (!isPair&&printable!==prepared.capabilityResult.native_printable_ascii_count) fail('EVENT_COUNT_MISMATCH','Slot printable/opaque counts differ.');
    return {schema_version:1,command:'query-events',query_status:'COMPLETE',artifact_directory:prepared.artifactDirectory,
      event_key:prepared.eventKey,replay_version:prepared.replayVersion,replay_sha256:prepared.replaySha,
      capability_status:'CANDIDATE',declared_event_count:prepared.declaredCount,scanned_count:scanned,matched_count:matched,
      emitted_count:emitted,rows_unmodified:true,source_provenance_status:verified?'SOURCE_REPLAY_VERIFIED':'SAVED_ONLY_UNVERIFIED',
      native_witness_check:verified?'FRESH_EXACT_IMAGE_REDECODE':'PERSISTED_REQUEST_FIELDS_AND_COMPLETE_DEPENDENCIES',
      ...(verified?{source_replay:verified.source}:{}),
      filters:{from_ms:options.fromMs??null,to_ms:options.toMs??null,participant:options.participant??null,
        raw_param:options.rawParam??null,slot_change_index:options.slotChangeIndex??null,
        slot_change_operation:options.slotChangeOperation??null,limit:options.limit??null}};
  }
  return {supports,prepare,stream};
}
module.exports={createSlotChangeQuery};
