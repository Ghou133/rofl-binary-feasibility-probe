'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const {parseReplayBuffer,walkBlocks,normalizePlayers} = require('../src/rofl');
const {replayFromChunks} = require('./helpers/synthetic_replay');
const {resolveCapability} = require('../src/build_registry');
const {decodeSemanticReplay} = require('../src/semantic_api');
const {capabilityQuery} = require('../src/cli');
const {collect821Routes} = require('../src/decoders/rofl_16_19_821_scan');
const {SPELL_SLOT_CHANGE_REQUEST_821_PROFILE: REQUEST} =
  require('../src/decoders/rofl_16_19_821_anonymous_049c_packet_candidate');
const {HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER} =
  require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const {associateSpellSlotChangeRosterKeys821: associate} =
  require('../src/decoders/rofl_16_19_821_spell_slot_change_roster_key_pair_candidate');
const BUILD='16.19.821.7343', FIRST=0x400000ae, CAP='spell_slot_change_roster_key_pair';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function packet(id,key,length,time=1000) {
  const head=Buffer.alloc(15);head.writeFloatLE(time/1000,1);head.writeUInt32LE(length,5);
  head.writeUInt16LE(id,9);head.writeUInt32LE(key,11);
  return Buffer.concat([head,Buffer.alloc(length)]);
}
function fixture(version=BUILD) {
  // Artificial framing/output-schema fixture: not native packet or roster-identity evidence.
  const original=replayFromChunks([
    {stream:1,body:Buffer.concat([packet(0x049c,FIRST,5),packet(0x028e,FIRST+1,19),
      packet(0x049c,FIRST+0x100,5),packet(0x049c,0x500000ae,5)])},
    {stream:2,body:Buffer.concat([packet(0x0375,FIRST+2,5),...Array.from({length:10},
      (_,i)=>packet(0x0089,FIRST+i,1263,2000))])},
  ],version);
  const stats=Array.from({length:10},(_,i)=>({SKIN:`Champion${i+1}`,TEAM:i<5?'100':'200',
    INDIVIDUAL_POSITION:['TOP','JUNGLE','MIDDLE','BOTTOM','UTILITY'][i%5],
    ID:'private-id',PUUID:'private-puuid',RIOT_ID_GAME_NAME:'private-name'}));
  const metadata=Buffer.from(JSON.stringify({gameLength:600000,statsJson:JSON.stringify(stats)}));
  const trailer=Buffer.alloc(4);trailer.writeUInt32LE(metadata.length);
  const oldLength=original.buffer.readUInt32LE(original.buffer.length-4);
  const replay=parseReplayBuffer(Buffer.concat([original.buffer.subarray(0,-oldLength-4),metadata,trailer]),'synthetic-test.rofl');
  const requests=[],refs=[];
  const walked=walkBlocks(replay,(block,chunk)=>{
    const ref={source_path:replay.source_path,replay_sha256:replay.source_sha256,
      chunk_index:chunk.index,chunk_id:chunk.chunk_id,chunk_stream:chunk.stream,chunk_file_offset:chunk.offset,
      decompressed_block_offset:block.offset,decompressed_payload_offset:block.payload_offset,
      packet_id:block.packet_id,replay_time_ms:block.timestamp_ms,payload_length:block.payload.length,
      raw_param:block.param,raw_payload_sha256:sha(block.payload)};
    if(block.packet_id===0x0089) {refs.push(ref);return;}
    const op=block.packet_id===0x028e?2:block.packet_id===0x0375?6:1;
    const word=Buffer.alloc(4);word.writeUInt32LE(op);
    const callback={status:'CANDIDATE_STATIC_RECEIVE_DATAFLOW',
      registered_packet_class:{1180:'PKT_ChangeSlotSpellData_s',654:'PKT_ChangeSlotSpellData_Summoner_s',
        885:'PKT_ChangeSlotSpellData_OwnerOnly_s'}[block.packet_id],registered_receiver_class:'AIBaseClient',
      operation_selector:op,slot_index:0,value_decode_witness:'NATIVE_PACKET_ONLY_CALLBACK_PREFIX',
      receiver_entity_status:'UNKNOWN',application_status:'NOT_OBSERVED',
      ...(op===2?{operation_kind:'SLOT_NAME_CHANGE_REQUEST',callback_stop_rva:'0x24ecdf',
        requested_name_bytes_hex:'4162',requested_name_ascii:'Ab',native_name_comparison_hash_u32:1650,
        anonymous_control_bytes:[0,0,0]}:op===6?{operation_kind:'SLOT_GATED_BYTE_FIELD_WRITE_REQUEST',
        callback_stop_rva:'0x24ed5e',requested_u8:18,receiver_field_offset:'0xe8',
        receiver_field_meaning:'UNKNOWN',callee_has_state_gate:true}:{operation_kind:'SLOT_BYTE_FIELD_WRITE_REQUEST',
        callback_stop_rva:'0x24ec26',requested_u8:18,receiver_field_offset:'0x2f',
        receiver_field_meaning:'UNKNOWN',native_lookup_index:0})};
    requests.push({event_type:'SPELL_SLOT_CHANGE_REQUEST_CANDIDATE',game_version:BUILD,build_profile:REQUEST.id,
      replay_sha256:replay.source_sha256,replay_time_ms:block.timestamp_ms,stream_tag:chunk.stream_tag,
      raw_param:block.param,native_packet_id:block.packet_id,raw_packet_ref:ref,
      confidence:'CANDIDATE',semantic_status:REQUEST.evidence_status,semantic_effect_status:'UNKNOWN',
      deserialize_return_al:1,bytes_consumed:block.payload.length,
      native_nested_field_bytes_hex:{'0x18':'bb','0x1c':word.toString('hex')},
      native_byte_vector_hex:op===2?'416200':'12',callback_request_candidate:callback});
  },{strict:true});
  assert.equal(walked.errors.length,0);
  const metadataSha=sha(JSON.stringify(replay.tail.metadata)),statsSha=sha(replay.tail.metadata.statsJson);
  const roster=normalizePlayers(replay).map((p,i)=>({event_type:'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE',
    game_version:BUILD,build_profile:ROSTER.id,replay_sha256:replay.source_sha256,replay_time_ms:2000,
    hero_raw_param:FIRST+i,participant_id_candidate:i+1,metadata_index_candidate:i,
    champion_metadata:p.champion,team_id_metadata:p.team_id,team_metadata:p.team,role_metadata:p.role,
    metadata_sha256:metadataSha,stats_json_sha256:statsSha,roster_to_metadata_status:ROSTER.evidence_status,
    per_packet_actor_status:'UNKNOWN',raw_packet_ref:refs[i]}));
  return {replay,spellSlotChangeRequestOutcome:{status:'CANDIDATE',profile_id:REQUEST.id,
    evidence_status:REQUEST.evidence_status,input_count:requests.length,event_count:requests.length,
    native_full_success_count:requests.length,events:requests,runtime_image_used:true,
    runtime_image_status:'MATCHED_USED',runtime_image_sha256:REQUEST.evidence_runtime_image_sha256},
  heroRosterMetadataBridgeOutcome:{status:'CANDIDATE',profile_id:ROSTER.id,evidence_status:ROSTER.evidence_status,
    unique_kda_match_count:10,metadata_player_count:10,event_count:10,events:roster,
    metadata_sha256:metadataSha,stats_json_sha256:statsSha}};
}
test('three routes join only full header keys, preserve request/refs and explicit unknown roles',()=>{
  const input=fixture(),result=associate(input.replay,input);
  assert.equal(result.status,'CANDIDATE',result.error);assert.equal(result.input_count,5);
  assert.equal(result.event_count,3);assert.equal(result.nonroster_header_count,2);
  assert.equal(result.plus_0x100_alias_excluded_count,1);assert.equal(result.low_byte_alias_excluded_count,2);
  assert.deepEqual(result.events.map(r=>r.participant_id_candidate),[1,2,3]);
  assert.deepEqual(result.events.map(r=>r.native_packet_id),[0x049c,0x028e,0x0375]);
  const named=result.events[1];assert.equal(named.request_candidate.requested_name_ascii,'Ab');
  assert.equal(named.champion_metadata,'Champion2');assert.equal(named.role_metadata,'jungle');
  for(const row of result.events) {
    assert.equal(row.raw_packet_ref.raw_param,row.roster_keyframe_packet_ref.raw_param);
    assert.equal(row.packet_actor_status,'UNKNOWN');assert.equal(row.live_receiver_status,'UNKNOWN');
    assert.equal(row.actual_application_status,'NOT_OBSERVED');
  }
  assert.doesNotMatch(JSON.stringify(result.events),/private-|puuid|riot_id|metadata_player_id/i);
  result.events[0].request_candidate.requested_u8=0;
  assert.equal(input.spellSlotChangeRequestOutcome.events[0].callback_request_candidate.requested_u8,18);
});
test('source-bound shared scan gives the same association and rejects another Replay token',()=>{
  const input=fixture();input.precollected=collect821Routes(input.replay,['spell_slot_change_request']);
  assert.equal(associate(input.replay,input).event_count,3);
  input.precollected=collect821Routes(fixture().replay,['spell_slot_change_request']);
  assert.equal(associate(input.replay,input).events,null);
});
test('late unmatched-row forgery, dropped source, native-image mismatch and promoted application fail closed',()=>{
  for(const mutate of [
    x=>x.spellSlotChangeRequestOutcome.events[3].raw_packet_ref.raw_payload_sha256=sha('forged'),
    x=>{x.spellSlotChangeRequestOutcome.events.pop();x.spellSlotChangeRequestOutcome.input_count--;
      x.spellSlotChangeRequestOutcome.event_count--;x.spellSlotChangeRequestOutcome.native_full_success_count--;},
    x=>x.spellSlotChangeRequestOutcome.runtime_image_sha256=sha('wrong-image'),
    x=>x.spellSlotChangeRequestOutcome.events[3].native_nested_field_bytes_hex['0x1c']=10000000,
    x=>x.spellSlotChangeRequestOutcome.events[4].callback_request_candidate.application_status='APPLIED',
  ]) {const input=fixture();mutate(input);const result=associate(input.replay,input);
    assert.equal(result.status,'DECODE_FAILED',result.error);assert.equal(result.events,null);}
});
test('physical metadata, ten-way bridge and roster source labels cannot be silently substituted',()=>{
  for(const mutate of [x=>x.replay.tail.stats[0].SKIN='Forged',
    x=>x.heroRosterMetadataBridgeOutcome.events[8].champion_metadata='Forged',
    x=>x.heroRosterMetadataBridgeOutcome.events[9].hero_raw_param=FIRST+0x100,
    x=>x.heroRosterMetadataBridgeOutcome.unique_kda_match_count=9,
    x=>x.heroRosterMetadataBridgeOutcome.events[9].per_packet_actor_status='CONFIRMED',
  ]) {const input=fixture();mutate(input);assert.equal(associate(input.replay,input).events,null);}
});
test('missing dependencies remain null and neighboring builds remain unsupported',()=>{
  const input=fixture();assert.equal(associate(input.replay).status,'MISSING_INPUT');
  input.spellSlotChangeRequestOutcome.status='MISSING_INPUT';
  assert.equal(associate(input.replay,input).input_count,null);
  const other=fixture('16.19.820.7193');assert.equal(associate(other.replay,other).status,'UNSUPPORTED');
  assert.equal(resolveCapability(BUILD,CAP).status,'CANDIDATE');
  assert.equal(resolveCapability('16.19.820.7193',CAP).status,'UNAVAILABLE');
});
test('pair-only API expands both sources, while CLI preflight exposes exact-image dependency',()=>{
  const {replay}=fixture();const decoded=decodeSemanticReplay(replay,{capabilities:[CAP]});
  assert.equal(decoded.capability_results.spell_slot_change_request.status,'MISSING_INPUT');
  assert.ok(decoded.capability_results.hero_roster_metadata_bridge);
  assert.equal(decoded.capability_results[CAP].status,'MISSING_INPUT');
  assert.equal(decoded.events,null);assert.equal(decoded.decoded_packet_count,0);
  const query=capabilityQuery(replay,{events:[CAP]}).capabilities.find(c=>c.capability===CAP);
  assert.equal(query.output,'spell_slot_change_roster_key_pair_candidates');
  assert.ok(query.missing_inputs.includes('exact_runtime_image'));
});
