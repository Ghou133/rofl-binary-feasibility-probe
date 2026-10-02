'use strict';
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const test=require('node:test');
const {prepareEventQuery,streamEventQuery}=require('../src/event_query');
const {SPELL_SLOT_CHANGE_REQUEST_821_PROFILE:PROFILE}=
  require('../src/decoders/rofl_16_19_821_anonymous_049c_packet_candidate');
const CLI=path.resolve(__dirname,'../src/cli.js'), EVENT='spell_slot_change_request_candidates';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function cli(dir,event=EVENT,...args) {return spawnSync(process.execPath,[CLI,'query-events',dir,'--event',event,...args],
  {encoding:'utf8',timeout:120000,maxBuffer:4*1024*1024});}
function cleanup(t,root) {t.after(()=>{
  const target=path.resolve(root),base=path.resolve(os.tmpdir())+path.sep;
  assert.ok(target.startsWith(base)&&path.basename(target).startsWith('rofl-slot-query-'));
  fs.rmSync(target,{recursive:true,force:true});
});}
function fixture(t) {
  // Artificial saved-schema fixture only; no claim that fake payloads decode natively.
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rofl-slot-query-'));cleanup(t,root);
  const relative='replays/sample',dir=path.join(root,'replays','sample');fs.mkdirSync(dir,{recursive:true});
  const replaySha='a'.repeat(64);
  const rows=[0x049c,0x028e,0x0375].map((id,i)=>{
    const op=i===0?1:i===1?2:6,vector=i===1?'416200':'12',time=1000+i*1000;
    const ophex=Buffer.alloc(4);ophex.writeUInt32LE(op);
    const callback={status:'CANDIDATE_STATIC_RECEIVE_DATAFLOW',registered_packet_class:
      {1180:'PKT_ChangeSlotSpellData_s',654:'PKT_ChangeSlotSpellData_Summoner_s',885:'PKT_ChangeSlotSpellData_OwnerOnly_s'}[id],
      registered_receiver_class:'AIBaseClient',operation_selector:op,slot_index:0,
      value_decode_witness:'NATIVE_PACKET_ONLY_CALLBACK_PREFIX',receiver_entity_status:'UNKNOWN',
      application_status:'NOT_OBSERVED',...(op===2?{callback_stop_rva:'0x24ecdf',operation_kind:'SLOT_NAME_CHANGE_REQUEST',
        requested_name_bytes_hex:'4162',requested_name_ascii:'Ab',native_name_comparison_hash_u32:1650,
        anonymous_control_bytes:[0,0,0]}:{callback_stop_rva:op===1?'0x24ec26':'0x24ed5e',
        operation_kind:op===1?'SLOT_BYTE_FIELD_WRITE_REQUEST':'SLOT_GATED_BYTE_FIELD_WRITE_REQUEST',
        requested_u8:18,receiver_field_offset:op===1?'0x2f':'0xe8',receiver_field_meaning:'UNKNOWN',
        ...(op===1?{native_lookup_index:0}:{callee_has_state_gate:true})})};
    return {event_type:'SPELL_SLOT_CHANGE_REQUEST_CANDIDATE',game_version:PROFILE.replay_version,patch:'16.19',
      build_profile:PROFILE.id,replay_sha256:replaySha,replay_time_ms:time,raw_param:0x400000ae+i,
      stream_tag:i===2?2:1,confidence:'CANDIDATE',semantic_status:PROFILE.evidence_status,
      semantic_effect_status:'UNKNOWN',deserialize_return_al:1,native_packet_id:id,bytes_consumed:i===1?19:5,
      native_nested_field_bytes_hex:{'0x18':'bb','0x1c':ophex.toString('hex'),'0x20':'fc273b'},
      native_byte_vector_length:vector.length/2,native_byte_vector_hex:vector,
      native_byte_vector_ascii_candidate:i===1?'Ab':null,
      native_byte_vector_text_status:i===1?'PRINTABLE_ASCII_CANDIDATE':'OPAQUE_BYTES',native_byte_vector_terminal_nul:i===1,
      callback_request_candidate:callback,raw_packet_ref:{source_path:'synthetic.rofl',replay_sha256:replaySha,
        chunk_index:i,chunk_id:i+1,chunk_stream:i===2?'keyframe':'game_chunk',chunk_file_offset:100+i,
        decompressed_block_offset:10,decompressed_payload_offset:25,packet_id:id,replay_time_ms:time,
        payload_length:i===1?19:5,raw_param:0x400000ae+i,raw_payload_sha256:sha('fake-payload')}};
  });
  const result={profile_id:PROFILE.id,evidence_status:PROFILE.evidence_status,status:'CANDIDATE',input_count:3,
    event_count:3,native_full_success_count:3,native_printable_ascii_count:1,native_opaque_vector_count:2,
    evidence_runtime_image_sha256:PROFILE.evidence_runtime_image_sha256,runtime_image_sha256:PROFILE.evidence_runtime_image_sha256,
    runtime_image_used:true,runtime_image_status:'MATCHED_USED',known_limits:[...PROFILE.known_limits],
    ordered_native_input_sha256:sha('synthetic-input'),input_packet_ids:[0x049c,0x028e,0x0375],
    memory_compatibility_operation:PROFILE.memory_compatibility_operation,
    memory_compatibility_leaf_rva:PROFILE.memory_compatibility_leaf_rva,
    memory_compatibility_prefix_sha256:PROFILE.memory_compatibility_prefix_sha256,
    native_callback_rva:PROFILE.native_callback_rva,registered_receiver_class:PROFILE.registered_receiver_class};
  const semantic={replay_version:PROFILE.replay_version,replay_sha256:replaySha,container_status:'PASS',status:'CANDIDATE',
    requested_capabilities:[PROFILE.capability],capability_results:{[PROFILE.capability]:result}};
  const analysis={patch:'16.19',replay_version:PROFILE.replay_version,replay_sha256:replaySha,source_path:'synthetic.rofl',
    event_storage:'JSONL_ONLY',event_counts:{[EVENT]:3},event_jsonl_files:{[EVENT]:`${EVENT}.jsonl`},
    semantic:{status:'CANDIDATE',capability_results:{[PROFILE.capability]:result}}};
  const manifest={command_args:['decode'],replay_inputs:[{artifact_directory:relative,sha256:replaySha,version:PROFILE.replay_version}],
    output_hashes_excluding_manifest:{}};
  const save=()=>{
    for(const [name,content] of [['semantic_run.json',JSON.stringify(semantic)],['replay_analysis.json',JSON.stringify(analysis)],
      [`${EVENT}.jsonl`,`${rows.map(JSON.stringify).join('\n')}\n`]]) {
      fs.writeFileSync(path.join(dir,name),content);manifest.output_hashes_excluding_manifest[`${relative}/${name}`]=sha(content);
    }
    fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify(manifest));
  };
  save();return {root,dir,rows,result,semantic,analysis,manifest,save};
}
function failed(run,code) {assert.equal(run.status,2,run.stderr);assert.equal(run.stdout,'');assert.equal(JSON.parse(run.stderr).code,code);}
test('saved query filters time, full header and internal slot/operation without changing row bytes',t=>{
  const f=fixture(t),run=cli(f.root,EVENT,'--from-ms','1500','--to-ms','2500','--slot-change-index','0',
    '--slot-change-operation','2','--raw-param','0x400000af','--limit','1');
  assert.equal(run.status,0,run.stderr);assert.equal(run.stdout,`${JSON.stringify(f.rows[1])}\n`);
  const summary=JSON.parse(run.stderr);assert.equal(summary.scanned_count,3);assert.equal(summary.matched_count,1);
  assert.equal(summary.source_provenance_status,'SAVED_ONLY_UNVERIFIED');
});
test('limit cannot hide late callback, unknown field, malformed JSON or source-identity changes',t=>{
  for(const mutate of [r=>r.callback_request_candidate.application_status='APPLIED',
    r=>r.callback_request_candidate.actor='CONFIRMED',r=>r.raw_packet_ref.replay_sha256='b'.repeat(64),
    r=>r.native_byte_vector_hex='13',r=>r.native_nested_field_bytes_hex['0x20']=123456,
    r=>r.raw_packet_ref.decompressed_payload_offset=0]) {
    const f=fixture(t);mutate(f.rows[2]);f.save();failed(cli(f.root,EVENT,'--limit','1'),'INVALID_EVENT_ROW');
  }
  const f=fixture(t);f.rows[2]=null;f.save();failed(cli(f.root,EVENT,'--limit','1'),'INVALID_EVENT_ROW');
});
test('library API publishes no early rows on a late saved failure',async t=>{
  const f=fixture(t);f.rows[2].callback_request_candidate.receiver_entity_status='CONFIRMED';f.save();
  const emitted=[];await assert.rejects(streamEventQuery(prepareEventQuery(f.dir,EVENT),{limit:1},line=>emitted.push(line)),
    error=>error.code==='INVALID_EVENT_ROW');assert.deepEqual(emitted,[]);
});
test('default embedded and JSONL output must agree even after the query limit',t=>{
  const f=fixture(t);delete f.analysis.event_storage;f.analysis.events={[EVENT]:structuredClone(f.rows)};f.save();
  assert.equal(cli(f.root,EVENT,'--limit','1').status,0);
  f.analysis.events[EVENT][2].callback_request_candidate.requested_u8=0;f.save();
  failed(cli(f.root,EVENT,'--limit','1'),'INVALID_EVENT_ROW');
});
test('saved native counts, exact build and manifest corruption reject even with a result limit',t=>{
  const f=fixture(t);f.result.native_full_success_count=2;f.save();
  failed(cli(f.root,EVENT,'--limit','1'),'CAPABILITY_METADATA_MISMATCH');
  const g=fixture(t);g.semantic.replay_version='16.19.820.7193';g.analysis.replay_version=g.semantic.replay_version;
  g.manifest.replay_inputs[0].version=g.semantic.replay_version;g.save();
  failed(cli(g.root,EVENT,'--limit','1'),'BATCH_EVENT_UNAVAILABLE');
  const h=fixture(t);fs.appendFileSync(path.join(h.dir,`${EVENT}.jsonl`),'{}\n');
  failed(cli(h.root,EVENT,'--limit','1'),'ARTIFACT_HASH_MISMATCH');
});
test('unsupported filters and missing native verification inputs are explicit failures',t=>{
  const f=fixture(t);failed(cli(f.root,EVENT,'--participant','1'),'UNSUPPORTED_FILTER');
  failed(cli(f.root,EVENT,'--slot-change-operation','3'),'INVALID_FILTER');
  failed(cli(f.root,EVENT,'--slot-change-index','256'),'INVALID_FILTER');
  failed(cli(f.root,EVENT,'--verify-source','--limit','1'),'MISSING_RUNTIME_IMAGE');
});

const SAVED=process.env.ROFL_821_SLOT_SAVED_ARTIFACTS, IMAGE=process.env.ROFL_821_RUNTIME_IMAGE;
test('real saved pair queries check all sources, exact-image re-decode, overrides and late forgeries',
  {skip:!SAVED||!IMAGE||!fs.existsSync(SAVED)||!fs.existsSync(IMAGE)?'authorized exact-821 saved run and image unavailable':false},t=>{
    const root=fs.mkdtempSync(path.join(os.tmpdir(),'rofl-slot-query-'));cleanup(t,root);
    const sourceManifest=JSON.parse(fs.readFileSync(path.join(SAVED,'manifest.json'))),entry=sourceManifest.replay_inputs[0];
    const dir=path.join(root,...entry.artifact_directory.split('/'));fs.mkdirSync(dir,{recursive:true});
    const files=['semantic_run.json','replay_analysis.json','rofl_inventory.json',`${EVENT}.jsonl`,
      'spell_slot_change_roster_key_pair_candidates.jsonl','hero_roster_metadata_bridge_candidates.jsonl'];
    for(const file of files)fs.copyFileSync(path.join(SAVED,...entry.artifact_directory.split('/'),file),path.join(dir,file));
    sourceManifest.replay_inputs=[entry];sourceManifest.output_hashes_excluding_manifest=Object.fromEntries(
      Object.entries(sourceManifest.output_hashes_excluding_manifest).filter(([key])=>key.startsWith(`${entry.artifact_directory}/`)));
    const manifestPath=path.join(root,'manifest.json');fs.writeFileSync(manifestPath,JSON.stringify(sourceManifest));
    const pairEvent='spell_slot_change_roster_key_pair_candidates',pairPath=path.join(dir,`${pairEvent}.jsonl`);
    const original=fs.readFileSync(pairPath,'utf8'),lines=original.trimEnd().split('\n'),first=JSON.parse(lines[0]);
    const saved=cli(root,pairEvent,'--participant',String(first.participant_id_candidate),'--slot-change-index',
      String(first.slot_index_candidate),'--slot-change-operation',String(first.request_candidate.operation_selector),'--limit','1');
    assert.equal(saved.status,0,saved.stderr);assert.equal(saved.stdout,`${lines[0]}\n`);
    assert.equal(JSON.parse(saved.stderr).scanned_count,lines.length);
    const native=cli(dir,pairEvent,'--verify-source','--runtime-image',IMAGE,'--source-replay',first.raw_packet_ref.source_path,'--limit','1');
    assert.equal(native.status,0,native.stderr);assert.equal(native.stdout,`${lines[0]}\n`);
    assert.equal(JSON.parse(native.stderr).native_witness_check,'FRESH_EXACT_IMAGE_REDECODE');
    const wrongImage=path.join(root,'wrong-image.bin');fs.writeFileSync(wrongImage,'x');
    const blocked=cli(dir,pairEvent,'--verify-source','--runtime-image',wrongImage,'--limit','1');
    failed(blocked,'SOURCE_REPLAY_DECODE_FAILED');assert.equal(JSON.parse(blocked.stderr).runtime_image_status,'SIZE_MISMATCH');
    const writeFile=(name,content)=>{
      fs.writeFileSync(path.join(dir,name),content);
      sourceManifest.output_hashes_excluding_manifest[`${entry.artifact_directory}/${name}`]=sha(content);
      fs.writeFileSync(manifestPath,JSON.stringify(sourceManifest));
    };
    const forged=JSON.parse(lines.at(-1));forged.champion_metadata='ForgedChampion';
    writeFile(`${pairEvent}.jsonl`,`${[...lines.slice(0,-1),JSON.stringify(forged)].join('\n')}\n`);
    failed(cli(root,pairEvent,'--limit','1'),'INVALID_EVENT_ROW');
    writeFile(`${pairEvent}.jsonl`,original);
    const requestOriginal=fs.readFileSync(path.join(dir,`${EVENT}.jsonl`),'utf8');
    const requests=requestOriginal.trimEnd().split('\n');
    // Coherent saved-output substitution can pass schema/source joins. Only
    // exact-image re-decode authenticates the native value against original bytes.
    const substituted=JSON.parse(requests[0]);assert.equal(substituted.callback_request_candidate.operation_selector,2);
    const name=Buffer.from(substituted.native_byte_vector_hex,'hex');name[0]^=32;
    substituted.native_byte_vector_hex=name.toString('hex');
    substituted.native_byte_vector_ascii_candidate=name.subarray(0,-1).toString('ascii');
    substituted.callback_request_candidate.requested_name_bytes_hex=name.subarray(0,-1).toString('hex');
    substituted.callback_request_candidate.requested_name_ascii=substituted.native_byte_vector_ascii_candidate;
    requests[0]=JSON.stringify(substituted);writeFile(`${EVENT}.jsonl`,`${requests.join('\n')}\n`);
    const coherentPair={...first,request_candidate:substituted.callback_request_candidate};
    writeFile(`${pairEvent}.jsonl`,`${[JSON.stringify(coherentPair),...lines.slice(1)].join('\n')}\n`);
    assert.equal(cli(root,pairEvent,'--limit','1').status,0);
    failed(cli(root,pairEvent,'--verify-source','--runtime-image',IMAGE,'--limit','1'),'SOURCE_PROVENANCE_MISMATCH');
    writeFile(`${pairEvent}.jsonl`,original);writeFile(`${EVENT}.jsonl`,requestOriginal);
    requests[0]=requestOriginal.trimEnd().split('\n')[0];
    const late=JSON.parse(requests.at(-1));late.callback_request_candidate.application_status='APPLIED';
    requests[requests.length-1]=JSON.stringify(late);writeFile(`${EVENT}.jsonl`,`${requests.join('\n')}\n`);
    const output=path.join(root,'must-not-exist.jsonl');
    failed(cli(root,pairEvent,'--limit','1','--output',output),'INVALID_EVENT_ROW');assert.equal(fs.existsSync(output),false);
  });
