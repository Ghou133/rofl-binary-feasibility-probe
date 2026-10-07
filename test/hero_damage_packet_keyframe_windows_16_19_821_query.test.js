'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {damageQueryFixture,cli,hash,WINDOW:EVENT,INTERVAL} = require('./helpers/damage_query_fixture');
const {prepareEventQuery,prepareBatchEventQuery,streamEventQuery,streamBatchEventQuery} = require('../src/event_query');
const {compareDamagePacketKeyframeWindows821:compare} = require('../src/decoders/rofl_16_19_821_damage_window_reconciliation_candidate');
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const native = {skip:!IMAGE||!fs.existsSync(IMAGE)?'exact 821 image unavailable':false};
const fixture = (t,options={}) => damageQueryFixture(t,{...options,withPackets:true,image:IMAGE});
const query = (f,...args) => cli('query-events',f.run,'--event',EVENT,...args);
function error(run,code){assert.equal(run.status,2,run.stderr);assert.equal(run.stdout,'');assert.equal(JSON.parse(run.stderr).code,code);}
function refresh(f){
  for(const relative of Object.keys(f.manifest.output_hashes_excluding_manifest)){
    f.manifest.output_hashes_excluding_manifest[relative]=hash(fs.readFileSync(path.join(f.run,relative)));
  }
  fs.writeFileSync(f.manifestPath,JSON.stringify(f.manifest));
}
function saveRows(f){fs.writeFileSync(f.eventPath,f.rows.map(JSON.stringify).join('\n')+(f.rows.length?'\n':''));refresh(f);}
const readRows=file=>fs.readFileSync(file,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
function metadata(f){
  const file=path.join(f.dir,'semantic_run.json'),semantic=JSON.parse(fs.readFileSync(file,'utf8'));
  return {file,semantic,result:semantic.candidate_associations.hero_damage_packet_keyframe_windows};
}

test('saved packet/window CLI and API reconcile every native/interval dependency and preserve unknown roles',native,async t=>{
  const f=fixture(t),info=metadata(f);
  assert.equal(info.result.native_packet_count,4);assert.equal(info.result.exact_endpoint_time_packets_excluded,1);
  assert.equal(info.result.packets_outside_sampled_windows,1);
  const listed=cli('query-events',f.run,'--list-events');assert.equal(listed.status,0,listed.stderr);
  assert.ok(JSON.parse(listed.stdout).event_keys.includes(EVENT));
  const result=query(f,'--participant','1','--raw-param','0x400000ae','--limit','1');
  assert.equal(result.status,0,result.stderr);
  const row=JSON.parse(result.stdout),summary=JSON.parse(result.stderr);
  assert.equal(summary.scanned_count,20);assert.equal(summary.matched_count,2);
  assert.equal(row.semantic_effect_status,'UNKNOWN');assert.equal(row.packet_time_window,'STRICT_OPEN_ENDPOINTS');
  assert.ok(Object.values(row.comparisons).every(group=>group.key_role_status==='UNKNOWN'));
  const emitted=[];
  const api=await streamEventQuery(prepareEventQuery(f.dir,EVENT),{limit:1},line=>emitted.push(line));
  assert.equal(api.native_witness_check,'COMPLETE_SAVED_DEPENDENCY_RECONCILIATION');
  assert.deepEqual(api.dependency_event_counts,{unit_apply_damage_packet:4,hero_damage_keyframe_intervals:20});
  assert.equal(emitted.length,1);
});

test('window source verification reproduces both complete dependencies with exact image and preserves path override',native,t=>{
  const f=fixture(t),copy=path.join(f.root,'copy.rofl');fs.copyFileSync(f.source,copy);
  error(query(f,'--verify-source','--limit','1'),'MISSING_RUNTIME_IMAGE');
  const result=cli('query-events',f.dir,'--event',EVENT,'--verify-source','--source-replay',copy,'--runtime-image',IMAGE,'--limit','1');
  assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stderr).native_witness_check,'FRESH_EXACT_IMAGE_REDECODE');
  assert.equal(JSON.parse(result.stdout).raw_packet_ref.source_path,f.source);
  error(query(f,'--verify-source','--runtime-image',__filename,'--limit','1'),'SOURCE_REPLAY_DECODE_FAILED');
});

test('late comparison sum/control/role edits cannot bypass limits or saved dependency reconstruction',native,async t=>{
  for(const mutate of [
    row=>row.comparisons.lookup_0x24.summed_callback_f32_0x20_candidate++,
    row=>row.comparisons.lookup_0x2c.rotated_key_control.summed_callback_f32_0x20_candidate++,
    row=>row.comparisons.lookup_0x24.key_role_status='TARGET',
    row=>row.semantic_effect_status='APPLIED']){
    const f=fixture(t);mutate(f.rows.at(-1));saveRows(f);
    error(query(f,'--participant','1','--limit','1'),'INVALID_EVENT_ROW');
    const emitted=[];
    await assert.rejects(streamBatchEventQuery(prepareBatchEventQuery(f.run,EVENT),
      {participant:1,limit:1},line=>emitted.push(line)),{code:'INVALID_EVENT_ROW'});
    assert.deepEqual(emitted,[]);
  }
});

test('late packet and sampled counter dependency edits are checked even for zero matched windows',native,t=>{
  for(const [event,edit] of [
    ['unit_apply_damage_packet_candidates',row=>row.semantic_effect_status='APPLIED'],
    [INTERVAL,row=>row.counters.TOTAL_DAMAGE_TAKEN.endpoint_delta_f32_candidate++]]){
    const f=fixture(t),file=path.join(f.dir,event+'.jsonl'),rows=readRows(file);
    edit(rows.at(-1));fs.writeFileSync(file,rows.map(JSON.stringify).join('\n')+'\n');refresh(f);
    error(query(f,'--from-ms','999999','--limit','1'),'INVALID_EVENT_ROW');
  }
});

test('coherent packet-position plus derived reference forgery passes saved reconciliation but fails native source',native,t=>{
  const f=fixture(t),packetFile=path.join(f.dir,'unit_apply_damage_packet_candidates.jsonl');
  const packets=readRows(packetFile);
  for(const packet of packets)packet.raw_packet_ref.chunk_file_offset++;
  fs.writeFileSync(packetFile,packets.map(JSON.stringify).join('\n')+'\n');
  const info=metadata(f),intervals=readRows(path.join(f.dir,INTERVAL+'.jsonl'));
  const result=compare({header:{version:'16.19.821.7343'},source_sha256:info.semantic.replay_sha256},
    {...info.semantic.capability_results.unit_apply_damage_packet,events:packets},
    {...info.semantic.capability_results.hero_damage_keyframe_intervals,events:intervals});
  assert.equal(result.status,'CANDIDATE',result.error);
  f.rows=result.events;saveRows(f);
  const saved=query(f,'--limit','1');assert.equal(saved.status,0,saved.stderr);
  assert.equal(JSON.parse(saved.stderr).source_provenance_status,'SAVED_ONLY_UNVERIFIED');
  error(query(f,'--verify-source','--runtime-image',IMAGE,'--limit','1'),'SOURCE_PROVENANCE_MISMATCH');
});

test('dependency output hash changes and missing dependency files reject before any output',native,t=>{
  const f=fixture(t),file=path.join(f.dir,INTERVAL+'.jsonl');
  fs.appendFileSync(file,'\n');error(query(f,'--limit','1'),'ARTIFACT_HASH_MISMATCH');
  fs.renameSync(file,file+'.hidden');error(query(f,'--limit','1'),'MISSING_EVENT_ARTIFACT');
});

test('native V5 profile and checked one-keyframe empty comparisons remain queryable',native,t=>{
  const f=fixture(t,{frames:1,packetProfile:'v5'});
  const result=query(f,'--verify-source','--runtime-image',IMAGE);
  assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'');
  assert.equal(JSON.parse(result.stderr).scanned_count,0);
});

test('embedded comparison arrays must match saved JSONL and generic foreign filters reject',native,async t=>{
  const f=fixture(t,{jsonlOnly:false});
  assert.equal(query(f,'--limit','1').status,0);
  await assert.rejects(streamEventQuery(prepareEventQuery(f.dir,EVENT),{killerParticipant:1},()=>{}),{code:'UNSUPPORTED_FILTER'});
  f.rows.at(-1).comparisons.lookup_0x24.packet_count++;saveRows(f);
  error(query(f,'--limit','1'),'INVALID_EVENT_ROW');
});
