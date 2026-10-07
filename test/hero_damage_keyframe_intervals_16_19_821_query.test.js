'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const test = require('node:test');
const {replayFromChunks} = require('./helpers/synthetic_replay');
const {decodeRuntimeCountByte} = require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {prepareEventQuery,prepareBatchEventQuery,streamEventQuery,streamBatchEventQuery} = require('../src/event_query');
const CLI = path.resolve(__dirname,'../src/cli.js');
const EVENT = 'hero_damage_keyframe_interval_candidates';
const CAP = 'hero_damage_keyframe_intervals';
const FIELDS = ['TOTAL_DAMAGE_DEALT_TO_CHAMPIONS','TOTAL_DAMAGE_DEALT','TOTAL_DAMAGE_TAKEN','TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS'];
const OFFSETS = [0x1e0,0x1d0,0x1f0,0x200];
const ENCODE = new Map(Array.from({length:256},(_,raw)=>[decodeRuntimeCountByte(raw),raw]));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const cli = (...args) => spawnSync(process.execPath,[CLI,...args],{encoding:'utf8',windowsHide:true,timeout:30000});
function fixture(t,{frames=3,jsonlOnly=true}={}) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rofl-damage-query-'));
  t.after(()=>{const resolved=path.resolve(root);
    assert.ok(resolved.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(resolved).startsWith('rofl-damage-query-'));
    fs.rmSync(resolved,{recursive:true,force:true});});
  const values=[[0,0,0,0],[0.9,10.5,15.25,7.5],[1.1,10.5,20.5,9.25]];
  const chunks=values.slice(0,frames).map((numbers,frame)=>({stream:2,
    body:Buffer.concat(Array.from({length:10},(_,participant)=>{
      const payload=Buffer.alloc(1263,0x97);payload.set([0x67,0,0xde]);
      OFFSETS.forEach((offset,column)=>{
        const bytes=Buffer.alloc(4);bytes.writeFloatLE(participant===0?numbers[column]:0);
        for(let i=0;i<4;i++)payload[1262-offset-i]=ENCODE.get(bytes[i]);
      });
      const header=Buffer.alloc(15);header.writeFloatLE(frame*60,1);header.writeUInt32LE(1263,5);
      header.writeUInt16LE(0x0089,9);header.writeUInt32LE(0x400000ae+participant,11);
      return Buffer.concat([header,payload]);
    }))}));
  const buffer=replayFromChunks(chunks,'16.19.821.7343').buffer;
  const stats=Array.from({length:10},(_,i)=>Object.fromEntries(FIELDS.map((field,column)=>
    [field,String(Math.ceil(i===0?values[frames-1][column]:0)+5)])));
  const metadata=Buffer.from(JSON.stringify({gameLength:180000,statsJson:JSON.stringify(stats)}));
  const oldLength=buffer.readUInt32LE(buffer.length-4), trailer=Buffer.alloc(4);trailer.writeUInt32LE(metadata.length);
  const source=path.join(root,'source.rofl');
  fs.writeFileSync(source,Buffer.concat([buffer.subarray(0,buffer.length-oldLength-4),metadata,trailer]));
  const run=path.join(root,'run');
  const decoded=cli('decode',source,'--events',CAP,...(jsonlOnly?['--event-jsonl-only']:[]),'--out-dir',run);
  assert.equal(decoded.status,0,decoded.stderr);
  const manifestPath=path.join(run,'manifest.json'),manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  const dir=path.join(run,manifest.replay_inputs[0].artifact_directory),eventPath=path.join(dir,EVENT+'.jsonl');
  const text=fs.readFileSync(eventPath,'utf8').trim();
  return {root,source,run,dir,eventPath,rows:text?text.split('\n').map(JSON.parse):[],manifest,manifestPath};
}
const query=(f,...args)=>cli('query-events',f.run,'--event',EVENT,...args);
function error(run,code){assert.equal(run.status,2,run.stderr);assert.equal(run.stdout,'');assert.equal(JSON.parse(run.stderr).code,code);}
function refresh(f){
  fs.writeFileSync(f.eventPath,f.rows.map(JSON.stringify).join('\n')+(f.rows.length?'\n':''));
  for(const relative of Object.keys(f.manifest.output_hashes_excluding_manifest)){
    f.manifest.output_hashes_excluding_manifest[relative]=hash(fs.readFileSync(path.join(f.run,relative)));
  }
  fs.writeFileSync(f.manifestPath,JSON.stringify(f.manifest));
}
function editMetadata(f,change){
  for(const name of ['semantic_run.json','replay_analysis.json']){
    const file=path.join(f.dir,name),doc=JSON.parse(fs.readFileSync(file,'utf8'));
    change(name==='semantic_run.json'?doc.capability_results[CAP]:doc.semantic.capability_results[CAP],doc);
    fs.writeFileSync(file,JSON.stringify(doc));
  }
  refresh(f);
}

test('saved sampled damage queries list and filter endpoints/participant/full header with complete scan',async t=>{
  const f=fixture(t);
  const listed=cli('query-events',f.run,'--list-events');assert.equal(listed.status,0,listed.stderr);
  assert.ok(JSON.parse(listed.stdout).event_keys.includes(EVENT));
  const result=query(f,'--participant','1','--from-ms','60000','--to-ms','120000','--raw-param','0x400000ae','--limit','1');
  assert.equal(result.status,0,result.stderr);
  const summary=JSON.parse(result.stderr),row=JSON.parse(result.stdout);
  assert.equal(summary.scanned_count,20);assert.equal(summary.matched_count,2);
  assert.equal(summary.source_provenance_status,'SAVED_ONLY_UNVERIFIED');
  assert.equal(row.previous_observation_time_ms,0);assert.equal(row.replay_time_ms,60000);
  assert.equal(row.confidence,'CANDIDATE');assert.equal(row.change_time_status,'UNRESOLVED_WITHIN_INTERVAL');
  const rows=[];
  const api=await streamEventQuery(prepareEventQuery(f.dir,EVENT),{participant:2},line=>rows.push(JSON.parse(line)));
  assert.equal(api.scanned_count,20);assert.equal(rows.length,2);
  assert.ok(rows.every(row=>!row.any_counter_changed));
});

test('full physical damage re-decode needs no runtime image and source override normalizes saved paths',t=>{
  const f=fixture(t),copy=path.join(f.root,'copied.rofl');fs.copyFileSync(f.source,copy);fs.renameSync(f.source,f.source+'.hidden');
  const result=cli('query-events',f.dir,'--event',EVENT,'--verify-source','--source-replay',copy,'--limit','1');
  assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stderr).scanned_count,20);
  assert.equal(JSON.parse(result.stderr).source_provenance_status,'SOURCE_REPLAY_VERIFIED');
  assert.equal(JSON.parse(result.stdout).raw_packet_ref.source_path,f.source);
  error(query(f,'--verify-source'),'SOURCE_REPLAY_READ_FAILED');
});

test('late invented effective damage emits no saved CLI/API/batch output despite limit and filter',async t=>{
  const f=fixture(t);f.rows.at(-1).effective_damage=1;refresh(f);
  error(query(f,'--participant','1','--limit','1'),'INVALID_EVENT_ROW');
  for(const [prepared,stream] of [[prepareEventQuery(f.dir,EVENT),streamEventQuery],[prepareBatchEventQuery(f.run,EVENT),streamBatchEventQuery]]){
    const emitted=[];
    await assert.rejects(stream(prepared,{participant:1,limit:1},line=>emitted.push(line)),{code:'INVALID_EVENT_ROW'});
    assert.deepEqual(emitted,[]);
  }
});

test('arithmetic forgery, broken endpoint chain and truncation cannot be hidden after limit',t=>{
  for(const mutation of [f=>f.rows.at(-1).counters.TOTAL_DAMAGE_TAKEN.endpoint_delta_f32_candidate=1,
    f=>f.rows.at(-1).previous_raw_packet_ref.decompressed_block_offset++,
    f=>f.rows.pop()]){
    const f=fixture(t);mutation(f);refresh(f);
    const result=query(f,'--limit','1');assert.equal(result.status,2,result.stderr);assert.equal(result.stdout,'');
    assert.ok(['INVALID_EVENT_ROW','EVENT_COUNT_MISMATCH'].includes(JSON.parse(result.stderr).code));
  }
});

test('self-consistent protected endpoint plus tail/count forgery remains saved-only and fails source verification',t=>{
  const f=fixture(t),row=f.rows.at(-1),field='TOTAL_DAMAGE_TAKEN';
  const bytes=Buffer.alloc(4);bytes.writeFloatLE(1);
  row.current_raw_payload_field_bytes_hex[field]=Buffer.from([...bytes].map(byte=>ENCODE.get(byte)).reverse()).toString('hex');
  row.counters[field]={previous_raw_f32_candidate:0,current_raw_f32_candidate:1,
    endpoint_delta_f32_candidate:1,endpoint_floor_difference_candidate:1};row.any_counter_changed=true;
  editMetadata(f,result=>{
    result.changed_interval_count++;result.unchanged_interval_count--;result.changed_interval_counts_by_field[field]++;
    const gap=result.tail_gaps.find(gap=>gap.participant_id_candidate===10&&gap.replay_tail_field===field);
    gap.last_snapshot_raw_f32_candidate=1;gap.last_snapshot_floor_candidate=1;gap.unobserved_tail_gap--;
  });
  const saved=query(f,'--limit','1');assert.equal(saved.status,0,saved.stderr);
  assert.equal(JSON.parse(saved.stderr).source_provenance_status,'SAVED_ONLY_UNVERIFIED');
  error(query(f,'--verify-source','--limit','1'),'SOURCE_PROVENANCE_MISMATCH');
});

test('checked one-keyframe zero intervals remain distinct from missing and invalid source',t=>{
  const f=fixture(t,{frames:1});const result=query(f,'--verify-source','--limit','1');
  assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'');assert.equal(JSON.parse(result.stderr).scanned_count,0);
  const wrong=path.join(f.root,'wrong.rofl');fs.writeFileSync(wrong,Buffer.from('wrong'));
  error(cli('query-events',f.dir,'--event',EVENT,'--verify-source','--source-replay',wrong),'SOURCE_REPLAY_INVALID');
});

test('embedded and JSONL interval rows must agree and unsupported combat/native filters reject',async t=>{
  const f=fixture(t,{jsonlOnly:false});
  assert.equal(query(f,'--limit','1').status,0);
  await assert.rejects(streamEventQuery(prepareEventQuery(f.dir,EVENT),{killerParticipant:1},()=>{}),{code:'UNSUPPORTED_FILTER'});
  assert.equal(query(f,'--killer-participant','1').status,1);
  error(query(f,'--runtime-image',__filename),'UNSUPPORTED_FILTER');
  f.rows.at(-1).any_counter_changed=true;refresh(f);error(query(f,'--limit','1'),'INVALID_EVENT_ROW');
});

test('tail gap/count corruption is rejected even for empty output selections',t=>{
  for(const change of [r=>r.tail_gaps[0]=null,r=>r.tail_gaps[0].unobserved_tail_gap++,
    r=>r.changed_interval_count++]){
    const f=fixture(t);editMetadata(f,change);
    error(query(f,'--from-ms','999999','--limit','1'),'CAPABILITY_METADATA_MISMATCH');
  }
});

test('inconsistent duplicate endpoint positions fail without output',t=>{
  const f=fixture(t),ref=f.rows[1].current_raw_packet_ref;
  ref.decompressed_block_offset=f.rows[0].current_raw_packet_ref.decompressed_block_offset;
  ref.decompressed_payload_offset=f.rows[0].current_raw_packet_ref.decompressed_payload_offset;
  f.rows[11].previous_raw_packet_ref=structuredClone(ref);
  editMetadata(f,result=>{
    for(const gap of result.tail_gaps.filter(row=>row.participant_id_candidate===2)){
      gap.last_raw_packet_ref=f.rows[11].current_raw_packet_ref;
    }
  });
  error(query(f,'--limit','1'),'INVALID_EVENT_ROW');
});

test('a later Replay failure suppresses all earlier batch CLI/API rows',async t=>{
  const first=fixture(t,{frames:2}),second=fixture(t);
  second.rows.at(-1).effective_damage=99;refresh(second);
  const relative='replays/second';
  fs.cpSync(second.dir,path.join(first.run,relative),{recursive:true});
  first.manifest.replay_inputs.push({...second.manifest.replay_inputs[0],artifact_directory:relative});
  for(const [file,digest] of Object.entries(second.manifest.output_hashes_excluding_manifest)){
    if(file.startsWith(second.manifest.replay_inputs[0].artifact_directory+'/')){
      first.manifest.output_hashes_excluding_manifest[relative+file.slice(second.manifest.replay_inputs[0].artifact_directory.length)]=digest;
    }
  }
  fs.writeFileSync(first.manifestPath,JSON.stringify(first.manifest));
  error(query(first,'--limit','1'),'INVALID_EVENT_ROW');
  const emitted=[];
  await assert.rejects(streamBatchEventQuery(prepareBatchEventQuery(first.run,EVENT),
    {limit:1},line=>emitted.push(line)),{code:'INVALID_EVENT_ROW'});
  assert.deepEqual(emitted,[]);
});
