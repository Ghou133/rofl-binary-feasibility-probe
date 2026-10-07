'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const test=require('node:test');
const {replayFromChunks}=require('./helpers/synthetic_replay');
const {cli,hash}=require('./helpers/damage_query_fixture');
const {decodeHeroStatsByte,HERO_DAMAGE_KEYFRAME_INTERVALS_820_PROFILE:PROFILE}=require('../src/decoders/rofl_16_19_hero_stats_candidate');
const {decodeHeroDamageKeyframeIntervalsCandidates821}=require('../src/decoders/rofl_16_19_821_damage_keyframe_intervals_candidate');
const {prepareEventQuery,streamEventQuery}=require('../src/event_query');
const EVENT='hero_damage_keyframe_interval_candidates',CAP='hero_damage_keyframe_intervals';
const ENCODE=new Map(Array.from({length:256},(_,i)=>[decodeHeroStatsByte(i),i]));

function fixture(t,{missingTail=false,absentRoute=false,frames=3,initial=0}={}){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rofl-hn-interval-'));
  t.after(()=>{assert.equal(path.dirname(path.resolve(root)),path.resolve(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
  const frame=time=>Buffer.concat(Array.from({length:10},(_,i)=>{
    const participant=10-i,payload=Buffer.alloc(1263);payload.set([0x1c,0xa6,0xe8]);
    PROFILE.fields.forEach((field,column)=>{
      const bytes=Buffer.alloc(4);bytes.writeFloatLE(initial+(time===0?0:participant*(time/60000)*(column+1)+0.25));
      for(let n=0;n<4;n++)payload[1262-field.blob_f32le_offset_candidate-n]=ENCODE.get(bytes[n]);
    });
    const header=Buffer.alloc(15);header.writeFloatLE(time/1000,1);header.writeUInt32LE(payload.length,5);
    header.writeUInt16LE(absentRoute?0x0089:0x0276,9);header.writeUInt32LE(0x400000ad+participant,11);
    return Buffer.concat([header,payload]);
  }));
  // HN starts in stream 3 and can place multiple epochs in the same physical chunk.
  const chunks=[{stream:3,body:frame(0)}];
  if(frames>1)chunks.push({stream:2,body:Buffer.concat([60000,120000].slice(0,frames-1).map(frame))});
  const replay=replayFromChunks(chunks,PROFILE.replay_version);
  const stats=Array.from({length:10},(_,i)=>Object.fromEntries(PROFILE.fields
    .filter(field=>!missingTail||field.replay_tail_field!=='TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS')
    .map((field,column)=>[field.replay_tail_field,String((i+1)*2*(column+1)+5)])));
  const metadata=Buffer.from(JSON.stringify({gameLength:180000,statsJson:JSON.stringify(stats)}));
  const oldLength=replay.buffer.readUInt32LE(replay.buffer.length-4),trailer=Buffer.alloc(4);trailer.writeUInt32LE(metadata.length);
  const source=path.join(root,'source.rofl');fs.writeFileSync(source,Buffer.concat([replay.buffer.subarray(0,replay.buffer.length-oldLength-4),metadata,trailer]));
  const run=path.join(root,'run');return {root,source,run,replay};
}
function decode(f){return cli('decode',f.source,'--events',CAP,'--event-jsonl-only','--out-dir',f.run);}
function artifacts(f){
  const manifestPath=path.join(f.run,'manifest.json'),manifest=JSON.parse(fs.readFileSync(manifestPath));
  const dir=path.join(f.run,manifest.replay_inputs[0].artifact_directory);
  return {dir,manifest,manifestPath,file:path.join(dir,EVENT+'.jsonl')};
}

test('exact HN decoder uses its own transform, stream-3 origin and same-chunk observation epochs',async t=>{
  const f=fixture(t);assert.equal(decodeHeroDamageKeyframeIntervalsCandidates821(f.replay).status,'UNSUPPORTED');
  const decoded=decode(f);assert.equal(decoded.status,0,decoded.stderr);
  const a=artifacts(f),semantic=JSON.parse(fs.readFileSync(path.join(a.dir,'semantic_run.json')));
  const result=semantic.capability_results[CAP];assert.equal(result.profile_id,PROFILE.id);
  assert.equal(result.input_packet_id,0x0276);assert.equal(result.runtime_image_used,false);
  assert.equal(result.lookup_table_sha256,PROFILE.lookup_table_sha256);
  assert.equal(result.keyframe_count,3);assert.equal(result.event_count,20);assert.equal(result.tail_gaps.length,40);
  const rows=fs.readFileSync(a.file,'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(rows[0].previous_raw_packet_ref.chunk_stream,'start_keyframe');
  assert.equal(rows[10].previous_raw_packet_ref.chunk_index,rows[10].current_raw_packet_ref.chunk_index);
  assert.equal(rows[0].counters.TOTAL_DAMAGE_TAKEN.endpoint_delta_f32_candidate,3.25);
  assert.equal(rows[10].counters.TOTAL_DAMAGE_TAKEN.endpoint_delta_f32_candidate,3);
  assert.equal(rows[0].change_time_status,'UNRESOLVED_WITHIN_INTERVAL');assert.equal('effective_damage' in rows[0],false);
  const emitted=[];const summary=await streamEventQuery(prepareEventQuery(a.dir,EVENT),
    {verifySource:true,participant:1,limit:1},line=>emitted.push(JSON.parse(line)));
  assert.equal(summary.scanned_count,20);assert.equal(summary.matched_count,2);
  assert.deepEqual(emitted,[rows[0]]);assert.equal(summary.source_provenance_status,'SOURCE_REPLAY_VERIFIED');
});

test('HN preflight reports all four tail requirements and missing fields block interval decoding',t=>{
  const f=fixture(t,{missingTail:true});
  const preflight=cli('capabilities',f.source,'--events',CAP,'--json');
  const data=JSON.parse(preflight.stdout),row=data.capabilities.find(row=>row.capability===CAP);
  assert.ok(row.missing_inputs.some(item=>JSON.stringify(item).includes('TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS')));
  const decoded=decode(f);assert.notEqual(decoded.status,0);
  const a=artifacts(f),semantic=JSON.parse(fs.readFileSync(path.join(a.dir,'semantic_run.json')));
  assert.equal(semantic.capability_results[CAP].status,'MISSING_INPUT');assert.equal(semantic.capability_results[CAP].event_count,null);
});

test('HN nonzero first observations and a single-epoch empty set retain protected tail evidence',t=>{
  for(const frames of [1,2]){
    const f=fixture(t,{frames,initial:0.125});const decoded=decode(f);assert.equal(decoded.status,0,decoded.stderr);
    const query=cli('query-events',f.run,'--event',EVENT,'--verify-source','--limit','1');
    assert.equal(query.status,0,query.stderr);assert.equal(JSON.parse(query.stderr).scanned_count,(frames-1)*10);
    if(frames===1)assert.equal(query.stdout,'');
    const a=artifacts(f),result=JSON.parse(fs.readFileSync(path.join(a.dir,'semantic_run.json'))).capability_results[CAP];
    assert.ok(result.tail_gaps.every(gap=>/^[0-9a-f]{8}$/.test(gap.last_raw_payload_field_bytes_hex)));
  }
});

test('foreign KR route in the same full build is unavailable rather than zero or decoded with KR bytes',t=>{
  const f=fixture(t,{absentRoute:true});assert.notEqual(decode(f).status,0);
  const a=artifacts(f),result=JSON.parse(fs.readFileSync(path.join(a.dir,'semantic_run.json'))).capability_results[CAP];
  assert.equal(result.status,'PROFILE_UNAVAILABLE');assert.equal(result.event_count,null);
});

test('HN late protected endpoint corruption fails before any limited CLI/API output',async t=>{
  const f=fixture(t);assert.equal(decode(f).status,0);const a=artifacts(f);
  const rows=fs.readFileSync(a.file,'utf8').trim().split('\n').map(JSON.parse);
  rows.at(-1).current_raw_payload_field_bytes_hex.TOTAL_DAMAGE_TAKEN='00000000';
  fs.writeFileSync(a.file,rows.map(JSON.stringify).join('\n')+'\n');
  for(const relative of Object.keys(a.manifest.output_hashes_excluding_manifest))a.manifest.output_hashes_excluding_manifest[relative]=hash(fs.readFileSync(path.join(f.run,relative)));
  fs.writeFileSync(a.manifestPath,JSON.stringify(a.manifest));
  const emitted=[];await assert.rejects(streamEventQuery(prepareEventQuery(a.dir,EVENT),{limit:1},line=>emitted.push(line)),{code:'INVALID_EVENT_ROW'});
  assert.deepEqual(emitted,[]);
  const run=cli('query-events',f.run,'--event',EVENT,'--limit','1');assert.equal(run.status,2,run.stderr);assert.equal(run.stdout,'');
});
