'use strict';

const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const test=require('node:test');
const {replayFromChunks}=require('./helpers/synthetic_replay');
const {prepareEventQuery,streamEventQuery}=require('../src/event_query');
const {decodeProtectedCooldownRequestFields821}=require('../src/decoders/rofl_16_19_821_cooldown_broadcast_packet_candidate');
const IMAGE=process.env.ROFL_821_RUNTIME_IMAGE;
const native={skip:!IMAGE||!fs.existsSync(IMAGE)?'exact 821 image unavailable':false};
const EVENT='cooldown_broadcast_packet_candidates';
const CAP='cooldown_broadcast_packet';
const CLI=path.resolve(__dirname,'../src/cli.js');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const cli=(...args)=>spawnSync(process.execPath,[CLI,...args],{encoding:'utf8',windowsHide:true,timeout:120000,maxBuffer:4*1024*1024});
function fixture(t){
  // Generated container around previously observed packet bytes: protocol test
  // inputs, never an observed receiver or gameplay-state fixture.
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rofl-cooldown-v2-'));
  t.after(()=>{const resolved=path.resolve(root);
    assert.ok(resolved.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(resolved).startsWith('rofl-cooldown-v2-'));
    fs.rmSync(resolved,{recursive:true,force:true});});
  const body=['733e','70661cc0ec7878'].map((hex,index)=>{
    const payload=Buffer.from(hex,'hex'),header=Buffer.alloc(12);
    header[0]=0x10;header.writeFloatLE(1+index,1);header[5]=payload.length;
    header.writeUInt16LE(0x039d,6);header.writeUInt32LE(0x400000ae,8);
    return Buffer.concat([header,payload]);
  });
  const source=path.join(root,'source.rofl');
  fs.writeFileSync(source,replayFromChunks([{stream:1,body:Buffer.concat(body)}],'16.19.821.7343').buffer);
  const run=path.join(root,'run');
  const decoded=cli('decode',source,'--events',CAP,'--cooldown-packet-v2','--runtime-image',IMAGE,'--event-jsonl-only','--out-dir',run);
  assert.equal(decoded.status,0,decoded.stderr);
  const manifestPath=path.join(run,'manifest.json');
  const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  const dir=path.join(run,manifest.replay_inputs[0].artifact_directory);
  const eventPath=path.join(dir,`${EVENT}.jsonl`);
  const rows=fs.readFileSync(eventPath,'utf8').trim().split('\n').map(JSON.parse);
  return {root,run,dir,eventPath,rows,manifest,manifestPath};
}
const query=(f,...args)=>cli('query-events',f.run,'--event',EVENT,...args);
function error(run,code){assert.equal(run.status,2,run.stderr);assert.equal(run.stdout,'');assert.equal(JSON.parse(run.stderr).code,code);}
function saveRows(f){fs.writeFileSync(f.eventPath,`${f.rows.map(JSON.stringify).join('\n')}\n`);}
function refreshManifest(f){
  for(const relative of Object.keys(f.manifest.output_hashes_excluding_manifest)){
    f.manifest.output_hashes_excluding_manifest[relative]=hash(fs.readFileSync(path.join(f.run,relative)));
  }
  fs.writeFileSync(f.manifestPath,JSON.stringify(f.manifest));
}

test('V2 query requires exact image only for full native verification and preserves candidate output',native,t=>{
  const f=fixture(t);
  const saved=query(f,'--limit','1');assert.equal(saved.status,0,saved.stderr);
  assert.equal(JSON.parse(saved.stdout).confidence,'CANDIDATE');
  assert.equal(JSON.parse(saved.stderr).scanned_count,2);
  error(query(f,'--verify-source','--limit','1'),'MISSING_RUNTIME_IMAGE');
  const verified=query(f,'--verify-source','--runtime-image',IMAGE,'--limit','1');
  assert.equal(verified.status,0,verified.stderr);
  const summary=JSON.parse(verified.stderr);
  assert.equal(summary.scanned_count,2);
  assert.equal(summary.native_witness_check,'FRESH_EXACT_IMAGE_REDECODE');
  assert.equal(JSON.parse(verified.stdout).native_callback_request.application_status,'NOT_OBSERVED');
});

test('late V2 intent or effect forgery emits no CLI or API rows even in saved-only mode',native,async t=>{
  const f=fixture(t);f.rows[1].native_callback_request.application_status='APPLIED';saveRows(f);refreshManifest(f);
  error(query(f,'--limit','1'),'INVALID_EVENT_ROW');
  const emitted=[];
  await assert.rejects(streamEventQuery(prepareEventQuery(f.dir,EVENT),{limit:1},line=>emitted.push(line)),{code:'INVALID_EVENT_ROW'});
  assert.deepEqual(emitted,[]);
});

test('coherent protected-field and digest forgery passes saved consistency but fails complete native re-decode',native,t=>{
  const f=fixture(t),request=f.rows[1].native_callback_request;
  const raw=Buffer.from(request.protected_fields_hex,'hex');raw[9]^=1;
  request.protected_fields_hex=raw.toString('hex');
  const fields=decodeProtectedCooldownRequestFields821(request.protected_fields_hex);assert.ok(fields);
  request.argument_f32_bits_hex=fields.bits_hex;request.argument_f32=fields.values;request.control_u8=fields.control_u8;
  saveRows(f);
  const nativeHash=crypto.createHash('sha256');
  for(const row of f.rows){const key=Buffer.alloc(4);key.writeUInt32LE(row.native_callback_lookup_key_u32);
    nativeHash.update(Buffer.from(row.native_protected_lookup_byte_hex,'hex')).update(key)
      .update(Buffer.from(row.native_callback_request.protected_fields_hex,'hex'))
      .update(Buffer.from(row.native_callback_request.argument_f32_bits_hex,'hex'))
      .update(Buffer.from([row.native_callback_request.control_u8]));}
  const digest=nativeHash.digest('hex');
  for(const name of ['semantic_run.json','replay_analysis.json']){
    const filename=path.join(f.dir,name),doc=JSON.parse(fs.readFileSync(filename,'utf8'));
    (name==='semantic_run.json'?doc.capability_results:doc.semantic.capability_results)[CAP].native_output_sha256=digest;
    fs.writeFileSync(filename,JSON.stringify(doc));
  }
  refreshManifest(f);
  const saved=query(f,'--limit','1');assert.equal(saved.status,0,saved.stderr);
  assert.equal(JSON.parse(saved.stderr).source_provenance_status,'SAVED_ONLY_UNVERIFIED');
  error(query(f,'--verify-source','--runtime-image',IMAGE,'--limit','1'),'SOURCE_PROVENANCE_MISMATCH');
});

test('native V2 verification failure preserves empty output and explicit decode error',native,t=>{
  const f=fixture(t),output=path.join(f.root,'failed.jsonl');
  error(query(f,'--verify-source','--runtime-image',__filename,'--limit','1','--output',output),'SOURCE_REPLAY_DECODE_FAILED');
  assert.equal(fs.existsSync(output),false);
});
