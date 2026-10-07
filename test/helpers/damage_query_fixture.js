'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {replayFromChunks} = require('./synthetic_replay');
const {decodeRuntimeCountByte} = require('../../src/decoders/rofl_16_19_821_runtime_bytes');
const CLI = path.resolve(__dirname,'../../src/cli.js');
const INTERVAL = 'hero_damage_keyframe_interval_candidates';
const WINDOW = 'hero_damage_packet_keyframe_window_candidates';
const FIELDS = ['TOTAL_DAMAGE_DEALT_TO_CHAMPIONS','TOTAL_DAMAGE_DEALT','TOTAL_DAMAGE_TAKEN','TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS'];
const OFFSETS = [0x1e0,0x1d0,0x1f0,0x200];
const ENCODE = new Map(Array.from({length:256},(_,raw)=>[decodeRuntimeCountByte(raw),raw]));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const cli = (...args) => spawnSync(process.execPath,[CLI,...args],{encoding:'utf8',windowsHide:true,timeout:60000,maxBuffer:8*1024*1024});
function block(id,param,payload,time) {
  const header=Buffer.alloc(15);header.writeFloatLE(time/1000,1);header.writeUInt32LE(payload.length,5);
  header.writeUInt16LE(id,9);header.writeUInt32LE(param,11);
  return Buffer.concat([header,payload]);
}
function damageQueryFixture(t,{frames=3,jsonlOnly=true,unusedRuntimeImage=false,withPackets=false,image,packetProfile='v6'}={}) {
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
      return block(0x0089,0x400000ae+participant,payload,frame*60000);
    }))}));
  if(withPackets) {
    // Existing observed packet bodies in a generated container: protocol tests,
    // not receiver, health, attack-role or gameplay-effect observations.
    const packets=[
      [1000,0x400000ae,'71875e460b083dbaef3ba6ec39b975'],
      [2000,0x400000af,'54814747c6c4d9a90b6ef07c44e2ecaf5b75'],
      [60000,0x400000ae,'71875e460b083dbaef3ba6ec39b975'],
      [180000,0x400000ae,'71875e460b083dbaef3ba6ec39b975'],
    ];
    chunks.unshift({stream:1,body:Buffer.concat(packets.map(([time,param,hex])=>block(0x005f,param,Buffer.from(hex,'hex'),time)))});
  }
  const buffer=replayFromChunks(chunks,'16.19.821.7343').buffer;
  const stats=Array.from({length:10},(_,i)=>Object.fromEntries(FIELDS.map((field,column)=>
    [field,String(Math.ceil(i===0?values[frames-1][column]:0)+5)])));
  const metadata=Buffer.from(JSON.stringify({gameLength:180000,statsJson:JSON.stringify(stats)}));
  const oldLength=buffer.readUInt32LE(buffer.length-4), trailer=Buffer.alloc(4);trailer.writeUInt32LE(metadata.length);
  const source=path.join(root,'source.rofl');
  fs.writeFileSync(source,Buffer.concat([buffer.subarray(0,buffer.length-oldLength-4),metadata,trailer]));
  const run=path.join(root,'run'),capabilities='hero_damage_keyframe_intervals'+(withPackets?',unit_apply_damage_packet':'');
  const decoded=cli('decode',source,'--events',capabilities,...(jsonlOnly?['--event-jsonl-only']:[]),
    ...(withPackets&&packetProfile==='v6'?['--damage-packet-v6']:[]),
    ...(withPackets?['--runtime-image',image]:unusedRuntimeImage?['--runtime-image',__filename]:[]),'--out-dir',run);
  assert.equal(decoded.status,0,decoded.stderr);
  const manifestPath=path.join(run,'manifest.json'),manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  const dir=path.join(run,manifest.replay_inputs[0].artifact_directory);
  const event=withPackets?WINDOW:INTERVAL,eventPath=path.join(dir,event+'.jsonl');
  const text=fs.readFileSync(eventPath,'utf8').trim();
  return {root,source,run,dir,eventPath,rows:text?text.split('\n').map(JSON.parse):[],manifest,manifestPath};
}
module.exports={damageQueryFixture,cli,hash,FIELDS,ENCODE,INTERVAL,WINDOW};
