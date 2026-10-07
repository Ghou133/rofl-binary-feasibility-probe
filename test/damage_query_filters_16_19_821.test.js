'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const {damageQueryFixture:fixture,cli,INTERVAL,WINDOW} = require('./helpers/damage_query_fixture');
const filters = require('../src/damage_query_filters');
const {prepareEventQuery,streamEventQuery} = require('../src/event_query');
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const native = {skip:!IMAGE||!fs.existsSync(IMAGE)?'exact 821 image unavailable':false};
const query=(f,event,...args)=>cli('query-events',f.run,'--event',event,...args);
const fail=(code,message)=>{const error=new Error(message);error.code=code;throw error;};

test('damage thresholds retain decimal double precision and validate zero, malformed and incoherent filters',()=>{
  assert.equal(filters.parseNonnegative('0.1','window-max-error'),0.1);
  assert.notEqual(filters.parseNonnegative('0.1','window-max-error'),Math.fround(0.1));
  assert.equal(filters.parseNonnegative('0','damage-min-delta'),0);
  for(const text of ['NaN','Infinity','1e309','-1','0x10',' '])assert.throws(()=>filters.parseNonnegative(text,'damage-min-delta'));
  for(const options of [{damageMinDelta:0},{windowMaxError:0},{windowKey:'target'},
    {damageCounter:'EFFECTIVE_DAMAGE'},{damageCounter:filters.COUNTERS[0],damageMinDelta:NaN},
    {damageChanged:'true'}]){
    assert.throws(()=>filters.validate(options,INTERVAL,fail),{code:'INVALID_FILTER'});
  }
  assert.throws(()=>filters.validate({damageChanged:true},'hero_death_candidates',fail),{code:'UNSUPPORTED_FILTER'});
  assert.throws(()=>filters.validate({windowKey:'lookup_0x24'},INTERVAL,fail),{code:'UNSUPPORTED_FILTER'});
  filters.validate({damageCounter:filters.COUNTERS[0],damageMinDelta:0},INTERVAL,fail);
});

test('absolute-error screen is inclusive, rejects empty groups and never rounds the tolerance',()=>{
  const field=filters.COUNTERS[0],options={damageCounter:field,windowKey:'lookup_0x24',windowMaxError:0.1};
  const row={comparisons:{lookup_0x24:{packet_count:1,counter_differences:{
    [field]:{counter_endpoint_delta_f32_candidate:1,anonymous_sum_minus_counter_delta:0.1}}}}};
  assert.equal(filters.matches(row,options),true);
  row.comparisons.lookup_0x24.counter_differences[field].anonymous_sum_minus_counter_delta=0.100000001;
  assert.equal(filters.matches(row,options),false);
  row.comparisons.lookup_0x24.packet_count=0;
  row.comparisons.lookup_0x24.counter_differences[field].anonymous_sum_minus_counter_delta=0;
  assert.equal(filters.matches(row,options),false);
});

test('static interval CLI/API select changed counters, fractional thresholds and explicit zero',async t=>{
  const f=fixture(t),field='TOTAL_DAMAGE_TAKEN';
  const changed=query(f,INTERVAL,'--damage-changed','--limit','1');assert.equal(changed.status,0,changed.stderr);
  assert.equal(JSON.parse(changed.stderr).matched_count,2);assert.equal(JSON.parse(changed.stderr).scanned_count,20);
  const selected=query(f,INTERVAL,'--damage-counter',field,'--damage-min-delta','5.25','--limit','1','--verify-source');
  assert.equal(selected.status,0,selected.stderr);
  assert.equal(JSON.parse(selected.stderr).matched_count,2);assert.equal(JSON.parse(selected.stderr).filters.damage_min_delta,5.25);
  const excluded=query(f,INTERVAL,'--damage-counter',field,'--damage-min-delta','5.250001','--limit','1');
  assert.equal(excluded.status,0,excluded.stderr);assert.equal(JSON.parse(excluded.stderr).matched_count,1);
  const zero=query(f,INTERVAL,'--damage-counter',field,'--damage-min-delta','0','--participant','2');
  assert.equal(zero.status,0,zero.stderr);assert.equal(JSON.parse(zero.stderr).matched_count,2);
  const emitted=[];
  const summary=await streamEventQuery(prepareEventQuery(f.dir,INTERVAL),
    {damageChanged:true,damageCounter:field,damageMinDelta:6},line=>emitted.push(JSON.parse(line)));
  assert.equal(summary.matched_count,1);assert.equal(emitted.length,1);
  assert.equal(emitted[0].confidence,'CANDIDATE');
});

test('damage filters reject list mode, foreign streams and window-only options without reading Replay inputs',t=>{
  const f=fixture(t);
  for(const args of [
    ['query-events',f.run,'--list-events','--damage-changed'],
    ['query-events',f.run,'--list-events','--damage-counter','TOTAL_DAMAGE_TAKEN','--damage-min-delta','0'],
    ['query-events',f.run,'--event','hero_death_candidates','--damage-changed'],
    ['query-events',f.run,'--event',INTERVAL,'--window-key','lookup_0x24'],
    ['query-events',f.run,'--event',INTERVAL,'--damage-min-delta','0'],
    ['query-events',f.run,'--event',INTERVAL,'--damage-counter','TOTAL_DAMAGE_TAKEN','--damage-min-delta','NaN']]){
    assert.equal(cli(...args).status,1);
  }
});

test('counter/window screens match only full validated groups and leave error/control fields unchanged',native,async t=>{
  const f=fixture(t,{withPackets:true,image:IMAGE}),field='TOTAL_DAMAGE_TAKEN';
  const options={damageCounter:field,damageMinDelta:0,windowKey:'lookup_0x24',windowMaxError:1e6};
  const expected=f.rows.filter(row=>filters.matches(row,options));
  const result=query(f,WINDOW,'--damage-counter',field,'--damage-min-delta','0','--window-key','lookup_0x24','--window-max-error','1000000','--limit','1');
  assert.equal(result.status,0,result.stderr);
  assert.equal(JSON.parse(result.stderr).scanned_count,20);
  assert.equal(JSON.parse(result.stderr).matched_count,expected.length);
  assert.ok(expected.length>0);
  assert.deepEqual(JSON.parse(result.stdout),expected[0]);
  const emitted=[];
  const summary=await streamEventQuery(prepareEventQuery(f.dir,WINDOW),{...options,limit:1},
    line=>emitted.push(JSON.parse(line)));
  assert.equal(summary.matched_count,expected.length);assert.deepEqual(emitted,[expected[0]]);
  assert.equal(emitted[0].semantic_effect_status,'UNKNOWN');
});
