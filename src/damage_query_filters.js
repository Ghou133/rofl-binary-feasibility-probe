'use strict';
const {DAMAGE_KEYFRAME_INTERVALS_821_PROFILE} = require('./decoders/rofl_16_19_821_damage_keyframe_intervals_candidate');
const COUNTERS = Object.freeze(DAMAGE_KEYFRAME_INTERVALS_821_PROFILE.fields.map(field=>field.replay_tail_field));
const FILTER_KEYS = Object.freeze(['damageChanged','damageCounter','damageMinDelta','windowKey','windowMaxError']);
const INTERVAL = 'hero_damage_keyframe_interval_candidates';
const WINDOW = 'hero_damage_packet_keyframe_window_candidates';
const active = options => FILTER_KEYS.some(key=>options[key]!=null && options[key]!==false);

function validate(options,event,fail) {
  if (options.damageChanged!=null && typeof options.damageChanged!=='boolean') {
    fail('INVALID_FILTER','damageChanged must be boolean.');
  }
  if (options.damageCounter!=null && !COUNTERS.includes(options.damageCounter)) {
    fail('INVALID_FILTER','--damage-counter must name one of the four exact-821 cumulative damage counter candidates.');
  }
  for (const [key,flag] of [['damageMinDelta','--damage-min-delta'],['windowMaxError','--window-max-error']]) {
    if (options[key]!=null && (!Number.isFinite(options[key]) || options[key]<0)) {
      fail('INVALID_FILTER',flag+' must be a finite nonnegative number.');
    }
  }
  if (options.damageMinDelta!=null && options.damageCounter==null) fail('INVALID_FILTER','--damage-min-delta requires --damage-counter.');
  if (options.windowKey!=null && !['lookup_0x24','lookup_0x2c'].includes(options.windowKey)) {
    fail('INVALID_FILTER','--window-key must be lookup_0x24 or lookup_0x2c.');
  }
  if (options.windowMaxError!=null && (options.windowKey==null || options.damageCounter==null)) {
    fail('INVALID_FILTER','--window-max-error requires --window-key and --damage-counter.');
  }
  if (active(options) && ![INTERVAL,WINDOW].includes(event)) {
    fail('UNSUPPORTED_FILTER','Damage counter/window filters require the exact-821 interval or packet/window comparison stream.');
  }
  if (event!==WINDOW && (options.windowKey!=null || options.windowMaxError!=null)) {
    fail('UNSUPPORTED_FILTER','Window key/error filters require packet/window comparisons.');
  }
}

function parseNonnegative(value,flag) {
  if (!/^(?:[+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)$/.test(String(value))
      || !Number.isFinite(Number(value))) throw new Error('--'+flag+' must be a finite nonnegative decimal number.');
  // These are comparison thresholds/differences, not on-wire f32 values.
  return Number(value);
}

function matches(row,options) {
  const delta = field => row.counters?.[field]?.endpoint_delta_f32_candidate
    ?? row.comparisons?.lookup_0x24?.counter_differences?.[field]?.counter_endpoint_delta_f32_candidate;
  if (options.damageChanged && !COUNTERS.some(field=>delta(field)>0)) return false;
  if (options.damageCounter!=null) {
    const value=delta(options.damageCounter);
    if (options.damageMinDelta==null ? !(value>0) : !(value>=options.damageMinDelta)) return false;
  }
  if (options.windowKey!=null) {
    const group=row.comparisons?.[options.windowKey];
    if (!group || group.packet_count===0) return false;
    if (options.windowMaxError!=null
        && !(Math.abs(group.counter_differences[options.damageCounter].anonymous_sum_minus_counter_delta)<=options.windowMaxError)) return false;
  }
  return true;
}

function summary(options) {
  return active(options)?{damage_changed:options.damageChanged??false,damage_counter:options.damageCounter??null,
    damage_min_delta:options.damageMinDelta??null,window_key:options.windowKey??null,
    window_max_error:options.windowMaxError??null}:{};
}
module.exports = {COUNTERS,FILTER_KEYS,active,validate,parseNonnegative,matches,summary};
