# Patch migration protocol

The authoritative detailed procedure remains `docs/ROFL_NEW_BUILD_PLAYBOOK.md`.
This document defines how the semantic-coverage artifacts participate in a
future new build. It does not assert that any particular future build exists.

## Automated first pass

Given exact new/old Replay directories and the matching runtime image,
`scripts/validate_new_build_compatibility.js` can automatically:

1. read exact header build, metadata, container, Zstd chunks, block framing, and
   per-stream timestamp chronology;
2. hash and inventory immutable inputs;
3. count prior routes and configured new-route candidates, payload lengths,
   champion-range raw parameters, Replay coverage, and bounded performance;
4. compare old/new packet distributions and known structural anchors;
5. refuse a corpus outside the exact expected build;
6. preserve `UNSUPPORTED_VERSION` for a build absent from `src/build_registry.js`.

The packet inventory and capability manifest then provide the baseline for
`UNCHANGED`, `ROUTE_MOVED`, `FIELD_SHIFT`, `SEMANTIC_CHANGED`, or `UNKNOWN`
triage. Those labels are migration findings; only a successful exact runtime
decode plus semantic anchors can authorize a profile.

## Frozen automatic migration and manual-last policy

```text
AUTO FIRST
MANUAL LAST
```

New-build migration first traverses **every public canonical capability**, not
only the currently high-value capabilities. For each capability, it consumes the
versioned `SemanticFingerprint`, `GroundTruthOracle`, deterministic matcher,
`RegressionIntegration`, `MigrationOracle`, and exception registry. The matcher
must evaluate structural, behavioral, cross-field, ground-truth-derived, and
negative-control evidence against the exact build before escalation.

A capability with one unique, passing candidate is automatically retained or
migrated. A passing capability is never manually revalidated merely because a
new build is being considered. Exact-build-only binding remains mandatory: no
nearest-build fallback, wildcard profile, or route/offset resemblance is a
semantic promotion.

The migration diff remains complete even when all known semantics pass. New
packet, component, runtime type, callback, and entity-family diffs must be
recorded and routed to the research queue as independent evidence work.

## Targeted manual work only after automatic exhaustion

Manual input is permitted only when the automatic evidence for one capability
is failed, ambiguous, structurally broken, semantically inconsistent, or unable
to identify a unique candidate. `ManualValidationCaseGenerator` then ranks
unresolved hypotheses by information gain and emits only concrete, targeted
cases (normally 5–20, or fewer when fewer unresolved cases exist) with replay,
build, timestamp, champion/entity, before/after observations, competing
hypotheses, and expected input fields.

The system cannot automatically prove a changed registration/deserializer chain,
recover a changed encrypted/encoded field layout, assign entity meaning, or
establish semantic equivalence when its evidence does not uniquely decide the
case. In that narrow situation a researcher must recover and hash-gate the
runtime route, prove full consumption, identify fields, and validate only the
failed or ambiguous capability. Combat state, Damage, Death, CastSpell, Buff,
Protection, and Ward are never inherited from a nearby build.

## Publication gate

After L1 format, L2 structure, L3 semantics, and old-build regression pass:

- add one exact profile to `src/build_registry.js`;
- add per-build capability records to the machine manifest;
- explicitly declare semantic equivalence in the compatibility matrix;
- retain route/decoder/schema/semantic compatibility as four independent
  values;
- regenerate artifacts without overwriting historical raw Replay or prior
  decode outputs.

Until an exact future profile is registered, that version returns
`UNSUPPORTED_VERSION`; neither 16.16 nor 16.15 is silently selected. A canonical
schema gives old Replays long-term value only where each exact build independently
proves the same semantic.
