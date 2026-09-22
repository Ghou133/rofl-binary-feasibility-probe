# Protection Telemetry V4 completion report

## A. STATUS

`PROTECTION_V4_COMPLETE`

Both completion routes are satisfied with real Replay-observed amounts: direct shield generation and target-total absorption, plus a direct reported heal amount. The final regression and review gates must be evidenced outside this self-referential archive hash.

The protocol/data result meets Route A and Route B: `0x00ed` exposes direct shield generation,
`0x0017` exposes direct target-total shield absorption, and `0x004b` exposes a direct reported
heal amount. No Wiki formula or Match Details value is used as Replay telemetry.

## B. HEALTH STATE

- `health_state_events`: **0 rows**.
- Current HP and max HP remain unavailable and therefore `NULL`.
- No HP increase is relabeled as healing, regeneration, temporary HP, or max-HP change.

## C. SHIELD

- **generated**: **5,080** canonical `0x00ed OnReceiveShield` events, direct source, target,
  timestamp, raw order, and generated amount. The **4,752** `0x00ee OnGrantShield` rows are exact
  immediately preceding duplicate routes and are retained only in the raw shield-state surface.
- **remaining**: unavailable; `NULL`.
- **absorbed**: **2** direct `0x0017 PKT_UnitApplyShieldDamage_s` target-total events and **2**
  state transitions. Amounts are `375.13690185546875` and `30.030563354492188`. Target is direct;
  source and shield instance are unavailable. Both are in V4-only Replay `HN1-11184800649`.
- **unused**: unavailable; `NULL`.

Raw shield-state total: **9,834** = 5,080 receive + 4,752 grant + 2 absorption rows.

## D. HEAL

- Direct reported heal rows: **81,652**, each with direct source, target, timestamp, raw order,
  and reported amount.
- Exact full-parameter-blob representatives: **77,415**. This is a conservative grouping lower
  bound, not permission to discard the other raw rows.
- **raw**: unavailable; the reported amount has not been proven pre-overheal.
- **effective**: unavailable because HP-before/after telemetry is unavailable.
- **overheal**: unavailable because raw/effective separation is unavailable.

## E. TEMPORARY HP

- `temporary_hp_events`: **0 rows**.
- The inventory contains 33 temporary-HP candidate casts, but amount/start/end and temporary
  max-HP modification are unavailable. They remain `NULL`.

## F. ADC PROTECTION

- `adc_survival_features_v4`: **120** rows for all frozen ADC deaths.
- `adc_death_protection`: **128** rows across
  **40** distinct ADC deaths.
- Distribution: **87** `HEAL_REPORTED` rows across 23 deaths and **41** `SHIELD_GENERATED`
  rows across 28 deaths.
- **40** deaths have any positive reported protection;
  27 have positive generated shield and 23 have a positive heal-report upper bound.
- Direct absorption context in frozen ADC deaths: **0**. Both direct absorption samples are in a
  V4-only Replay that is not present in the frozen `adc_deaths` table.

## G. V3 REGRESSION

- Frozen decoder SHA-256: `c3959b3163c391a97ee0d6fc63641ad1f4507fbbe6dab87cd647e9a174fca6e7`.
- V3 runtime packet regression: **1,000 / 1,000 exact matches**.
- Final hash-bound regression/review attestation: **PASS**.
- Exact final test counts, V3 verifier classification, and their log hashes are accepted only from
  the attested regression input; this report does not hard-code a prior run's result.
- Frozen baseline counts remain exact, including replays=10,
  damage_events=27625, spell_events=32290,
  buff_events=312813, ward_spawns=1357, and
  adc_deaths=120.

## H. TESTS

- `Independent read-only Protection V4 prepublication final gate` — **PASS**: APPROVE; no BLOCK/HIGH/MEDIUM/LOW findings
- `Independent read-only final code review of H1/H2/L1 closure` — **PASS**: PASS; production trust boundary, JS manifest, and image pinning accepted
- `Independent real-bundle, read-only DuckDB, NULL-honesty, adversarial, and V3-freeze QA` — **PASS**: PASS; real all14 bundles accepted, 40/120 ADC deaths have protection context
- `npm test` — **PASS**: 59 tests; 59 pass; 0 fail
- `python -B -m unittest discover -s research-v3/tests -v` — **PASS**: 38 tests; OK
- `python -B research-v3/verify_v3.py --db research-v3/output/replay_research.duckdb` — **PASS**: PASS; EXPECTED_ADDITIVE_V4_CONTAINER_CHANGE; failures=[]
- `python -B -m unittest discover -s research-v4/tests -v` — **PASS**: 15 tests; OK
- `python -B research-v4/verify_v4.py --db research-v3/output/replay_research.duckdb` — **PASS**: PROTECTION_V4_COMPLETE; failures=[]; run1/run2 byte-identical
- `npm run verify-v2` — **PASS**: test_status PASS; evidence_status PASS; missing_files=[]
- `npm run validate-ward-spawn-current` — **PASS**: PASS; 17406 packets; 1357 verified wards

The selected V4 verifier artifact reports `PROTECTION_V4_COMPLETE` with
`0` failures. Archive release status is separately gated by
Section A so a passing data verifier cannot silently override a pending independent code/QA/final
review.

## I. REVIEW PACKAGE

- Target: `protection-v4-independent-review-lite.zip`, hard limit **20 MiB**.
- The archive is written only when `--release-status PROTECTION_V4_COMPLETE` is explicit.
- `package_manifest.json` is a closed payload manifest covering every archive file except itself;
  its self-exclusion is documented to avoid recursive hashing.
- The external adjacent manifest covers the archive and the internal manifest. Adjacent SHA-256
  files cover both the archive and external manifest.
- The builder writes the archive twice with fixed timestamps, sorted paths, fixed permissions,
  and compression settings; byte-identical SHA-256 is required.
- Explicit exclusions: DuckDB, `.rofl`, runtime memory images, exhaustive `0x009e`/OnEvent JSONL,
  decoded full damage JSONL, and existing archives.

The exact archive hash/size are published only in the adjacent external manifest; embedding the
archive hash inside the archive would be self-referential.

## J. STILL-UNAVAILABLE FIELDS

- `health.current_hp`
- `health.max_hp`
- `heal.raw_heal`
- `heal.effective_heal`
- `heal.overheal`
- `shield.remaining`
- `shield.unused`
- `shield.absorption.source`
- `shield.absorption.caster`
- `shield.absorption.spell`
- `shield.absorption.shield_instance`
- `shield.consumption_order`
- `temporary_hp.amount`
- `temporary_hp.start`
- `temporary_hp.end`
- `temporary_max_hp.modification`
- `total_external_protection`

Also unavailable: raw-versus-effective semantics for `heal.reported_amount`, shield removal
time/remainder, and the unobserved `0x00ef DamageShieldedParams` layout. These fields must remain
`NULL` or explicitly `UNAVAILABLE`; they must never become zero through decoder failure or
missing evidence.

Inventory evidence: **25 rows / 1055 casts /
1097 target references / 1128 Buff candidates /
87 damage windows**.
