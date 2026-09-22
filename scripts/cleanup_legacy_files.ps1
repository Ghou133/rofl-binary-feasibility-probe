[CmdletBinding()]
param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$rootPrefix = $root.TrimEnd([System.IO.Path]::DirectorySeparatorChar) +
    [System.IO.Path]::DirectorySeparatorChar

function Resolve-WorkspacePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $candidate = [System.IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    if (-not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing path outside workspace: $candidate"
    }
    return $candidate
}

function Get-PathBytes {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (-not $item.PSIsContainer) {
        return [long]$item.Length
    }
    return [long]((Get-ChildItem -LiteralPath $LiteralPath -Recurse -File -Force |
        Measure-Object Length -Sum).Sum)
}

function Get-WorkspaceRelativePath {
    param([Parameter(Mandatory = $true)][string]$FullPath)

    $candidate = [System.IO.Path]::GetFullPath($FullPath)
    if (-not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing path outside workspace: $candidate"
    }
    return $candidate.Substring($rootPrefix.Length)
}

$legacyTargets = @(
    # Superseded entry documents and packaging implementations.
    'REVIEW_START_HERE.md',
    'V3_REVIEW_START_HERE.md',
    'docs\DECODER_BLOCKER.md',
    'docs\PROTOCOL_RE_REPORT.md',
    'docs\REPLAY_CAPABILITY_MATRIX.md',
    'scripts\build_final_review_bundle.js',
    'scripts\package_final_review_bundle.ps1',
    'scripts\package_v2_review_lite.ps1',
    'scripts\package_v2_complete_review_lite.ps1',
    'scripts\package_v3_review_lite.ps1',

    # Old review bundles, stages, extracts and portability generations.
    'protection-v4-independent-review-lite.zip',
    'protection-v4-independent-review-lite.zip.sha256',
    'protection-v4-independent-review-lite.manifest.json',
    'protection-v4-independent-review-lite.manifest.json.sha256',
    'artifacts\review_bundle',
    'artifacts\independent-review-bundle.zip',
    'artifacts\bundle_verification.json',
    'artifacts\v2-independent-review-lite-stage',
    'artifacts\v2-independent-review-lite.zip',
    'artifacts\v2-independent-review-lite.json',
    'artifacts\v2-complete-independent-review-lite-stage',
    'artifacts\v2-complete-independent-review-lite-audit-final',
    'artifacts\v2-complete-independent-review-lite.zip',
    'artifacts\v2-complete-independent-review-lite.json',
    'artifacts\v2-portability-stage-20260810',
    'artifacts\v2-portability-extract-20260810',
    'artifacts\v2-portability-stage-20260810b',
    'artifacts\v2-portability-extract-20260810b',
    'artifacts\v2-portability-stage-20260810c',
    'artifacts\v2-portability-extract-20260810c',
    'artifacts\v2-portability-20260810.zip',
    'artifacts\v2-portability-20260810b.zip',
    'artifacts\v2-portability-20260810c.zip',
    'artifacts\v2-portability-package-20260810.json',
    'artifacts\v2-portability-package-20260810b.json',
    'artifacts\v2-portability-package-20260810c.json',
    'artifacts\research-platform-v3-review-lite-stage-20260811a',
    'artifacts\research-platform-v3-review-lite-stage-20260811b',
    'artifacts\research-platform-v3-review-lite-extract-20260811b',
    'artifacts\research-platform-v3-review-lite-20260811a.zip',
    'artifacts\research-platform-v3-review-lite-20260811b.zip',
    'artifacts\research-platform-v3-review-lite-20260811a.verification.json',
    'artifacts\research-platform-v3-review-lite-20260811b.verification.json',
    'artifacts\v3_wheels',

    # Generated smoke, failed, duplicate and example runs.
    'artifacts\bundle_smoke_decode_final',
    'artifacts\bundle_smoke_decode_final_v2',
    'artifacts\castspell-cli-smoke',
    'artifacts\cli-buff-smoke',
    'artifacts\cli-damage-smoke',
    'artifacts\cli-damage-smoke-v2',
    'artifacts\single-run',
    'artifacts\post-fix-single',
    'artifacts\ward-filter-smoke',
    'artifacts\ward-filter-team100-smoke',
    'artifacts\ward-filter-team-enemy-smoke',
    'artifacts\ward-filter-team-enemy-smoke2',
    'artifacts\final_validation',
    'artifacts\holdout_castspell_blind',
    'artifacts\holdout_blind',
    'artifacts\replays',
    'artifacts\holdout_match_details.json',
    'artifacts\holdout_timeline.json',
    'artifacts\oracle_manifest.json',
    'artifacts\v2_research\cli-validation',
    'artifacts\v2_research\cli-validation-final',
    'artifacts\v2_research\cli-v2-complete-smoke',
    'artifacts\v2_research\cli-v2-complete-final',
    'artifacts\v2_research\cli-v2-complete-provenance-final',
    'artifacts\v2_research\cli-semantic-smoke',
    'artifacts\v2_research\smoke-raw',
    'artifacts\v2_research\smoke-semantic',
    'artifacts\v2_research\ward_analysis_smoke',

    # Reproducible runtime decoder corpora; pinned image/dictionary stay.
    'artifacts\runtime_probe\global_16.15.802.4387.memory.bin',
    'artifacts\runtime_probe\global_16.15.802.4387.memory.bin.json',
    'artifacts\runtime_probe\league_replay_live.memory.bin',
    'artifacts\runtime_probe\league_replay_live.memory.bin.json',
    'artifacts\runtime_probe\packet_0650_wrapped_decode_all.jsonl',
    'artifacts\runtime_probe\packet_0650_decode_all.jsonl',
    'artifacts\runtime_probe\packet_0650_all.jsonl',
    'artifacts\runtime_probe\buff_add_decoded_all10.jsonl',
    'artifacts\runtime_probe\buff_remove_decoded_all10.jsonl',
    'artifacts\runtime_probe\buff_update_count_decoded_all10.jsonl',
    'artifacts\runtime_probe\buff_add_packets_all10.jsonl',
    'artifacts\runtime_probe\buff_remove_packets_all10.jsonl',
    'artifacts\runtime_probe\buff_update_count_packets_all10.jsonl',
    'artifacts\runtime_probe\packet_1113_decoded_all.jsonl',
    'artifacts\runtime_probe\packet_1113_all.jsonl',
    'artifacts\runtime_probe\all_packet_shapes.json',
    'artifacts\runtime_probe\exact_012e_shape_emulation.json',
    'artifacts\runtime_probe\castspell_targets_debug.jsonl',
    'artifacts\runtime_probe\castspell_business_debug.jsonl',
    'artifacts\runtime_probe\dynamic_damage_handler_hits.jsonl',

    # Ward/path reverse-engineering scratch and exhaustive decoded duplicate.
    'artifacts\v2_ward_spawn\_candidate_ctor.json',
    'artifacts\v2_ward_spawn\_factory_entry.json',
    'artifacts\v2_ward_spawn\_factory_xrefs_and_exit.json',
    'artifacts\v2_ward_spawn\_generic_dispatcher.json',
    'artifacts\v2_ward_spawn\_global_factory_windows.json',
    'artifacts\v2_ward_spawn\_handler_registration.json',
    'artifacts\v2_ward_spawn\_immediate_851_refs.json',
    'artifacts\v2_ward_spawn\_path_ctor_tmp.json',
    'artifacts\v2_ward_spawn\_path_vtable_refs_tmp.json',
    'artifacts\v2_ward_spawn\_registration_callsite_window.json',
    'artifacts\v2_ward_spawn\current_exact_constructor_xrefs.json',
    'artifacts\v2_ward_spawn\current_global_candidate_constructor_xrefs.json',
    'artifacts\v2_ward_spawn\current_global_candidate_vtable_xrefs.json',
    'artifacts\v2_ward_spawn\current_ward_emulation_all_shapes.json',
    'artifacts\v2_ward_spawn\current_ward_emulation_all_shapes_v2.json',
    'artifacts\v2_ward_spawn\current_path_emulation_all_shapes.json',
    'artifacts\v2_ward_spawn\current_path_emulation_progress.log',
    'artifacts\v2_ward_spawn\current_path_emulation_smoke.json',
    'artifacts\v2_ward_spawn\current_ward_emulation_all_shapes_v2.progress.log',
    'artifacts\v2_ward_spawn\current_ward_emulation_packet_0353.progress.log',
    'artifacts\v2_ward_spawn\current_ward_emulation_progress.log',
    'artifacts\v2_ward_spawn\current_ward_emulation_smoke.json',
    'artifacts\v2_ward_spawn\current_ward_emulation_packet_0353.json',
    'artifacts\v2_ward_spawn\current_path_emulation_packet_02d1.json',
    'artifacts\v2_ward_spawn\current_path_decoded_packets_all10.jsonl',
    'artifacts\v2_ward_spawn\old_build_5-5',
    'artifacts\v2_ward_spawn\upstream',

    # Full V4 re-decode corpora and scratch; compact attested summaries stay.
    'artifacts\protection_v4_probe\on_event_protection_decoded_all14.jsonl',
    'artifacts\protection_v4_probe\packet_009e_decoded_all14.jsonl',
    'artifacts\protection_v4_probe\packet_009e_all14.jsonl',
    'artifacts\protection_v4_probe\HN1-11184800649_damage_decoded.jsonl',
    'artifacts\protection_v4_probe\HN1-11184800649_packet_028a.jsonl',
    'artifacts\protection_v4_probe\HN1-11185011797_packet_0313.jsonl',
    'artifacts\protection_v4_probe\HN1-11185011797_packet_009e.jsonl',
    'artifacts\protection_v4_probe\janna_decode',
    'artifacts\protection_v4_probe\janna_all_packet_shapes.json',
    'artifacts\protection_v4_probe\v3_regression_unit_apply_damage_runtime_validation.jsonl',
    'artifacts\protection_v4_probe\on_event_protection_decoded_smoke.jsonl',
    'artifacts\protection_v4_probe\on_event_protection_decoded_smoke.summary.json',
    'artifacts\protection_v4_probe\packet_009e_decoded_smoke.jsonl',
    'artifacts\protection_v4_probe\packet_009e_decoded_smoke.summary.json',
    'artifacts\protection_v4_probe\_tmp_shield_packet_chain.json',
    'artifacts\protection_v4_probe\_tmp_shield_handlers.json',
    'artifacts\protection_v4_probe\_tmp_memroutine.json',
    'artifacts\protection_v4_probe\_tmp_consumer.json',
    'artifacts\protection_v4_probe\protection_v4_verify_after_timeout.json',
    'artifacts\protection_v4_probe\protection_v4_verify_run2.json',
    'artifacts\protection_v4_probe\protection_v4_verify_final_root.json',

    # Reproducible V3 convenience exports and historical logs.
    'research-v3\output\parquet-core',
    'research-v3\output\queries',
    'research-v3\output\current_ingest.stdout.log',
    'research-v3\output\current_ingest.stderr.log',
    'research-v3\output\full_ingest.stdout.log',
    'research-v3\output\full_ingest.stderr.log'
)

$resolvedTargets = [System.Collections.Generic.List[object]]::new()
foreach ($relative in $legacyTargets) {
    $candidate = Resolve-WorkspacePath $relative
    if (Test-Path -LiteralPath $candidate) {
        $resolvedTargets.Add([PSCustomObject]@{
            RelativePath = $relative
            FullPath = $candidate
            Bytes = Get-PathBytes $candidate
        })
    }
}

# final_run JSONL fact tables are retained for V3 ingest. These redundant per-replay
# views and samples are generated by src/cli.js and are not read by V3.
$finalRunReplayRoot = Resolve-WorkspacePath 'artifacts\final_run\replays'
$redundantReplayFiles = @(
    'replay_analysis.json',
    'events.json',
    'packet_timeline_sample.jsonl',
    'packet_type_inventory.csv',
    'raw_packet_anchors.json',
    'rofl_inventory.json',
    'item_events.jsonl',
    'heal_events.jsonl',
    'shield_events.jsonl',
    'position_events.jsonl'
)
if (Test-Path -LiteralPath $finalRunReplayRoot) {
    foreach ($replayDir in Get-ChildItem -LiteralPath $finalRunReplayRoot -Directory -Force) {
        $resolvedReplayDir = [System.IO.Path]::GetFullPath($replayDir.FullName)
        if (-not $resolvedReplayDir.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing replay directory outside workspace: $resolvedReplayDir"
        }
        foreach ($name in $redundantReplayFiles) {
            $candidate = [System.IO.Path]::GetFullPath((Join-Path $resolvedReplayDir $name))
            if (-not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing replay artifact outside workspace: $candidate"
            }
            if (Test-Path -LiteralPath $candidate) {
                $resolvedTargets.Add([PSCustomObject]@{
                    RelativePath = Get-WorkspaceRelativePath $candidate
                    FullPath = $candidate
                    Bytes = Get-PathBytes $candidate
                })
            }
        }
    }
}

# Python bytecode caches are always reproducible.
foreach ($cache in Get-ChildItem -LiteralPath $root -Recurse -Directory -Force |
    Where-Object { $_.Name -eq '__pycache__' }) {
    $candidate = [System.IO.Path]::GetFullPath($cache.FullName)
    if (-not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing cache outside workspace: $candidate"
    }
    $resolvedTargets.Add([PSCustomObject]@{
        RelativePath = Get-WorkspaceRelativePath $candidate
        FullPath = $candidate
        Bytes = Get-PathBytes $candidate
    })
}

$uniqueTargets = @($resolvedTargets | Sort-Object FullPath -Unique)
$totalBytes = [long](($uniqueTargets | Measure-Object Bytes -Sum).Sum)

if ($Apply) {
    foreach ($target in $uniqueTargets) {
        if (Test-Path -LiteralPath $target.FullPath) {
            Remove-Item -LiteralPath $target.FullPath -Recurse -Force
        }
    }
}

[PSCustomObject]@{
    schema_version = 1
    mode = if ($Apply) { 'APPLY' } else { 'DRY_RUN' }
    workspace = $root
    target_count = $uniqueTargets.Count
    total_bytes = $totalBytes
    total_gib = [math]::Round($totalBytes / 1GB, 3)
    targets = @($uniqueTargets | ForEach-Object {
        [PSCustomObject]@{
            path = $_.RelativePath.Replace('\', '/')
            bytes = $_.Bytes
        }
    })
} | ConvertTo-Json -Depth 5
