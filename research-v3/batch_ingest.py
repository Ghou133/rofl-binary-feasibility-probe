"""Replay-directory batch ingest with SHA de-duplication and patch gating."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable

import duckdb

try:
    from .core import (
        DEFAULT_ARTIFACT_ROOT, DEFAULT_DB, DEFAULT_MANIFEST, PROJECT_ROOT,
        SUPPORTED_PATCHES, ReplayStore,
    )
    from .research_layer import publication_paths, publish_all
except ImportError:
    from core import (
        DEFAULT_ARTIFACT_ROOT, DEFAULT_DB, DEFAULT_MANIFEST, PROJECT_ROOT,
        SUPPORTED_PATCHES, ReplayStore,
    )
    from research_layer import publication_paths, publish_all


RUNTIME_IMAGE = PROJECT_ROOT / "artifacts" / "runtime_probe" / "league_16.15.801.3452.memory.bin"
PROTECTION_V4_LAYER = PROJECT_ROOT / "research-v4" / "protection_layer.py"


def runtime_preflight(*, require_runtime_image: bool = False) -> None:
    """Fail before a batch stage starts when its executable inputs are absent."""
    if shutil.which("node") is None:
        raise RuntimeError("batch ingest requires Node.js on PATH for ROFL validation and version detection")
    if require_runtime_image and not RUNTIME_IMAGE.is_file():
        raise RuntimeError(f"16.15 runtime image is required for unknown replays: {RUNTIME_IMAGE}")


def discover_replays(directory: str | Path) -> list[Path]:
    root = Path(directory).resolve()
    if root.is_file():
        return [root] if root.suffix.lower() == ".rofl" else []
    if not root.is_dir():
        raise FileNotFoundError(root)
    return sorted(path for path in root.rglob("*.rofl") if path.is_file())


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def replay_version(path: str | Path) -> str:
    runtime_preflight()
    script = (
        "const {parseReplayFile}=require('./src/rofl');"
        "const r=parseReplayFile(process.argv[1]);process.stdout.write(r.header.version);"
    )
    result = subprocess.run(
        ["node", "-e", script, str(Path(path).resolve())],
        cwd=PROJECT_ROOT, check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def inventory_replays(
    replay_paths: Iterable[Path],
    version_reader: Callable[[str | Path], str] = replay_version,
) -> list[dict[str, Any]]:
    result = []
    for path in replay_paths:
        result.append({
            "path": str(path.resolve()), "sha256": sha256_file(path),
            "patch": version_reader(path), "game_id": path.stem.rsplit("-", 1)[-1],
        })
    return result


def deduplicate_inventory(inventory: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Retain the first deterministic occurrence of every replay SHA in a batch."""
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicate_count = 0
    for row in inventory:
        sha = row.get("sha256")
        if sha in seen:
            duplicate_count += 1
            continue
        seen.add(sha)
        unique.append(row)
    return unique, duplicate_count


def _write_manifest(path: Path, replays: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1, "replay_count": len(replays),
        "patch": sorted({row.get("patch") for row in replays}),
        "sample_roles": ["BATCH_INGEST"], "replays": replays,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _run(command: list[str], *, cwd: Path, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    log_path.write_text(
        "$ " + " ".join(command) + "\n\nSTDOUT\n" + result.stdout
        + "\nSTDERR\n" + result.stderr,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {log_path}")


def _run_json(command: list[str], *, cwd: Path, log_path: Path) -> dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    log_path.write_text(
        "$ " + " ".join(command) + "\n\nSTDOUT\n" + result.stdout
        + "\nSTDERR\n" + result.stderr,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {log_path}")
    return json.loads(result.stdout)


def _read_json_artifact(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"{label} was not produced: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid {label}: {path}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"invalid {label}: expected a JSON object at {path}")
    return value


def _validate_packet_export(
    manifest: dict[str, Any], *, packet_id: int, replays: list[dict[str, Any]]
) -> None:
    expected_shas = [row["sha256"] for row in replays]
    scan_rows = manifest.get("replays") or []
    scan_shas = [row.get("sha256") for row in scan_rows]
    if manifest.get("packet_ids") != [packet_id]:
        raise RuntimeError(f"packet export manifest does not cover opcode 0x{packet_id:04x}")
    if manifest.get("replay_count") != len(replays) or scan_shas != expected_shas:
        raise RuntimeError(f"packet 0x{packet_id:04x} export did not cover every replay")
    if any(row.get("parser_error_count") for row in scan_rows):
        raise RuntimeError(f"packet 0x{packet_id:04x} export reported parser errors")
    selected = sum(int(row.get("selected_packet_count") or 0) for row in scan_rows)
    if manifest.get("selected_packet_count") != selected:
        raise RuntimeError(f"packet 0x{packet_id:04x} export count mismatch")


def _validate_on_event_summary(
    summary: dict[str, Any], *, selected_packet_count: int
) -> str:
    input_count = summary.get("input_event_count")
    if input_count != selected_packet_count:
        raise RuntimeError("0x009e decoder input count does not match packet export")
    if summary.get("deserialize_success_count") != input_count:
        raise RuntimeError("0x009e decoder did not deserialize every exported packet")
    if summary.get("fully_consumed_count") != input_count:
        raise RuntimeError("0x009e decoder did not fully consume every exported packet")
    if summary.get("schema_mismatch_count", 0):
        raise RuntimeError("0x009e decoder reported a protection schema mismatch")
    if summary.get("parameter_size_mismatch_count", 0):
        raise RuntimeError("0x009e decoder reported a protection parameter-size mismatch")
    return "DECODED" if int(summary.get("output_event_count") or 0) else "NO_PROTECTION_EVENT"


def _validate_shield_damage_summary(
    summary: dict[str, Any], *, manifest: dict[str, Any], replays: list[dict[str, Any]]
) -> str:
    input_count = summary.get("input_event_count")
    selected_count = manifest.get("selected_packet_count")
    if input_count != selected_count:
        raise RuntimeError("0x0017 decoder input count does not match packet export")
    if summary.get("scan_replay_count") != len(replays):
        raise RuntimeError("0x0017 decoder summary does not cover every replay")
    if summary.get("scan_selected_packet_count") != selected_count:
        raise RuntimeError("0x0017 decoder scan count does not match packet export")
    if summary.get("scan_parser_error_count") != 0:
        raise RuntimeError("0x0017 decoder scan reported parser errors")
    scan_shas = [row.get("replay_sha256") for row in summary.get("scan_replays") or []]
    if scan_shas != [row["sha256"] for row in replays]:
        raise RuntimeError("0x0017 decoder summary replay coverage mismatch")
    for field in (
        "deserialize_success_count", "fully_consumed_count",
        "network_fields_agree_count", "target_matches_raw_param_count",
    ):
        if summary.get(field) != input_count:
            raise RuntimeError(f"0x0017 decoder validation failed: {field}")
    return "DECODED" if input_count else "NO_PROTECTION_EVENT"


def _decode_protection_v4(
    replays: list[dict[str, Any]], output_root: Path, db_path: Path
) -> dict[str, Any] | None:
    """Decode and ingest V4 for newly ingested supported replays only."""
    if not replays:
        return None
    runtime_preflight(require_runtime_image=True)
    stage = output_root / f"protection-v4-{uuid.uuid4()}"
    logs = stage / "logs"
    on_event_raw = stage / "packet_009e.jsonl"
    on_event_manifest_path = Path(f"{on_event_raw}.manifest.json")
    on_event_decoded = stage / "on_event_protection_decoded.jsonl"
    on_event_summary_path = stage / "on_event_protection_decoded.summary.json"
    shield_damage_raw = stage / "packet_0017.jsonl"
    shield_damage_manifest_path = Path(f"{shield_damage_raw}.manifest.json")
    shield_damage_decoded = stage / "shield_damage_decoded.jsonl"
    shield_damage_summary_path = stage / "shield_damage_decoded.summary.json"
    replay_paths = [row["path"] for row in replays]
    _run(
        ["node", "scripts/export_selected_packets.js", "--output", str(on_event_raw),
         "--packet-id", "158", *replay_paths],
        cwd=PROJECT_ROOT, log_path=logs / "packet_009e_export.log",
    )
    _run(
        ["node", "scripts/export_selected_packets.js", "--output", str(shield_damage_raw),
         "--packet-id", "23", *replay_paths],
        cwd=PROJECT_ROOT, log_path=logs / "packet_0017_export.log",
    )
    _run(
        [sys.executable, "scripts/decode_on_event_protection_v4.py",
         "--image", str(RUNTIME_IMAGE), "--events", str(on_event_raw),
         "--output", str(on_event_decoded), "--summary", str(on_event_summary_path),
         "--progress-every", "0"],
        cwd=PROJECT_ROOT, log_path=logs / "decode_on_event.log",
    )
    _run(
        [sys.executable, "scripts/decode_shield_damage_v4.py",
         "--image", str(RUNTIME_IMAGE), "--events", str(shield_damage_raw),
         "--output", str(shield_damage_decoded),
         "--summary", str(shield_damage_summary_path)],
        cwd=PROJECT_ROOT, log_path=logs / "decode_shield_damage.log",
    )

    on_event_manifest = _read_json_artifact(on_event_manifest_path, "0x009e export manifest")
    shield_damage_manifest = _read_json_artifact(
        shield_damage_manifest_path, "0x0017 export manifest"
    )
    _validate_packet_export(on_event_manifest, packet_id=0x009E, replays=replays)
    _validate_packet_export(shield_damage_manifest, packet_id=0x0017, replays=replays)
    on_event_summary = _read_json_artifact(on_event_summary_path, "0x009e decoder summary")
    shield_damage_summary = _read_json_artifact(
        shield_damage_summary_path, "0x0017 decoder summary"
    )
    on_event_status = _validate_on_event_summary(
        on_event_summary,
        selected_packet_count=on_event_manifest["selected_packet_count"],
    )
    shield_damage_status = _validate_shield_damage_summary(
        shield_damage_summary, manifest=shield_damage_manifest, replays=replays
    )

    backfill = _run_json(
        [sys.executable, str(PROTECTION_V4_LAYER), "--db", str(db_path),
         *[value for replay in replays for value in ("--replay-sha256", replay["sha256"])],
         "--decoded-jsonl", str(on_event_decoded),
         "--decoded-jsonl", str(shield_damage_decoded)],
        cwd=PROJECT_ROOT, log_path=logs / "duckdb_backfill_selected.log",
    )
    backfill_results = backfill.get("results")
    expected_shas = [replay["sha256"] for replay in replays]
    if (
        backfill.get("mode") != "SELECTED_REPLAYS_SHARED_DECODER_ATTESTATION"
        or backfill.get("backfilled_replay_count") != len(replays)
        or not isinstance(backfill_results, list)
        or [result.get("replay_sha256") for result in backfill_results] != expected_shas
    ):
        raise RuntimeError("Protection V4 selected backfill returned incomplete replay coverage")
    for result in backfill_results:
        if result.get("profile_status") not in ("DECODED", "NO_PROTECTION_EVENT"):
            raise RuntimeError(
                f"Protection V4 backfill did not complete for {result.get('replay_sha256')}: "
                f"{result.get('profile_status')}"
            )
    return {
        "status": "PROTECTION_V4_COMPLETE",
        "artifact_root": str(stage),
        # Retain the original OnEvent aliases for callers written before the
        # separate shield-damage route was integrated.
        "raw_packets": str(on_event_raw),
        "decoded_events": str(on_event_decoded),
        "decoder_summary": str(on_event_summary_path),
        "decoder_statuses": {
            "on_event": on_event_status,
            "shield_damage": shield_damage_status,
        },
        "decoders": {
            "on_event": {
                "status": on_event_status,
                "raw_packets": str(on_event_raw),
                "raw_manifest": str(on_event_manifest_path),
                "decoded_events": str(on_event_decoded),
                "decoder_summary": str(on_event_summary_path),
            },
            "shield_damage": {
                "status": shield_damage_status,
                "raw_packets": str(shield_damage_raw),
                "raw_manifest": str(shield_damage_manifest_path),
                "decoded_events": str(shield_damage_decoded),
                "decoder_summary": str(shield_damage_summary_path),
            },
        },
        "decoded_jsonl_paths": [str(on_event_decoded), str(shield_damage_decoded)],
        "backfill": backfill,
    }


def _decode_unknown(replays: list[dict[str, Any]], output_root: Path) -> tuple[Path, Path]:
    runtime_preflight(require_runtime_image=True)
    stage = output_root / f"batch-{uuid.uuid4()}"
    final_run = stage / "final_run"
    v2 = stage / "v2_ward_spawn"
    full_decode = v2 / "current_full_decode"
    logs = stage / "logs"
    replay_paths = [row["path"] for row in replays]

    _run(
        ["node", "src/cli.js", "validate", *replay_paths, "--out-dir", str(final_run)],
        cwd=PROJECT_ROOT, log_path=logs / "v1_validate.log",
    )
    raw_ward = full_decode / "packet_0353.jsonl"
    _run(
        ["node", "scripts/export_selected_packets.js", "--output", str(raw_ward),
         "--packet-id", "851", *replay_paths],
        cwd=PROJECT_ROOT, log_path=logs / "ward_packet_export.log",
    )
    _run(
        [sys.executable, "scripts/decode_ward_spawn_16_15.py", "--image", str(RUNTIME_IMAGE),
         "--packets", str(raw_ward), "--casts-root", str(final_run / "replays"),
         "--output-dir", str(full_decode)],
        cwd=PROJECT_ROOT, log_path=logs / "ward_decode.log",
    )

    raw_path = v2 / "current_path_raw_packets_all10.jsonl"
    shapes = v2 / "current_path_shapes.json"
    _run(
        ["node", "scripts/export_selected_packets.js", "--output", str(raw_path),
         "--packet-id", "721", *replay_paths],
        cwd=PROJECT_ROOT, log_path=logs / "path_packet_export.log",
    )
    _run(
        ["node", "scripts/export_packet_shapes.js", "--output", str(shapes), *replay_paths],
        cwd=PROJECT_ROOT, log_path=logs / "path_shape_export.log",
    )
    hero_paths = v2 / "current_path_hero_events_all10.jsonl"
    positions = v2 / "current_path_hero_positions_1s_all10.jsonl"
    _run(
        [sys.executable, "scripts/migrate_path_packet_16_15.py",
         "--image", str(RUNTIME_IMAGE), "--shapes", str(shapes),
         "--analysis-output", str(v2 / "current_path_packet_analysis.json"),
         "--emulation-output", str(v2 / "current_path_emulation_all_shapes.json"),
         "--raw-packets", str(raw_path), "--cast-events-root", str(final_run / "replays"),
         "--decoded-packets-output", str(v2 / "current_path_decoded_packets_all10.jsonl"),
         "--hero-path-output", str(hero_paths), "--hero-positions-output", str(positions),
         "--calibration-output", str(v2 / "current_path_coordinate_calibration.json")],
        cwd=PROJECT_ROOT, log_path=logs / "path_decode.log",
    )
    enriched = v2 / "current_path_hero_positions_1s_all10_enriched.jsonl"
    _run(
        [sys.executable, "scripts/enrich_path_hero_position_provenance.py",
         "--raw-packets", str(raw_path), "--hero-events", str(hero_paths),
         "--hero-positions", str(positions), "--output", str(enriched),
         "--manifest", str(v2 / "current_path_hero_positions_1s_all10_enriched_provenance_manifest.json")],
        cwd=PROJECT_ROOT, log_path=logs / "path_enrich.log",
    )

    inventory = json.loads((final_run / "rofl_inventory.json").read_text(encoding="utf-8"))
    by_sha = {row["sha256"]: row for row in inventory}
    manifest_rows = []
    for replay in replays:
        decoded = by_sha[replay["sha256"]]
        manifest_rows.append({
            "game_id": decoded.get("game_id") or replay["game_id"],
            "sample_role": "BATCH_INGEST", "replay_path": replay["path"],
            "replay_sha256": replay["sha256"], "patch": replay["patch"],
            "decoder_status": "RESEARCH_READY_COMPLETE",
        })
    return _write_manifest(stage / "replay_manifest.json", manifest_rows), stage


def ingest_replay_directory(
    replay_directory: str | Path,
    *, db_path: str | Path = DEFAULT_DB,
    canonical_manifest: str | Path = DEFAULT_MANIFEST,
    canonical_artifact_root: str | Path = DEFAULT_ARTIFACT_ROOT,
    max_position_age_ms: int = 2000,
    output_root: str | Path | None = None,
) -> dict[str, Any]:
    """Discover, hash, patch-gate, decode, ingest and publish a replay directory."""
    paths = discover_replays(replay_directory)
    inventory, duplicate_in_batch = deduplicate_inventory(inventory_replays(paths))
    db_file = Path(db_path).resolve()
    existing: set[str] = set()
    if db_file.is_file():
        # Existing-only batches must not acquire a writable connection or mutate
        # the database while checking whether every replay is already ingested.
        with duckdb.connect(str(db_file), read_only=True) as connection:
            existing = {
                row[0]
                for row in connection.execute("SELECT replay_sha256 FROM replays").fetchall()
            }
    pending = [row for row in inventory if row["sha256"] not in existing]
    if not pending:
        publication = {"status": "UNCHANGED_EXISTING_PUBLICATION"}
        manifest_path = publication_paths(db_file)["manifest"]
        if manifest_path.is_file():
            publication["publication_manifest"] = str(manifest_path)
        return {
            "status": "COMPLETED",
            "discovered": len(paths), "unique_by_sha": len(inventory),
            "duplicate_in_batch": duplicate_in_batch,
            "already_ingested": len(inventory),
            "ingested_known": 0, "decoded_new": 0, "unsupported": 0,
            "runs": [], "publication": publication,
        }

    store = ReplayStore(db_path)
    store.init()
    canonical = json.loads(Path(canonical_manifest).read_text(encoding="utf-8"))
    known_by_sha = {row["replay_sha256"]: row for row in canonical.get("replays", [])}
    known, unknown, unsupported = [], [], []
    for row in pending:
        if row["patch"] not in SUPPORTED_PATCHES:
            unsupported.append({
                "game_id": row["game_id"], "sample_role": "BATCH_INGEST",
                "replay_path": row["path"], "replay_sha256": row["sha256"],
                "patch": row["patch"], "decoder_status": "UNSUPPORTED_REPLAY_VERSION",
            })
        elif row["sha256"] in known_by_sha:
            known.append(known_by_sha[row["sha256"]])
        else:
            unknown.append(row)

    runs = []
    scratch = Path(output_root or (Path(__file__).resolve().parent / "output" / "batch")).resolve()
    if unsupported:
        manifest = _write_manifest(scratch / f"unsupported-{uuid.uuid4()}.json", unsupported)
        runs.append(store.ingest_artifacts(manifest, canonical_artifact_root,
                                           max_position_age_ms=max_position_age_ms))
    if known:
        manifest = _write_manifest(scratch / f"known-{uuid.uuid4()}.json", known)
        runs.append(store.ingest_artifacts(manifest, canonical_artifact_root,
                                           max_position_age_ms=max_position_age_ms))
    if unknown:
        runtime_preflight(require_runtime_image=True)
        manifest, artifact_root = _decode_unknown(unknown, scratch)
        runs.append(store.ingest_artifacts(manifest, artifact_root,
                                           max_position_age_ms=max_position_age_ms))
    protection_v4 = _decode_protection_v4(
        [row for row in pending if row["patch"] in SUPPORTED_PATCHES],
        scratch,
        db_file,
    )
    publication = publish_all(db_path, max_position_age_ms=max_position_age_ms)
    return {
        "status": "COMPLETED" if not unsupported else "COMPLETED_WITH_REJECTIONS",
        "discovered": len(paths), "unique_by_sha": len(inventory),
        "duplicate_in_batch": duplicate_in_batch,
        "already_ingested": len(inventory) - len(pending),
        "ingested_known": len(known), "decoded_new": len(unknown),
        "unsupported": len(unsupported), "runs": runs,
        "protection_v4": protection_v4, "publication": publication,
    }


__all__ = [
    "discover_replays", "sha256_file", "replay_version", "inventory_replays",
    "deduplicate_inventory", "runtime_preflight", "_decode_protection_v4",
    "ingest_replay_directory",
]
