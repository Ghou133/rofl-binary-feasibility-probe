import collections
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'validate_multi_build_runtime',
    ROOT / 'scripts' / 'validate_multi_build_runtime.py',
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)

WARD_SPEC = importlib.util.spec_from_file_location(
    'decode_ward_spawn_16_16',
    ROOT / 'scripts' / 'decode_ward_spawn_16_16.py',
)
WARD_DECODER = importlib.util.module_from_spec(WARD_SPEC)
assert WARD_SPEC.loader is not None
WARD_SPEC.loader.exec_module(WARD_DECODER)


class MultiBuildRuntimeValidatorTests(unittest.TestCase):
    def test_16_16_emulator_passes_the_explicit_runtime_profile_to_the_base_class(self):
        with mock.patch.object(
                VALIDATOR.exact.ExactPacketEmulator, '__init__', return_value=None) as base_init:
            VALIDATOR.Build1616Emulator(b'image')
        base_init.assert_called_once_with(
            b'image', VALIDATOR.exact.RUNTIME_PROFILES[VALIDATOR.REPLAY_VERSION],
        )

    def test_empty_structural_inputs_never_pass(self):
        self.assertFalse(VALIDATOR.path_structural_gate(collections.Counter(), [], True))
        self.assertFalse(VALIDATOR.level_structural_gate(0, [], [], [], [], True))

    def test_ward_profile_is_exact_route_and_rejects_old_candidate(self):
        profile = VALIDATOR.WARD_PROFILE
        self.assertEqual(profile['client_opcode'], 0x049A)
        self.assertEqual(profile['constructor_rva'], 0x00EABB20)
        self.assertEqual(profile['vtable_rva'], 0x01B14570)
        self.assertEqual(profile['deserialize_rva'], 0x01025D50)
        self.assertEqual(profile['rejected_deserialize_candidate_rva'], 0x00FC7770)
        self.assertEqual(profile['object_size'], 0x90)

    def test_ward_lifecycle_same_id_requires_owner_and_coordinate_corroboration(self):
        ward = {
            'replay_label': 'game',
            'replay_sha256': 'a' * 64,
            'replay_time_ms': 1000,
            'entity_network_id': 0x500,
            'owner_network_id': 0x400000AE,
            'owner_mapping': {'participant_id': 1, 'team_id': 100},
            'ward_type': 'YELLOW_OR_SIGHT_WARD',
            'vision_entity_class': 'PLAYER_ACTIVE_WARD_CONFIRMED',
            'position': {'x': 100.0, 'y': 200.0},
            'raw_packet_ref': {'packet_id': 0x049A},
        }
        corpse = {
            'replay_label': 'game',
            'replay_time_ms': 2000,
            'entity_network_id': 0x500,
            'owner_network_id': 0,
            'position': {'x': 100.0, 'y': 200.0},
            'raw_packet_ref': {'packet_id': 0x049A},
        }
        lifecycles, used = WARD_DECODER.build_lifecycles([ward], [corpse])
        self.assertEqual(lifecycles[0]['end_observation'], 'UNAVAILABLE')
        self.assertEqual(used, set())

        corpse['owner_network_id'] = ward['owner_network_id']
        lifecycles, used = WARD_DECODER.build_lifecycles([ward], [corpse])
        self.assertEqual(lifecycles[0]['end_observation'], 'OBSERVED_END')
        self.assertEqual(
            lifecycles[0]['match_rule'],
            'SAME_NETWORK_ID_OWNER_COORDINATE_DERIVED',
        )
        self.assertEqual(used, {0})

    def test_packet_manifest_is_exact_build_and_exact_route_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            packet_path = pathlib.Path(temporary) / 'packets.jsonl'
            packet_path.write_text('', encoding='utf-8')
            manifest = {
                'schema_version': 1,
                'target_replay_version': VALIDATOR.REPLAY_VERSION,
                'output': str(packet_path),
                'packet_ids': [0x0314],
                'selected_packet_count': 1,
                'packet_counts': {str(0x0314): 1},
                'replay_count': 1,
                'replays': [{
                    'path': 'game.rofl',
                    'sha256': 'a' * 64,
                    'version': VALIDATOR.REPLAY_VERSION,
                    'selected_packet_count': 1,
                    'parser_error_count': 0,
                }],
            }
            pathlib.Path(f'{packet_path}.manifest.json').write_text(
                json.dumps(manifest), encoding='utf-8',
            )
            loaded = VALIDATOR.load_packet_manifest(packet_path, 0x0314)
            self.assertEqual(loaded['selected_packet_count'], 1)
            with self.assertRaises(RuntimeError):
                VALIDATOR.load_packet_manifest(packet_path, 0x00F6)

    def test_packet_row_hash_and_length_are_recomputed(self):
        payload = b'\x01\x02'
        row = {
            'replay_version': VALIDATOR.REPLAY_VERSION,
            'packet_id': 0x0314,
            'replay_label': 'game',
            'replay_sha256': 'a' * 64,
            'raw_payload_hex': payload.hex(),
            'raw_payload_sha256': __import__('hashlib').sha256(payload).hexdigest(),
            'payload_length': len(payload),
            'replay_time_ms': 1,
            'raw_param': 0x400000AE,
            'chunk_index': 0,
            'chunk_stream': 1,
            'decompressed_block_offset': 5,
            'occurrence_index': 0,
        }
        manifest = {'replay_shas': {'game': 'a' * 64}}
        self.assertEqual(
            VALIDATOR.validate_packet_row(row, 0x0314, manifest, 1), payload,
        )
        row['raw_payload_sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'raw payload SHA-256 mismatch'):
            VALIDATOR.validate_packet_row(row, 0x0314, manifest, 1)

    def test_level_anchor_matching_is_one_to_one(self):
        anchors = {'game': [{
            'anchor_index': 0,
            'replay_label': 'game',
            'participant_id': 1,
            'timestamp_ms': 100,
            'level_after': 2,
        }]}
        row = {'replay_label': 'game', 'participant_id': 1, 'replay_time_ms': 100}
        used = set()
        first = VALIDATOR.nearest_unused_anchor(row, anchors, used)
        self.assertIsNotNone(first)
        used.add(('game', first['anchor_index']))
        self.assertIsNone(VALIDATOR.nearest_unused_anchor(row, anchors, used))


if __name__ == '__main__':
    unittest.main()
