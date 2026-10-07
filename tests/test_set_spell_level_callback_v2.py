"""Exact-821 native SetSpellLevel callback witness and negative controls."""

import os
import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import decode_set_spell_level_packet_16_19_821 as spell
import emulate_exact_packet_decoder as exact


IMAGE = Path(os.environ.get(
    'ROFL_821_RUNTIME_IMAGE',
    str(ROOT / 'artifacts' / '16_19_development' / 'kr_821_runtime_capture'
        / 'LeagueOfLegends_16.19.821.7343.memory.bin')))


@unittest.skipUnless(IMAGE.is_file(), 'private exact-821 runtime image unavailable')
class SetSpellLevelCallbackV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = IMAGE.read_bytes()
        import hashlib
        if hashlib.sha256(cls.image).hexdigest() != spell.IMAGE_SHA256:
            raise AssertionError('private exact-821 runtime image has wrong SHA-256')
        spell.check_static_identity(cls.image, callback_witness_v2=True)
        cls.tables = spell.callback_tables()

    def setUp(self):
        self.emulator, self.context = spell.make_decoder_emulator(
            self.image, callback_witness_v2=True)

    def decode(self, payload_hex, raw_param):
        self.context['raw_param'] = raw_param
        result = self.emulator.decode(bytes.fromhex(payload_hex), spell.PROFILE)
        self.assertEqual(result['deserialize_return_al'], 1)
        self.assertTrue(result['fully_consumed'])
        self.assertEqual(result['bytes_consumed'], len(bytes.fromhex(payload_hex)))
        return spell.witness_callback(self.emulator, self.context, self.tables)

    def set_decoded_u32(self, offset, value, table_name):
        table = self.tables[table_name]
        inverse = {decoded: encoded for encoded, decoded in enumerate(table)}
        encoded = bytes(inverse[byte] for byte in struct.pack('<I', value))
        self.emulator.emulator.mem_write(exact.OBJECT_ADDRESS + offset, encoded)

    def test_three_original_replay_packets_select_and_write_distinct_values(self):
        # Source-bound KR_8392938200: fa / c37b / cd7bb2, payload SHA-256
        # aa7225e7... / f9a84baf... / 5dc79c4b... .
        samples = (
            ('fa', 0x400000b6, 0, 1),
            ('c37b', 0x400000b4, 12, 2),
            ('cd7bb2', 0x400000b4, 12, 3),
        )
        for payload, raw_param, slot, scalar in samples:
            with self.subTest(payload=payload):
                self.emulator, self.context = spell.make_decoder_emulator(
                    self.image, callback_witness_v2=True)
                self.assertEqual(self.decode(payload, raw_param), {
                    'native_receiver_slot_candidate': slot,
                    'native_receiver_selection_source': 'INDEXED',
                    'native_clamped_scalar_candidate': scalar,
                    'native_positive_flag_written': True,
                })

    def test_fallback_and_clamp_use_exact_native_callback_and_callee(self):
        self.context['raw_param'] = 0x400000b4
        native = self.emulator.decode(bytes.fromhex('c37b'), spell.PROFILE)
        self.assertTrue(native['fully_consumed'])
        self.set_decoded_u32(0x10, 64, 'opaque_u32_0x10')
        self.set_decoded_u32(0x14, 9, 'opaque_u32_0x14')
        self.assertEqual(spell.witness_callback(self.emulator, self.context, self.tables), {
            'native_receiver_slot_candidate': 0,
            'native_receiver_selection_source': 'FALLBACK_0',
            'native_clamped_scalar_candidate': 6,
            'native_positive_flag_written': True,
        })

    def test_zero_does_not_take_positive_flag_write(self):
        self.context['raw_param'] = 0x400000b4
        native = self.emulator.decode(bytes.fromhex('c37b'), spell.PROFILE)
        self.assertTrue(native['fully_consumed'])
        self.set_decoded_u32(0x14, 0, 'opaque_u32_0x14')
        self.assertEqual(spell.witness_callback(self.emulator, self.context, self.tables), {
            'native_receiver_slot_candidate': 12,
            'native_receiver_selection_source': 'INDEXED',
            'native_clamped_scalar_candidate': 0,
            'native_positive_flag_written': False,
        })

    def test_signed_negative_is_witnessed_then_rejected_from_bounded_v2(self):
        self.context['raw_param'] = 0x400000b4
        native = self.emulator.decode(bytes.fromhex('c37b'), spell.PROFILE)
        self.assertTrue(native['fully_consumed'])
        self.set_decoded_u32(0x14, 0xffffffff, 'opaque_u32_0x14')
        with self.assertRaisesRegex(ValueError, 'receiver scalar or flag differs'):
            spell.witness_callback(self.emulator, self.context, self.tables)
        target = exact.WORK_BASE + 0x102000 + 12 * 0x40
        self.assertEqual(
            struct.unpack('<i', self.emulator.emulator.mem_read(target + 0x28, 4))[0],
            -1)


if __name__ == '__main__':
    unittest.main()
