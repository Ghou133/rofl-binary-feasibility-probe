"""Exact-821 SetSpellTimerFromBuff callback call-entry witness controls."""

import hashlib
import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import decode_set_spell_timer_from_buff_packet_16_19_821 as timer
import emulate_exact_packet_decoder as exact


IMAGE = Path(os.environ.get(
    'ROFL_821_RUNTIME_IMAGE',
    str(ROOT / 'artifacts' / '16_19_development' / 'kr_821_runtime_capture'
        / 'LeagueOfLegends_16.19.821.7343.memory.bin')))


@unittest.skipUnless(IMAGE.is_file(), 'private exact-821 runtime image unavailable')
class SetSpellTimerCallbackV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = IMAGE.read_bytes()
        if hashlib.sha256(cls.image).hexdigest() != timer.IMAGE_SHA256:
            raise AssertionError('private exact-821 runtime image has wrong SHA-256')
        timer.check_static_identity(cls.image, callback_witness_v2=True)
        cls.tables = timer.callback_tables(cls.image)

    def setUp(self):
        self.emulator, self.context = timer.make_decoder_emulator(
            self.image, callback_witness_v2=True)

    def decode(self, payload_hex, raw_param):
        self.context['raw_param'] = raw_param
        payload = bytes.fromhex(payload_hex)
        native = self.emulator.decode(payload, timer.PROFILE)
        self.assertEqual(native['deserialize_return_al'], 1)
        self.assertTrue(native['fully_consumed'])
        self.assertEqual(native['bytes_consumed'], len(payload))
        return timer.witness_receiver_call(self.emulator, self.context, self.tables)

    def set_decoded_selector(self, value):
        table = self.tables['opaque_u8_0x20']
        inverse = {decoded: encoded for encoded, decoded in enumerate(table)}
        self.emulator.emulator.mem_write(exact.OBJECT_ADDRESS + 0x20,
                                         bytes([inverse[value]]))

    def test_three_original_replay_packets_select_0_2_and_63(self):
        # Payloads are source-bound in KR_8392938200 / KR_8393456728.
        samples = (
            ('3abf186252ad70', 0x400000b0, 2, 'INDEX_0_TO_5'),
            ('3bbdee9721a533', 0x400000b3, 0, 'INDEX_0_TO_5'),
            ('1abe9dae5aa4b243', 0x400000b3, 63, 'INDEX_63'),
        )
        for payload, raw_param, slot, path in samples:
            with self.subTest(payload=payload):
                self.emulator, self.context = timer.make_decoder_emulator(
                    self.image, callback_witness_v2=True)
                self.assertEqual(self.decode(payload, raw_param), {
                    'native_receiver_slot_candidate': slot,
                    'native_receiver_selection_path': path,
                    'native_receiver_forwarded_fields_witnessed': True,
                })

    def test_unaccepted_selector_values_have_no_receiver_call(self):
        for selector in (6, 62, 64):
            with self.subTest(selector=selector):
                self.emulator, self.context = timer.make_decoder_emulator(
                    self.image, callback_witness_v2=True)
                self.context['raw_param'] = 0x400000b0
                native = self.emulator.decode(bytes.fromhex('3abf186252ad70'),
                                              timer.PROFILE)
                self.assertTrue(native['fully_consumed'])
                self.set_decoded_selector(selector)
                with self.assertRaisesRegex(ValueError, 'receiver call was not witnessed'):
                    timer.witness_receiver_call(self.emulator, self.context,
                                                self.tables)
                self.assertEqual(len(self.context['receiver_calls']), 0)

    def test_callback_and_lookup_region_drift_fail_static_identity(self):
        for offset, reason in (
                (timer.CALLBACK_RVA + 0x10, 'callback region differs'),
                (timer.RECEIVER_LOOKUP_RVA + 0x3, 'receiver lookup region differs')):
            with self.subTest(offset=offset):
                changed = bytearray(self.image)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, reason):
                    timer.check_static_identity(changed, callback_witness_v2=True)


if __name__ == '__main__':
    unittest.main()
