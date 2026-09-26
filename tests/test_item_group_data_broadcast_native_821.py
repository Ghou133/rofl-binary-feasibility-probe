"""Exact-image checks for the experimental KR 821 item-group packet field."""

import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import decode_item_group_data_broadcast_packet_16_19_821 as item_group


IMAGE = os.environ.get('ROFL_821_RUNTIME_IMAGE')
SAMPLES = (
    ('1e567825e7f836', 0x400000ae),
    ('1e54761726fe84', 0x400000ae),
    ('1e5278f3ff74e90b', 0x400000ae),
    ('1e5672d1fc35ff53', 0x400000ae),
    ('1e5472bbcaf99f53', 0x400000ae),
    ('1e53706ed9b75736', 0x400000ae),
    ('1e5078b49d2e82f6', 0x400000ae),
    ('1e5172f39fe1c53d70', 0x400000ae),
    ('1e577643df85e87170', 0x400000ae),
    ('1e5272f393e9a9fc07', 0x400000ae),
    ('1e5578f3e25754dfe5', 0x400000af),
    ('1e5578f3ff74e90b', 0x400000b0),
    ('1e5776f3ff74e90b', 0x400000b5),
    ('1e5172f3ff74e90b', 0x400000b2),
    ('1e5078c257c166', 0x400000b3),
)


@unittest.skipUnless(IMAGE and Path(IMAGE).is_file(),
                     'exact KR 821 runtime image unavailable')
class ItemGroupNativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image, cls.digest, cls.transform = item_group.read_image(Path(IMAGE))

    def new_native(self):
        return item_group.make_native(self.image)

    def test_all_observed_shape_representatives_and_negative_lengths(self):
        emulator, context, captured = self.new_native()
        seen_shapes = set()
        for payload_hex, raw_param in SAMPLES:
            payload = bytes.fromhex(payload_hex)
            seen_shapes.add((len(payload), payload[1]))
            decoded = item_group.decode_one(emulator, context, captured,
                                            self.transform, raw_param, payload)
            self.assertEqual(decoded['native_callback_lookup_key_u32'],
                             item_group.struct.unpack(
                                 '<I', bytes(self.transform[byte] for byte in
                                             bytes.fromhex(decoded[
                                                 'native_protected_lookup_bytes_hex'])))[0])
            with self.assertRaisesRegex(ValueError, 'fully consume'):
                item_group.decode_one(emulator, context, captured,
                                      self.transform, raw_param, payload[:-1])
            with self.assertRaisesRegex(ValueError, 'fully consume'):
                item_group.decode_one(emulator, context, captured,
                                      self.transform, raw_param, payload + b'\x00')
        self.assertEqual(seen_shapes, item_group.OBSERVED_SHAPES)

    def test_raw_parameter_is_separate_from_callback_key(self):
        emulator, context, captured = self.new_native()
        payload = bytes.fromhex(SAMPLES[0][0])
        keys = [item_group.decode_one(emulator, context, captured, self.transform,
                                      raw_param, payload)['native_callback_lookup_key_u32']
                for raw_param in (0x400000ae, 0x400000b7)]
        self.assertEqual(keys, [5247418, 5247418])
        changed = bytearray(payload)
        changed[-1] ^= 0x01
        different_key = item_group.decode_one(
            emulator, context, captured, self.transform, 0x400000ae,
            bytes(changed))['native_callback_lookup_key_u32']
        self.assertNotEqual(different_key, keys[0])

    def test_wrong_image_fails_exact_hash(self):
        with self.assertRaisesRegex(ValueError, 'wrong size'):
            item_group.read_image(Path(__file__))


if __name__ == '__main__':
    unittest.main()
