"""Optional exact-image tests; no private packet or image bytes are embedded."""
import json
import os
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from decode_anonymous_049c_packet_16_19_821 import create_emulator, decode_packet, PROFILE
from decode_mapview_inventory_16_19_821 import read_image, make_emulator
import emulate_exact_packet_decoder as exact


class Native049cTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        image_path = os.environ.get('ROFL_821_RUNTIME_IMAGE')
        sample_path = os.environ.get('ROFL_821_049C_SAMPLES')
        if not image_path or not sample_path:
            raise unittest.SkipTest('authorized exact-821 image and original 0x049c samples absent')
        cls.image, _, _ = read_image(Path(image_path))
        data = json.loads(Path(sample_path).read_text(encoding='utf-8'))
        if data.get('build') != '16.19.821.7343':
            raise ValueError('foreign sample build')
        cls.samples = [sample for group in data['groups'] for sample in group['samples']]
        if not cls.samples:
            raise ValueError('original packet representatives are required')

    def test_original_shapes_and_real_native_consumption_controls(self):
        emulator, context = create_emulator(self.image)
        for sample in self.samples:
            with self.subTest(stream=sample['stream_tag'], length=len(sample['payload_hex']) // 2):
                row = decode_packet(emulator, context, sample)
                self.assertEqual(row['status'], 'NATIVE_ACCEPTED')
                self.assertEqual(row['bytes_consumed'], len(sample['payload_hex']) // 2)
                payload = bytes.fromhex(sample['payload_hex'])
                for changed in (payload[:-1], payload + b'\x00'):
                    # Bypass observed-shape gates: exercise native code itself.
                    context['raw_param'] = sample['raw_param']
                    native = emulator.decode(changed, PROFILE)
                    self.assertFalse(native['deserialize_return_al'] == 1 and native['fully_consumed'])

    def test_memset_host_layer_matches_exact_native_sse_and_preserves_sentinels(self):
        native, _ = make_emulator(self.image)
        compatible, _ = create_emulator(self.image)
        # In the isolated emulator only, choose the same image's SSE CPU path.
        # This neither edits the captured file nor changes any running client.
        cpu_level_rva = 0x1a6546d + 0x4b5dab
        native.emulator.mem_write(exact.IMAGE_BASE + cpu_level_rva, struct.pack('<I', 2))
        destination = exact.WORK_BASE + 0x7000
        for length in (0, 1, 15, 16, 32, 33, 47, 64, 256):
            for fill in (0, 1, 0xab, 0xff):
                with self.subTest(length=length, fill=fill):
                    buffers = []
                    returns = []
                    for emulator in (native, compatible):
                        emulator.emulator.mem_write(destination - 16, b'\x7d' * (length + 32))
                        returns.append(emulator.call(exact.IMAGE_BASE + 0x1a653a0,
                            rcx=destination, rdx=fill, r8=length))
                        buffers.append(bytes(emulator.emulator.mem_read(destination - 16, length + 32)))
                    self.assertEqual(returns, [destination, destination])
                    self.assertEqual(buffers[0], buffers[1])
                    self.assertEqual(buffers[0][:16], b'\x7d' * 16)
                    self.assertEqual(buffers[0][-16:], b'\x7d' * 16)


if __name__ == '__main__':
    unittest.main()
