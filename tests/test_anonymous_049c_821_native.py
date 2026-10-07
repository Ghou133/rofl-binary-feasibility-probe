"""Optional exact-image tests; no private packet or image bytes are embedded."""
import json
import os
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from decode_anonymous_049c_packet_16_19_821 import (
    create_emulator, decode_packet, PROFILE, callback_request, check_callback_identity, CALLBACK_SPANS,
    check_sibling_identity, SIBLING_SPANS, SIBLING_PROFILES, PACKET_CLASSES,
)
from decode_mapview_inventory_16_19_821 import read_image, make_emulator


class Native049cTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        image_path = os.environ.get('ROFL_821_RUNTIME_IMAGE')
        sample_path = os.environ.get('ROFL_821_049C_SAMPLES')
        if not image_path or not sample_path:
            raise unittest.SkipTest('authorized exact-821 image and original 0x049c samples absent')
        # Keep clean public runs dependency-free when private fixtures are absent.
        # With fixtures provided, missing native dependencies still fail normally.
        global exact
        import emulate_exact_packet_decoder as exact
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

    def test_callback_binding_rejects_changed_registration_class_and_dataflow(self):
        for begin, _, _ in CALLBACK_SPANS:
            with self.subTest(span=hex(begin)):
                changed = bytearray(self.image)
                changed[begin] ^= 1
                with self.assertRaises(ValueError):
                    check_callback_identity(changed)
        for address in (0x1ac2c30 + 0x18, 0x1f28690 + 31):
            changed = bytearray(self.image)
            changed[address] ^= 1
            with self.assertRaises(ValueError):
                check_callback_identity(changed)

    def test_packet_only_callback_all_indices_flags_and_native_name_hash(self):
        emulator, context = create_emulator(self.image)
        vector_address = exact.WORK_BASE + 0x7000
        table = self.image[0x1ab62d0:0x1ab63d0]

        def ror(byte, count):
            return ((byte >> count) | (byte << (8-count))) & 255

        def exchange(byte):
            return (((byte & 0xd5) << 1) | ((byte >> 1) & 0x55)) & 255

        def request(raw_index, operation=2, flags=b'\xfc\x27\x3b', vector=b'Ab\0'):
            # Synthetic packet object only. No receiver object is supplied or
            # executed; both prefix stops precede the first downstream call.
            obj = bytearray(0x38)
            obj[0x18] = raw_index
            struct.pack_into('<I', obj, 0x1c, operation)
            obj[0x20:0x23] = flags
            struct.pack_into('<QII', obj, 0x28, vector_address, len(vector), len(vector))
            emulator.emulator.mem_write(exact.OBJECT_ADDRESS, bytes(obj))
            emulator.emulator.mem_write(vector_address, vector)
            return callback_request(emulator, context, obj, vector)

        for raw_index in range(256):
            slot = (ror(ror((exchange(raw_index)+0x68)&255, 6)^255, 6)-2)&255
            for operation in (1, 2):
                row = request(raw_index, operation, vector=b'\x12' if operation == 1 else b'Ab\0')
                self.assertEqual(row['slot_index'], slot)
                self.assertEqual(row['application_status'], 'NOT_OBSERVED')
                if operation == 1:
                    self.assertEqual(row['native_lookup_index'], slot if slot <= 63 else 0)
                else:
                    self.assertEqual(row['anonymous_control_bytes'], [0, 0, 0])
        for position in range(3):
            for value in range(256):
                flags = bytearray(b'\xfc\x27\x3b')
                flags[position] = value
                expected = [0, 0, 0]
                if position == 0:
                    byte = table[exchange(ror(value, 2))]
                    expected[0] = ror((((byte^0xea)+0x4f)&255)^0xb0, 4)^0xeb
                elif position == 1:
                    expected[1] = ror((ror(table[(~table[value])&255], 2)-0x1d)&255, 7)
                else:
                    expected[2] = (exchange((~ror(((value+0x34)&255)^0x34, 4))&255)+0x7b)&255
                self.assertEqual(request(0, flags=bytes(flags))['anonymous_control_bytes'], expected)
        a = request(0, vector=b'Ab\0')['native_name_comparison_hash_u32']
        self.assertEqual(a, request(0, vector=b'aB\0')['native_name_comparison_hash_u32'])
        self.assertNotEqual(a, request(0, vector=b'Ac\0')['native_name_comparison_hash_u32'])
        for operation, vector in ((1, b''), (1, b'\x00\x00'), (2, b'Ab'), (2, b'A\0B\0')):
            with self.assertRaises(ValueError):
                request(0, operation, vector=vector)

    def test_exact_byte_setter_changes_only_expected_synthetic_slot_field(self):
        emulator, _ = create_emulator(self.image)
        slot = exact.WORK_BASE + 0x8000
        vtable = exact.WORK_BASE + 0x8100
        emulator.emulator.mem_write(vtable + 0x40, struct.pack('<Q', exact.RETURN_ADDRESS))
        original = struct.pack('<Q', vtable) + b'\x7d' * 56
        for value in (0, 1, 7, 18, 255):
            emulator.emulator.mem_write(slot, original)
            emulator.call(exact.IMAGE_BASE + 0x8f2f70, rcx=slot, rdx=value)
            expected = bytearray(original)
            expected[0x2f] = value
            self.assertEqual(bytes(emulator.emulator.mem_read(slot, len(original))), bytes(expected))

    def test_original_sibling_shapes_callback_requests_and_native_controls(self):
        sample_path = os.environ.get('ROFL_821_SLOT_SIBLING_SAMPLES')
        if not sample_path:
            self.skipTest('authorized exact-821 sibling representatives absent')
        data = json.loads(Path(sample_path).read_text(encoding='utf-8'))
        self.assertEqual(data['build'], '16.19.821.7343')
        samples = [sample for group in data['groups'] for sample in group['samples']]
        self.assertTrue(samples)
        emulator, context = create_emulator(self.image, True)
        kinds = set()
        for sample in samples:
            row = decode_packet(emulator, context, sample, True)
            request = row['callback_request_candidate']
            self.assertEqual(request['registered_packet_class'], PACKET_CLASSES[sample['packet_id']])
            self.assertEqual(request['application_status'], 'NOT_OBSERVED')
            self.assertEqual(request['receiver_entity_status'], 'UNKNOWN')
            kinds.add(request['operation_kind'])
            payload = bytes.fromhex(sample['payload_hex'])
            for changed in (payload[:-1], payload+b'\0'):
                context['raw_param'] = sample['raw_param']
                native = emulator.decode(changed, SIBLING_PROFILES[sample['packet_id']])
                self.assertFalse(native['deserialize_return_al'] == 1 and native['fully_consumed'])
        self.assertEqual(kinds, {'SLOT_NAME_CHANGE_REQUEST','SLOT_GATED_BYTE_FIELD_WRITE_REQUEST',
                                'SLOT_DWORD_VECTOR_CHANGE_REQUEST'})
        for begin, _, _ in SIBLING_SPANS:
            changed = bytearray(self.image)
            changed[begin] ^= 1
            with self.assertRaises(ValueError):
                check_sibling_identity(changed)


if __name__ == '__main__':
    unittest.main()
