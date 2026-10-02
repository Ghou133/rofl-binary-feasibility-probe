#!/usr/bin/env python3
"""Exact-821 numeric 0x049c native nested bytes and dynamic byte vector.

The pinned decoder owns packet processing. Only a proven memset leaf is replaced
with its host-memory semantics because this Unicorn build lacks its AVX path.
No game object lookup, callback, actor or gameplay effect is stubbed.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator, read_image

BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x049c
CONSTRUCTOR_RVA = 0xe9a6c0
DESERIALIZER_RVA = 0x10d0d30
VTABLE_RVA = 0x1ba8de8
NESTED_VTABLE_RVA = 0x1ba8dc0
MEMSET_LEAF_RVA = 0x1a653c3
MEMSET_PREFIX_SHA256 = '961ec6b7a19ad835ada16a4cd076ebd87c7038c770e0ca8db6cf0aa6b04b3d38'
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA, 'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x38, 'fields': []}
LENGTHS = {
    1: frozenset([5, 6, *range(9, 41), 42, 48, 49, 52]),
    2: frozenset([5, 6, *range(10, 38), 39, 49, 52]),
}
MAX_PACKETS = 10_000
MAX_INPUT_BYTES = 4_000_000
MAX_VECTOR_BYTES = 64
CALLBACK_RVA = 0x24ebb0
CALLBACK_SPANS = (
    (0x263238, 0x263287, 'b4511756aaa921c7c4bfc031ce0de3d81a3f4d232df158b222298e7f72157de5'),
    (0x24f200, 0x24f238, '005e0bdb7e96a5b6f4b243b5952d451adc29fcce678a352220278511d0916ca8'),
    (0x252220, 0x25228d, 'a73921161a6cf6a4e840ee4cf724407407867d2de61f6a6d4a518b6f7ec1abe4'),
    (0x303820, 0x303828, 'dd7798c79872244cbf9118d2fb78708c3d6228edb3c6c432cb0d2116b84b17cd'),
    (0x2bbe30, 0x2bbe35, '94765465052845bb1ef5e4a2a97d2549b73cfd3e48ebb6fdd0ae88e4d162acbc'),
    (0x24ebb0, 0x24ee18, '62e8f48e4b0b36ea54a466b04dd82813a6204c98d904413bbf2ad566200f0e3e'),
    (0x8f2f30, 0x8f2f7a, '1f5f58ef5c0c7ddfd9219886914e88385e5b7f955024b522549f20a9d4752d79'),
    (0x98a840, 0x98a859, '88974afa23e856901f874805af9cb11670298ac9082f8bc4526e9a1a1c70a1d5'),
    (0x287350, 0x2875a9, 'b4be11da556109a6c252e237f6146a60dd5d7980376647fe6c9482e7970155b1'),
    (0x97f7a0, 0x97f8a8, '548fed449cc4b3c41294a9d872365207495916de9636c924aeb1f70b5523fc93'),
    (0x1168ba0, 0x1168bf0, 'e8103d1a6ca53e920b27f349ec71446eeef982a1df02eeffd9ce7be74a6af1e3'),
)
CALLBACK_PACKET_CLASS = 'PKT_ChangeSlotSpellData_s'


def check_callback_identity(image):
    for begin, end, digest in CALLBACK_SPANS:
        if hashlib.sha256(image[begin:end]).hexdigest() != digest:
            raise ValueError('exact 821 callback registration/dataflow span differs')
    base = 0x7ff67f410000
    if struct.unpack_from('<Q', image, 0x1ac2c30 + 0x18)[0] != base + 0x303820:
        raise ValueError('exact 821 callback closure type differs')
    name = image[0x1f28690:0x1f28790]
    if b'MakeFunction@VAIBaseClient@@' not in name or b'AEBVPKT_ChangeSlotSpellData_s@@' not in name:
        raise ValueError('exact 821 callback receiver/packet class differs')


def install_callback_prefix_witness(emulator, context):
    import emulate_exact_packet_decoder as exact
    from unicorn import UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_RBP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP

    def stop_before_receiver(uc, address, size, user):
        if not context.get('callback_prefix_active'):
            raise ValueError('unexpected callback prefix execution')
        context['callback_prefix_witness'] = {
            'slot_index': uc.reg_read(UC_X86_REG_RBP) & 0xff,
            'stop_rva': hex(address - exact.IMAGE_BASE),
        }
        if address == exact.IMAGE_BASE + 0x24ecdf:
            stack = uc.reg_read(UC_X86_REG_RSP)
            context['callback_prefix_witness']['anonymous_control_bytes'] = [
                uc.reg_read(UC_X86_REG_R8) & 0xff, uc.reg_read(UC_X86_REG_R9) & 0xff,
                bytes(uc.mem_read(stack + 0x20, 1))[0]]
        uc.emu_stop()

    for stop in (0x24ec26, 0x24ecdf):
        emulator.emulator.hook_add(UC_HOOK_CODE, stop_before_receiver,
            begin=exact.IMAGE_BASE + stop, end=exact.IMAGE_BASE + stop)


def callback_request(emulator, context, obj, vector):
    import emulate_exact_packet_decoder as exact
    operation = struct.unpack_from('<I', obj, 0x1c)[0]
    if operation not in (1, 2):
        return {'status': 'UNOBSERVED_OPERATION', 'operation_selector': operation,
                'application_status': 'NOT_OBSERVED'}
    if (operation == 1 and len(vector) != 1) or (operation == 2 and
            (len(vector) < 2 or vector[-1] != 0 or 0 in vector[:-1])):
        raise ValueError('callback request vector is outside observed operation scope')
    context['callback_prefix_active'] = True
    context['callback_prefix_witness'] = None
    try:
        # RCX is deliberately zero: execution stops before any receiver lookup
        # or downstream call. This witnesses packet-only argument conversion.
        emulator.call(exact.IMAGE_BASE + CALLBACK_RVA, rcx=0, rdx=exact.OBJECT_ADDRESS)
    finally:
        context['callback_prefix_active'] = False
    witness = context['callback_prefix_witness']
    if not witness or witness['stop_rva'] != ('0x24ec26' if operation == 1 else '0x24ecdf'):
        raise ValueError('native callback prefix did not reach the selected operation')
    request = {'status': 'CANDIDATE_STATIC_RECEIVE_DATAFLOW',
        'registered_packet_class': CALLBACK_PACKET_CLASS, 'registered_receiver_class': 'AIBaseClient',
        'operation_selector': operation, 'slot_index': witness['slot_index'],
        'value_decode_witness': 'NATIVE_PACKET_ONLY_CALLBACK_PREFIX',
        'callback_stop_rva': witness['stop_rva'], 'receiver_entity_status': 'UNKNOWN',
        'application_status': 'NOT_OBSERVED'}
    if operation == 1:
        request.update({'operation_kind': 'SLOT_BYTE_FIELD_WRITE_REQUEST',
            'requested_u8': vector[0], 'receiver_field_offset': '0x2f',
            'receiver_field_meaning': 'UNKNOWN',
            'native_lookup_index': witness['slot_index'] if witness['slot_index'] <= 63 else 0})
    else:
        pointer = struct.unpack_from('<Q', obj, 0x28)[0]
        request.update({'operation_kind': 'SLOT_NAME_CHANGE_REQUEST',
            'requested_name_bytes_hex': vector[:-1].hex(),
            'requested_name_ascii': vector[:-1].decode('ascii') if all(32 <= b <= 126 for b in vector[:-1]) else None,
            'native_name_comparison_hash_u32': emulator.call(exact.IMAGE_BASE + 0x1168ba0, rcx=pointer) & 0xffffffff,
            'anonymous_control_bytes': witness['anonymous_control_bytes']})
    return request


def create_emulator(image):
    import emulate_exact_packet_decoder as exact
    from unicorn import UC_HOOK_CODE
    prefix = image[0x1a653a0:MEMSET_LEAF_RVA]
    if hashlib.sha256(prefix).hexdigest() != MEMSET_PREFIX_SHA256:
        raise ValueError('exact 821 memset prefix differs')
    if struct.unpack_from('<I', image, 0xf0e4bc + PACKET_ID * 4)[0] != 0xf0cfeb:
        raise ValueError('exact 821 factory route differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] != 0x7ff67f410000 + DESERIALIZER_RVA:
        raise ValueError('exact 821 vtable decoder differs')
    emulator, context = make_emulator(image)
    check_callback_identity(image)
    install_callback_prefix_witness(emulator, context)
    emulator.emulator.hook_add(UC_HOOK_CODE, emulator._memset_leaf,
        begin=exact.IMAGE_BASE + MEMSET_LEAF_RVA, end=exact.IMAGE_BASE + MEMSET_LEAF_RVA)
    return emulator, context


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet must have numeric route 0x049c')
    stream = packet.get('stream_tag')
    raw_param = packet.get('raw_param')
    if type(stream) is not int or stream not in LENGTHS:
        raise ValueError('observed game/keyframe stream is required')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero uint32')
    text = packet.get('payload_hex')
    if not isinstance(text, str) or len(text) % 2 or len(text) > 104 or not re.fullmatch(r'[0-9a-fA-F]*', text):
        raise ValueError('bounded hexadecimal payload is required')
    payload = bytes.fromhex(text)
    if len(payload) not in LENGTHS[stream]:
        raise ValueError('payload is outside observed exact-821 stream/length shapes')
    return raw_param, payload


def decode_packet(emulator, context, packet):
    import emulate_exact_packet_decoder as exact
    raw_param, payload = validate_packet(packet)
    context['raw_param'] = raw_param
    result = emulator.decode(payload, PROFILE)
    if result['deserialize_return_al'] != 1 or not result['fully_consumed']:
        raise ValueError('native decoder did not accept and fully consume payload')
    obj = bytes(emulator.emulator.mem_read(exact.OBJECT_ADDRESS, 0x38))
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID or struct.unpack_from('<I', obj, 12)[0] != raw_param:
        raise ValueError('native opcode/raw-param differs')
    if struct.unpack_from('<Q', obj, 0)[0] != exact.IMAGE_BASE + VTABLE_RVA or struct.unpack_from('<Q', obj, 16)[0] != exact.IMAGE_BASE + NESTED_VTABLE_RVA:
        raise ValueError('native outer/nested vtable differs')
    pointer, count, capacity = struct.unpack_from('<QII', obj, 0x28)
    if count > capacity or count > MAX_VECTOR_BYTES:
        raise ValueError('native byte vector exceeds bounded observed scope')
    if count and not (exact.HEAP_BASE <= pointer and pointer + count <= emulator.heap_cursor):
        raise ValueError('native byte vector is outside current allocated emulator heap')
    vector = bytes(emulator.emulator.mem_read(pointer, count)) if count else b''
    visible = vector[:-1] if vector.endswith(b'\x00') else vector
    printable = bool(visible) and all(0x20 <= value <= 0x7e for value in visible)
    return {'status': 'NATIVE_ACCEPTED', 'deserialize_return_al': 1,
        'bytes_consumed': len(payload), 'native_nested_field_bytes_hex':
            {'0x18': obj[0x18:0x19].hex(), '0x1c': obj[0x1c:0x20].hex(),
             '0x20': obj[0x20:0x23].hex()},
        'native_byte_vector_length': count, 'native_byte_vector_hex': vector.hex(),
        'native_byte_vector_ascii_candidate': visible.decode('ascii') if printable else None,
        'native_byte_vector_text_status': 'PRINTABLE_ASCII_CANDIDATE' if printable else 'OPAQUE_BYTES',
        'native_byte_vector_terminal_nul': vector.endswith(b'\x00'),
        'callback_request_candidate': callback_request(emulator, context, obj, vector)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('native request exceeds bounded size')
    request = json.loads(raw)
    packets = request.get('packets') if isinstance(request, dict) else None
    if not isinstance(request, dict) or request.get('replay_version') != BUILD or not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError('exact build and bounded packets array are required')
    image, image_sha, _ = read_image(args.image)
    emulator, context = create_emulator(image)
    rows = []
    for index, packet in enumerate(packets):
        try:
            rows.append({'index': index, **decode_packet(emulator, context, packet)})
        except Exception as error:
            rows.append({'index': index, 'status': 'FAILED', 'error': str(error)})
    print(json.dumps({'replay_version': BUILD, 'runtime_image_sha256': image_sha,
        'callback_packet_class': CALLBACK_PACKET_CLASS, 'callback_body_rva': hex(CALLBACK_RVA),
        'memory_compatibility': {'operation': 'MEMSET_ONLY', 'leaf_rva': hex(MEMSET_LEAF_RVA),
            'prefix_sha256': MEMSET_PREFIX_SHA256}, 'rows': rows}, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'FAILED', 'error': str(error)}))
        raise SystemExit(1)
