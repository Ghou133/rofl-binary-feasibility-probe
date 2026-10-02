#!/usr/bin/env python3
"""Exact-821 0x049c and optional slot-change sibling native request candidates.

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
SIBLING_PROFILES = {
    0x028e: {'constructor_rva': 0xe9a670, 'deserialize_rva': 0x10d0bd0, 'object_size': 0x38, 'fields': []},
    0x0375: {'constructor_rva': 0xe9a620, 'deserialize_rva': 0x10d0a70, 'object_size': 0x38, 'fields': []},
}
PACKET_CLASSES = {0x049c: CALLBACK_PACKET_CLASS, 0x028e: 'PKT_ChangeSlotSpellData_Summoner_s',
                  0x0375: 'PKT_ChangeSlotSpellData_OwnerOnly_s'}
SIBLING_LENGTHS = {0x028e: {1: frozenset([17,18,19,21,22,32,33,34,46]),
                          2: frozenset([17,18,19,21,22,32,33,34,46])},
                  0x0375: {2: frozenset([5,6,9,10])}}
SIBLING_SPANS = (
    (0x263287, 0x263325, 'a11ed117f94565892ddb404b2c1a7ec2eb6e48e376f904aead444cf591eb99cf'),
    (0x24f180, 0x24f238, '80e2069a24c240ebf0b922ec61cc3375ce258f4653581492fbf5747f742c42b6'),
    (0x252140, 0x252220, 'c7c06d820f72399557d6ce6efff22b04f3b5762501956fccf83e650f15904f3f'),
    (0x303800, 0x303828, '9dc3838029358fae3a304d7a7d74a7c405e17b6ee754b61259e5a7c693ec3f05'),
    (0x97f8b0, 0x97f916, '9e246ba19b3976d8c1aa3e9164c700cb00a7fed314f170e033dc75822597db02'),
    (0x2875b0, 0x2876b8, '5b11f11d3239c905bafc8506c439d9077220f2209f5f0d8c666f35f138f1f7f2'),
)


def check_sibling_identity(image):
    for begin, end, digest in SIBLING_SPANS:
        if hashlib.sha256(image[begin:end]).hexdigest() != digest:
            raise ValueError('exact 821 sibling registration/dataflow span differs')
    base = 0x7ff67f410000
    for route, case, vt, closure, type_fn, descriptor in (
            (0x028e, 0xf06391, 0x1ba8e48, 0x1ac2c90, 0x303810, 0x1f28460),
            (0x0375, 0xf0945a, 0x1ba8e18, 0x1ac2c60, 0x303800, 0x1f28570)):
        if struct.unpack_from('<I', image, 0xf0e4bc+route*4)[0] != case or \
                struct.unpack_from('<Q', image, vt+8)[0] != base+SIBLING_PROFILES[route]['deserialize_rva'] or \
                struct.unpack_from('<Q', image, closure+0x18)[0] != base+type_fn:
            raise ValueError('exact 821 sibling factory/closure differs')
        name = image[descriptor+16:descriptor+256]
        if b'MakeFunction@VAIBaseClient@@' not in name or PACKET_CLASSES[route].encode()+b'@@' not in name:
            raise ValueError('exact 821 sibling receiver/packet class differs')


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

    for stop in (0x24ec26, 0x24ecdf, 0x24ed5e, 0x24ed7b):
        emulator.emulator.hook_add(UC_HOOK_CODE, stop_before_receiver,
            begin=exact.IMAGE_BASE + stop, end=exact.IMAGE_BASE + stop)

    def stop_vector_reader(uc, address, size, user):
        if not context.get('callback_vector_active'):
            raise ValueError('unexpected packet-only vector reader execution')
        stack = uc.reg_read(UC_X86_REG_RSP)
        begin, end = struct.unpack('<QQ', bytes(uc.mem_read(stack+0x30, 16)))
        length = end-begin
        if length < 0 or length > 8 or length % 4 or (length and not
                (exact.HEAP_BASE <= begin and end <= emulator.heap_cursor)):
            raise ValueError('native packet-only word vector exceeds observed scope')
        words = bytes(uc.mem_read(begin,length)) if length else b''
        context['callback_vector_words'] = list(struct.unpack('<'+'I'*(length//4),words))
        uc.emu_stop()

    emulator.emulator.hook_add(UC_HOOK_CODE, stop_vector_reader,
        begin=exact.IMAGE_BASE+0x287633, end=exact.IMAGE_BASE+0x287633)


def callback_request(emulator, context, obj, vector, packet_id=PACKET_ID):
    import emulate_exact_packet_decoder as exact
    operation = struct.unpack_from('<I', obj, 0x1c)[0]
    observed_operations = {0x049c: (1,2), 0x028e: (2,), 0x0375: (6,7)}[packet_id]
    if operation not in observed_operations:
        return {'status': 'UNOBSERVED_OPERATION', 'operation_selector': operation,
                'application_status': 'NOT_OBSERVED'}
    if (operation in (1,6) and len(vector) != 1) or (operation == 2 and
            (len(vector) < 2 or vector[-1] != 0 or 0 in vector[:-1])):
        raise ValueError('callback request vector is outside observed operation scope')
    if operation == 7 and (len(vector) != 5 or vector[0] != 1):
        raise ValueError('callback counted dword vector differs from observed scope')
    context['callback_prefix_active'] = True
    context['callback_prefix_witness'] = None
    try:
        # RCX is deliberately zero: execution stops before any receiver lookup
        # or downstream call. This witnesses packet-only argument conversion.
        emulator.call(exact.IMAGE_BASE + CALLBACK_RVA, rcx=0, rdx=exact.OBJECT_ADDRESS)
    finally:
        context['callback_prefix_active'] = False
    witness = context['callback_prefix_witness']
    stop_rva = {1:'0x24ec26',2:'0x24ecdf',6:'0x24ed5e',7:'0x24ed7b'}[operation]
    if not witness or witness['stop_rva'] != stop_rva:
        raise ValueError('native callback prefix did not reach the selected operation')
    request = {'status': 'CANDIDATE_STATIC_RECEIVE_DATAFLOW',
        'registered_packet_class': PACKET_CLASSES[packet_id], 'registered_receiver_class': 'AIBaseClient',
        'operation_selector': operation, 'slot_index': witness['slot_index'],
        'value_decode_witness': 'NATIVE_PACKET_ONLY_CALLBACK_PREFIX',
        'callback_stop_rva': witness['stop_rva'], 'receiver_entity_status': 'UNKNOWN',
        'application_status': 'NOT_OBSERVED'}
    if operation == 1:
        request.update({'operation_kind': 'SLOT_BYTE_FIELD_WRITE_REQUEST',
            'requested_u8': vector[0], 'receiver_field_offset': '0x2f',
            'receiver_field_meaning': 'UNKNOWN',
            'native_lookup_index': witness['slot_index'] if witness['slot_index'] <= 63 else 0})
    elif operation == 2:
        pointer = struct.unpack_from('<Q', obj, 0x28)[0]
        request.update({'operation_kind': 'SLOT_NAME_CHANGE_REQUEST',
            'requested_name_bytes_hex': vector[:-1].hex(),
            'requested_name_ascii': vector[:-1].decode('ascii') if all(32 <= b <= 126 for b in vector[:-1]) else None,
            'native_name_comparison_hash_u32': emulator.call(exact.IMAGE_BASE + 0x1168ba0, rcx=pointer) & 0xffffffff,
            'anonymous_control_bytes': witness['anonymous_control_bytes']})
    elif operation == 6:
        request.update({'operation_kind':'SLOT_GATED_BYTE_FIELD_WRITE_REQUEST', 'requested_u8':vector[0],
            'receiver_field_offset':'0xe8', 'receiver_field_meaning':'UNKNOWN', 'callee_has_state_gate':True})
    else:
        pointer = struct.unpack_from('<Q', obj, 0x28)[0]
        context['callback_vector_active'] = True
        context['callback_vector_words'] = None
        try:
            emulator.call(exact.IMAGE_BASE+0x2875b0, rcx=0, rdx=witness['slot_index'], r8=pointer)
        finally:
            context['callback_vector_active'] = False
        words = context['callback_vector_words']
        if words != [struct.unpack_from('<I',vector,1+i*4)[0] for i in range(vector[0])]:
            raise ValueError('native packet-only word construction differs')
        request.update({'operation_kind':'SLOT_DWORD_VECTOR_CHANGE_REQUEST', 'requested_word_count':vector[0],
            'requested_words_u32':words, 'word_decode_witness':'NATIVE_CALLEE_PACKET_ONLY_VECTOR_CONSTRUCTION',
            'nested_holder_vector_offset':'0x40', 'word_meaning':'UNKNOWN', 'callee_has_state_gate':True})
    return request


def create_emulator(image, include_siblings=False):
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
    if include_siblings:
        check_sibling_identity(image)
    install_callback_prefix_witness(emulator, context)
    emulator.emulator.hook_add(UC_HOOK_CODE, emulator._memset_leaf,
        begin=exact.IMAGE_BASE + MEMSET_LEAF_RVA, end=exact.IMAGE_BASE + MEMSET_LEAF_RVA)
    return emulator, context


def validate_packet(packet, include_siblings=False):
    if not isinstance(packet, dict) or packet.get('packet_id') not in (PACKET_CLASSES if include_siblings else (PACKET_ID,)):
        raise ValueError('packet must have numeric route 0x049c')
    stream = packet.get('stream_tag')
    raw_param = packet.get('raw_param')
    lengths = LENGTHS if packet['packet_id'] == PACKET_ID else SIBLING_LENGTHS[packet['packet_id']]
    if type(stream) is not int or stream not in lengths:
        raise ValueError('observed game/keyframe stream is required')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero uint32')
    text = packet.get('payload_hex')
    if not isinstance(text, str) or len(text) % 2 or len(text) > 104 or not re.fullmatch(r'[0-9a-fA-F]*', text):
        raise ValueError('bounded hexadecimal payload is required')
    payload = bytes.fromhex(text)
    if len(payload) not in lengths[stream]:
        raise ValueError('payload is outside observed exact-821 stream/length shapes')
    return raw_param, payload


def decode_packet(emulator, context, packet, include_siblings=False):
    import emulate_exact_packet_decoder as exact
    raw_param, payload = validate_packet(packet, include_siblings)
    packet_id = packet['packet_id']
    context['raw_param'] = raw_param
    result = emulator.decode(payload, PROFILE if packet_id == PACKET_ID else SIBLING_PROFILES[packet_id])
    if result['deserialize_return_al'] != 1 or not result['fully_consumed']:
        raise ValueError('native decoder did not accept and fully consume payload')
    obj = bytes(emulator.emulator.mem_read(exact.OBJECT_ADDRESS, 0x38))
    if struct.unpack_from('<H', obj, 8)[0] != packet_id or struct.unpack_from('<I', obj, 12)[0] != raw_param:
        raise ValueError('native opcode/raw-param differs')
    vt = {0x049c: VTABLE_RVA, 0x028e:0x1ba8e48, 0x0375:0x1ba8e18}[packet_id]
    if struct.unpack_from('<Q', obj, 0)[0] != exact.IMAGE_BASE + vt or struct.unpack_from('<Q', obj, 16)[0] != exact.IMAGE_BASE + NESTED_VTABLE_RVA:
        raise ValueError('native outer/nested vtable differs')
    pointer, count, capacity = struct.unpack_from('<QII', obj, 0x28)
    if count > capacity or count > MAX_VECTOR_BYTES:
        raise ValueError('native byte vector exceeds bounded observed scope')
    if count and not (exact.HEAP_BASE <= pointer and pointer + count <= emulator.heap_cursor):
        raise ValueError('native byte vector is outside current allocated emulator heap')
    vector = bytes(emulator.emulator.mem_read(pointer, count)) if count else b''
    visible = vector[:-1] if vector.endswith(b'\x00') else vector
    printable = bool(visible) and all(0x20 <= value <= 0x7e for value in visible)
    return {'status': 'NATIVE_ACCEPTED', 'deserialize_return_al': 1, 'native_packet_id': packet_id,
        'bytes_consumed': len(payload), 'native_nested_field_bytes_hex':
            {'0x18': obj[0x18:0x19].hex(), '0x1c': obj[0x1c:0x20].hex(),
             '0x20': obj[0x20:0x23].hex()},
        'native_byte_vector_length': count, 'native_byte_vector_hex': vector.hex(),
        'native_byte_vector_ascii_candidate': visible.decode('ascii') if printable else None,
        'native_byte_vector_text_status': 'PRINTABLE_ASCII_CANDIDATE' if printable else 'OPAQUE_BYTES',
        'native_byte_vector_terminal_nul': vector.endswith(b'\x00'),
        'callback_request_candidate': callback_request(emulator, context, obj, vector, packet_id)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--include-slot-siblings', action='store_true')
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('native request exceeds bounded size')
    request = json.loads(raw)
    packets = request.get('packets') if isinstance(request, dict) else None
    if not isinstance(request, dict) or request.get('replay_version') != BUILD or not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError('exact build and bounded packets array are required')
    image, image_sha, _ = read_image(args.image)
    emulator, context = create_emulator(image, args.include_slot_siblings)
    rows = []
    for index, packet in enumerate(packets):
        try:
            rows.append({'index': index, **decode_packet(emulator, context, packet, args.include_slot_siblings)})
        except Exception as error:
            rows.append({'index': index, 'status': 'FAILED', 'error': str(error)})
    print(json.dumps({'replay_version': BUILD, 'runtime_image_sha256': image_sha,
        'callback_packet_class': CALLBACK_PACKET_CLASS, 'callback_body_rva': hex(CALLBACK_RVA),
        'slot_siblings_enabled':args.include_slot_siblings,
        'memory_compatibility': {'operation': 'MEMSET_ONLY', 'leaf_rva': hex(MEMSET_LEAF_RVA),
            'prefix_sha256': MEMSET_PREFIX_SHA256}, 'rows': rows}, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'FAILED', 'error': str(error)}))
        raise SystemExit(1)
