"""Canonical ordered V9 CastSpellAns digest over fields saved in JSONL.

Each row is local-index u32le, raw parameter u32le, consumed payload length
u32le, payload SHA-256 bytes, then these native packet fields in order:
flag u8, signed i32le, protected f32 +0xe0 bytes, protected u8 +0x140,
decoded u8, protected nested bits +0x24, decoded bits, protected and decoded
u32 +0x1c, protected and decoded u32 +0x4c, protected f32 +0xa0 bytes,
protected and decoded lookup-key u32 +0x28. All integers are little endian.
Decoded f32 values are checked against protected bytes by the decoder/query;
the bytes are hashed to avoid JSON float formatting differences.
"""

import hashlib
import struct


SCHEMA = 'CAST_SPELL_ANS_821_V9_NATIVE_OUTPUT_V1'
BATCH_DOMAIN = (SCHEMA + '\0').encode('ascii')


def batch_digest(rows):
    digest = hashlib.sha256(BATCH_DOMAIN)
    for index, row in enumerate(rows):
        digest.update(struct.pack('<III', index, row['raw_param'],
                                  row['bytes_consumed']))
        digest.update(bytes.fromhex(row['raw_payload_sha256']))
        digest.update(struct.pack('<Bi', row['opaque_flag_0x148'],
                                  row['opaque_i32_0x14c']))
        digest.update(bytes.fromhex(row['raw_f32_bytes_hex']))
        digest.update(bytes.fromhex(row['raw_u8_0x140_hex']))
        digest.update(struct.pack('<B', row['opaque_u8_0x140']))
        digest.update(bytes.fromhex(row['raw_nested_bits_0x24_hex']))
        digest.update(struct.pack('<B', row['opaque_nested_bits_0x24']))
        digest.update(bytes.fromhex(row['raw_u32_0x1c_hex']))
        digest.update(struct.pack('<I', row['opaque_u32_0x1c']))
        digest.update(bytes.fromhex(row['raw_u32_0x4c_hex']))
        digest.update(struct.pack('<I', row['opaque_u32_0x4c']))
        digest.update(bytes.fromhex(row['raw_f32_0xa0_hex']))
        digest.update(bytes.fromhex(row['raw_u32_0x28_hex']))
        digest.update(struct.pack('<I', row['opaque_u32_0x28']))
    return digest.hexdigest()
