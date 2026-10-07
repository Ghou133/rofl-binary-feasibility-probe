"""Exact-image packet-code tests; generated mutations are not receiver evidence."""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import decode_cooldown_broadcast_packet_16_19_821 as decoder
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RDI

IMAGE=os.environ.get('ROFL_821_RUNTIME_IMAGE')

@unittest.skipUnless(IMAGE and Path(IMAGE).is_file(),'exact 821 runtime image unavailable')
class CooldownRequestFields(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image,_=decoder.read_image(Path(IMAGE))

    def setUp(self):
        self.emulator,self.context,self.captured=decoder.make_native(self.image,request_fields=True)

    def decode(self,hex_value):
        return decoder.decode_one(self.emulator,self.context,self.captured,0x400000ae,
                                  bytes.fromhex(hex_value),request_fields=True)

    def test_original_fields_stop_before_receiver_effects(self):
        first=self.decode('733e')['native_callback_request']
        second=self.decode('70661cc0ec7878')['native_callback_request']
        self.assertEqual(first['argument_f32'],(0.,-1.,0.,0.))
        self.assertEqual(second['argument_f32'],(15.,0.,0.,0.))
        self.assertEqual(second['application_status'],'NOT_OBSERVED')
        self.assertEqual(set(self.context['request_slice_values']),{0x2bbda0,0x2bbddf,0x2bbe23})

    def native_first_slice(self):
        uc=self.emulator.emulator
        uc.reg_write(UC_X86_REG_RBX,decoder.exact.OBJECT_ADDRESS)
        uc.reg_write(UC_X86_REG_RAX,0)
        uc.reg_write(UC_X86_REG_RDI,0)
        self.emulator.call(decoder.IMAGE_BASE+0x2bbcca)
        return self.context['request_slice_values'][0x2bbda0]

    def test_native_nonfinite_argument_is_explicitly_rejected(self):
        self.decode('733e')
        uc=self.emulator.emulator
        inverse={}
        # Derive this test mutation from the actual original native transform,
        # independently of the JavaScript/static arithmetic implementation.
        for encoded in range(256):
            uc.mem_write(decoder.exact.OBJECT_ADDRESS+0x20,bytes([encoded])*4)
            bits=self.native_first_slice()[0]
            values=bits.to_bytes(4,'little')
            self.assertEqual(values,values[:1]*4)
            inverse[values[0]]=encoded
        self.assertEqual(len(inverse),256)
        uc.mem_write(decoder.exact.OBJECT_ADDRESS+0x20,
                     bytes(inverse[value] for value in bytes.fromhex('0000807f')))
        obj=bytes(uc.mem_read(decoder.exact.OBJECT_ADDRESS,0x28))
        with self.assertRaisesRegex(ValueError,'nonfinite/control'):
            decoder.request_from_native_slices(self.emulator,self.context,obj)

    def test_unobserved_control_is_rejected_without_receiver_execution(self):
        self.decode('733e')
        uc=self.emulator.emulator
        inverse={}
        for encoded in range(256):
            uc.mem_write(decoder.exact.OBJECT_ADDRESS+0x18,bytes([encoded]))
            inverse[self.native_first_slice()[2]&0xff]=encoded
        self.assertEqual(len(inverse),256)
        uc.mem_write(decoder.exact.OBJECT_ADDRESS+0x18,bytes([inverse[2]]))
        obj=bytes(uc.mem_read(decoder.exact.OBJECT_ADDRESS,0x28))
        with self.assertRaisesRegex(ValueError,'nonfinite/control'):
            decoder.request_from_native_slices(self.emulator,self.context,obj)

if __name__=='__main__':
    unittest.main()
