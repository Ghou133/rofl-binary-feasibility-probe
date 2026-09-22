import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "trace_stat_selector_consumers",
    ROOT / "scripts" / "trace_stat_selector_consumers.py",
)
TRACE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(TRACE)


def decode(code: bytes):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    return list(decoder.disasm(code, TRACE.IMAGE_BASE + 0x1000))


class StatSelectorConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime_image = (
            ROOT / "artifacts" / "new_build_rofl_compatibility_gate_v1" / "runtime"
            / "league_16.16.805.0442.memory.bin"
        )
        image = cls.runtime_image.read_bytes()
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        cls.mana_records = {
            insn.address - TRACE.IMAGE_BASE: TRACE.instruction_record(insn)
            for insn in decoder.disasm(
                image[0x00B36B69:0x00B36D2F], TRACE.IMAGE_BASE + 0x00B36B69,
            )
        }

    def test_constant_selector_and_lane_are_recovered(self):
        # xor r8d,r8d; mov dl,0xb; call rel32
        insns = decode(bytes.fromhex("4533c0b20be800000000"))
        result = TRACE.recover_call_arguments(insns, 2)
        self.assertEqual(result["selector"], 11)
        self.assertEqual(result["lane"], 0)
        self.assertEqual(result["selector_status"], "STATIC_CONSTANT")
        self.assertEqual(result["lane_status"], "STATIC_CONSTANT")

    def test_dynamic_selector_is_unknown_not_guessed(self):
        # mov dl,al; xor r8d,r8d; call rel32
        insns = decode(bytes.fromhex("88c24533c0e800000000"))
        result = TRACE.recover_call_arguments(insns, 2)
        self.assertIsNone(result["selector"])
        self.assertEqual(result["selector_status"], "DYNAMIC_OR_UNRESOLVED")
        self.assertEqual(result["lane"], 0)

    def test_hashes_are_deterministic_known_fnv_vectors(self):
        self.assertEqual(TRACE.fnv1a32(b"hello"), 0x4F9F2CAB)
        self.assertEqual(TRACE.fnv1a64(b"hello"), 0xA430D84680AABD0B)

    def test_holdout_paths_fail_before_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            prohibited = pathlib.Path(temporary) / "Protected_Holdout" / "image.bin"
            with self.assertRaisesRegex(ValueError, "Holdout paths are prohibited"):
                TRACE.reject_holdout(prohibited)

    def test_exact_runtime_end_to_end_when_fixture_is_present(self):
        image = self.runtime_image
        self.assertTrue(image.is_file(), "exact-build runtime fixture must be present")
        with mock.patch.object(
                TRACE, "sha256_file",
                side_effect=AssertionError("analyze must hash the same bytes it reads")):
            report = TRACE.analyze(image)
        self.assertEqual(report["build"], TRACE.BUILD)
        self.assertEqual(report["image"]["sha256"], TRACE.EXPECTED_IMAGE_SHA256)
        self.assertEqual(report["caller_enumeration"]["counts"], {
            "wrapper": 0, "storage_accessor": 4, "selector_lane_lookup": 9,
        })
        self.assertEqual(report["mana_regen_neighborhood"]["status"],
                         "VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING")
        self.assertTrue(report["mana_regen_neighborhood"]["matching_lookup_calls"])
        proof = report["mana_regen_neighborhood"]["control_flow_and_value_flow_proof"]
        self.assertTrue(proof["verified"])
        self.assertTrue(all(proof["cfg_checks"].values()))
        self.assertTrue(all(proof["value_flow_checks"].values()))
        self.assertEqual(report["selector_enum_table_search"]["verified_entries"],
                         [{"selector": 11, "lane": 0, "semantic": "MANA_REGEN"}])
        self.assertEqual(report["reflection_search_summary"]
                         ["selector_mapping_promotions_from_reflection_only"], 0)
        self.assertTrue(all(value is False for value in report["protected_holdout"].values()))


    def test_adjacent_pdata_and_literals_do_not_promote_broken_value_flow(self):
        # Keep the exact runtime's adjacent PDATA/literal universe, but corrupt
        # the output-slot load.  The gate must reject proximity-only evidence.
        records = {rva: dict(row) for rva, row in self.mana_records.items()}
        records[0x00B36BC3]["operands"] = "xmm7, dword ptr [rsp + 0x34]"
        rejected = TRACE.verify_mana_chain_records(records, 0x01ACE414, 0x01ACE420)
        self.assertFalse(rejected["verified"])
        self.assertEqual(rejected["status"], "FAILED_CLOSED")
        self.assertFalse(rejected["value_flow_checks"]
                         ["lookup_output_loaded_from_rsp_30_into_xmm7"])


if __name__ == "__main__":
    unittest.main()
