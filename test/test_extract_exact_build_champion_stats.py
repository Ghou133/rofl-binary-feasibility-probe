import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "extract_exact_build_champion_stats",
    ROOT / "scripts" / "extract_exact_build_champion_stats.py",
)
EXTRACTOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(EXTRACTOR)


class FakeValue:
    def __init__(self, value):
        self.value = value


class FakeHash:
    def __init__(self, value):
        self.h = value


class FakeRecord:
    def __init__(self, path_hash, type_hash, fields):
        self.path = FakeHash(path_hash)
        self.type = FakeHash(type_hash)
        self._fields = fields

    def getv(self, key, default=None):
        return self._fields.get(key, default)

    def to_serializable(self):
        return {
            key: value.to_serializable() if hasattr(value, "to_serializable") else value
            for key, value in self._fields.items()
        }


class FakeModifiable(FakeRecord):
    def __init__(self, value):
        super().__init__(0, 0, {"baseValue": value})

    def to_serializable(self):
        return {"__type": "ModifiableFloat", "baseValue": self._fields["baseValue"]}


class FakeMember:
    def __init__(self, path, data):
        self.path = path
        self.path_hash = int.from_bytes(path.encode("ascii")[:8].ljust(8, b"\0"), "little")
        self.data = data


class FakeWad:
    opened = []

    def __init__(self, path, hashes):
        self.path = pathlib.Path(path)
        self.files = [
            FakeMember("data/characters/aatrox/aatrox.bin", b"ROOT-BIN"),
            FakeMember("assets/characters/aatrox/skin.bin", b"MUST-NOT-BE-READ"),
        ]

    def read_file_data(self, _stream, member):
        self.opened.append(member.path)
        return member.data


class FakeBinFile:
    parsed = []

    def __init__(self, stream):
        data = stream.read()
        self.parsed.append(data)
        primary = FakeRecord(0, 0, {
            "arType": 0, "arBase": 345.0, "arPerLevel": 40.0,
            "arBaseStaticRegen": 8.0, "arRegenPerLevel": 0.8,
        })
        basic_attack = FakeRecord(0, 0, {"mAttackDelayCastOffsetPercent": -0.3})
        fields = {
            "mCharacterName": "Aatrox",
            "baseHPModifiable": FakeModifiable(650.0),
            "hpPerLevelModifiable": FakeModifiable(114.0),
            "baseStaticHPRegenModifiable": FakeModifiable(3.0),
            "hpRegenPerLevelModifiable": FakeModifiable(0.5),
            "baseArmorModifiable": FakeModifiable(38.0),
            "armorPerLevelModifiable": FakeModifiable(4.8),
            "baseMR": FakeModifiable(32.0), "mrPerLevel": FakeModifiable(2.05),
            "baseDamageModifiable": FakeModifiable(60.0),
            "damagePerLevelModifiable": FakeModifiable(5.0),
            "attackSpeedModifiable": FakeModifiable(0.651),
            "attackSpeedRatioModifiable": FakeModifiable(0.65),
            "attackSpeedPerLevelModifiable": FakeModifiable(2.5),
            "mAttackDelayOffsetPercent": -0.1,
            "basicAttack": basic_attack,
            "baseMoveSpeedModifiable": FakeModifiable(345.0),
            "primaryAbilityResource": primary,
        }
        self.entries = [FakeRecord(
            fake_hash("Characters/Aatrox/CharacterRecords/Root"),
            fake_hash("CharacterRecord"), fields,
        )]


def fake_hash(value):
    result = 0x811C9DC5
    for byte in value.lower().encode("ascii"):
        result = ((result ^ byte) * 0x01000193) & 0xFFFFFFFF
    return result


class FakeApi:
    Wad = FakeWad
    BinFile = FakeBinFile
    compute_binhash = staticmethod(fake_hash)
    game_hashes = {}


def create_fixture(root: pathlib.Path, version="16.16.805.442"):
    (root / "build-metadata.json").write_text(
        json.dumps({"file_version": version}), encoding="utf-8"
    )
    champions = root / "DATA" / "FINAL" / "Champions"
    champions.mkdir(parents=True)
    (champions / "Aatrox.wad.client").write_bytes(b"AATROX-WAD")
    (champions / "Aatrox.en_US.wad.client").write_bytes(b"LOCALIZED-MUST-BE-IGNORED")
    hashes = root / "hashes"
    hashes.mkdir()
    for name in (
        "hashes.game.txt", "hashes.binentries.txt", "hashes.bintypes.txt",
        "hashes.binfields.txt", "hashes.binhashes.txt",
    ):
        (hashes / name).write_text("0000000000000000 fixture\n", encoding="ascii")
    return hashes


class ExactBuildChampionStatsTests(unittest.TestCase):
    def setUp(self):
        FakeWad.opened.clear()
        FakeBinFile.parsed.clear()

    def test_canonical_build_reconciliation_and_root_only_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            game_root = pathlib.Path(temporary)
            hashes = create_fixture(game_root)
            report = EXTRACTOR.build_report(
                game_root, hashes, "16.16.805.0442", FakeApi,
            )
        self.assertEqual(report["exact_build"], "16.16.805.0442")
        self.assertEqual(report["build_binding"]["observed_form"], "16.16.805.442")
        self.assertEqual(report["build_binding"]["observed_canonical"], "16.16.805.0442")
        self.assertEqual(report["champion_count"], 1)
        self.assertEqual(FakeWad.opened, ["data/characters/aatrox/aatrox.bin"])
        self.assertEqual(FakeBinFile.parsed, [b"ROOT-BIN"])
        champion = report["champions"][0]
        self.assertEqual(champion["normalized_stats"]["armor"]["base"]["value"], 38.0)
        self.assertEqual(
            champion["normalized_stats"]["armor"]["base"]["source_wrapper_field"],
            "baseValue",
        )
        self.assertEqual(champion["normalized_stats"]["attack_speed"]["ratio"]["value"],
                         0.65)
        self.assertEqual(
            champion["normalized_stats"]["attack_speed"]["delay_cast_offset_percent"]
            ["source_container_field"],
            "basicAttack",
        )
        self.assertEqual(champion["normalized_stats"]["resources"]["primary"]["base"]["value"],
                         345.0)
        self.assertNotIn("attack_speed.ratio", champion["missing_fields"])
        self.assertIn("resources.secondary.base", champion["missing_fields"])
        self.assertEqual(len(report["source_hashes"]["champion_wads"]), 1)
        self.assertTrue(all(value is False for value in report["protected_holdout"].values()))

    def test_build_metadata_mismatch_fails_before_wad_enumeration(self):
        with tempfile.TemporaryDirectory() as temporary:
            game_root = pathlib.Path(temporary)
            hashes = create_fixture(game_root, "16.17.1.1")
            with self.assertRaisesRegex(RuntimeError, "exact build metadata mismatch"):
                EXTRACTOR.build_report(game_root, hashes, "16.16.805.0442", FakeApi)
        self.assertEqual(FakeWad.opened, [])

    def test_localized_wads_are_not_enumerated_or_hashed(self):
        with tempfile.TemporaryDirectory() as temporary:
            game_root = pathlib.Path(temporary)
            create_fixture(game_root)
            rows = EXTRACTOR.enumerate_nonlocalized_wads(game_root)
        self.assertEqual([path.name for path in rows], ["Aatrox.wad.client"])

    def test_direct_and_realpath_holdout_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            direct = root / "Protected_Holdout" / "game"
            with self.assertRaisesRegex(ValueError, "Holdout paths are prohibited"):
                EXTRACTOR.reject_holdout(direct)
            target = root / "synthetic-Holdout-target"
            target.mkdir()
            alias = root / "safe-alias"
            try:
                alias.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlink/junction unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "realpath resolves"):
                EXTRACTOR.reject_holdout(alias)

    def test_output_is_deterministic_for_identical_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            game_root = pathlib.Path(temporary)
            hashes = create_fixture(game_root)
            first = EXTRACTOR.build_report(game_root, hashes, "16.16.805.442", FakeApi)
            second = EXTRACTOR.build_report(game_root, hashes, "16.16.805.442", FakeApi)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )


if __name__ == "__main__":
    unittest.main()
