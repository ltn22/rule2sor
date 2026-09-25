import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pycoreconf import CORECONFModel

from rule2sor.gen_rulemanager import RuleManager


ROOT = Path(__file__).parents[1]
SID = str(ROOT / "rule2sor" / "ietf-schc@2026-09-22.sid")
FIXTURE = ROOT / "fixtures" / "example.json"


def convert(document):
    manager = RuleManager()
    manager.Add(dev_info=document)
    manager.add_sid_file(SID)
    return CORECONFModel(SID).decode(manager.to_coreconf(), as_rfc7951=True)


def compression_rule(rule_id=1, rule_length=3, entries=None, **extra):
    rule = {
        "RuleID": rule_id,
        "RuleIDLength": rule_length,
        "Compression": entries or [
            {"FID": "IPV6.VER", "FL": 4, "TV": 6,
             "MO": "equal", "CDA": "not-sent"},
        ],
    }
    rule.update(extra)
    return rule


class CurrentModelTests(unittest.TestCase):
    def test_bundled_sid_uses_current_authoritative_assignments(self):
        with open(SID) as sid_file:
            sid_file_data = json.load(sid_file)["ietf-sid-file:sid-file"]
        items = {
            (item["namespace"], item["identifier"]): item["sid"]
            for item in sid_file_data["item"]
        }
        self.assertEqual(items[("data", "/ietf-schc:context")], 2801)
        self.assertEqual(items[("data", "/ietf-schc:schc")], 2800)
        self.assertEqual(items[("data", "/ietf-schc:schc/rule")], 2823)
        self.assertEqual(items[("identity", "cda-compress-sent")], 2631)
        self.assertEqual(sid_file_data["key-mapping"], {
            "2823": [2825, 2824],
            "2846": [2847],
            "2855": [2856],
            "2859": [2860],
            "2863": [2864],
            "2893": [2894],
        })

    def test_ordinary_compression_and_ordered_universal_entries(self):
        decoded = convert(compression_rule(
            rule_id=7,
            rule_length=5,
            entries=[
                {"FID": "IPV6.VER", "FL": 4, "TV": 6,
                 "MO": "equal", "CDA": "not-sent"},
                {"FID": "UDP.DEV_PORT", "FL": 16,
                 "MO": "ignore", "CDA": "value-sent"},
            ],
        ))
        rule = decoded["ietf-schc:schc"]["rule"][0]
        self.assertEqual(rule["rule-id-value"], 7)
        self.assertEqual(rule["rule-id-length"], 5)
        self.assertEqual(rule["rule-nature"], "ietf-schc:nature-compression")
        self.assertEqual([e["entry-index"] for e in rule["entry-universal"]], [0, 1])

    def test_management_and_universal_coap_option(self):
        decoded = convert({
            "Context": {"GuardPeriod": {"TicksDuration": 20, "TicksNumbers": 10}},
            "SoR": [compression_rule(
                rule_id=28,
                rule_length=5,
                RuleNature="Management",
                entries=[
                    {"FID": "IPV6.VER", "FL": 4, "TV": 6,
                     "MO": "equal", "CDA": "not-sent"},
                    {"FID": "COAP.URI-PATH", "FL": "var", "TV": "status",
                     "MO": "equal", "CDA": "value-sent"},
                ],
            )],
        })
        rule = decoded["ietf-schc:schc"]["rule"][0]
        self.assertEqual(rule["rule-nature"], "ietf-schc:nature-management")
        option = rule["entry-universal"][1]
        self.assertEqual(option["space-id"], "ietf-schc:space-id-coap")
        self.assertEqual(option["universal-value"], "11")
        self.assertEqual(decoded["ietf-schc:context"]["guard-period"], {
            "ticks-duration": 20, "ticks-numbers": 10,
        })

    def test_all_field_length_forms_and_structured_reference(self):
        cases = [
            ("IPV6.LEN", "var", "fl-variable"),
            ("IPV6.TC", "var_bit", "fl-variable-bits"),
            ("COAP.TOKEN", "tkl", "fl-token-length"),
            ("UDP.LEN", "fl-length-bytes(0)", "fl-length-bytes"),
            ("IPV6.NXT", "fl-length-bits(0)", "fl-length-bits"),
            ("PAYLOAD", "fl-remaining", "fl-remaining"),
        ]
        for fid, field_length, expected in cases:
            with self.subTest(field_length=field_length):
                entry = {"FID": fid, "FL": field_length,
                         "MO": "ignore", "CDA": "value-sent"}
                result = convert(compression_rule(entries=[entry]))[
                    "ietf-schc:schc"]["rule"][0]["entry-universal"][0]
                self.assertEqual(result["field-length"].split(":")[-1], expected)
                if "length-" in expected:
                    self.assertEqual(result["field-length-value"], 0)

        result = convert(compression_rule(entries=[
            {"FID": "IPV6.NXT",
             "FL": {"Function": "length-bits", "EntryIndex": 1},
             "MO": "ignore", "CDA": "value-sent", "EntryIndex": 0},
            {"FID": "IPV6.VER", "FL": 4, "MO": "ignore",
             "CDA": "value-sent", "EntryIndex": 1},
        ]))["ietf-schc:schc"]["rule"][0]["entry-universal"]
        self.assertEqual([entry["entry-index"] for entry in result], [0, 1])
        self.assertEqual(result[0]["field-length-value"], 1)

        with self.assertRaisesRegex(ValueError, "does not name an entry index"):
            convert(compression_rule(entries=[
                {"FID": "IPV6.NXT", "FL": "fl-length-bytes(1)",
                 "MO": "ignore", "CDA": "value-sent"},
            ]))

    def test_forward_and_reverse_matching_and_actions(self):
        decoded = convert(compression_rule(entries=[
            {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "rule-match",
             "CDA": "compress-sent"},
            {"FID": "IPV6.TC", "FL": 8, "TV": 0, "MO": "rev-rule-match",
             "CDA": "rev-compressed-sent"},
        ]))
        entries = decoded["ietf-schc:schc"]["rule"][0]["entry-universal"]
        self.assertEqual(entries[0]["matching-operator"], "ietf-schc:mo-rule-match")
        self.assertEqual(entries[0]["comp-decomp-action"], "ietf-schc:cda-compress-sent")
        self.assertEqual(entries[1]["matching-operator"], "ietf-schc:mo-rev-rule-match")
        self.assertEqual(entries[1]["comp-decomp-action"], "ietf-schc:cda-rev-compress-sent")

    def test_forward_yang_flagbit_identity_mappings(self):
        identities = [
            "fid-coap-option-oscore-flags-flagbits",
            "fid-coap-option-kudos-x-flagbits",
        ]
        sid_path = Path(self._write_identity_sid(identities))
        self.addCleanup(sid_path.unlink)
        manager = RuleManager()
        manager.add_sid_file(str(sid_path))

        self.assertEqual(manager._identity("COAP.OSCORE_FLAGS_FLAGS"),
                         "ietf-schc:fid-coap-option-oscore-flags-flagbits")
        self.assertEqual(manager._identity("COAP.KUDOS_X_FLAGS"),
                         "ietf-schc:fid-coap-option-kudos-x-flagbits")

    def test_explicit_rule_action_is_rejected(self):
        rules = [
            compression_rule(Action="experimental"),
            {"RuleID": 1, "RuleIDLength": 3,
             "NoCompression": [], "Action": "experimental"},
            {"RuleID": 1, "RuleIDLength": 3,
             "NoCompression": [], "Action": None},
        ]
        for rule in rules:
            with self.subTest(rule=rule):
                with self.assertRaisesRegex(ValueError, "Action is not supported"):
                    RuleManager().Add(dev_info=rule)

    def test_overlapping_rule_with_action_is_rejected(self):
        manager = RuleManager()
        manager.Add(dev_info=compression_rule())
        with self.assertRaisesRegex(ValueError, "Action is not supported"):
            manager.Add(dev_info=compression_rule(Action=None))

    @staticmethod
    def _write_identity_sid(identities):
        sid_file = tempfile.NamedTemporaryFile(mode="w", suffix=".sid", delete=False)
        with sid_file:
            json.dump({"ietf-sid-file:sid-file": {"item": [
                {"namespace": "identity", "identifier": identity, "sid": index}
                for index, identity in enumerate(identities, start=1)
            ]}}, sid_file)
        return sid_file.name

    def test_target_value_constraints(self):
        cases = [
            {"MO": "equal", "CDA": "not-sent"},
            {"MO": "ignore", "CDA": "not-sent"},
            {"MO": "match-mapping", "CDA": "mapping-sent", "TV": []},
        ]
        for entry in cases:
            with self.subTest(entry=entry):
                with self.assertRaisesRegex(ValueError, "requires a non-empty TV"):
                    RuleManager().Add(dev_info=compression_rule(entries=[{
                        "FID": "IPV6.VER", "FL": 4, **entry,
                    }]))
        decoded = convert(compression_rule(entries=[{
            "FID": "IPV6.VER", "FL": 4, "MO": "ignore", "CDA": "value-sent",
        }]))
        self.assertNotIn("target-value", decoded["ietf-schc:schc"]["rule"][0]["entry-universal"][0])

        indirect = convert(compression_rule(entries=[{
            "FID": "IPV6.VER", "FL": 4, "MO": "equal",
            "CDA": "not-sent", "TV": {"INDIRECT": 6},
        }]))
        self.assertEqual(indirect["ietf-schc:schc"]["rule"][0][
            "entry-universal"][0]["target-value"][0]["index"], 0)

    def test_negative_integer_target_values_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-negative"):
            convert({
                "RuleID": 1, "RuleIDLength": 3,
                "Compression": [{
                    "FID": "IPV6.VER", "FL": 4, "TV": -1,
                    "MO": "equal", "CDA": "not-sent",
                }],
            })

    def test_coap_end_fid_is_case_insensitive(self):
        decoded = convert({
            "RuleID": 1, "RuleIDLength": 3,
            "Compression": [{"FID": "coap.end"}],
        })
        self.assertEqual(decoded["ietf-schc:schc"]["rule"][0][
            "entry-universal"], [])

    def test_remaining_and_payload_are_final(self):
        with self.assertRaisesRegex(ValueError, "final"):
            RuleManager().Add(dev_info=compression_rule(entries=[
                {"FID": "PAYLOAD", "FL": "fl-remaining", "MO": "ignore", "CDA": "value-sent"},
                {"FID": "IPV6.VER", "FL": 4, "MO": "ignore", "CDA": "value-sent"},
            ]))
        with self.assertRaisesRegex(ValueError, "fid-payload"):
            RuleManager().Add(dev_info=compression_rule(entries=[
                {"FID": "PAYLOAD", "FL": "var", "MO": "ignore", "CDA": "value-sent"},
            ]))
        decoded = convert(compression_rule(entries=[
            {"FID": "IPV6.VER", "FL": 4, "MO": "ignore", "CDA": "value-sent"},
            {"FID": "PAYLOAD", "FL": "fl-remaining", "MO": "ignore", "CDA": "value-sent"},
        ]))
        self.assertEqual(decoded["ietf-schc:schc"]["rule"][0]["entry-universal"][-1]["field-length"],
                         "ietf-schc:fl-remaining")
        default_payload = convert(compression_rule(entries=[{
            "FID": "PAYLOAD", "MO": "ignore", "CDA": "value-sent",
        }]))
        self.assertEqual(default_payload["ietf-schc:schc"]["rule"][0][
            "entry-universal"][0]["field-length"], "ietf-schc:fl-remaining")

    def test_fragmentation_timers_bitmaps_and_optional_fields(self):
        decoded = convert({
            "RuleID": 1, "RuleIDLength": 3,
            "Fragmentation": {"FRMode": "AckOnError", "FRDirection": "UP",
                "FRModeProfile": {"FCNSize": 3,
                    "InactivityTimer": {"TicksDuration": 20, "TicksNumbers": 0},
                    "RetransmissionTimer": {"ticks-duration": 21, "ticks-numbers": 1},
                    "BitmapFormat": "compound-ack", "LastBitmapCompression": False,
                    "MaxInterFrame": 2}},
        })
        rule = decoded["ietf-schc:schc"]["rule"][0]
        self.assertNotIn("tile-size", rule)
        self.assertNotIn("tile-in-all-1", rule)
        self.assertEqual(rule["inactivity-timer"], {"ticks-duration": 20, "ticks-numbers": 0})
        self.assertEqual(rule["retransmission-timer"], {"ticks-duration": 21, "ticks-numbers": 1})
        self.assertEqual(rule["bitmap-format"], "ietf-schc:bitmap-compound-ack")
        self.assertFalse(rule["last-bitmap-compression"])
        self.assertEqual(rule["max-interleaved-frames"], 2)

    def test_fragmentation_ranges_and_kudos_defaults(self):
        for key, value in (("FCNSize", 256), ("dtagSize", -1), ("WSize", 256),
                           ("tileSize", 256), ("maxRetry", 0), ("MaxPcktSize", 65536)):
            with self.subTest(key=key):
                profile = {"FCNSize": 3, "tileSize": 1}
                profile[key] = value
                with self.assertRaises(ValueError):
                    RuleManager().Add(dev_info={"RuleID": 1, "RuleIDLength": 3,
                        "Fragmentation": {"FRMode": "AckOnError", "FRDirection": "UP",
                            "FRModeProfile": profile}})
        decoded = convert(compression_rule(entries=[
            {"FID": "COAP.KUDOS_X", "MO": "ignore", "CDA": "value-sent"},
            {"FID": "COAP.KUDOS_X_FLAGS", "MO": "ignore", "CDA": "value-sent"},
            {"FID": "COAP.KUDOS_X_M", "MO": "ignore", "CDA": "value-sent"},
        ]))
        entries = decoded["ietf-schc:schc"]["rule"][0]["entry-universal"]
        self.assertEqual([e["field-length"] for e in entries], [8, 4, 4])

    def test_guard_period_absent_present_defaults_and_bounds(self):
        without_context = convert(compression_rule())
        self.assertNotIn("ietf-schc:context", without_context)
        self.assertEqual(convert({"Context": {}, "SoR": [compression_rule()]})[
            "ietf-schc:context"], {})
        self.assertEqual(convert({"Context": {"GuardPeriod": {}},
                                  "SoR": [compression_rule()]})[
            "ietf-schc:context"]["guard-period"], {})
        bounds = convert({"Context": {"GuardPeriod": {
            "TicksDuration": 255, "TicksNumbers": 65535,
        }}, "SoR": [compression_rule()]})
        self.assertEqual(bounds["ietf-schc:context"]["guard-period"], {
            "ticks-duration": 255, "ticks-numbers": 65535,
        })
        for guard in ({"TicksDuration": -1}, {"TicksDuration": 256},
                      {"TicksNumbers": -1}, {"TicksNumbers": 65536}):
            with self.subTest(guard=guard):
                with self.assertRaises(ValueError):
                    convert({"Context": {"GuardPeriod": guard},
                             "SoR": [compression_rule()]})

    def test_context_rejects_unknown_members_and_non_integer_ticks(self):
        invalid_contexts = [
            {"Unexpected": {}},
            {"GuardPeriod": {"Unexpected": 1}},
        ]
        for context in invalid_contexts:
            with self.subTest(context=context):
                with self.assertRaises(ValueError):
                    convert({"Context": context, "SoR": [compression_rule()]})

        for member in ("TicksDuration", "TicksNumbers"):
            for value in (1.5, "1", True):
                with self.subTest(member=member, value=value):
                    with self.assertRaises(ValueError):
                        convert({"Context": {"GuardPeriod": {member: value}},
                                 "SoR": [compression_rule()]})

    def test_rule_nature_combinations_are_rejected(self):
        fragment = {
            "RuleID": 1, "RuleIDLength": 3, "RuleNature": "Compression",
            "Fragmentation": {"FRMode": "NoAck", "FRDirection": "UP",
                               "FRModeProfile": {}},
        }
        with self.assertRaisesRegex(ValueError, "Fragmentation cannot"):
            RuleManager().Add(dev_info=fragment)
        with self.assertRaisesRegex(ValueError, "NoCompression cannot"):
            RuleManager().Add(dev_info={
                "RuleID": 1, "RuleIDLength": 3, "RuleNature": "Compression",
                "NoCompression": [],
            })
        with self.assertRaisesRegex(ValueError, "exactly one"):
            RuleManager().Add(dev_info={
                "RuleID": 1, "RuleIDLength": 3,
                "Compression": [], "NoCompression": [],
            })
        with self.assertRaisesRegex(ValueError, "Unknown RuleNature"):
            RuleManager().Add(dev_info=compression_rule(RuleNature="other"))

    def test_no_compression_and_basic_fragmentation(self):
        decoded = convert({"RuleID": 2, "RuleIDLength": 3, "NoCompression": []})
        self.assertEqual(decoded["ietf-schc:schc"]["rule"][0]["rule-nature"],
                         "ietf-schc:nature-no-compression")

        decoded = convert({
            "RuleID": 1, "RuleIDLength": 3,
            "Fragmentation": {"FRMode": "NoAck", "FRDirection": "UP",
                               "FRModeProfile": {}},
        })
        rule = decoded["ietf-schc:schc"]["rule"][0]
        self.assertEqual(rule["fragmentation-mode"],
                         "ietf-schc:fragmentation-mode-no-ack")
        self.assertEqual(rule["fcn-size"], 1)
        self.assertEqual(rule["dtag-size"], 0)
        self.assertNotIn("w-size", rule)

        for mode in ("AckAlways", "AckOnError"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(ValueError, "FCNSize must be specified"):
                    RuleManager().Add(dev_info={
                        "RuleID": 1, "RuleIDLength": 3,
                        "Fragmentation": {"FRMode": mode, "FRDirection": "UP",
                                           "FRModeProfile": {}},
                    })

        with self.assertRaisesRegex(ValueError, "scalar timeout"):
            RuleManager().Add(dev_info={
                "RuleID": 1, "RuleIDLength": 3,
                "Fragmentation": {"FRMode": "AckAlways", "FRDirection": "UP",
                                   "FRModeProfile": {"FCNSize": 3, "timeout": 600}},
            })

    def test_ack_on_error_serializes_last_tile_in_all1(self):
        decoded = convert({
            "RuleID": 1, "RuleIDLength": 3,
            "Fragmentation": {
                "FRMode": "AckOnError", "FRDirection": "UP",
                "FRModeProfile": {
                    "FCNSize": 3, "tileSize": 9, "lastTileInAll1": False,
                },
            },
        })
        rule = decoded["ietf-schc:schc"]["rule"][0]
        self.assertEqual(rule["tile-in-all-1"], "ietf-schc:all-1-data-no")

        decoded = convert({
                "RuleID": 1, "RuleIDLength": 3,
                "Fragmentation": {
                    "FRMode": "AckOnError", "FRDirection": "UP",
                    "FRModeProfile": {
                        "FCNSize": 3, "tileSize": 9, "lastTileInAll1": True,
                    },
                },
            })
        self.assertEqual(decoded["ietf-schc:schc"]["rule"][0]["tile-in-all-1"],
                         "ietf-schc:all-1-data-yes")

    def test_ack_on_error_rejects_non_bool_last_tile_in_all1(self):
        for value in ("false", 0, None, 1):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "lastTileInAll1"):
                    RuleManager().Add(dev_info={
                        "RuleID": 1, "RuleIDLength": 3,
                        "Fragmentation": {
                            "FRMode": "AckOnError", "FRDirection": "UP",
                            "FRModeProfile": {
                                "FCNSize": 3, "tileSize": 9,
                                "lastTileInAll1": value,
                            },
                        },
                    })

    def test_rule_id_validation_and_prefix_ambiguity(self):
        invalid = [
            {"RuleID": True, "RuleIDLength": 1},
            {"RuleID": 0, "RuleIDLength": True},
            {"RuleID": 0, "RuleIDLength": -1},
            {"RuleID": 0, "RuleIDLength": 33},
            {"RuleID": 2, "RuleIDLength": 1},
            {"RuleID": -1, "RuleIDLength": 3},
            {"RuleID": 1, "RuleIDLength": 0},
        ]
        for ids in invalid:
            with self.subTest(ids=ids):
                with self.assertRaises(ValueError):
                    RuleManager().Add(dev_info={**ids, "Compression": []})

        zero = convert(compression_rule(rule_id=0, rule_length=0))
        self.assertEqual(zero["ietf-schc:schc"]["rule"][0]["rule-id-length"], 0)

        first = compression_rule(rule_id=0, rule_length=1)
        second = compression_rule(rule_id=1, rule_length=2)
        manager = RuleManager()
        with contextlib.redirect_stdout(io.StringIO()):
            manager.Add(dev_info=[first, second])
        self.assertEqual(len(manager._ctxt[0]["SoR"]), 1)

    def test_explicit_entry_index_order_uniqueness_and_range(self):
        entries = [
            {"FID": "IPV6.VER", "FL": 4, "MO": "ignore", "CDA": "value-sent",
             "EntryIndex": 0},
            {"FID": "IPV6.TC", "FL": 8, "MO": "ignore", "CDA": "value-sent",
             "EntryIndex": 1},
        ]
        decoded = convert(compression_rule(entries=entries))
        self.assertEqual([e["entry-index"] for e in decoded["ietf-schc:schc"]["rule"][0][
            "entry-universal"]], [0, 1])
        for bad in (65536, -1, True, "7"):
            with self.subTest(index=bad):
                with self.assertRaisesRegex(ValueError, "EntryIndex"):
                    RuleManager().Add(dev_info=compression_rule(entries=[
                        {"FID": "IPV6.VER", "FL": 4, "MO": "ignore",
                         "CDA": "value-sent", "EntryIndex": bad},
                        {"FID": "IPV6.TC", "FL": 8, "MO": "ignore",
                         "CDA": "value-sent", "EntryIndex": 7},
                    ]))
        with self.assertRaisesRegex(ValueError, "EntryIndex"):
            RuleManager().Add(dev_info=compression_rule(entries=[
                {"FID": "IPV6.VER", "FL": 4, "MO": "ignore",
                 "CDA": "value-sent", "EntryIndex": 0},
                {"FID": "IPV6.TC", "FL": 8, "MO": "ignore",
                 "CDA": "value-sent", "EntryIndex": 0},
            ]))
        with self.assertRaisesRegex(ValueError, "EntryIndex"):
            RuleManager().Add(dev_info=compression_rule(entries=[
                {"FID": "IPV6.VER", "FL": 4, "MO": "ignore",
                 "CDA": "value-sent", "EntryIndex": 1},
                {"FID": "IPV6.TC", "FL": 8, "MO": "ignore",
                 "CDA": "value-sent", "EntryIndex": 2},
            ]))

    def test_field_position_and_direction_validation(self):
        for fp in (-1, 256, 1.5, True):
            with self.subTest(fp=fp):
                with self.assertRaisesRegex(ValueError, "FP"):
                    RuleManager().Add(dev_info=compression_rule(entries=[
                        {"FID": "IPV6.VER", "FL": 4, "FP": fp,
                         "MO": "ignore", "CDA": "value-sent"},
                    ]))
        for direction in ("", "up", "DOWN", "INVALID", None):
            with self.subTest(direction=direction):
                with self.assertRaisesRegex(ValueError, "DI"):
                    RuleManager().Add(dev_info=compression_rule(entries=[
                        {"FID": "IPV6.VER", "FL": 4, "DI": direction,
                         "MO": "ignore", "CDA": "value-sent"},
                    ]))

    def test_collection_over_255_entries(self):
        entries = [{"FID": "IPV6.VER", "FL": 4, "MO": "ignore",
                    "CDA": "value-sent"} for _ in range(260)]
        decoded = convert(compression_rule(rule_id=1, rule_length=8, entries=entries))
        output = decoded["ietf-schc:schc"]["rule"][0]["entry-universal"]
        self.assertEqual(len(output), 260)
        self.assertEqual(output[-1]["entry-index"], 259)

    def test_fixture_and_cli_default_and_custom_sid(self):
        with FIXTURE.open() as fixture_file:
            fixture = json.load(fixture_file)
        decoded = convert(fixture)
        self.assertEqual(len(decoded["ietf-schc:schc"]["rule"]), 3)
        self.assertIn("ietf-schc:context", decoded)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            input_file = temp / "fixture.json"
            shutil.copyfile(FIXTURE, input_file)
            default_result = subprocess.run(
                [sys.executable, "-m", "rule2sor.cli", str(input_file), "-q"],
                cwd=ROOT, capture_output=True, text=True, check=True,
            )
            self.assertIn("fixture.sor written", default_result.stdout)
            self.assertTrue((temp / "fixture.sor").exists())

            custom_output = temp / "custom.sor"
            subprocess.run(
                [sys.executable, "-m", "rule2sor.cli", str(input_file), "-q",
                 "-s", SID, "-o", str(custom_output)],
                cwd=ROOT, capture_output=True, text=True, check=True,
            )
            self.assertEqual(
                CORECONFModel(SID).decode(custom_output.read_bytes(), as_rfc7951=True),
                decoded,
            )

    def test_context_does_not_leak_between_documents(self):
        manager = RuleManager()
        manager.Add(dev_info={"Context": {"GuardPeriod": {"TicksDuration": 1}},
                              "SoR": [compression_rule()]})
        manager.Add(dev_info=compression_rule(rule_id=2))
        manager.add_sid_file(SID)
        decoded = CORECONFModel(SID).decode(manager.to_coreconf(), as_rfc7951=True)
        self.assertNotIn("ietf-schc:context", decoded)


if __name__ == "__main__":
    unittest.main()
