"""Tests for check_private_reveal_policies.py: it passes on specification 10
and fails when any payload, binding, trace, permutation count, proof-length
bound, gas constant, worked fee or formula of it is damaged."""

import contextlib
import importlib.util
import io
import json
import re
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = ROOT / "docs" / "spec" / "10-private-reveal-policies.md"
RECORD = ROOT / "docs" / "benchmarks" / "reveal-parameters.md"
STARK = ROOT / "proofs" / "src" / "stark.rs"

_spec = importlib.util.spec_from_file_location("check_private_reveal_policies",
                                               HERE / "check_private_reveal_policies.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)

# (old text, damaged text, a fragment of the gap it must raise). Each old
# text occurs exactly once in the specification.
STRUCTURE = (
    ("## 10. Gas constants and fees", "## 10. Gas", "contains 'Gas constants and fees'"),
    ("## 12. Ghost Guard", "## 13. Ghost Guard", "sections are numbered"),
    ("## 14. Properties", "## Properties", "is not numbered"),
    ("### 10.2 The verification charge", "### The verification charge", "no subsection '### 10.2"),
)
NOTE = (
    ("zero pad (10)", "zero pad (11)", "capsule fields are"),
    ("`NOTE_BYTES = 12 + 352 + 16 = 380`", "`NOTE_BYTES = 12 + 352 + 16 = 381`",
     "section 3.2: NOTE_BYTES is 381"),
    ("| Notes | 380 bytes", "| Notes | 381 bytes", "section 1: note is 381"),
    ("plaintext (352) =", "plaintext (353) =", "section 3.2: plaintext is 353"),
    ("215 bytes, two Keccak blocks", "216 bytes, two Keccak blocks", "rule hash input is 216"),
    ("215 bytes, two Keccak blocks", "215 bytes, one Keccak blocks",
     "rule Keccak blocks is 'one'"),
    ('rule = K("ghost/reveal-policy/v2",', 'rule = K("ghost/reveal-policy/v3",', "rule tag is"),
)
PAYLOADS = (
    ("The payload is 1,311,290 bytes", "The payload is 1,311,289 bytes",
     "section 4.1: payload is 1311289"),
    ("+ 32 + 1,310,720 + 380 = 1,311,290", "+ 32 + 1,310,720 + 156 = 1,311,290",
     "section 4.1: payload terms"),
    ("ENVELOPE_BYTES = 1,311,291", "ENVELOPE_BYTES = 1,311,290",
     "section 4.1: ENVELOPE_BYTES is 1311290"),
    ("| 170 | 20 | `policy_address` | The frozen policy |",
     "| 170 | 32 | `policy_address` | The frozen policy |",
     "field 'policy_address' is 32 bytes, expected 20"),
    ("Payload 1,311,450 bytes", "Payload 1,311,451 bytes", "section 5.1: payload is 1311451"),
    ("| 318 | 32 | `instr` | A 32-byte payout instruction, bound but not read by the chain |\n",
     "", "section 5.1 payload: fields are"),
    ("| 1,148 | 948,224 | `proof` |", "| 1,148 | 947,283 | `proof` |",
     "field 'proof' is 947283 bytes, expected 948224"),
    ("Payload 949,372 bytes", "Payload 949,371 bytes", "section 8.1: payload is 949371"),
    ("| 124 | 1,024 | `calldata` |", "| 124 | 512 | `calldata` |",
     "field 'calldata' is 512 bytes, expected 1024"),
)
BINDINGS = (
    ("Total: 607 bytes after the tag", "Total: 606 bytes after the tag",
     "section 4.2 binding: bytes after the tag is 606"),
    ("636 with the 29-byte tag", "636 with the 28-byte tag", "tag bytes is 28"),
    ("29-byte tag, five Keccak", "29-byte tag, four Keccak",
     "section 4.2 binding: permutations is 'four'"),
    ("(four today)", "(three today)", "version 1 binding permutations"),
    ("and the 32-byte digest: 639 bytes", "and the 32-byte digest: 640 bytes",
     "public values is 640"),
    ("| 195 | 32 | `fee` | Amount word |", "| 195 | 20 | `fee` | Amount word |",
     "field 'fee' is 20 bytes, expected 32"),
    ("| 43 | 1 | `statement_version` | `0x02` |", "| 43 | 1 | `statement_version` | `0x01` |",
     "statement_version is 0x01, expected 0x02"),
    ('`binding = K("ghost/coin-reveal-binding/v2", fields)`',
     '`binding = K("ghost/coin-reveal-binding/v3", fields)`', "section 4.2 binding: tag is"),
    ("| 387 | 380 | `remainder_note` | |", "| 387 | 156 | `remainder_note` | |",
     "field 'remainder_note' is 156 bytes, expected 380"),
    ("31-byte tag, six permutations", "31-byte tag, five permutations",
     "section 5.1 binding: permutations is 'five'"),
    ("| 42 | 1 | `statement` | `0x04` |", "| 42 | 1 | `statement` | `0x03` |",
     "statement is 0x03, expected 0x04"),
    ("Public values: 767 plus", "Public values: 766 plus", "public binding bytes is 766"),
    ("Total: 273 bytes after the tag", "Total: 272 bytes after the tag",
     "section 8.2 binding: bytes after the tag is 272"),
    ("| 44 | 1 | `purpose` (`0x06`) |", "| 44 | 1 | `purpose` (`0x07`) |",
     "purpose is 0x07, expected 0x06"),
    ("one permutation, 87 bytes of input", "one permutation, 86 bytes of input",
     "A1 input is 86"),
    ("**A3.** The binding (three permutations)", "**A3.** The binding (two permutations)",
     "A3 permutations is 'two'"),
    ("`purpose = 0x06`.", "`purpose = 0x07`.", "A4 codes"),
    ("161 bytes, 187 with the tag", "160 bytes, 187 with the tag",
     "section 9.2: binding bytes is 160"),
    ("`context (64)`;", "`context (32)`;", "section 9.2 binding: fields are"),
    ("| `KNOW_PREIMAGE_v1` | `0x06` |", "| `KNOW_PREIMAGE_v1` | `0x05` |",
     "codes of `KNOW_PREIMAGE_v1`"),
)
TRACES = (
    ("| `B` (binding) | 5 |", "| `B` (binding) | 4 |", "section 4.4: permutations per hash"),
    ("| Total | 47 |", "| Total | 46 |", "section 4.4: total permutations is 46"),
    ("Four more than the 43", "Three more than the 43", "permutations added is 'Three'"),
    ("| `OV` (override) | 1 | 57 bytes of input |", "| `OV` (override) | 1 | 58 bytes of input |",
     "section 4.4: input of OV is 58"),
    ("go from 102 to 168", "go from 102 to 170", "section 4.4: carried columns is 170"),
    ("`Sinv` (1)", "`Sinv` (2)", "section 4.4: new carried columns"),
    ("**3,890 columns**", "**3,891 columns**", "section 4.4: width is 3891"),
    ("1,128 rows, padded", "1,129 rows, padded", "section 4.4: rows is 1129"),
    ("goes from 3,824 to 3,890", "goes from 3,824 to 3,856", "section 4.4: MAX_TRACE_WIDTH is"),
    ("about 0.025 bit", "about 0.25 bit", "estimator shift"),
    ("134 in all", "135 in all", "section 5.4: carried column total is 135"),
    ("`B` 6; 47", "`B` 5; 47", "section 5.4: permutations per hash"),
    ("**3,856**", "**3,857**", "section 5.4: width is 3857"),
    ("Four permutations, 96 rows", "Five permutations, 96 rows",
     "section 8.2: permutations is 'Five'"),
    ("96 rows, padded to 128", "96 rows, padded to 256", "section 8.2: padded rows is 256"),
    ("Three permutations, 72 rows", "Four permutations, 72 rows",
     "section 9.2: permutations is 'Four'"),
    ("72 rows, padded to 128", "72 rows, padded to 64", "section 9.2: padded rows is 64"),
    ("| `MAX_TRACE_WIDTH` | 3,890 |", "| `MAX_TRACE_WIDTH` | 3,856 |",
     "constant MAX_TRACE_WIDTH is 3856"),
)
BOUNDS = (
    ("| 2,048 | 3,890 | 1,070,715 |", "| 2,048 | 3,890 | 1,070,716 |",
     "S1 version 2 proof_length_bound is 1070716"),
    ("| 128 | 3,722 | 947,283 |", "| 128 | 3,722 | 947,282 |",
     "Small statements proof_length_bound is 947282"),
    ("| 2,048 | 3,856 | 1,063,507 |", "| 2,048 | 3,890 | 1,063,507 |",
     "Policy class rows and columns"),
    ("| 2,048 | 3,824 | 1,056,723 |", "| 2,048 | 3,824 | 1,056,722 |",
     "S1 version 1 proof_length_bound is 1056722"),
    ("947,283, rounded", "947,000, rounded", "section 8.1: small statement bound is 947000"),
    ("| `ACTION_PROOF_BYTES` | 948,224 |", "| `ACTION_PROOF_BYTES` | 947,283 |",
     "constant ACTION_PROOF_BYTES is 947283"),
    ("`ceil(947,283 / 1,024) * 1,024`", "`ceil(947,283 / 1,024) * 1,000`",
     "the formula of ACTION_PROOF_BYTES gives"),
)
VERIFICATION = (
    ("is **10.61 ms**", "is **10.50 ms**", "section 10.2: recorded slowest ms"),
    ("= 10.79 ms", "= 10.80 ms", "section 10.2: scaled slowest"),
    ("->  107,900 gas", "->  107,000 gas", "section 10.2: scaled gas is 107000"),
    ("estimate = 110,000", "estimate = 100,000", "section 10.2: estimate is 100000"),
    ("| `S4` | 1,000 | 1,000 | 43.99 | 440,000 |", "| `S4` | 999 | 1,000 | 43.99 | 440,000 |",
     "fewer than 1,000"),
    ("| `S4` | 1,000 | 1,000 | 43.99 | 440,000 |", "| `S4` | 1,000 | 1,000 | 43.98 | 440,000 |",
     "section 10.2: `S4` slowest ms"),
    ("| `S4` | 1,000 | 1,000 | 43.99 | 440,000 |", "| `S4` | 1,000 | 1,000 | 43.99 | 430,000 |",
     "section 10.2: `S4` charge"),
    ("| `KNOW_ACTION_v1` | 1,000 | 1,000 | 42.71 | 430,000 |\n", "",
     "the measurement has no row for `KNOW_ACTION_v1`"),
    ("raised to 370,000, 440,000 and 430,000 gas", "raised to 370,000, 430,000 and 430,000 gas",
     "section 17: measured charges"),
    ("10.61 ms * (3,890 / 3,824)", "10.61 ms * (3,856 / 3,824)", "section 10.2: width ratio"),
    ("exceeds 11.0 ms (110,000 gas)", "exceeds 12.0 ms (110,000 gas)",
     "section 10.2: threshold ms"),
    ("exceeds 11.0 ms (110,000 gas)", "exceeds 11.0 ms (120,000 gas)",
     "section 10.2: threshold gas"),
    ("`VERIFY_GAS_DATA = 92,300`", "`VERIFY_GAS_DATA = 92,000`", "VERIFY_GAS_DATA is 92000"),
    ("measures at least 1,000 verifications", "measures at least 100 verifications",
     "fewer than 1,000"),
    ("| `VERIFY_GAS_ORD` | 370,000 |", "| `VERIFY_GAS_ORD` | 360,000 |",
     "constant VERIFY_GAS_ORD is 360000"),
    ("`PREIMAGE_VERIFY_GAS = 430,000`", "`PREIMAGE_VERIFY_GAS = 110,000`",
     "PREIMAGE_VERIFY_GAS is 110000"),
    ("10.61 ms in nine runs", "10.61 ms in eight runs", "section 2: runs"),
    ("10.61 ms in nine runs", "10.60 ms in nine runs", "section 2: recorded slowest ms"),
    ("from the recorded 10.61 ms (section 10.2) and", "from the recorded 10.62 ms (section 10.2) and",
     "section 15: recorded slowest ms"),
    ("110,000 gas for each new statement", "100,000 gas for each new statement",
     "section 17: verification charge"),
    ("`GAS_PER_MS = 10,000`", "`GAS_PER_MS = 12,000`", "section 10.1: GAS_PER_MS is 12000"),
    ("`BYTE_GAS = 16`", "`BYTE_GAS = 8`", "section 10.1: BYTE_GAS is 8"),
)
GAS = (
    ("| `G_PRIV` | 21,371,656 |", "| `G_PRIV` | 21,371,657 |",
     "constant G_PRIV is 21371657, recomputed 21371656"),
    ("| `G_POLICY` | 21,604,216 |", "| `G_POLICY` | 21,604,215 |",
     "constant G_POLICY is 21604215, recomputed 21604216"),
    ("| `G_ACTION` | 15,905,968 |", "| `G_ACTION` | 15,905,967 |",
     "constant G_ACTION is 15905967, recomputed 15905968"),
    ("+ 440,000 + 160,000` |", "+ 440,000 + 150,000` |", "the formula of G_POLICY gives"),
    ("| `ACTION_CALL_GAS` | 250,000 |", "| `ACTION_CALL_GAS` | 200,000 |",
     "the table's own entries give"),
    ("| `SLOT_OPEN_GAS` | 160,000 |", "| `SLOT_OPEN_GAS` | 140,000 |",
     "constant SLOT_OPEN_GAS is 140000"),
    ("| `ACTION_STATE_GAS` | 15,000 |", "| `ACTION_STATE_GAS` | 10,000 |",
     "constant ACTION_STATE_GAS is 10000"),
    ("| `ORD_ENVELOPE_BYTES` | 1,311,291 |", "| `ORD_ENVELOPE_BYTES` | 1,311,067 |",
     "constant ORD_ENVELOPE_BYTES is 1311067"),
    ("`G_ACTION` 15,905,968;", "`G_ACTION` 15,905,969;", "section 1: gas"),
    ("92,300 = 21,090,372`", "92,300 = 21,090,373`", "section 10.5: G_DATA is 21090373"),
    ("payload stays 1,311,066 bytes", "payload stays 1,311,290 bytes",
     "section 10.5: data payload is 1311290"),
    ("| `ORD_TX_TYPE`, `ORD_TX_VERSION` | `0x50`, `0x0002` |",
     "| `ORD_TX_TYPE`, `ORD_TX_VERSION` | `0x51`, `0x0002` |", "transaction types"),
    ("| `REGISTRY_GAS` | 40,000 |", "| `REGISTRY_FEE` | 40,000 |",
     "the tables lack ['REGISTRY_GAS']"),
    ("`ESCROW_NATIVES = 0x0000000000000000000000000000000000000060`",
     "`ESCROW_NATIVES = 0x0000000000000000000000000000000000000063`",
     "section 7.2: ESCROW_NATIVES"),
    ("| `HOLD_BLOCKS`, `HOLD_SECONDS` | 8,640, 259,200 |",
     "| `HOLD_BLOCKS`, `HOLD_SECONDS` | 8,641, 259,200 |", "constant HOLD_BLOCKS is 8641"),
    ("| `FEE_WINDOW`, `FEE_STEPS`, `TIP_DIVISOR` | 4, 1, 10 |",
     "| `FEE_WINDOW`, `FEE_STEPS`, `TIP_DIVISOR` | 4, 2, 10 |", "constant FEE_STEPS is 2"),
    ("| `FEE_WINDOW`, `FEE_STEPS`, `TIP_DIVISOR` | 4, 1, 10 |",
     "| `FEE_WINDOW`, `FEE_STEPS`, `TIP_DIVISOR` | 4, 2, 10 |", "section 10.3: price is"),
    ("| `PEER_FAIL_LIMIT` | 3 |", "| `PEER_FAIL_LIMIT` | 4 |", "section 11: PEER_FAIL_LIMIT"),
)
FEES = (
    ("price = 1,125,050,001", "price = 1,125,050,000", "section 10.3: price is 1125050000"),
    ("[window-genesis-policy]", "[window-genesis-other]",
     "no worked example [window-genesis-policy]"),
    ("rises by 348,104,420,929,412 wei", "rises by 348,104,420,929,413 wei",
     "section 10.3: fee rise is"),
    ("version 1's\n26,100,495,343,659,410", "version 1's\n26,100,495,343,659,411",
     "section 10.3: version 1 fee is"),
    ("(about 1.3 percent)", "(about 1.4 percent)", "fee rise percent"),
    ("= 15,905,968,000,000,000` wei", "= 15,905,968,000,000,001` wei",
     "section 10.3: lowest debit is"),
    ("about 0.0159 GHOST", "about 0.0158 GHOST", "lowest debit in GHOST"),
    ("`G_ACTION` is 15.9 million", "`G_ACTION` is 15.8 million", "G_ACTION in millions"),
    ("is 37.3 million", "is 37.4 million", "G_ACTION + G_PRIV in millions"),
    ("are 31.8 million", "are 31.7 million", "two actions in millions"),
    ("`MaxBytes = 16 * 1,311,451 = 20,983,216`", "`MaxBytes = 16 * 1,311,291 = 20,980,656`",
     "section 11: MaxBytes envelope"),
    ("= 7,594,984`", "= 7,594,985`", "section 11: MaxActionBytes is"),
)
SLOTS = (
    ("| 3 | `action_debits` (12), `forfeited` (12) | 24 |",
     "| 3 | `action_debits` (12), `forfeited` (12) | 32 |", "word 3 holds 24 bytes"),
    ("`SLOT_OPEN_GAS = 8 * 20,000 = 160,000`", "`SLOT_OPEN_GAS = 7 * 20,000 = 140,000`",
     "SLOT_OPEN_GAS words is 7"),
    ("| 7 | `instr` | 32 |\n", "", "section 7.1: slot words"),
    ("16 gas each (6,848)", "16 gas each (6,080)", "recommit byte gas is 6080"),
    ("`note (380)`", "`note (156)`", "section 7.2: recommit note is 156"),
    ("`ACTION_CALL_GAS = 250,000`", "`ACTION_CALL_GAS = 200,000`",
     "section 8.4: ACTION_CALL_GAS"),
    ("`REGISTRY_GAS = 40,000`", "`REGISTRY_GAS = 20,000`", "section 6.1: REGISTRY_GAS"),
    ("`S` is at most 8,160", "`S` is at most 8,192", "largest byte sum S"),
    ("(72 hours at 30", "(48 hours at 30", "hold hours and block time"),
    ("`HOLD_BLOCKS = 8,640`", "`HOLD_BLOCKS = 8,000`", "section 12: HOLD_BLOCKS is 8000"),
    ("72 hour and 8,640 block hold", "72 hour and 8,000 block hold", "section 1: hold"),
)
PROPERTIES = (
    ("- **RP-3. ", "- **RP-31. ", "properties are numbered"),
    ("Test: RP-25, RP-26.", "Test: RP-25, RP-26, RP-99.", "RP-99 is cited but not defined"),
    ("still takes `G_DATA`.", "still takes its gas.", "RP-24 does not fix"),
)
FORMULAS = (
    ("+ 15,000 + 250,000 = 15,905,968", "+ 15,000 + 250,000 = 15,905,969",
     "section 19: G_ACTION: '15,905,969' is 15905969"),
    ("16*1,311,291 + 21,000 + 370,000 = 21,371,656", "16*1,311,291 + 21,000 + 360,000 = 21,371,656",
     "section 19: G_PRIV: '16*1,311,291 + 21,000 + 360,000' is"),
    ("+ 440,000 + 160,000 = 21,604,216", "+ 440,000 + 160,000 = 21,604,217",
     "section 19: G_POLICY"),
    ("1+20+32+32+32+32+1+64+10", "1+20+32+32+32+32+1+64+11", "section 19: capsule"),
    ("12 + (128 + 224) + 16 = 380", "12 + (128 + 224) + 16 = 381", "section 19: NOTE_BYTES"),
    ("+ 1,310,720 + 380 = 1,311,450", "+ 1,310,720 + 380 = 1,311,451",
     "section 19: POLICY_PAYLOAD"),
    ("+1,024 + 948,224 = 949,372", "+1,024 + 947,283 = 949,372", "section 19: ACTION_PAYLOAD"),
    ("+32+20+32+32+380 = 607", "+32+20+32+32+156 = 607", "section 19: ordinary binding"),
    ("+32+32+32+32+380 = 767", "+32+32+32+32+380 = 768", "section 19: policy binding"),
    ("+8+32 = 273", "+8+32 = 274", "section 19: action binding"),
    ("2,633 + 1,088 + 1 + carried", "2,633 + 1,088 + 2 + carried", "section 19: trace width"),
    ("16*1,311,067 + 21,000 + 92,300 = 21,090,372", "16*1,311,067 + 21,000 + 92,300 = 21,090,371",
     "section 19: G_DATA"),
    ("floor((767+31)/136) + 1 = 6", "ceil((767+31)/136) = 6", "is not floor(binding"),
    ("floor((273+24)/136) + 1 = 3", "floor((273+23)/136) + 1 = 3", "is not floor(binding"),
    ("floor((607+29)/136) + 1 = 5", "floor((607+29)/136) + 1 = 4", "section 19: permutations"),
    ("G_DATA           = 16*1,311,067 + 21,000 + 92,300 = 21,090,372\n", "",
     "section 19 lacks the formulas ['G_DATA']"),
    ("NOTE_BYTES       = 12", "NOTE_SIZE        = 12", "unknown formula 'NOTE_SIZE'"),
    ("takes `floor(n / 136) + 1` permutations", "takes `ceil(n / 136)` permutations",
     "does not state that n bytes take"),
)


class CheckerTest(unittest.TestCase):
    def setUp(self):
        self.text = SPEC.read_text(encoding="utf-8")

    def damaged(self, old, new):
        self.assertEqual(self.text.count(old), 1, f"'{old}' must occur once")
        return self.text.replace(old, new)

    def damaged_after(self, anchor, old, new):
        """Replace the first `old` after `anchor`."""
        start = self.text.index(anchor)
        at = self.text.index(old, start)
        return self.text[:at] + new + self.text[at + len(old):]

    def assert_gap(self, text, fragment, **sources):
        errors = checker.check_text(text, **sources)
        self.assertTrue(any(fragment in e for e in errors), f"no '{fragment}' in {errors}")

    def assert_cases(self, cases):
        for old, new, fragment in cases:
            with self.subTest(old=old, new=new):
                self.assert_gap(self.damaged(old, new), fragment)

    # The specification

    def test_specification_passes(self):
        self.assertEqual(checker.check_text(self.text), [])
        record, stark = RECORD.read_text(encoding="utf-8"), STARK.read_text(encoding="utf-8")
        self.assertEqual(checker.check_text(self.text, record, stark), [])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(checker.main(["x", str(SPEC)]), 0)

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(checker.main(["x", str(Path(tmp) / "absent.md")]), 0)

    def test_damaged_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "10.md"
            path.write_text(self.damaged("| `G_PRIV` | 21,371,656 |", "| `G_PRIV` | 21,111,600 |"),
                            encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertNotEqual(checker.main(["x", str(path)]), 0)
            self.assertIn("GAP: constant G_PRIV is 21111600", out.getvalue())

    # Each damage is caught

    def test_structure_damaged(self):
        self.assert_cases(STRUCTURE)

    def test_note_and_rule_damaged(self):
        self.assert_cases(NOTE)

    def test_payloads_damaged(self):
        self.assert_cases(PAYLOADS)

    def test_bindings_damaged(self):
        self.assert_cases(BINDINGS)

    def test_traces_damaged(self):
        self.assert_cases(TRACES)

    def test_proof_length_bounds_damaged(self):
        self.assert_cases(BOUNDS)

    def test_verification_charge_damaged(self):
        self.assert_cases(VERIFICATION)

    def test_gas_constants_damaged(self):
        self.assert_cases(GAS)

    def test_fees_damaged(self):
        self.assert_cases(FEES)

    def test_slots_and_guard_damaged(self):
        self.assert_cases(SLOTS)

    def test_properties_damaged(self):
        self.assert_cases(PROPERTIES)

    def test_formulas_damaged(self):
        self.assert_cases(FORMULAS)

    def test_window_fee_examples_damaged(self):
        for name in ("window-genesis-ordinary", "window-genesis-policy"):
            start = self.text.index(f"[{name}]")
            block = self.text[start:self.text.index("\n\n", start)]
            for key in ("g", "base_part", "tip", "fee", "cover_limit"):
                with self.subTest(name=name, key=key):
                    value = re.search(rf"^{key} = (\d+)$", block, re.M).group(1)
                    text = self.damaged_after(f"[{name}]", f"{key} = {value}",
                                              f"{key} = {int(value) + 1}")
                    self.assert_gap(text, f"example {name}: {key} is {int(value) + 1}")
                with self.subTest(name=name, key=key, missing=True):
                    text = self.damaged_after(f"[{name}]", f"{key} = ", f"{key}_old = ")
                    self.assert_gap(text, f"example {name}: '{key}' is missing")

    def test_every_case_is_a_damage(self):
        # The damaged text of every case differs from the specification, and
        # no case is listed twice.
        cases = (STRUCTURE + NOTE + PAYLOADS + BINDINGS + TRACES + BOUNDS + VERIFICATION + GAS
                 + FEES + SLOTS + PROPERTIES + FORMULAS)
        self.assertEqual(len(set(cases)), len(cases))
        for old, new, _ in cases:
            self.assertNotEqual(old, new)

    # The sources beside the specification

    def test_benchmark_record_damaged(self):
        record, stark = RECORD.read_text(encoding="utf-8"), STARK.read_text(encoding="utf-8")
        self.assertIn("8.00; 7.94; 8.39; 8.28; 8.08 |", record)
        changed = record.replace("8.00; 7.94; 8.39; 8.28; 8.08 |",
                                 "8.00; 7.94; 8.39; 11.28; 8.08 |")
        self.assert_gap(self.text, "the benchmark record's slowest verification is 282/25 ms",
                        record=changed, stark_source=stark)
        self.assert_gap(self.text, "the benchmark record's slowest verification is None",
                        record="no table", stark_source=stark)

    def test_stark_source_damaged(self):
        record, stark = RECORD.read_text(encoding="utf-8"), STARK.read_text(encoding="utf-8")
        for old, new, name in (("pub const MAX_TRACE_WIDTH: usize = 3890;",
                                "pub const MAX_TRACE_WIDTH: usize = 3824;", "MAX_TRACE_WIDTH"),
                               ("pub const NUM_QUERIES: usize = 43;",
                                "pub const NUM_QUERIES: usize = 57;", "NUM_QUERIES"),
                               ("pub const LOG_BLOWUP: usize = 3;",
                                "pub const LOG_BLOWUP: usize = 2;", "LOG_BLOWUP")):
            with self.subTest(name=name):
                self.assertEqual(stark.count(old), 1)
                self.assert_gap(self.text, f"proofs/src/stark.rs sets {name}",
                                record=record, stark_source=stark.replace(old, new))

    # The constants a node pins (RP-24)

    def test_constants_output_matches_the_specification(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(checker.main(["x", "--constants", str(SPEC)]), 0)
        printed = json.loads(out.getvalue())
        self.assertEqual(printed, checker.constants())
        # The RP-24 gas of each type, as section 10.3 and 10.5 state it.
        self.assertEqual({k: printed[k] for k in checker.RP24},
                         {"G_PRIV": 21_371_656, "G_POLICY": 21_604_216, "G_ACTION": 15_905_968,
                          "G_DATA": 21_090_372})
        table = checker.Checker(self.text)
        table.run()
        for name, value in printed.items():
            if name in table.params:
                self.assertEqual(table.params[name], value, name)
        self.assertEqual(printed["VERIFY_GAS_ORD"], 370_000)
        self.assertEqual(printed["VERIFY_GAS_POLICY"], 440_000)
        self.assertEqual(printed["VERIFY_GAS_ACTION"], 430_000)
        self.assertEqual(printed["PREIMAGE_VERIFY_GAS"], 430_000)
        self.assertEqual(printed["VERIFY_GAS_DATA"], 92_300)

    def test_constants_not_printed_for_a_damaged_specification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "10.md"
            path.write_text(self.damaged("| `G_ACTION` | 15,905,968 |", "| `G_ACTION` | 1 |"),
                            encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertNotEqual(checker.main(["x", "--constants", str(path)]), 0)
            self.assertNotIn("{", out.getvalue())

    # The verification charge rule (section 10.2)

    def test_slowest_verification_within_the_charge(self):
        # At most the constant divided by GAS_PER_MS: 110,000 gas is 11.0 ms.
        self.assertTrue(checker.verification_within_charge(Fraction(11), 110_000))
        self.assertFalse(checker.verification_within_charge(Fraction(110_001, 10_000), 110_000))
        self.assertTrue(checker.verification_within_charge(Fraction(1079, 100), 110_000))
        e = checker.expected()
        for kind in ("ordinary", "policy", "action", "preimage"):
            with self.subTest(kind=kind):
                width = e["dims"][kind][1]
                slowest = checker.RECORDED_SLOWEST_MS * Fraction(max(width, checker.V1_WIDTH),
                                                                 checker.V1_WIDTH)
                self.assertTrue(checker.verification_within_charge(slowest, 110_000))

    def patched(self, **values):
        old = {k: getattr(checker, k) for k in values}
        for k, v in values.items():
            setattr(checker, k, v)
        self.addCleanup(lambda: [setattr(checker, k, v) for k, v in old.items()])

    def test_slowest_above_the_threshold_raises_the_constants(self):
        # A recorded 10.90 ms scales to 11.09 ms at the ordinary width, above
        # 11.0 ms: VERIFY_GAS 110,000 no longer covers it.
        self.patched(RECORDED_SLOWEST_MS=Fraction(1090, 100))
        errors = checker.check_text(self.text)
        self.assertTrue(any("VERIFY_GAS 110000 is not the scaled charge rounded up, 120000" in e
                            for e in errors), errors)

    def test_raised_constant_moves_every_gas_figure(self):
        # A slower measurement raises each charge and recomputes G_PRIV,
        # G_POLICY, G_ACTION and the window fee examples, so the document's
        # figures no longer match.
        self.patched(VERIFY={"ordinary": 380_000, "policy": 450_000, "action": 440_000,
                             "preimage": 440_000})
        errors = checker.check_text(self.text)
        for fragment in ("constant G_PRIV is 21371656, recomputed 21381656",
                         "constant G_POLICY is 21604216, recomputed 21614216",
                         "constant G_ACTION is 15905968, recomputed 15915968",
                         "example window-genesis-ordinary: g is 21371656",
                         "example window-genesis-policy: g is 21604216",
                         "section 19: G_PRIV"):
            self.assertTrue(any(fragment in e for e in errors), (fragment, errors))
        self.assertTrue(any("section 10.2: `S1` version 2 charge" in e for e in errors), errors)

    def test_measured_slowest_above_its_charge_fails(self):
        # A measured slowest above the charge the document states.
        self.patched(MEASURED_SLOWEST_MS=dict(checker.MEASURED_SLOWEST_MS,
                                              policy=Fraction(4401, 100)))
        errors = checker.check_text(self.text)
        self.assertTrue(any("`S4` slowest ms" in e for e in errors), errors)
        self.assertTrue(any("VERIFY_GAS_POLICY 440000 is not the measured slowest rounded up" in e
                            for e in errors), errors)

    # The arithmetic itself

    def test_bound_port_matches_the_prover(self):
        # The values pinned by proofs/src/stark.rs's own tests.
        self.assertEqual(checker.proof_length_bound(2048, 3824), 1_056_723)
        self.assertEqual(checker.proof_length_bound(2048, 3890), 1_070_715)
        self.assertEqual(checker.proof_length_bound(2048, 3856), 1_063_507)
        self.assertEqual(checker.proof_length_bound(1000, 10), checker.proof_length_bound(1024, 10))
        self.assertGreater(checker.proof_length_bound(4096, 3890), 1_070_715)
        self.assertEqual(checker.proof_length_bound(2048, 3891) - 1_070_715, 2 * 20 + 43 * 4)
        self.assertEqual(checker.proof_length_bound(128, 3722), 947_283)
        # Below the zero-knowledge minimum height (106) every trace is padded
        # to 128.
        self.assertEqual(checker.proof_length_bound(72, 3722), 947_283)
        self.assertLessEqual(checker.proof_length_bound(2048, 3890), checker.PROOF_FIELD_BYTES)

    def test_permutations(self):
        self.assertEqual(checker.permutations(0), 1)
        self.assertEqual(checker.permutations(135), 1)
        self.assertEqual(checker.permutations(136), 2)
        self.assertEqual(checker.permutations(636), 5)
        self.assertEqual(checker.permutations(798), 6)
        self.assertEqual(checker.permutations(297), 3)
        self.assertEqual(checker.tag_bytes("ghost/coin-reveal-binding/v2"), 29)

    def test_evaluate(self):
        self.assertEqual(checker.evaluate("ceil(947,283 / 1,024) * 1,024"), 948_224)
        self.assertEqual(checker.evaluate("floor((607+29)/136) + 1"), 5)
        self.assertEqual(checker.evaluate("16 * 1,311,291 + 21,000 + 110,000"), 21_111_656)
        self.assertIsNone(checker.evaluate("1 / 3"))
        self.assertIsNone(checker.evaluate("__import__('os')"))
        self.assertIsNone(checker.evaluate("2 ** 8"))
        self.assertIsNone(checker.evaluate("1 +"))

    def test_window_fee_matches_spec_07(self):
        price = checker.growth_bound(10**9, 1)
        self.assertEqual(price, 1_125_050_001)
        self.assertEqual(checker.window_fee(price, 21_090_372),
                         (23_727_723_039_690_372, 2_372_772_303_969_038, 26_100_495_343_659_410))

    def test_expected_values(self):
        e = checker.expected()
        self.assertEqual((e["NOTE_BYTES"], e["CAPSULE_BYTES"]), (380, 224))
        self.assertEqual((e["ORD_ENVELOPE_BYTES"], e["POLICY_ENVELOPE_BYTES"],
                          e["ACTION_ENVELOPE_BYTES"]), (1_311_291, 1_311_451, 949_373))
        self.assertEqual(e["binding"], {"ordinary": 607, "policy": 767, "action": 273,
                                        "preimage": 161})
        self.assertEqual((e["ORD_PERMS"], e["POLICY_PERMS"], e["ACTION_PERMS"],
                          e["PREIMAGE_PERMS"]), (47, 47, 4, 3))
        self.assertEqual(e["dims"], {"v1": (2048, 3824), "ordinary": (2048, 3890),
                                     "policy": (2048, 3856), "action": (128, 3722),
                                     "preimage": (128, 3722)})
        self.assertEqual(e["ACTION_PROOF_BYTES"], 948_224)


if __name__ == "__main__":
    unittest.main()
