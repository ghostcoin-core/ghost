"""Tests for scripts/derive_genesis.py: on the node's genesis fixtures it prints
exactly the golden genesis bytes, follows the heavier branch, and refuses a
selection with too few confirmations.

The fixtures next to this file are the node's genesis test data: each
*.headers.hex file holds one 80-byte header in hex per line, each
*.genesis.hex file the golden genesis block. T_L of all of them is 1800000000."""

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent.parent / "scripts" / "derive_genesis.py"
FIXTURE_TL = 1800000000
POWLIMIT_BITS = "207fffff"
NORMAL_BITCOIN_BLOCK = "76bd570ac40f731cd8fbc244dcd0edffc4c8b5c1a510265cde25e8d32ebbd31a"
OUTPUT_NAMES = ["bitcoin-block", "confirmations", "median-time-past", "genesis-hash", "genesis-block"]


def _fixture(name):
    return (HERE / name).read_text().strip()


def _headers(name):
    return _fixture(name).split()


NORMAL_HEADERS = _headers("normal.headers.hex")
# The normal main branch, then a heavier competing branch forking after block 10.
REORG_HEADERS = _headers("reorg.headers.hex")
# The normal fixture without its last header: the same block has 5 confirmations.
TOO_FEW_CONFIRMATIONS_HEADERS = _headers("too_few_confirmations.headers.hex")
TOO_FEW_CONFIRMATIONS_REFUSED = _fixture("too_few_confirmations.refused.txt")
NORMAL_GENESIS = _fixture("normal.genesis.hex")
REORG_GENESIS = _fixture("reorg.genesis.hex")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


derive_genesis = _load("derive_genesis", SCRIPT)


def _raw(headers):
    return b"".join(bytes.fromhex(header) for header in headers)


def _header_slice(block_hex):
    """The header's RLP inside a golden block `[header, [], []]`."""
    block = bytes.fromhex(block_hex)
    assert block[0] == 0xF9 and block[3] == 0xF9
    length = int.from_bytes(block[4:6], "big")
    return block[3:6 + length]


class DeriveGenesisTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_raw(self, name, data, t_l=FIXTURE_TL, powlimit_bits=POWLIMIT_BITS):
        raw = Path(self.tmp.name) / (name + ".raw")
        raw.write_bytes(data)
        command = [sys.executable, str(SCRIPT), "-tl", str(t_l), "-headers", str(raw)]
        if powlimit_bits is not None:
            command += ["-powlimit-bits", powlimit_bits]
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def run_script(self, name, headers, t_l=FIXTURE_TL):
        return self.run_raw(name, _raw(headers), t_l=t_l)

    def derived(self, name, headers):
        result = self.run_script(name, headers)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines()
        self.assertTrue(result.stdout.endswith("\n"))
        self.assertEqual([line.split(" ", 1)[0] for line in lines], OUTPUT_NAMES)
        fields = dict(line.split(" ", 1) for line in lines)
        self.assertEqual(fields["genesis-hash"],
                         derive_genesis.keccak256(_header_slice(fields["genesis-block"])).hex())
        return fields

    def assert_refused(self, result, *needles):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        for needle in needles:
            self.assertIn(needle, result.stderr)

    def test_fixtures(self):
        self.assertEqual(len(NORMAL_HEADERS), 26)
        self.assertEqual(REORG_HEADERS[:26], NORMAL_HEADERS)
        self.assertEqual(TOO_FEW_CONFIRMATIONS_HEADERS, NORMAL_HEADERS[:-1])
        for golden in (NORMAL_GENESIS, REORG_GENESIS):
            # 19 header fields: the 18-field genesis was 1232 hex digits.
            self.assertEqual(len(golden), 1298)
            # timestamp = MTP(B) + GENESIS_OFFSET = 1800000000 + 6000
            self.assertIn("84" + (FIXTURE_TL + 6000).to_bytes(4, "big").hex() + "a0", golden)

    def test_keccak256_empty_vector(self):
        self.assertEqual(derive_genesis.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        # The uncle hash of spec 06 section 7, Keccak-256 of 0xc0, and a
        # message longer than one 136-byte block.
        self.assertEqual(derive_genesis.keccak256(b"\xc0").hex(),
                         "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
        self.assertEqual(len(derive_genesis.keccak256(bytes(300))), 32)
        self.assertNotEqual(derive_genesis.keccak256(b""), derive_genesis.keccak256(b"\x00"))

    def test_normal(self):
        fields = self.derived("normal", NORMAL_HEADERS)
        self.assertEqual(fields["genesis-block"], NORMAL_GENESIS)
        self.assertEqual(fields["genesis-hash"],
                         derive_genesis.keccak256(_header_slice(NORMAL_GENESIS)).hex())
        self.assertEqual(fields["median-time-past"], "1800000000")
        self.assertEqual(fields["bitcoin-block"], NORMAL_BITCOIN_BLOCK)
        self.assertEqual(fields["confirmations"], "6")

    def test_reorg(self):
        fields = self.derived("reorg", REORG_HEADERS)
        self.assertEqual(fields["genesis-block"], REORG_GENESIS)
        self.assertEqual(fields["genesis-hash"],
                         derive_genesis.keccak256(_header_slice(REORG_GENESIS)).hex())
        self.assertNotEqual(fields["genesis-block"], NORMAL_GENESIS)
        self.assertNotEqual(fields["bitcoin-block"], NORMAL_BITCOIN_BLOCK)

    def test_genesis_header_carries_the_empty_marker_set_root(self):
        # The root of the data marker-set tree holding only the sentinel
        # (0, 0, 0) at position 0 (spec 05, section 6), computed here from the
        # definition with the script's own Keccak-256.
        def tagged(tag, *parts):
            return derive_genesis.keccak256(bytes([len(tag)]) + tag.encode("ascii") + b"".join(parts))

        root = tagged("ghost/data-marker-set-leaf/v1", bytes(32), bytes(32), bytes(5))
        empty = tagged("ghost/empty-leaf/v1")
        for level in range(40):
            root = tagged("ghost/data-marker-set-node/v1", bytes([level]), root, empty)
            empty = tagged("ghost/data-marker-set-node/v1", bytes([level]), empty, empty)
        self.assertEqual(root, derive_genesis.EMPTY_DATA_MARKER_SET_ROOT)
        spec05 = (HERE.parent.parent / "docs" / "spec" / "05-trees-and-headers.md").read_text()
        self.assertIn("| `dataMarkerRoot` | `%s`" % root.hex(), spec05)
        for golden in (NORMAL_GENESIS, REORG_GENESIS):
            header = _header_slice(golden)
            # The header list is 19 items and its last is the 32-byte root,
            # right after the empty data tree root.
            self.assertTrue(header.endswith(b"\xa0" + derive_genesis.EMPTY_DATA_TREE_ROOT
                                            + b"\xa0" + root))
            items, at = 0, 3
            while at < len(header):
                lead = header[at]
                if lead < 0x80:
                    at += 1
                elif lead <= 0xB7:
                    at += 1 + lead - 0x80
                else:
                    size = lead - 0xB7
                    at += 1 + size + int.from_bytes(header[at + 1:at + 1 + size], "big")
                items += 1
            self.assertEqual(at, len(header))
            self.assertEqual(items, 19)

    def test_too_few_confirmations_refused(self):
        block_hash = TOO_FEW_CONFIRMATIONS_REFUSED.split("block ")[-1].split()[0]
        self.assertEqual(len(block_hash), 64)
        result = self.run_script("too_few_confirmations", TOO_FEW_CONFIRMATIONS_HEADERS)
        self.assert_refused(result, block_hash, "has 5, want 6")

    def test_t_l_one_second_later_refused(self):
        result = self.run_script("normal", NORMAL_HEADERS, t_l=FIXTURE_TL + 1)
        self.assert_refused(result, "has 5, want 6")
        self.assertNotIn(NORMAL_BITCOIN_BLOCK, result.stderr)

    def test_default_powlimit_refuses_easy_headers(self):
        result = self.run_raw("normal", _raw(NORMAL_HEADERS), powlimit_bits=None)
        self.assert_refused(result, "proof-of-work limit")

    def test_truncated_file_refused(self):
        result = self.run_raw("short", _raw(NORMAL_HEADERS)[:-1])
        self.assert_refused(result, "multiple of 80")

    def test_broken_link_and_bad_work_refused(self):
        raws = [bytes.fromhex(header) for header in NORMAL_HEADERS]
        unlinked = bytearray(raws[5])
        unlinked[4] ^= 1
        with self.assertRaisesRegex(derive_genesis.Refusal, "does not link"):
            derive_genesis.derive(b"".join(raws[:5] + [bytes(unlinked)] + raws[6:]),
                                  FIXTURE_TL, 0x207FFFFF)
        # Raise the nonce until the header no longer meets its target.
        for nonce in range(1, 64):
            reworked = bytearray(raws[0])
            reworked[76:80] = nonce.to_bytes(4, "little")
            if int.from_bytes(derive_genesis.sha256d(bytes(reworked)), "little") > \
                    derive_genesis.bits_to_target(0x207FFFFF):
                break
        with self.assertRaisesRegex(derive_genesis.Refusal, "does not meet"):
            derive_genesis.derive(bytes(reworked), FIXTURE_TL, 0x207FFFFF)

    def test_tie_refused(self):
        raws = [bytes.fromhex(header) for header in NORMAL_HEADERS]
        # A second child of the last-but-one header, with the same bits as the
        # last header, ties with it for the most work.
        twin = None
        for nonce in range(1, 256):
            candidate = bytearray(raws[-1])
            candidate[76:80] = nonce.to_bytes(4, "little")
            if candidate != raws[-1] and int.from_bytes(derive_genesis.sha256d(bytes(candidate)),
                                                        "little") <= \
                    derive_genesis.bits_to_target(0x207FFFFF):
                twin = bytes(candidate)
                break
        self.assertIsNotNone(twin)
        with self.assertRaisesRegex(derive_genesis.Refusal, "tie"):
            derive_genesis.derive(b"".join(raws + [twin]), FIXTURE_TL, 0x207FFFFF)


if __name__ == "__main__":
    unittest.main()
