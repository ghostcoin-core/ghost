"""Tests for scripts/derive_genesis.py: on the node's genesis fixtures it prints
exactly the golden genesis bytes, follows the heavier branch, and refuses a
selection with too few confirmations."""

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


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


derive_genesis = _load("derive_genesis", SCRIPT)


def _golden(name):
    return (HERE / name).read_text(encoding="utf-8").strip()


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

    def run_script(self, headers_name, t_l=FIXTURE_TL):
        lines = (HERE / headers_name).read_text(encoding="utf-8").split()
        raw = Path(self.tmp.name) / (headers_name + ".raw")
        raw.write_bytes(b"".join(bytes.fromhex(line) for line in lines))
        return subprocess.run(
            [sys.executable, str(SCRIPT), "-tl", str(t_l), "-headers", str(raw),
             "-powlimit-bits", POWLIMIT_BITS],
            capture_output=True, text=True, check=False)

    def derived(self, headers_name):
        result = self.run_script(headers_name)
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
        golden = _golden("normal.genesis.hex")
        fields = self.derived("normal.headers.hex")
        self.assertEqual(fields["genesis-block"], golden)
        self.assertEqual(fields["genesis-hash"],
                         derive_genesis.keccak256(_header_slice(golden)).hex())
        self.assertEqual(fields["median-time-past"], "1800000000")
        self.assertEqual(fields["bitcoin-block"], NORMAL_BITCOIN_BLOCK)
        self.assertEqual(fields["confirmations"], "6")

    def test_reorg(self):
        golden = _golden("reorg.genesis.hex")
        fields = self.derived("reorg.headers.hex")
        self.assertEqual(fields["genesis-block"], golden)
        self.assertEqual(fields["genesis-hash"],
                         derive_genesis.keccak256(_header_slice(golden)).hex())
        self.assertNotEqual(fields["genesis-block"], _golden("normal.genesis.hex"))
        self.assertNotEqual(fields["bitcoin-block"], NORMAL_BITCOIN_BLOCK)

    def test_too_few_confirmations_refused(self):
        refused = _golden("too_few_confirmations.refused.txt")
        block_hash = refused.split("block ")[-1].split()[0]
        self.assertEqual(len(block_hash), 64)
        result = self.run_script("too_few_confirmations.headers.hex")
        self.assert_refused(result, block_hash, "has 5, want 6")

    def test_t_l_one_second_later_refused(self):
        result = self.run_script("normal.headers.hex", t_l=FIXTURE_TL + 1)
        self.assert_refused(result, "has 5, want 6")
        self.assertNotIn(NORMAL_BITCOIN_BLOCK, result.stderr)

    def test_default_powlimit_refuses_easy_headers(self):
        lines = (HERE / "normal.headers.hex").read_text(encoding="utf-8").split()
        raw = Path(self.tmp.name) / "normal.raw"
        raw.write_bytes(b"".join(bytes.fromhex(line) for line in lines))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-tl", str(FIXTURE_TL), "-headers", str(raw)],
            capture_output=True, text=True, check=False)
        self.assert_refused(result, "proof-of-work limit")

    def test_truncated_file_refused(self):
        lines = (HERE / "normal.headers.hex").read_text(encoding="utf-8").split()
        raw = Path(self.tmp.name) / "short.raw"
        raw.write_bytes(b"".join(bytes.fromhex(line) for line in lines)[:-1])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-tl", str(FIXTURE_TL), "-headers", str(raw),
             "-powlimit-bits", POWLIMIT_BITS],
            capture_output=True, text=True, check=False)
        self.assert_refused(result, "multiple of 80")

    def test_broken_link_and_bad_work_refused(self):
        raws = [bytes.fromhex(line) for line in
                (HERE / "normal.headers.hex").read_text(encoding="utf-8").split()]
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
        raws = [bytes.fromhex(line) for line in
                (HERE / "normal.headers.hex").read_text(encoding="utf-8").split()]
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
