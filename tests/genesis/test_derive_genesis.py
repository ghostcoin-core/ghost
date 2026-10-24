"""Tests for scripts/derive_genesis.py: on the node's genesis fixtures it prints
exactly the golden genesis bytes, follows the heavier branch, and refuses a
selection with too few confirmations.

The fixtures are the node's genesis test data, one 80-byte header per hex
string; T_L of all of them is 1800000000."""

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

NORMAL_HEADERS = [
    "00000020f7e762469fba92a8fe6303d80dd87566800bcf915a397a48509207401db8acc4f84718e51e0d170b6afb9d23663f57af2a514a6a5a868585f133b37213d63bedd8ae496bffff7f2002000000",
    "0000002099a57afca1ab0cf676269dd9689731ff02a1c166816f537606d164fc3132fe2d682177d998ab39494944c102777cd56e4ec476662f9becdcf9cb85fd1789f04f30b1496bffff7f2001000000",
    "00000020c3823f3f389a01068a33a8fd3bdfc7a3cbffd2efda803f2173cf05a9191ddf72bd6a7ac56224e30b5284311184d9ce12e267d1ba03123c384642c93972c76a8988b3496bffff7f2000000000",
    "00000020779ec214a80ca7ce252be25b5aa82a7b2a0b9af4c5162a9c5ed34449718e350a20cc976e810af081ff2fd2c23cbba7977ec72e41c9648fd65fd859a091c89639e0b5496bffff7f2004000000",
    "000000203100cbc9987a6866508c03854d4ddf5d253aa6f6b044260ae18f2bdb648bfd0ffa77c8c630de26d1f43d56e1609b088eada0e04345dce33174b8d2eaf0ff446e38b8496bffff7f2001000000",
    "0000002096b32fe3e1bfe0255c73a881ba13194ebf4b96c1679d24cccfa5ed7a8c5ddb0de5f008a29e402b199eacece9528978841e41bb1527f5437081ef2b5a6973b7ef90ba496bffff7f2005000000",
    "0000002044ef0c65611e0df107bd34a33ac9ac2363beb63577f530ace32b11f1a3dd4e267b9689edbf2c2193e68da8c5c7cd93fe065b6bff8a89c1933a05660ff332526be8bc496bffff7f2000000000",
    "00000020b5c8dacfd4e862734d8cefa4a952fb0fc9fa668ca5a3e943997acdac5d4842521bd1b2de49a40422c3a7cc0999e3624220b95a3e72952d432af6b1a1dbed68ca40bf496bffff7f2001000000",
    "00000020c65e5292df341112509df4a6d02540e7836aba7ddb8bbe1363fa2a3e62fb964fc330ab7f6f34d72cb4e1e5be24dce689441e946c4ed34f6868dacd923b36952298c1496bffff7f2000000000",
    "0000002040888ad9d54fd333cbf10528fb5a566e85bfe04b7f5d5dbdd2b886a8842bde03ff6fa957fcd5b01b6cae219c481ab957ec614525651f50d366edc56ed4a0d59ef0c3496bffff7f2000000000",
    "000000201acddd1d79341093ee297f9cc16e0653d3ea17808b72eee80862ab1c00394536a7e4f798eb521a0f92173b736beceacd279c20b2231c608b3954ae6db98f0ca448c6496bffff7f2000000000",
    "00000020b098af47f6793465c2dffd34596a6c892711553985e3030813d111a0f7c4d5100f00a7b34914619f0a919f3a18432872c8d3e39e5b17e965b7940a17b77db62aa0c8496bffff7f2000000000",
    "00000020d29f193aa3e9efe38417575839dc2fc6d3b57d2c505fd8f3c7921dcedfeefe5f30aaa6aea8f9ec241f44690a781a2a69caf13011ca40a7f4db1bbbef4acb42a0f8ca496bffff7f2001000000",
    "00000020b76cd3fc3b95e020b4145f4201c8c64050935640efca11fc2a7136e130b5d64a9a337607136b65239cbdfc25990ccde452c8bb0d58bcb18aa98b4103e320feb350cd496bffff7f2000000000",
    "000000208111bfa9c0a7c127615e34b3e1997ce3805a150a284baf79e829b4ce80e6af789e0284d824f88e6ef74375d15620d2ee3e7032a23333c7d4f0a811873c41932ba8cf496bffff7f2001000000",
    "000000207c9bb2f3678f5419b978841882dd41be264ff9172ad2fd432a6fd1d3ab963e090a9f3eeccb5b9525417b3a88006e0bd83b6f1ad56f974e0328f8213a0c7fc3ae00d2496bffff7f2000000000",
    "00000020ddce4562adff637a1382aca5f8af3d58085129da12e6aa682de3ff572257bf37b6b8dc86b3d2e36f74d18bf3afae820d429bf48f8f7843870ce29bbed7e9adc858d4496bffff7f2003000000",
    "00000020c5a817866e8ce2f5e5e1408407d04ec16939a211b0c9639444559bbaf78d874e6aeba4ea3b6f540ad54cdd873e869c96658a9f72e3f579ad68b28135a5a611ceb0d6496bffff7f2000000000",
    "000000206a13c022c6716d15197592c577fb790c3b4c20bcd4d0b6c75a30335ab35e717d584c7b3b4b6ece909c0a31ac923e436be3139b606173a243ac73fdb1323cfcf008d9496bffff7f2000000000",
    "000000207efd863eabd0d9c1403fe07d3d35ad3e008c4964cd2be9577779a9e66538b12b8d328e52ec583d5549265de3cd5b2c1327fe7e42bfc35e3310b3bf9cefe9a13c60db496bffff7f2000000000",
    "00000020e49394c998667cacc99277082ecfcbd0fa7e3569676db8e6e035be46e9cb4c19e46e889a1dea494760492b270ca32a129fd762dcc180429ee6c9e22825d247b4b8dd496bffff7f2000000000",
    "000000201ad3bb2ed3e825de5c2610a5c1b5c8c4ffedd0dc44c2fbd81c730fc40a57bd761c9b6b85263bb0536fda69f64aa6e166ebbb5acd6d5e92ca70445bdc799e258910e0496bffff7f2000000000",
    "000000201c1853ccb6f803a2a8312369b33fa8ebcc3c60d50ef147a8900bdf5d2dd04d7be4569a104a4361ba34017b23a3980af44b1e6078efbd0da98b2e556c2a16f70b68e2496bffff7f2000000000",
    "00000020a51e0b7a3333d24ed9b5666dd607bec3744fc174229e0ed7a4fcdf0734229d269c07eb5829369f4074eea3eea43a65b2577d799efe7eea78418cd67b9ffba435c0e4496bffff7f2000000000",
    "000000206f9847f59306e488940b923eaaa59cff0a4841b8c25756d6434dde762a28ae45627d662facf0f88cf82d2458fd3c16f0c1ae9a584ad31801e387b73087c23a2218e7496bffff7f2000000000",
    "00000020c9df8dd19597e660dc43e2f4618a05c981e090f6d76e195021d476e151f0df509e82a82e6ba75faef34d9f27692a2740c15530bbecb7d37695fcccd9a7589f6e70e9496bffff7f2002000000",
]

# The reorg fixture: the normal main branch, then a heavier competing branch
# forking after block 10.
REORG_HEADERS = NORMAL_HEADERS + [
    "00000020b098af47f6793465c2dffd34596a6c892711553985e3030813d111a0f7c4d510a925ca3372dcc03f71de99e418a8fa56fcf8c7362fea6abc567181184382902474c7496bffff7f2000000000",
    "00000020bf7666e50561219639288e91be68606f44528a8e044c0a3e785c70b9bd2f757e5d00647a3bb933181318cfd0ab7b3278c9c11e6f9163db2b5cac5096aeef15bca0c8496bffff7f2001000000",
    "000000207f7e392ac6826d400ae17b5a864fec5e7b54174ecad28f80c16c9d2f91c34a4827cc7ceec3cf7886b91447307f81e4a0e0aa32efa2493ae7796f49ee746b7e0eccc9496bffff7f2003000000",
    "00000020daa99fc54f3fcb68eaa2939a41592edb381b3546c4a40a799c447e53c61e1d77b2c18d57f49964400d48b22ab3c7140d4c75eac0e4d6354e4a3a617f69e48609f8ca496bffff7f2002000000",
    "000000203f9428158707d0b7b5973d6e0e79ecbb54a4a2cab5c2b9755e8b6669383f523a695c0bb1d89c4cbc4e5ac34b408fddeae7d6b0682ee337ac29658dcfaaa164fd24cc496bffff7f2000000000",
    "000000209f10d99669547b732a32a03dda8b903de27beedd903f73678c4ec5e658da12312401e12a3089eb312907a9f00da85239e4446c6e9c4f0f2031d03de44edea3b850cd496bffff7f2001000000",
    "00000020c2e3bbb4b028bad21010e6433fc3f369671ca69e47ae40c33c27f8da3655302f389ac6751d1e998320df6dcc50f4cb9d1cce24c946e048b8446459269bd8d75f7cce496bffff7f2001000000",
    "0000002070492770b89b778f258af562c63279fe125afeaa0f7d61594abcb13dadbe130fc0a9e52e14738b43d5e6cb5baced11a39373b5f029a2d2723f87a2bd51796596a8cf496bffff7f2002000000",
    "000000207f3ba0d7cb4f4cdad0ef0ddf3b443818391b9be86c19a2e1236c919f28747b1d0c4cd69267d4fff19c90670dd2817bbfc173ad3525bf9846a9023c935985d198d4d0496bffff7f2000000000",
    "00000020eba86f4c644d1f455b2bdefa04200849aac6874b25e5146d7dd7498408810a27f42603fd5d14740ccc15ede40178d684ef52311c3e2c5f083450c9922ae4f08d00d2496bffff7f2001000000",
    "00000020de65f20c30d837f49a0fe3768617168c04e9aa4204863b7b65ebd73a1be2f550ff9dc64e4f8658a00d8df6269512f4d7565d12d89741005d36820e7ead4e4ef02cd3496bffff7f2003000000",
    "00000020169412e31fd39e0a195dd7f8e6cfce4f365d74b16aedb29466f86e19d3db4d30f5f7c90f6022f2d442b8a8667efed95f8b57155e010c1a91cc68308811d611c158d4496bffff7f200b000000",
    "00000020ac640530972da7db2ba01375bd43526253122f44f0875aaea3d73d843014711767e373680954b03e48d4a9e18f51636ef5e9cb55974c7e1968a4b8c7a33bbb3084d5496bffff7f2000000000",
    "0000002056a785546b19afcf584bc0cfa62168d3fd5bc96a5062f10a5b7c2572042e0721b36172af493a3fc7b215a5120bc7c64a7a539d6c0e75983a804db9d7776952eeb0d6496bffff7f2000000000",
    "000000206d18720498748c0edc6926369dc28a0c1c1597422078d3d85df3f2c0419b4e02d190312f7e4556a60cbe13e0cf718557ae11157ed2e4f90c9e034b4ddb9861c7dcd7496bffff7f2000000000",
    "000000208321a2ebdb88e304cfc803edc5f029d87b3d17b2e1de900f55b3789d44895667fff6b85722d144f5a558a5ba0d4fe32fcca20371d32e6cc78082478e15876dc508d9496bffff7f2001000000",
    "00000020bb4370755f8233243aaa31d9f29b8b6a8dde7edf3bc75125e3c57b7d8c98464e20099cd4771428eba78180eb214cc0c429daf53d6ce3665dba65488556ec12f034da496bffff7f2000000000",
    "00000020abd81a868221a5111b3e011479674e1f80f9363208cbac3c56f605355c7310476abd6d4c9373d2ae104ed02b4d01c93c29a4b811874d8a1f61bebdee422e5fab60db496bffff7f2000000000",
    "00000020d2e693044088eaa1c15cee7b6b523e8bf05899038a763eb98021d2b299f4fe52ad08bc5bdc3b9d585c4c272e5447a78448e044eeda39d23c42a07f4f127d009f8cdc496bffff7f2000000000",
    "0000002044d2ba1a4d217e602228b3b8aea128612e69671377ed46288f2648670604580b1126cbb62d2b4f60dedfba22360c68fc0928566ac5a375c37d44fe7350c1a26db8dd496bffff7f2000000000",
]

# The normal fixture without its last header: the same block has 5 confirmations.
TOO_FEW_CONFIRMATIONS_HEADERS = NORMAL_HEADERS[:-1]
TOO_FEW_CONFIRMATIONS_REFUSED = (
    "selected block has too few confirmations: block "
    "76bd570ac40f731cd8fbc244dcd0edffc4c8b5c1a510265cde25e8d32ebbd31a has 5, want 6")

NORMAL_GENESIS = "f90265f90260a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000808401c9c38080846b49d200a076bd570ac40f731cd8fbc244dcd0edffc4c8b5c1a510265cde25e8d32ebbd31aa00000000000000000000000000000000000000000000000000000000000000000880000000000000000843b9aca00a08e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8a03d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03c0c0"
REORG_GENESIS = "f90265f90260a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000808401c9c38080846b49d200a0675689449d78b3550f90dee1b2173d7bd829f0c5ed03c8cf04e388dbeba22183a00000000000000000000000000000000000000000000000000000000000000000880000000000000000843b9aca00a08e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8a03d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03c0c0"


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
