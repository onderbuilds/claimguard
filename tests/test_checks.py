import unittest

from claimguard.url_check import check_url
from claimguard.tx_check import check_calldata
from claimguard.near_rpc import check_account
from claimguard.cli import main

SPENDER = "000000000000000000000000" + "ab" * 20


class UrlTests(unittest.TestCase):
    def test_official_allowed(self):
        for u in ["https://docs.near.org/", "https://nearhackathon.com/", "https://phantom.com/"]:
            self.assertEqual(check_url(u).decision, "allow", u)

    def test_fake_claim_blocked(self):
        for u in ["https://phtmfoundation.info/claim", "https://near-airdrop-claim.xyz/connect-wallet",
                  "http://robinhood-chain-rewards.top/claim", "https://metamsk.io/restore"]:
            self.assertEqual(check_url(u).decision, "block", u)

    def test_punycode_and_ip(self):
        self.assertNotEqual(check_url("https://xn--phntom-3ya.app/").decision, "allow")
        self.assertNotEqual(check_url("http://192.168.1.5/airdrop").decision, "allow")

    def test_userinfo_trick(self):
        codes = {f.code for f in check_url("https://near.org@evil.xyz/claim").findings}
        self.assertIn("userinfo_trick", codes)


class TxTests(unittest.TestCase):
    def test_unlimited_approve_blocked(self):
        v = check_calldata("0x095ea7b3" + SPENDER + "f" * 64)
        self.assertEqual(v.decision, "block")

    def test_small_approve_known_spender_allowed(self):
        v = check_calldata("0x095ea7b3" + SPENDER + "0" * 60 + "03e8", {"0x" + "ab" * 20})
        self.assertEqual(v.decision, "allow")

    def test_set_approval_for_all(self):
        v = check_calldata("0xa22cb465" + SPENDER + "0" * 63 + "1")
        self.assertEqual(v.decision, "block")

    def test_permit_warn(self):
        self.assertEqual(check_calldata("0xd505accf" + SPENDER).decision, "warn")


class NearAccountTests(unittest.TestCase):
    def fake_rpc(self, exists=True, contract=False):
        def rpc(network, method, params):
            if not exists:
                return {"error": {"name": "HANDLER_ERROR"}}
            return {"result": {"code_hash": "abc" if contract else "11111111111111111111111111111111"}}
        return rpc

    def test_blocklisted(self):
        self.assertEqual(check_account("drainer.near", blocklist={"drainer.near"}, rpc=self.fake_rpc()).decision, "block")

    def test_missing_account(self):
        self.assertEqual(check_account("nobody.near", rpc=self.fake_rpc(exists=False)).decision, "block")

    def test_normal_account(self):
        self.assertEqual(check_account("alice.near", rpc=self.fake_rpc()).decision, "allow")


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(main(["url", "https://near.org"]), 0)
        self.assertEqual(main(["url", "https://near-airdrop-claim.xyz/claim"]), 2)


if __name__ == "__main__":
    unittest.main()
