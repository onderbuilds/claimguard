import unittest
from unittest import mock

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
        self.assertEqual(check_calldata("0xd505accf" + SPENDER * 7).decision, "warn")


class NearAccountTests(unittest.TestCase):
    def fake_rpc(self, exists=True, contract=False):
        def rpc(network, method, params):
            if not exists:
                return {"error": {"name": "HANDLER_ERROR"}}
            if params["request_type"] == "view_access_key_list":
                return {"result": {"keys": []}}
            return {"result": {"code_hash": "abc" if contract else "11111111111111111111111111111111",
                               "amount": str(10**24)}}
        return rpc

    def test_blocklisted(self):
        self.assertEqual(check_account("drainer.near", blocklist={"drainer.near"}, rpc=self.fake_rpc()).decision, "block")

    def test_missing_account(self):
        self.assertEqual(check_account("nobody.near", rpc=self.fake_rpc(exists=False)).decision, "block")

    def test_normal_account(self):
        self.assertEqual(check_account("alice.near", rpc=self.fake_rpc()).decision, "allow")


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        with mock.patch("sys.stdout"):
            self.assertEqual(main(["url", "https://near.org"]), 0)
            self.assertEqual(main(["url", "https://near-airdrop-claim.xyz/claim"]), 2)


import base64, json
from unittest import mock
from claimguard import near_rpc as nr


def rpc_with(account=None, keys=(), view=None):
    def rpc(network, method, params):
        rt = params["request_type"]
        if rt == "view_account":
            return {"error": {}} if account is None else {"result": account}
        if rt == "view_access_key_list":
            return {"result": {"keys": [{"access_key": {"permission": p}} for p in keys]}}
        if rt == "call_function":
            if view is None:
                return {"error": {}}
            arg = json.loads(base64.b64decode(params["args_base64"]))
            return {"result": {"result": list(json.dumps(view(params["method_name"], arg)).encode())}}
    return rpc

RICH = {"code_hash": "11111111111111111111111111111111", "amount": str(5 * 10**24), "storage_usage": 2000}


class RpcSignalTests(unittest.TestCase):
    def test_established_account_clean(self):
        v = check_account("alice.near", rpc=rpc_with(RICH, ["FullAccess"]))
        self.assertEqual([f.code for f in v.findings if f.weight], [])

    def test_upgradable_contract(self):
        acc = dict(RICH, code_hash="9xyz")
        codes = {f.code for f in check_account("app.near", rpc=rpc_with(acc, ["FullAccess"])).findings}
        self.assertIn("contract_upgradable", codes)

    def test_fresh_throwaway_warns(self):
        acc = {"code_hash": RICH["code_hash"], "amount": "0", "storage_usage": 182}
        v = check_account("a" * 64, rpc=rpc_with(acc, ["FullAccess"] * 5))
        self.assertIn(v.decision, ("warn", "block"))

    def test_onchain_blocklist_view(self):
        rpc = rpc_with(view=lambda m, a: m == "is_blocked" and a["value"] == "evil.xyz")
        self.assertTrue(nr.is_blocked_onchain("evil.xyz", "bl.testnet", rpc=rpc))
        self.assertFalse(nr.is_blocked_onchain("near.org", "bl.testnet", rpc=rpc))
        self.assertIsNone(nr.is_blocked_onchain("x", "missing.testnet", rpc=rpc_with()))

    def test_combine_scores(self):
        v = nr.combine(check_account("alice.near", rpc=rpc_with(RICH)), check_url("https://phtmfoundation.info/claim"))
        self.assertEqual(v.decision, "block")

    def test_cli_account_with_blocklist(self):
        fake = rpc_with(RICH, view=lambda m, a: a["value"] == "evil.xyz")
        with mock.patch.object(nr, "_rpc", fake), mock.patch("sys.stdout"):
            self.assertEqual(main(["account", "alice.near", "--url", "https://evil.xyz/", "--blocklist", "bl.testnet"]), 2)
            self.assertEqual(main(["blocked", "near.org", "--contract", "bl.testnet"]), 0)


class AccountAgeTests(unittest.TestCase):
    PLAIN_SMALL = {"code_hash": "11111111111111111111111111111111", "amount": str(10**25), "storage_usage": 182}

    def test_missing_age_is_not_new(self):
        v = check_account("root.near", rpc=rpc_with(self.PLAIN_SMALL, ["FullAccess"]))
        codes = {f.code for f in v.findings}
        self.assertNotIn("new_account", codes)
        self.assertIn("age_unknown", codes)
        self.assertEqual(v.score, 0)
        self.assertEqual(v.decision, "allow")

    def test_known_new_account_warns(self):
        v = check_account("fresh.near", rpc=rpc_with(self.PLAIN_SMALL), age_days=1)
        self.assertIn("new_account", {f.code for f in v.findings})

    def test_old_account_not_flagged(self):
        v = check_account("old.near", rpc=rpc_with(self.PLAIN_SMALL), age_days=900)
        self.assertEqual(v.findings, [])


if __name__ == "__main__":
    unittest.main()
