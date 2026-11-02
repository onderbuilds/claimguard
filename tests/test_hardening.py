import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from claimguard import guard, near_rpc as nr
from claimguard.cli import main
from claimguard.tx_check import check_calldata
from claimguard.url_check import check_url

GOOD = {"code_hash": "1" * 32, "amount": str(5 * 10**24), "storage_usage": 2000}


def ok_rpc(network, method, params):
    if params["request_type"] == "view_access_key_list":
        return {"result": {"keys": []}}
    if params["request_type"] == "call_function":
        return {"result": {"result": list(b"false")}}
    return {"result": GOOD}


def down_rpc(network, method, params):
    raise nr.RpcError("testnet RPC unreachable: timed out")


class FailClosedTests(unittest.TestCase):
    def test_rpc_down_never_allows(self):
        v = guard.evaluate({"receiver": "alice.near"}, rpc=down_rpc)
        self.assertNotEqual(v.decision, "allow")
        called = []
        with self.assertRaises(guard.Blocked):
            guard.check_and_sign({"receiver": "alice.near"}, called.append, rpc=down_rpc)
        self.assertEqual(called, [])

    def test_blocklist_down_never_allows(self):
        def rpc(network, method, params):
            if params["request_type"] == "call_function":
                raise nr.RpcError("down")
            return ok_rpc(network, method, params)
        v = guard.evaluate({"url": "https://near.org"}, blocklist_contract="bl.testnet", rpc=rpc)
        self.assertNotEqual(v.decision, "allow")

    def test_real_rpc_retries_then_raises(self):
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError("slow")), mock.patch("time.sleep"):
            with self.assertRaises(nr.RpcError):
                nr._rpc("testnet", "query", {})


class EdgeCaseTests(unittest.TestCase):
    def test_url_edges(self):
        self.assertEqual(check_url("").decision, "block")
        self.assertEqual(check_url("javascript:alert(1)").decision, "block")
        self.assertEqual(check_url("https://near.org:99999/").decision, "block")
        self.assertEqual(check_url("HTTPS://NEAR.ORG./").decision, "allow")
        self.assertNotEqual(check_url("https://phаntom.com/").decision, "allow")  # cyrillic a

    def test_calldata_edges(self):
        self.assertEqual(check_calldata("0xzzzz1234").decision, "block")
        self.assertNotEqual(check_calldata("").decision, "allow")
        self.assertNotEqual(check_calldata("0x095ea7b3" + "0" * 70).decision, "allow")

    def test_account_ids(self):
        self.assertTrue(nr.valid_account_id("alice.near"))
        for bad in ["A", "Alice.near", "a..b.near", "-x.near", "x" * 65, ""]:
            self.assertFalse(nr.valid_account_id(bad), bad)
        self.assertEqual(nr.check_account("Bad Id", rpc=ok_rpc).decision, "block")
        # uppercase from the user is normalised before lookup
        v = guard.evaluate({"receiver": " Alice.NEAR "}, rpc=ok_rpc)
        self.assertEqual(v.decision, "allow")

    def test_bad_actions(self):
        for act in [{}, [], {"url": "x", "amount": 5}, {"url": "x", "network": "devnet"}]:
            with self.assertRaises(ValueError):
                guard.evaluate(act, rpc=ok_rpc)


class CliErrorTests(unittest.TestCase):
    def run_cli(self, *argv):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            return main(list(argv)), err.getvalue()

    def test_bad_json(self):
        code, err = self.run_cli("guard", "--json", "{nope")
        self.assertEqual(code, 3)
        self.assertIn("not valid JSON", err)

    def test_empty_guard(self):
        self.assertEqual(self.run_cli("guard")[0], 3)

    def test_offline_guard_is_not_allow(self):
        with mock.patch.object(nr, "_rpc", down_rpc):
            self.assertNotEqual(self.run_cli("guard", "--receiver", "alice.near")[0], 0)
            self.assertEqual(self.run_cli("blocked", "x.xyz", "--contract", "bl.testnet")[0], 1)


if __name__ == "__main__":
    unittest.main()
