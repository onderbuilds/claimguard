"""Cases that used to slip through as ALLOW. Each one must stay caught."""
import base64
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from claimguard import cli, guard, near_rpc as nr
from claimguard.tx_check import check_calldata

SP = "0" * 24 + "ab" * 20
GOOD = {"code_hash": "1" * 32, "amount": str(10**24), "storage_usage": 1000}


def rpc_blocking(listed):
    """Fake RPC where the blocklist contains exactly `listed`."""
    def rpc(network, method, params):
        rt = params["request_type"]
        if rt == "call_function":
            value = json.loads(base64.b64decode(params["args_base64"]))["value"]
            return {"result": {"result": list(json.dumps(value in listed).encode())}}
        if rt == "view_access_key_list":
            return {"result": {"keys": []}}
        return {"result": GOOD}
    return rpc


def blocklist_down(network, method, params):
    if params["request_type"] == "call_function":
        raise nr.RpcError("testnet RPC unreachable")
    return rpc_blocking(set())(network, method, params)


def quiet(argv):
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        try:
            rc = cli.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue()


class CalldataTests(unittest.TestCase):
    def test_none_of_these_allow(self):
        cases = {
            "approve 2^200": "0x095ea7b3" + SP + format(2**200, "064x"),
            "approve no args": "0x095ea7b3",
            "approve one arg": "0x095ea7b3" + SP,
            "permit2 unknown selector": "0x2b67b570" + "00" * 64,
            "setApprovalForAll(2)": "0xa22cb465" + SP + format(2, "064x"),
        }
        for name, data in cases.items():
            self.assertNotEqual(check_calldata(data).decision, "allow", name)

    def test_specific_codes(self):
        self.assertIn("unlimited_approve", {f.code for f in check_calldata("0x095ea7b3" + SP + format(2**200, "064x")).findings})
        self.assertEqual(check_calldata("0x095ea7b3" + SP).decision, "block")
        self.assertEqual(check_calldata("0xa22cb465" + SP + format(2, "064x")).decision, "block")

    def test_video_calldata_is_clean(self):
        v = check_calldata("0x095ea7b3" + SP + "f" * 64)
        self.assertEqual([f.code for f in v.findings], ["unlimited_approve"])


class BlocklistTests(unittest.TestCase):
    def test_scheme_less_url_is_looked_up(self):
        rpc = rpc_blocking({"evil.com"})
        for url in ["https://evil.com/x", "evil.com/x", "https://evil.com./", "https://www.evil.com/", "a.b.evil.com"]:
            self.assertEqual(guard.evaluate({"url": url}, "bl.testnet", rpc=rpc).decision, "block", url)

    def test_cli_account_blocklist_down_is_not_allow(self):
        with mock.patch.object(nr, "_rpc", blocklist_down):
            rc, out = quiet(["account", "alice.near", "--blocklist", "bl.testnet"])
            self.assertNotEqual(rc, 0)
            self.assertIn("blocklist_unavailable", out)
            rc, out = quiet(["guard", "--receiver", "alice.near", "--blocklist", "bl.testnet"])
            self.assertNotEqual(rc, 0)

    def test_blocked_needs_contract(self):
        self.assertEqual(quiet(["blocked", "evil.com"])[0], 3)
        with self.assertRaises(ValueError):
            nr.is_blocked_onchain("evil.com", None)


class RetestTests(unittest.TestCase):
    def test_idn_host_matches_punycode_entry(self):
        self.assertEqual(guard.url_host("https://Bücher.example./"), "xn--bcher-kva.example")
        rpc = rpc_blocking({"xn--bcher-kva.example"})
        self.assertEqual(guard.evaluate({"url": "https://bücher.example/"}, "bl.testnet", rpc=rpc).decision, "block")

    def test_bad_idn_fails_closed(self):
        url = "https://" + "ü" * 70 + ".com/"   # label too long for idna
        self.assertIsNone(guard.url_host(url))
        v = guard.evaluate({"url": url}, "bl.testnet", rpc=rpc_blocking(set()))
        self.assertNotEqual(v.decision, "allow")
        self.assertIn("bad_idn", {f.code for f in v.findings})

    def test_huge_transfer_warns(self):
        self.assertEqual(check_calldata("0xa9059cbb" + SP + "f" * 64).decision, "warn")
        self.assertEqual(check_calldata("0xa9059cbb" + SP + format(2**128, "064x")).decision, "warn")
        self.assertEqual(check_calldata("0xa9059cbb" + SP + format(10**18, "064x")).decision, "allow")


class BrokenRpcTests(unittest.TestCase):
    def test_garbled_replies_are_not_allow(self):
        replies = [{}, {"result": {"error": "account does not exist"}}, {"result": {"code_hash": "1" * 32}}]
        for r in replies:
            v = nr.check_account("alice.near", rpc=lambda n, m, p, r=r: r)
            self.assertEqual(v.decision, "warn", r)
            self.assertIn("rpc_unavailable", {f.code for f in v.findings})

    def test_broken_key_list(self):
        def rpc(network, method, params):
            if params["request_type"] == "view_access_key_list":
                return {"result": {"error": "boom"}}
            return {"result": GOOD}
        self.assertEqual(nr.check_account("alice.near", rpc=rpc).decision, "warn")


class ExitCodeTests(unittest.TestCase):
    def test_argparse_errors_are_3_not_2(self):
        self.assertEqual(quiet(["guard", "--network", "devnet", "--url", "x"])[0], 3)
        self.assertEqual(quiet(["nope"])[0], 3)
        self.assertEqual(quiet([])[0], 3)


if __name__ == "__main__":
    unittest.main()
