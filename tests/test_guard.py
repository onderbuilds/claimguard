import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from claimguard import guard, near_rpc as nr
from claimguard.cli import main

GOOD = {"code_hash": "1" * 32, "amount": str(5 * 10**24), "storage_usage": 2000}


def rpc(network, method, params):
    if params.get("account_id") == "ghost.near":
        return {"error": {}}
    if params["request_type"] == "view_access_key_list":
        return {"result": {"keys": []}}
    return {"result": GOOD}


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.signer = lambda a: self.calls.append(a) or "ok"

    def test_clean_action_is_signed(self):
        out = guard.check_and_sign({"url": "https://near.org", "receiver": "alice.near"}, self.signer, rpc=rpc)
        self.assertEqual(out, "ok")
        self.assertEqual(len(self.calls), 1)

    def test_block_never_calls_signer(self):
        with self.assertRaises(guard.Blocked):
            guard.check_and_sign({"url": "https://phtmfoundation.info/claim"}, self.signer, rpc=rpc)
        with self.assertRaises(guard.Blocked):
            guard.check_and_sign({"receiver": "ghost.near"}, self.signer, rpc=rpc)
        self.assertEqual(self.calls, [])

    def test_warn_needs_confirm(self):
        act = {"calldata": "0xd505accf" + ("0" * 24 + "ab" * 20) * 7}
        with self.assertRaises(guard.Blocked):
            guard.check_and_sign(act, self.signer, rpc=rpc)
        guard.check_and_sign(act, self.signer, confirm=lambda v: True, rpc=rpc)
        self.assertEqual(len(self.calls), 1)

    def test_empty_action(self):
        with self.assertRaises(ValueError):
            guard.evaluate({})

    def test_cli_guard(self):
        with mock.patch.object(nr, "_rpc", rpc), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["guard", "--json", '{"url": "https://phtmfoundation.info/claim"}']), 2)
            self.assertEqual(main(["guard", "--url", "https://near.org", "--receiver", "alice.near"]), 0)
        self.assertIn('"BLOCK"', out.getvalue())

    def test_demo_blocks(self):
        import demo.injection_demo as d
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(d.main(), 0)
        self.assertIn("BLOCK", out.getvalue())
        self.assertEqual(len(d.signed), 1)  # only the unguarded call


if __name__ == "__main__":
    unittest.main()
