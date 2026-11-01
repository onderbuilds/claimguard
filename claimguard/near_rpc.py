import json
import urllib.request

from .verdict import Finding, Verdict

RPC = {"mainnet": "https://rpc.mainnet.near.org", "testnet": "https://rpc.testnet.near.org"}
EMPTY_CODE_HASH = "11111111111111111111111111111111"


def _rpc(network: str, method: str, params: dict, timeout=10):
    body = json.dumps({"jsonrpc": "2.0", "id": "cg", "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC[network], body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def view_account(account_id: str, network="mainnet", rpc=_rpc) -> dict:
    return rpc(network, "query", {"request_type": "view_account", "finality": "final", "account_id": account_id})


def check_account(account_id: str, network="mainnet", blocklist=frozenset(), rpc=_rpc) -> Verdict:
    v = Verdict(target=account_id)
    add = lambda c, w, r: v.findings.append(Finding(c, w, r))
    if account_id in blocklist:
        add("blocklisted", 100, "Receiver is on the shared blocklist")
        return v
    resp = view_account(account_id, network, rpc)
    if "error" in resp:
        add("not_found", 60, "Account does not exist on " + network)
        return v
    res = resp.get("result", {})
    if res.get("code_hash", EMPTY_CODE_HASH) != EMPTY_CODE_HASH:
        add("is_contract", 10, "Receiver is a contract; review what the call does")
    if len(account_id) == 64 and all(c in "0123456789abcdef" for c in account_id):
        add("implicit_account", 15, "Implicit (hex) account: no human-readable name")
    return v
