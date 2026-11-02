"""NEAR counterparty signals from the free public RPC. Read-only, no keys needed.
Docs: https://docs.near.org/api/rpc/providers , https://docs.near.org/api/rpc/contracts
"""
import base64
import json
import re
import time
import urllib.error
import urllib.request

from .verdict import Finding, Verdict

RPC = {"mainnet": "https://rpc.mainnet.near.org", "testnet": "https://rpc.testnet.near.org"}
EMPTY_CODE_HASH = "11111111111111111111111111111111"
YOCTO = 10 ** 24
NEW_ACCOUNT_DAYS = 7


# NEAR account id rules: 2-64 chars, lowercase a-z 0-9 and - _ . separators
ACCOUNT_RE = re.compile(r"^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$")


class RpcError(Exception):
    pass


def valid_account_id(account_id) -> bool:
    return isinstance(account_id, str) and 2 <= len(account_id) <= 64 and bool(ACCOUNT_RE.match(account_id))


def _rpc(network: str, method: str, params: dict, timeout=8, retries=2):
    body = json.dumps({"jsonrpc": "2.0", "id": "cg", "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC[network], body, {"Content-Type": "application/json"})
    last = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = e
            time.sleep(0.5 * (attempt + 1))
    raise RpcError(f"{network} RPC unreachable: {last}")


def _query(rpc, network, **params):
    # looked up at call time so tests can swap _rpc out
    return (rpc or _rpc)(network, "query", {"finality": "final", **params})


def view_account(account_id, network="mainnet", rpc=None):
    return _query(rpc, network, request_type="view_account", account_id=account_id)


def view_access_keys(account_id, network="mainnet", rpc=None):
    return _query(rpc, network, request_type="view_access_key_list", account_id=account_id)


def call_view(contract_id, method, args, network="testnet", rpc=None):
    """Call a view method and decode the JSON result. Returns None on any RPC error."""
    resp = _query(rpc, network, request_type="call_function", account_id=contract_id, method_name=method,
                  args_base64=base64.b64encode(json.dumps(args).encode()).decode())
    if "error" in resp or "result" not in resp.get("result", {}):
        return None
    return json.loads(bytes(resp["result"]["result"]).decode() or "null")


def is_blocked_onchain(value, contract_id, network="testnet", rpc=None):
    if not contract_id:
        raise ValueError("a blocklist contract id is required")
    return call_view(contract_id, "is_blocked", {"value": value}, network, rpc)


def check_account(account_id, network="mainnet", blocklist=frozenset(), rpc=None, age_days=None) -> Verdict:
    v = Verdict(target=account_id)
    add = lambda c, w, r: v.findings.append(Finding(c, w, r))
    if not valid_account_id(account_id):
        add("bad_account_id", 60, "Not a valid NEAR account id (lowercase, 2-64 chars)")
        return v
    if account_id in blocklist:
        add("blocklisted", 100, "Receiver is on the blocklist")
        return v
    unavailable = lambda why: add("rpc_unavailable", 40, f"Could not check account ({why})")
    try:
        resp = view_account(account_id, network, rpc)
        if not isinstance(resp, dict):
            raise RpcError("unexpected response")
        if "error" in resp:
            add("not_found", 60, "Account does not exist on " + network)
            return v
        kresp = view_access_keys(account_id, network, rpc)
    except RpcError as e:
        # fail closed: unknown is never treated as safe
        unavailable(e)
        return v
    res = resp.get("result")
    # a reply without the fields we score on is treated like no reply at all
    if not isinstance(res, dict) or "error" in res or "amount" not in res or "code_hash" not in res:
        unavailable("incomplete account data")
        return v
    kres = kresp.get("result") if isinstance(kresp, dict) else None
    if "error" in (kresp or {}) or not isinstance(kres, dict) or "error" in kres or not isinstance(kres.get("keys"), list):
        unavailable("incomplete access key data")
        return v
    keys = kres["keys"]
    is_contract = res["code_hash"] != EMPTY_CODE_HASH
    if is_contract:
        add("is_contract", 10, "Receiver is a contract; review what the call does")
    if len(account_id) == 64 and all(c in "0123456789abcdef" for c in account_id):
        add("implicit_account", 15, "Implicit (hex) account: no human-readable name")
    if int(res["amount"]) < YOCTO // 100:
        add("near_empty", 10, "Almost no NEAR balance: fresh or throwaway account")
    # The RPC has no creation date. Low storage is not proof of a new account (plain
    # accounts like root.near stay small for years), so only age data from the caller counts.
    if age_days is None:
        add("age_unknown", 0, "Account age unknown (not available from RPC); not scored")
    elif age_days < NEW_ACCOUNT_DAYS:
        add("new_account", 15, f"Account is only {age_days} day(s) old")

    full = [k for k in keys if k.get("access_key", {}).get("permission") == "FullAccess"]
    if is_contract and full:
        # a contract that still has full-access keys can be swapped out by its owner at any time
        add("contract_upgradable", 15, f"Contract still has {len(full)} full-access key(s)")
    if len(full) > 3:
        add("many_full_keys", 10, f"{len(full)} full-access keys on one account")
    return v


def combine(*verdicts, target="combined") -> Verdict:
    """Merge url/tx/account verdicts into one score for a single signing decision."""
    out = Verdict(target=target)
    for vd in verdicts:
        for f in vd.findings:
            out.findings.append(Finding(f.code, f.weight, f"[{vd.target}] {f.reason}"))
    return out
