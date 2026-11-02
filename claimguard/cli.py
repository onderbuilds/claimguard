import argparse
import json
import sys

from .url_check import check_url
from .tx_check import check_calldata


def main(argv=None) -> int:
    try:
        return _main(argv)
    except (ValueError, KeyError) as e:
        print(f"claimguard: error: {e}", file=sys.stderr)
        return 3
    except Exception as e:  # network or anything unexpected: say so, never look like a pass
        print(f"claimguard: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 3


class _Parser(argparse.ArgumentParser):
    # argparse exits with 2 on bad input, which would look like BLOCK; use 3 instead
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def _main(argv=None) -> int:
    p = _Parser(prog="claimguard", description="Check links and transactions before an agent signs.")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("url", help="score one or more URLs")
    u.add_argument("urls", nargs="+")
    t = sub.add_parser("tx", help="decode EVM calldata for drainer patterns")
    t.add_argument("calldata")
    a = sub.add_parser("account", help="NEAR account signals via public RPC (network)")
    a.add_argument("account_id")
    a.add_argument("--network", default="mainnet", choices=["mainnet", "testnet"])
    a.add_argument("--url", action="append", default=[], help="link that came with the request")
    a.add_argument("--calldata", help="EVM calldata that came with the request")
    a.add_argument("--blocklist", metavar="CONTRACT_ID", help="also ask this on-chain blocklist (testnet)")
    b = sub.add_parser("blocked", help="ask an on-chain blocklist contract about a domain or account")
    b.add_argument("value")
    b.add_argument("--contract", required=True, metavar="CONTRACT_ID", help="blocklist contract account id")
    b.add_argument("--network", default="testnet", choices=["mainnet", "testnet"])
    g = sub.add_parser("guard", help="check a proposed action before signing (exit 2 = refuse)")
    g.add_argument("--json", help='action as JSON, e.g. {"url": "...", "receiver": "bob.near"}')
    g.add_argument("--url")
    g.add_argument("--calldata")
    g.add_argument("--receiver")
    g.add_argument("--network", default="mainnet", choices=["mainnet", "testnet"])
    g.add_argument("--blocklist", metavar="CONTRACT_ID")
    args = p.parse_args(argv)

    if args.cmd == "url":
        results = [check_url(x).to_dict() for x in args.urls]
    elif args.cmd == "tx":
        results = [check_calldata(args.calldata).to_dict()]
    elif args.cmd == "guard":
        from .guard import evaluate
        try:
            action = json.loads(args.json) if args.json else {}
        except json.JSONDecodeError as e:
            raise ValueError(f"--json is not valid JSON ({e.msg})")
        for k in ("url", "calldata", "receiver"):
            if getattr(args, k):
                action[k] = getattr(args, k)
        action.setdefault("network", args.network)
        v = evaluate(action, args.blocklist).to_dict()
        v["decision"] = v["decision"].upper()
        print(json.dumps(v, indent=2, ensure_ascii=False))
        return {"ALLOW": 0, "WARN": 1, "BLOCK": 2}[v["decision"]]
    elif args.cmd == "blocked":
        from .near_rpc import is_blocked_onchain, RpcError
        try:
            hit = is_blocked_onchain(args.value.strip().lower().rstrip("."), args.contract, args.network)
        except RpcError as e:
            hit = None
            print(f"claimguard: {e}", file=sys.stderr)
        print(json.dumps({"value": args.value, "blocked": hit}))
        return 2 if hit else (0 if hit is False else 1)
    else:
        from .guard import evaluate
        action = {"receiver": args.account_id, "url": args.url, "network": args.network}
        if args.calldata:
            action["calldata"] = args.calldata
        v = evaluate(action, args.blocklist)
        results = [v.to_dict()]
    print(json.dumps(results if len(results) > 1 else results[0], indent=2, ensure_ascii=False))
    worst = max({"allow": 0, "warn": 1, "block": 2}[r["decision"]] for r in results)
    return worst  # exit code: 0 allow, 1 warn, 2 block


if __name__ == "__main__":
    sys.exit(main())
