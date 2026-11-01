import argparse
import json
import sys

from .url_check import check_url
from .tx_check import check_calldata


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="claimguard", description="Check links and transactions before an agent signs.")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("url", help="score one or more URLs")
    u.add_argument("urls", nargs="+")
    t = sub.add_parser("tx", help="decode EVM calldata for drainer patterns")
    t.add_argument("calldata")
    a = sub.add_parser("account", help="NEAR account signals via public RPC (network)")
    a.add_argument("account_id")
    a.add_argument("--network", default="mainnet", choices=["mainnet", "testnet"])
    args = p.parse_args(argv)

    if args.cmd == "url":
        results = [check_url(x).to_dict() for x in args.urls]
    elif args.cmd == "tx":
        results = [check_calldata(args.calldata).to_dict()]
    else:
        from .near_rpc import check_account
        results = [check_account(args.account_id, args.network).to_dict()]
    print(json.dumps(results if len(results) > 1 else results[0], indent=2, ensure_ascii=False))
    worst = max({"allow": 0, "warn": 1, "block": 2}[r["decision"]] for r in results)
    return worst


if __name__ == "__main__":
    sys.exit(main())
