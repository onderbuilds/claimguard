# ClaimGuard

A small pre-signing check for wallets and agents that can sign transactions on their own.

## Why

Airdrop scams are moving from people to software. An agent reads a post or a web page that says "claim your $TOKEN here", the page has hidden instructions, and the agent happily opens a fake claim site, approves unlimited tokens and pays a "fee" account. ClaimGuard sits between the agent and the signer and says no.

## Quick start

Python 3.10+, no dependencies.

```bash
git clone https://github.com/onderbuilds/claimguard && cd claimguard
python3 -m unittest                # 49 tests, offline
python3 demo/injection_demo.py     # the attack, with and without the guard
```

Exit codes everywhere: `0` allow, `1` warn, `2` block, `3` bad input or bad arguments.

## Commands

```bash
python3 -m claimguard url https://phtmfoundation.info/claim      # fake domain, lookalikes, punycode, lure words
python3 -m claimguard tx 0x095ea7b3...                            # unlimited approve, setApprovalForAll, permit
python3 -m claimguard account bob.near --url https://x.y          # NEAR RPC: exists, contract, balance, keys
python3 -m claimguard blocked evil.xyz --contract <id>.testnet    # ask the on-chain blocklist
python3 -m claimguard guard --url ... --calldata ... --receiver bob.near [--blocklist <id>.testnet]
python3 -m claimguard guard --json '{"url": "...", "receiver": "bob.near"}'
```

From code:

```python
from claimguard.guard import check_and_sign, Blocked
check_and_sign(action, signer, confirm=ask_human)   # signer is never called on BLOCK
```

WARN only goes through if `confirm(verdict)` returns True. When a NEAR account or blocklist lookup fails, times out or comes back incomplete, that check reports WARN (`rpc_unavailable` / `blocklist_unavailable`) instead of passing. This covers `guard` and `account`. The URL and calldata checks are offline heuristics, so they can still miss a scam they've never seen.

## Demo

`demo/injection_demo.py` runs offline with a faked RPC. A poisoned "$PHTM airdrop" post tells the agent to open `phtmfoundation.info`, approve unlimited tokens and pay `claim-fees.near`. Without the guard the dummy signer signs. With it the action is blocked and every reason is printed.

## Blocklist contract

`contract/` is a tiny Rust contract (near-sdk 5.5). The owner can `add` / `remove` domains and account ids; anyone can call `is_blocked(value)` and `list(from_index, limit)` for free.

```bash
cd contract
cargo test                                            # unit tests
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release   # or: cargo near build
near contract deploy <id>.testnet use-file target/wasm32-unknown-unknown/release/claimguard_blocklist.wasm \
  with-init-call new json-args '{"owner":"<id>.testnet"}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config testnet
```

Testnet only for now. There is no default blocklist: `blocked` needs `--contract`, and `guard` / `account` only ask a blocklist when you pass `--blocklist`. A built-in account name that nobody controls could be registered by anyone and made to answer "not blocked". Use a contract whose owner you trust. The owner is whoever deploys it, and `owner()` returns that account.

## Limitations

- URL checks are heuristics with a short list of brands. New brands need adding.
- Calldata decoding covers common drainer patterns on EVM, not every contract. Unknown selectors (Permit2 and friends) come back as WARN. Simulate them before signing.
- NEAR account signals are simple (balance, storage, keys, contract code). They flag throwaway accounts, not every scam.
- The blocklist is only as good as whoever maintains it.

## License

See [LICENSE](LICENSE) (MIT).
