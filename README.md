# claimguard

Checks links, EVM calldata and NEAR accounts before a wallet or an AI agent signs anything. Returns `allow`, `warn` or `block` with reasons as JSON.

Exit codes: 0 allow, 1 warn, 2 block.

## What it checks

- `url`: look-alike and impersonation domains, punycode, `@` tricks, raw IPs, shorteners, risky TLDs, "claim/airdrop" lures
- `tx`: unlimited `approve`, `setApprovalForAll(true)`, `permit`, `transferFrom`, unknown selectors
- `account`: NEAR account lookup over public RPC (exists, contract, implicit) plus a blocklist

## Usage

Python 3.10+, no dependencies.

```sh
python3 -m claimguard url https://near-airdrop-claim.xyz/claim
python3 -m claimguard tx 0x095ea7b3...
python3 -m claimguard account root.near
```

## Tests

```sh
python3 -m unittest discover -s tests
```

## License

MIT
