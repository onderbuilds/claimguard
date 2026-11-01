from .verdict import Finding, Verdict

MAX_UINT = (1 << 256) - 1
SELECTORS = {
    "095ea7b3": "approve(address,uint256)",
    "a22cb465": "setApprovalForAll(address,bool)",
    "d505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "39509351": "increaseAllowance(address,uint256)",
}


def _words(data: str):
    body = data[8:]
    return [body[i:i + 64] for i in range(0, len(body), 64)]


def check_calldata(calldata: str, known_spenders: set | None = None) -> Verdict:
    data = calldata.lower().removeprefix("0x")
    v = Verdict(target="0x" + data[:8] + "…")
    add = lambda c, w, r: v.findings.append(Finding(c, w, r))
    if len(data) < 8:
        add("bad_calldata", 30, "Calldata too short to decode")
        return v
    sel = data[:8]
    name = SELECTORS.get(sel)
    w = _words(data)
    spender = ("0x" + w[0][24:]) if w else "?"
    trusted = known_spenders and spender in {s.lower() for s in known_spenders}
    if name is None:
        add("unknown_selector", 20, f"Unknown function selector 0x{sel}; simulate before signing")
    elif sel in ("095ea7b3", "39509351") and len(w) >= 2:
        amount = int(w[1], 16)
        if amount >= MAX_UINT // 2:
            add("unlimited_approve", 45 if trusted else 70, f"Unlimited token allowance to {spender}")
        elif not trusted:
            add("approve_unknown", 25, f"Token allowance to unknown spender {spender}")
    elif sel == "a22cb465" and len(w) >= 2 and int(w[1], 16) == 1:
        add("approval_for_all", 45 if trusted else 70, f"setApprovalForAll(true) gives {spender} control of every NFT in the collection")
    elif sel == "d505accf":
        add("permit_signature", 50, "Off-chain permit grants allowance without an on-chain approve; common in drainer kits")
    elif sel == "23b872dd":
        add("transfer_from", 30, "transferFrom moves tokens from another address")
    return v
