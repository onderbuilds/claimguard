"""Signing guard: run every check on a proposed action before it reaches the signer.

An action is a dict with any of: url, calldata, receiver (NEAR account id), network.
"""
from urllib.parse import urlsplit

from . import near_rpc as nr
from .tx_check import check_calldata
from .url_check import check_url
from .verdict import BLOCK, WARN, Finding


class Blocked(Exception):
    def __init__(self, verdict):
        super().__init__("action blocked: " + "; ".join(f.reason for f in verdict.findings))
        self.verdict = verdict


def _unchecked(value):
    from .verdict import Verdict
    return Verdict(target=value, findings=[Finding("blocklist_unavailable", 30, "On-chain blocklist could not be read")])


def url_host(url):
    """Host the same way check_url sees it: scheme optional, lowercase, no trailing dot."""
    url = (url or "").strip()
    if "://" not in url:
        url = "http://" + url
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    if any(ord(ch) > 127 for ch in host):
        # blocklist entries are stored as punycode, so look up the xn-- form
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return host


def domain_candidates(host):
    """evil.com entry should also catch www.evil.com and a.b.evil.com."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)] or [host]


def evaluate(action, blocklist_contract=None, rpc=None):
    if not isinstance(action, dict):
        raise ValueError("action must be a JSON object")
    unknown = set(action) - {"url", "calldata", "receiver", "network"}
    if unknown:
        raise ValueError("unknown action fields: " + ", ".join(sorted(unknown)))
    if action.get("network", "mainnet") not in nr.RPC:
        raise ValueError("network must be mainnet or testnet")
    parts = []
    urls, calldata, receiver = action.get("url"), action.get("calldata"), action.get("receiver")
    urls = [urls] if isinstance(urls, str) else list(urls or [])
    network = action.get("network", "mainnet")
    host = (url_host(urls[0]) or "") if urls else ""

    def onchain(values):
        # True if any value is listed; a failed or garbled lookup adds a warning instead of passing
        if not blocklist_contract:
            return False
        for value in values:
            try:
                hit = nr.is_blocked_onchain(value, blocklist_contract, "testnet", rpc)
            except nr.RpcError:
                hit = None
            if hit is None or not isinstance(hit, bool):
                parts.append(_unchecked(value))
                return False
            if hit:
                return True
        return False

    for url in urls:
        v = check_url(url)
        h = url_host(url)
        if h is None:
            v.findings.append(Finding("bad_idn", 40, "Host could not be converted to punycode; blocklist not checked"))
        elif h and onchain(domain_candidates(h)):
            v.findings.append(Finding("blocklisted", 100, "Domain is on the on-chain blocklist"))
        parts.append(v)
    if calldata:
        parts.append(check_calldata(calldata))
    if receiver:
        receiver = receiver.strip().lower()
        bl = frozenset([receiver]) if onchain([receiver]) else frozenset()
        parts.append(nr.check_account(receiver, network, bl, rpc))
    if not parts:
        raise ValueError("action needs at least one of url, calldata, receiver")
    return nr.combine(*parts, target=receiver or host or "action")


def check_and_sign(action, signer, confirm=None, blocklist_contract=None, rpc=None):
    """Call signer(action) only if the checks allow it.

    BLOCK raises Blocked and the signer is never touched. WARN needs confirm(verdict)
    to return True (a human in the loop); with no confirm callback a warning is refused too.
    """
    v = evaluate(action, blocklist_contract, rpc)
    if v.decision == BLOCK:
        raise Blocked(v)
    if v.decision == WARN and not (confirm and confirm(v)):
        raise Blocked(v)
    return signer(action)
