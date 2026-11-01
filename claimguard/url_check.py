import ipaddress
import re
from urllib.parse import urlsplit, unquote

from .verdict import Finding, Verdict


BRANDS = {
    "near": ["near.org", "near.ai", "nearhackathon.com", "near-intents.org"],
    "phantom": ["phantom.com", "phantom.app"],
    "metamask": ["metamask.io"],
    "uniswap": ["uniswap.org"],
    "robinhood": ["robinhood.com"],
    "binance": ["binance.com"],
    "ledger": ["ledger.com"],
    "opensea": ["opensea.io"],
    "jupiter": ["jup.ag"],
    "arbitrum": ["arbitrum.io", "arbitrum.foundation"],
}
ALIASES = {"phantom": ["phtm"], "metamask": ["mmask"], "binance": ["bnb-"], "uniswap": ["uni-swap"]}
LURE_WORDS = ["foundation", "claim", "airdrop", "reward", "bonus", "giveaway", "free", "drop", "eligib",
              "verify", "wallet-connect", "walletconnect", "connect-wallet", "restore", "unlock",
              "migrate", "validate", "sync", "rectify"]
RISKY_TLDS = {"xyz", "top", "click", "info", "live", "site", "online", "shop", "icu", "buzz",
              "rest", "cfd", "sbs", "lol", "pro", "app", "fun", "gift", "claims"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at"}


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_url(raw: str) -> Verdict:
    v = Verdict(target=raw)
    url = raw.strip()
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    full = unquote(url).lower()
    add = lambda c, w, r: v.findings.append(Finding(c, w, r))

    if not host:
        add("no_host", 60, "URL has no host")
        return v
    if parts.scheme == "http":
        add("no_tls", 10, "Plain HTTP, no TLS")
    if "@" in (parts.netloc or ""):
        add("userinfo_trick", 40, "'@' in authority can hide the real host")
    try:
        ipaddress.ip_address(host)
        add("ip_host", 35, "Raw IP address instead of a domain")
    except ValueError:
        pass
    if "xn--" in host or any(ord(ch) > 127 for ch in host):
        add("punycode", 45, "Internationalized/punycode host: possible homograph attack")
    if host in SHORTENERS:
        add("shortener", 25, "URL shortener hides the destination")
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        add("risky_tld", 15, f"TLD .{tld} is frequently abused in phishing")
    if host.count(".") >= 3:
        add("deep_subdomain", 10, "Many subdomain levels")

    reg = _registrable(host)
    official = {d for ds in BRANDS.values() for d in ds}
    is_official = reg in official or host in official
    if not is_official:
        label = reg.split(".")[0]
        for brand, domains in BRANDS.items():
            tokens = re.split(r"[.\-_]", host)
            if any(al in host for al in ALIASES.get(brand, [])):
                add("brand_alias", 45, f"Uses an abbreviation of '{brand}' on a non-official domain")
                break
            if brand in tokens or any(t.startswith(brand) or t.endswith(brand) for t in tokens if len(brand) >= 4):
                add("brand_impersonation", 45, f"Mentions '{brand}' but is not an official {brand} domain ({', '.join(domains)})")
                break
            if len(label) >= 5 and any(0 < _levenshtein(label, d.split(".")[0]) <= 2 for d in domains if len(d.split(".")[0]) >= 5):
                add("lookalike", 50, f"Domain '{label}' looks like official {brand} domain")
                break
    lures = sorted({w for w in LURE_WORDS if w in full})
    if lures and not is_official:
        add("lure_words", min(40, 15 * len(lures)), "Lure keywords: " + ", ".join(lures))
    return v
