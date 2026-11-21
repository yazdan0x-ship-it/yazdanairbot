#!/usr/bin/env python3
"""
Airdrop Scout Bot v3  -  multi-source discovery + security screening (all free)

DISCOVERY (many sources, merged by project/domain):
  DefiLlama (new listings + funding history) | GitHub (new org repos) |
  crypto news RSS (The Block, CoinDesk, Decrypt, Cointelegraph, ...) |
  community feeds (Reddit, Medium) | your own EXTRA_FEEDS

SECURITY (a project is dropped if any check fails):
  MetaMask phishing list + ScamSniffer domain/address blacklists | domain age (RDAP) |
  lookalike / scam-like domain names | risky TLDs | no HTTPS | software downloads (.exe/.apk/.zip)
  seed-phrase / private-key / "verify wallet" pages | missing social links |
  contract addresses on the site (GoPlus address + token security) |
  optional: VirusTotal (VT_API_KEY) and Google Safe Browsing (GSB_API_KEY)

Run once:       python airdrop_bot.py --once
Run forever:    python airdrop_bot.py
Check one link: python airdrop_bot.py --check https://some-site.xyz
Telegram commands (while running): /start /latest /scan /check <url> /status
"""
import argparse
import difflib
import email.utils
import json
import os
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
GSB_API_KEY = os.getenv("GSB_API_KEY", "")
MIN_SCORE = int(os.getenv("MIN_SCORE", "55"))
MAX_AGE_MONTHS = int(os.getenv("MAX_FUNDING_AGE_MONTHS", "18"))
NEW_LISTING_DAYS = int(os.getenv("NEW_LISTING_DAYS", "120"))
MAX_DETAIL = int(os.getenv("MAX_DETAIL", "150"))
GITHUB_DAYS = int(os.getenv("GITHUB_DAYS", "45"))
GITHUB_MIN_STARS = int(os.getenv("GITHUB_MIN_STARS", "15"))
NEWS_DAYS = int(os.getenv("NEWS_DAYS", "30"))
CHECK_EVERY_HOURS = float(os.getenv("CHECK_EVERY_HOURS", "12"))
MAX_PER_RUN = int(os.getenv("MAX_PER_RUN", "10"))
MIN_DOMAIN_AGE_DAYS = int(os.getenv("MIN_DOMAIN_AGE_DAYS", "30"))
COMMUNITY_MIN_AGE_DAYS = int(os.getenv("COMMUNITY_MIN_AGE_DAYS", "90"))
STRICT_FREE = os.getenv("STRICT_FREE", "1") == "1"
USE_GITHUB = os.getenv("USE_GITHUB", "1") == "1"
USE_NEWS = os.getenv("USE_NEWS", "1") == "1"
USE_COMMUNITY = os.getenv("USE_COMMUNITY", "1") == "1"
EXTRA_FEEDS = [u.strip() for u in os.getenv("EXTRA_FEEDS", "").split(",") if u.strip()]
STATE_FILE = Path(os.getenv("STATE_FILE", "seen.json"))
CACHE_DIR = Path(os.getenv("CACHE_DIR", "cache"))
LAST_FILE = Path(os.getenv("LAST_FILE", "last_sent.json"))
RUN_LOCK = threading.Lock()
STATUS = {"last_run": None, "last_sent": 0}

HEADERS = {"User-Agent": "Mozilla/5.0 (airdrop-scout-bot)"}

# ---------------------------------------------------------------- quality lists
TIER1_INVESTORS = {
    "a16z", "andreessen horowitz", "paradigm", "polychain", "multicoin",
    "pantera", "sequoia", "coinbase ventures", "binance labs", "dragonfly",
    "framework", "variant", "delphi", "1kx", "hack vc", "jump crypto",
    "okx ventures", "animoca", "founders fund", "electric capital",
    "placeholder", "robot ventures", "spartan", "galaxy", "lightspeed",
}
CAPITAL_CATEGORIES = {
    "lending", "yield", "yield aggregator", "liquid staking", "dexs", "dex",
    "derivatives", "cdp", "leveraged farming", "options", "bridge",
    "staking pool", "restaking", "liquid restaking", "rwa", "algo-stables",
    "stablecoin", "synthetics", "yield lottery", "insurance", "launchpad",
    "nft launchpad", "prediction market",
}
PAID_WORDS = [
    "presale", "pre-sale", "private sale", "public sale", "buy token", "buy $",
    "purchase nft", "mint price", "pay to claim", "fee to claim", "claim fee",
    "nft required", "hold at least", "minimum deposit", "min. deposit",
    "minimum stake", "ido ", "ico ", "launchpad sale", "paid access",
    "subscription required",
]
CAPITAL_WORDS = [
    "deposit", "stake your", "provide liquidity", "supply assets", "lend",
    "borrow", "minimum balance", "add liquidity", "bridge funds",
]
FREE_WORDS = [
    "testnet", "devnet", "quest", "waitlist", "points", "season", "faucet",
    "join the community", "early access", "galxe", "zealy", "layer3",
    "incentivized", "testnet campaign", "bug bounty",
]
CONFIRM_WORDS = ["airdrop", "retroactive", "token distribution", "claim your"]
POINTS_WORDS = ["points", "season 1", "season one", "incentivized testnet", "rewards program"]
NO_AIRDROP_WORDS = ["no airdrop", "not offering an airdrop", "no token"]

# ---------------------------------------------------------------- security lists
BAD_TLDS = {"tk", "ml", "ga", "cf", "gq", "zip", "mov"}
RISKY_TLDS = {"top", "icu", "win", "click", "site", "online", "live", "shop", "cyou",
              "buzz", "sbs", "rest", "lol", "fun", "pw", "cam", "monster"}
FREE_HOSTS = ("pages.dev", "vercel.app", "netlify.app", "github.io", "web.app",
              "firebaseapp.com", "herokuapp.com", "glitch.me", "replit.app",
              "onrender.com", "workers.dev", "framer.website", "webflow.io",
              "wixsite.com", "blogspot.com")
BRANDS = ["metamask", "uniswap", "opensea", "binance", "coinbase", "phantom", "ledger",
          "trezor", "arbitrum", "optimism", "pancakeswap", "trustwallet", "layerzero",
          "eigenlayer", "starknet", "polygon", "ethereum", "solana", "chainlink",
          "walletconnect", "etherscan", "rainbow", "zksync", "pendle", "jupiter"]
HARD_SCAM_WORDS = ["giveaway", "freemint", "claimeth", "airdropclaim", "claimairdrop",
                   "drainer", "walletverify", "verifywallet", "freeairdrop", "claimnow"]
LURE_WORDS = ["claim", "airdrop", "reward", "bonus", "verify", "support", "wallet",
              "connect", "login", "giveaway", "free", "official", "app"]
SOFT_SCAM_WORDS = ["claim", "airdrop", "reward", "bonus", "verify"]

DOWNLOAD_RE = re.compile(
    r"""href=["']([^"']+?\.(?:exe|msi|apk|dmg|scr|bat|cmd|ps1|jar|zip|rar|7z|pkg|deb))(?:[?#][^"']*)?["']""", re.I)
SEED_INPUT_RE = re.compile(
    r"<(?:input|textarea)[^>]*(?:seed|mnemonic|private[\s_-]?key|secret[\s_-]?recovery|recovery[\s_-]?phrase)[^>]*>", re.I)
SCAM_PHRASES = [
    "enter your seed phrase", "enter your private key", "enter your recovery phrase",
    "import your wallet", "validate your wallet", "verify your wallet",
    "synchronize your wallet", "wallet synchronization", "rectify your wallet",
    "connect wallet to claim", "submit your seed", "12 or 24 words",
]
ADDR_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
HANDLE_RE = re.compile(r"(?<![A-Za-z0-9-])(?:twitter|x)\.com/(?:#!/)?([A-Za-z0-9_]{1,15})(?=[\"'/?#\s<])", re.I)
HANDLE_SKIP = {"share", "intent", "home", "search", "i", "hashtag", "widgets", "privacy", "tos", "login"}

GOPLUS = "https://api.gopluslabs.io/api/v1"
GOPLUS_CHAINS = [1, 56, 8453, 42161]
BAD_ADDRESS_FLAGS = {"cybercrime", "money_laundering", "financial_crime", "darkweb_transactions",
                     "phishing_activities", "blacklist_doubt", "stealing_attack",
                     "blackmail_activities", "sanctioned", "malicious_mining_activities",
                     "mixer", "honeypot_related_address"}
BAD_TOKEN_FLAGS = {"is_honeypot", "cannot_sell_all", "owner_change_balance", "selfdestruct",
                   "honeypot_with_same_creator"}

SKIP_DOMAINS = {
    "twitter.com", "x.com", "t.me", "telegram.me", "discord.gg", "discord.com", "youtube.com",
    "youtu.be", "medium.com", "reddit.com", "redd.it", "redditmedia.com", "github.com",
    "linkedin.com", "facebook.com", "instagram.com", "google.com", "mirror.xyz", "substack.com",
    "notion.so", "gitbook.io", "bit.ly", "linktr.ee", "coingecko.com", "coinmarketcap.com",
    "defillama.com", "etherscan.io", "wikipedia.org", "apple.com", "tiktok.com", "imgur.com",
    "cointelegraph.com", "coindesk.com", "theblock.co", "decrypt.co", "blockworks.co",
    "cryptoslate.com", "thedefiant.io", "beincrypto.com", "cryptopotato.com", "u.today",
    "gravatar.com", "wp.com", "cloudfront.net", "w3.org", "schema.org", "twimg.com",
    "googleapis.com", "gstatic.com", "doubleclick.net", "bloomberg.com", "reuters.com",
}
NEWS_FEEDS = [
    ("The Block", "https://www.theblock.co/rss.xml"),
    ("CoinDesk", "https://www.coindesk.com/arc/outboundfeeds/rss/"),
    ("Decrypt", "https://decrypt.co/feed"),
    ("Cointelegraph", "https://cointelegraph.com/rss"),
    ("Blockworks", "https://blockworks.co/feed"),
    ("CryptoSlate", "https://cryptoslate.com/feed/"),
    ("The Defiant", "https://thedefiant.io/api/feed"),
    ("BeInCrypto", "https://beincrypto.com/feed/"),
    ("CryptoPotato", "https://cryptopotato.com/feed/"),
]
COMMUNITY_FEEDS = [
    ("Reddit", "https://www.reddit.com/r/CryptoAirdrop/new/.rss"),
    ("Reddit", "https://www.reddit.com/r/airdrops/new/.rss"),
    ("Medium", "https://medium.com/feed/tag/airdrop"),
    ("Medium", "https://medium.com/feed/tag/testnet"),
]
NEWS_KEYS = re.compile(
    r"\b(airdrops?|testnet|points program|incentiv\w+|raises?|raised|secures|seed round|"
    r"pre-seed|series [ab]|funding round|retroactive)\b", re.I)
RAISE_RE = re.compile(
    r"^\s*([A-Z0-9][\w\.\-]*(?:\s[A-Z0-9][\w\.\-]*){0,2})\s+(?:raises|secures|closes|lands|bags|nabs|"
    r"gets|launches|unveils|announces|opens|debuts|introduces)\b")
TESTNET_RE = re.compile(r"\b([A-Z][\w\-]{2,})\s+(?:[Tt]estnet|[Aa]irdrop|[Pp]oints [Pp]rogram|[Ii]ncentivized)")
NAME_STOP = {"bitcoin", "ethereum", "binance", "coinbase", "solana", "ripple", "tether", "circle",
             "visa", "mastercard", "google", "microsoft", "amazon", "meta", "apple", "robinhood",
             "kraken", "cardano", "dogecoin", "blackrock", "fidelity", "sec", "trump", "the",
             "crypto", "this", "new", "how", "why", "what"}

TEXT_CACHE = {}
PAGE_CACHE = {}
RDAP_CACHE = {}
GOPLUS_CACHE = {}
BL = {"domains": set(), "addrs": set(), "loaded": False}


def log(*a):
    print(datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def get_json(url, timeout=40, headers=None):
    r = requests.get(url, headers=headers or HEADERS, timeout=timeout)
    r.raise_for_status()
    return r.json()


TWO_LEVEL = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "com.cn", "co.kr", "com.tr", "co.za"}


def domain(url):
    try:
        return urlparse(url).netloc.lower().replace("www.", "").split(":")[0]
    except Exception:
        return ""


def reg_domain(host):
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ------------------------------------------------------------------ blocklists
def cached_download(name, url, ttl_h=24):
    CACHE_DIR.mkdir(exist_ok=True)
    f = CACHE_DIR / name
    if f.exists() and time.time() - f.stat().st_mtime < ttl_h * 3600:
        return f.read_text(encoding="utf-8")
    try:
        r = requests.get(url, headers=HEADERS, timeout=120)
        r.raise_for_status()
        f.write_text(r.text, encoding="utf-8")
        return r.text
    except Exception as e:
        log("blocklist download failed:", name, e)
        return f.read_text(encoding="utf-8") if f.exists() else ""


def load_blocklists():
    if BL["loaded"]:
        return
    domains, addrs = set(), set()
    try:
        mm = json.loads(cached_download(
            "metamask.json",
            "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json") or "{}")
        domains |= {d.lower() for d in mm.get("blacklist", [])}
    except Exception as e:
        log("metamask list error:", e)
    try:
        ss = json.loads(cached_download(
            "scamsniffer_domains.json",
            "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json") or "[]")
        domains |= {d.lower() for d in ss}
    except Exception as e:
        log("scamsniffer domains error:", e)
    try:
        sa = json.loads(cached_download(
            "scamsniffer_addresses.json",
            "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json") or "[]")
        addrs |= {a.lower() for a in sa}
    except Exception as e:
        log("scamsniffer addresses error:", e)
    BL["domains"], BL["addrs"], BL["loaded"] = domains, addrs, True
    log(f"blocklists loaded: {len(domains)} domains, {len(addrs)} addresses")


def domain_blocked(host):
    parts = (host or "").lower().split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in BL["domains"]:
            return True
    return False


# ------------------------------------------------------------------ page fetch
def extract_features(raw, text):
    low = raw.lower()
    f = {
        "downloads": sorted({m.group(1) for m in DOWNLOAD_RE.finditer(raw)})[:5],
        "seed_input": bool(SEED_INPUT_RE.search(raw)),
        "scam_phrases": [p for p in SCAM_PHRASES if p in text],
        "approval": "setapprovalforall" in low or "increaseallowance" in low,
        "eth_sign": bool(re.search(r"[\"']eth_sign[\"']", low)),
        "handles": sorted({h.lower() for h in HANDLE_RE.findall(raw)} - HANDLE_SKIP)[:8],
        "has_chat": bool(re.search(r"(discord\.(?:gg|com)|t\.me/)", low)),
    }
    addrs = []
    for a in ADDR_RE.findall(raw):
        a = a.lower()
        if a not in addrs and a != "0x" + "0" * 40 and not a.startswith("0xdead"):
            addrs.append(a)
    f["addrs"] = addrs[:6]
    return f


def fetch_page(url, timeout=15):
    if not url:
        return {"ok": False, "final": "", "text": "", "features": {}}
    if url in PAGE_CACHE:
        return PAGE_CACHE[url]
    res = {"ok": False, "final": url, "text": "", "features": {}}
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        res["final"] = r.url
        if r.status_code == 200:
            raw = r.text[:400000]
            h = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw)
            t = re.sub(r"<[^>]+>", " ", h)
            res["text"] = re.sub(r"\s+", " ", t).lower()[:40000]
            res["features"] = extract_features(raw, res["text"])
            res["ok"] = True
    except Exception:
        pass
    PAGE_CACHE[url] = res
    return res


def page_text(url):
    return fetch_page(url)["text"]


# ------------------------------------------------------------------ misc helpers
def load_state():
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()))
        except Exception:
            pass
    return set()


def save_state(seen):
    STATE_FILE.write_text(json.dumps(sorted(seen)))


def tg_send(text, html=True):
    if not TG_TOKEN or not TG_CHAT_ID:
        print(text, "\n" + "-" * 40)
        return
    for i in range(0, len(text), 3900):
        payload = {"chat_id": TG_CHAT_ID, "text": text[i:i + 3900], "disable_web_page_preview": True}
        if html:
            payload["parse_mode"] = "HTML"
        try:
            r = requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", json=payload, timeout=30)
            if not r.ok:
                log("telegram error", r.status_code, r.text[:200])
        except Exception as e:
            log("telegram send failed:", e)


def remember_message(text):
    try:
        data = json.loads(LAST_FILE.read_text(encoding="utf-8")) if LAST_FILE.exists() else []
    except Exception:
        data = []
    data.append(text)
    LAST_FILE.write_text(json.dumps(data[-20:], ensure_ascii=False), encoding="utf-8")


def fmt_money(x):
    return f"${x:,.1f}M" if x else "\u062b\u0628\u062a \u0646\u0634\u062f\u0647"


def has_token(proto):
    if not proto:
        return None
    sym = (proto.get("symbol") or "").strip()
    return bool((sym and sym != "-") or proto.get("gecko_id"))


def new_candidate(**kw):
    c = {
        "name": "", "key": "", "category": "", "description": "", "url": "",
        "twitter": "", "chains": [], "amount": 0, "round": "", "fund_ts": None,
        "investors": [], "source": "", "origin": "", "proto": None,
        "gh_url": "", "gh_stars": 0, "gh_created": "", "sources": set(), "news": [],
    }
    c.update(kw)
    if not c["sources"]:
        c["sources"] = {c["origin"]} if c["origin"] else set()
    return c


def add_cand(pool, dom_idx, c):
    d = reg_domain(domain(c["url"])) if c["url"] else ""
    k = dom_idx.get(d) if d else None
    if k is None and c["key"] in pool:
        k = c["key"]
    if k is None:
        pool[c["key"]] = c
        if d:
            dom_idx[d] = c["key"]
        return
    ex = pool[k]
    ex["sources"] |= c["sources"]
    for f in ("url", "twitter", "category", "description"):
        if not ex[f] and c[f]:
            ex[f] = c[f]
    if not ex["proto"] and c["proto"]:
        ex["proto"] = c["proto"]
    if not ex["fund_ts"] and c["fund_ts"]:
        for f in ("amount", "round", "fund_ts", "investors", "source"):
            ex[f] = c[f]
    if not ex["gh_url"] and c["gh_url"]:
        for f in ("gh_url", "gh_stars", "gh_created"):
            ex[f] = c[f]
    ex["news"] = (ex.get("news") or []) + (c.get("news") or [])


# ------------------------------------------------------------------ funding helpers
def norm_date(d):
    if isinstance(d, (int, float)):
        return float(d)
    try:
        return datetime.strptime(str(d)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return 0.0


def norm_amount(a):
    try:
        a = float(a or 0)
    except Exception:
        return 0.0
    return a / 1e6 if a >= 100000 else a


def convert_raise(r, name, p):
    return {
        "name": name, "date": norm_date(r.get("date")), "amount": norm_amount(r.get("amount")),
        "round": r.get("round") or "", "chains": r.get("chains") or p.get("chains") or [],
        "category": p.get("category") or "", "source": r.get("source") or "",
        "leadInvestors": r.get("leadInvestors") or [], "otherInvestors": r.get("otherInvestors") or [],
    }


def enrich_funding(c):
    slug = (c["proto"] or {}).get("slug")
    if not slug:
        return
    try:
        d = get_json(f"https://api.llama.fi/protocol/{slug}", timeout=30)
    except Exception:
        return
    rs = [convert_raise(r, c["name"], c["proto"]) for r in (d.get("raises") or []) if r.get("date")]
    rs = [r for r in rs if r["date"] > 0]
    if not rs:
        return
    r = max(rs, key=lambda x: x["date"])
    c["amount"], c["round"], c["fund_ts"] = r["amount"], r["round"], r["date"]
    c["investors"] = r["leadInvestors"] + r["otherInvestors"]
    c["source"] = r["source"]


# ------------------------------------------------------------------ discovery sources
def funding_candidates(raises, by_name):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30 * MAX_AGE_MONTHS)).timestamp()
    recent = [x for x in raises if x.get("date", 0) >= cutoff and x.get("name")]
    recent.sort(key=lambda x: x["date"], reverse=True)
    out = {}
    for x in recent:
        key = x["name"].lower()
        if key in out:
            continue
        p = by_name.get(key)
        out[key] = new_candidate(
            name=x["name"], key=key,
            category=(x.get("category") or (p or {}).get("category") or "").strip(),
            description=(p or {}).get("description") or "",
            url=(p or {}).get("url") or "", twitter=(p or {}).get("twitter") or "",
            chains=x.get("chains") or [], amount=x.get("amount") or 0,
            round=x.get("round") or "", fund_ts=x["date"],
            investors=(x.get("leadInvestors") or []) + (x.get("otherInvestors") or []),
            source=x.get("source") or "", origin="DefiLlama", proto=p,
        )
    return out


def listing_candidates(protocols):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=NEW_LISTING_DAYS)).timestamp()
    out = {}
    for p in protocols:
        if (p.get("listedAt") or 0) < cutoff:
            continue
        key = p["name"].lower()
        out[key] = new_candidate(
            name=p["name"], key=key, category=(p.get("category") or "").strip(),
            description=p.get("description") or "", url=p.get("url") or "",
            twitter=p.get("twitter") or "", chains=p.get("chains") or [],
            origin="DefiLlama", proto=p,
        )
    return out


def github_candidates(by_domain):
    since = (datetime.now(timezone.utc) - timedelta(days=GITHUB_DAYS)).strftime("%Y-%m-%d")
    queries = [
        f"incentivized testnet in:name,description,readme created:>{since} stars:>{GITHUB_MIN_STARS}",
        f"testnet node in:name,description created:>{since} stars:>{GITHUB_MIN_STARS}",
        f"airdrop points testnet in:description,readme created:>{since} stars:>{GITHUB_MIN_STARS}",
    ]
    hdr = {"Accept": "application/vnd.github+json", "User-Agent": HEADERS["User-Agent"]}
    if GITHUB_TOKEN:
        hdr["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    out = {}
    for q in queries:
        try:
            data = get_json(
                "https://api.github.com/search/repositories?per_page=30&sort=stars&q="
                + requests.utils.quote(q), headers=hdr)
        except Exception as e:
            log("github search failed:", e)
            continue
        for it in data.get("items", []):
            if it.get("fork") or it.get("archived"):
                continue
            owner = it["owner"]
            if owner.get("type") != "Organization":
                continue
            home = (it.get("homepage") or "").strip()
            if not home.startswith("http"):
                continue
            p = by_domain.get(domain(home))
            key = (p["name"].lower() if p else owner["login"].lower())
            if key in out:
                continue
            out[key] = new_candidate(
                name=p["name"] if p else owner["login"], key=key,
                category=(p or {}).get("category") or "",
                description=(p or {}).get("description") or it.get("description") or "",
                url=(p or {}).get("url") or home, twitter=(p or {}).get("twitter") or "",
                chains=(p or {}).get("chains") or [], origin="GitHub", proto=p,
                gh_url=it["html_url"], gh_stars=it.get("stargazers_count", 0),
                gh_created=(it.get("created_at") or "")[:10],
            )
        time.sleep(7 if not GITHUB_TOKEN else 1)
    return out


def parse_dt(s):
    if not s:
        return None
    try:
        d = email.utils.parsedate_to_datetime(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        return datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except Exception:
        return None


def parse_feed(url):
    r = requests.get(url, headers=HEADERS, timeout=25)
    r.raise_for_status()
    content = r.content[:3_000_000]
    if b"<!ENTITY" in content:  # refuse XML entity tricks
        return []
    root = ET.fromstring(content)
    items = []
    for it in root.iter():
        if it.tag.split("}")[-1] not in ("item", "entry"):
            continue
        d = {"title": "", "link": "", "summary": "", "date": None}
        for ch in it:
            t = ch.tag.split("}")[-1]
            if t == "title":
                d["title"] = (ch.text or "").strip()
            elif t == "link":
                d["link"] = (ch.text or "").strip() or ch.attrib.get("href", "")
            elif t in ("description", "summary", "content", "encoded"):
                d["summary"] += " " + (ch.text or "")
            elif t in ("pubDate", "published", "updated", "date"):
                d["date"] = parse_dt(ch.text)
        items.append(d)
    return items


def article_links(html_text):
    return re.findall(r"""href=["'](https?://[^"'\s>]+)""", html_text or "")


def good_outbound_domain(host):
    rd = reg_domain(host)
    return bool(rd) and rd not in SKIP_DOMAINS and not any(
        host == s or host.endswith("." + s) for s in SKIP_DOMAINS)


def guess_site(name_norm, article_url):
    try:
        r = requests.get(article_url, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return ""
        for h in article_links(r.text[:600000]):
            host = domain(h)
            if not good_outbound_domain(host):
                continue
            label = re.sub(r"[^a-z0-9]", "", reg_domain(host).split(".")[0])
            if len(label) >= 4 and (name_norm in label or label in name_norm):
                return "https://" + reg_domain(host)
    except Exception:
        pass
    return ""


def news_candidates(by_norm):
    cutoff = datetime.now(timezone.utc) - timedelta(days=NEWS_DAYS)
    out, guesses = {}, 0
    for outlet, url in NEWS_FEEDS:
        try:
            items = parse_feed(url)
        except Exception as e:
            log(f"news feed failed ({outlet}):", str(e)[:80])
            continue
        n = 0
        for it in items:
            if it["date"] and it["date"] < cutoff:
                continue
            blob = it["title"] + " " + re.sub(r"<[^>]+>", " ", it["summary"])[:600]
            if not NEWS_KEYS.search(blob):
                continue
            names = []
            m = RAISE_RE.match(it["title"])
            if m:
                names.append(m.group(1).strip())
            names += TESTNET_RE.findall(it["title"])
            for name in names:
                norm = re.sub(r"[^a-z0-9]", "", name.lower())
                if len(norm) < 3 or norm in NAME_STOP or name.lower() in NAME_STOP:
                    continue
                p = by_norm.get(norm)
                site = (p or {}).get("url") or ""
                if not site and guesses < 25:
                    guesses += 1
                    site = guess_site(norm, it["link"])
                if not site:
                    continue
                key = (p["name"].lower() if p else norm)
                c = new_candidate(
                    name=p["name"] if p else name, key=key,
                    category=(p or {}).get("category") or "", description=(p or {}).get("description") or "",
                    url=site, twitter=(p or {}).get("twitter") or "", chains=(p or {}).get("chains") or [],
                    origin=outlet, proto=p, news=[(outlet, it["title"], it["link"])])
                if key in out:
                    out[key]["sources"].add(outlet)
                    out[key]["news"].append((outlet, it["title"], it["link"]))
                else:
                    out[key] = c
                n += 1
        log(f"news {outlet}: {len(items)} items, {n} project mentions")
    return out


def community_candidates():
    feeds = ([] if not USE_COMMUNITY else list(COMMUNITY_FEEDS)) + [("Custom", u) for u in EXTRA_FEEDS]
    out, seen_dom = {}, set()
    for label, url in feeds:
        try:
            items = parse_feed(url)
        except Exception as e:
            log(f"community feed failed ({label}):", str(e)[:80])
            continue
        n = 0
        for it in items:
            if it["date"] and it["date"] < datetime.now(timezone.utc) - timedelta(days=NEWS_DAYS):
                continue
            for h in article_links(it["summary"]):
                host = domain(h)
                if not good_outbound_domain(host):
                    continue
                rd = reg_domain(host)
                if rd in seen_dom or len(seen_dom) >= 60:
                    continue
                seen_dom.add(rd)
                nm = rd.split(".")[0]
                out[nm] = new_candidate(name=nm.capitalize(), key=nm, url="https://" + rd, origin=label,
                                        news=[(label, it["title"], it["link"])])
                n += 1
        log(f"community {label}: {len(items)} posts, {n} new domains")
    return out


# ------------------------------------------------------------------ security
def precheck_domain(url):
    """Cheap checks done BEFORE any request to the site. Returns (reject_reason, penalty, warns)."""
    host = domain(url)
    if not host:
        return "no domain", 0, []
    if domain_blocked(host):
        return "blacklisted domain (MetaMask/ScamSniffer)", 0, []
    rd = reg_domain(host)
    tld = rd.split(".")[-1]
    if tld in BAD_TLDS:
        return f"high-risk TLD .{tld}", 0, []
    label = rd.split(".")[0].replace("-", "")
    for w in HARD_SCAM_WORDS:
        if w in label:
            return "scam-like domain name", 0, []
    for b in BRANDS:
        if label == b:
            continue
        rest = label.replace(b, "")
        if difflib.SequenceMatcher(None, label, b).ratio() >= 0.86 or (
                b in label and any(w in rest for w in LURE_WORDS)):
            return f"lookalike of {b}", 0, []
    penalty, warns = 0, []
    if any(w in label for w in SOFT_SCAM_WORDS):
        penalty += 10
        warns.append("\u0627\u0633\u0645 \u062f\u0627\u0645\u0646\u0647 \u06a9\u0644\u0645\u0647\u200c\u06cc \u0648\u0633\u0648\u0633\u0647\u200c\u0627\u0646\u06af\u06cc\u0632 \u062f\u0627\u0631\u062f (claim/airdrop/reward)")
    if tld in RISKY_TLDS:
        penalty += 8
        warns.append(f"\u067e\u0633\u0648\u0646\u062f \u067e\u0631\u0631\u06cc\u0633\u06a9 .{tld}")
    if any(host == h or host.endswith("." + h) for h in FREE_HOSTS):
        penalty += 8
        warns.append("\u0633\u0627\u06cc\u062a \u0631\u0648\u06cc \u0647\u0627\u0633\u062a \u0631\u0627\u06cc\u06af\u0627\u0646 \u0627\u0633\u062a")
    return None, penalty, warns


def security_pre(c, page):
    """Checks that need the page. Returns dict(reject, penalty, warns, facts)."""
    out = {"reject": None, "penalty": 0, "warns": [], "facts": []}
    feat = page["features"]
    final = page["final"]
    fhost = domain(final)
    if not final.startswith("https://"):
        out["reject"] = "no HTTPS"
        return out
    if domain_blocked(fhost):
        out["reject"] = "redirects to a blacklisted domain"
        return out
    if reg_domain(fhost) != reg_domain(domain(c["url"])):
        out["penalty"] += 10
        out["warns"].append("\u0633\u0627\u06cc\u062a \u0628\u0647 \u062f\u0627\u0645\u0646\u0647\u200c\u06cc \u062f\u06cc\u06af\u0631\u06cc \u0631\u06cc\u062f\u0627\u06cc\u0631\u06a9\u062a \u0645\u06cc\u200c\u0634\u0648\u062f")
    if feat["downloads"]:
        out["reject"] = "software download link (exe/apk/zip)"
        return out
    if feat["seed_input"] or feat["scam_phrases"]:
        out["reject"] = "asks for seed phrase/private key or wallet verification"
        return out
    handles = feat["handles"]
    expected = (c["twitter"] or "").lower().lstrip("@")
    if not handles and not feat["has_chat"]:
        out["reject"] = "no social links on site"
        return out
    if expected and expected in handles:
        out["facts"].append(f"\u062a\u0648\u06cc\u06cc\u062a\u0631 \u0631\u0633\u0645\u06cc \u062f\u0631 \u062e\u0648\u062f \u0633\u0627\u06cc\u062a \u0644\u06cc\u0646\u06a9 \u0634\u062f\u0647 (@{expected})")
    elif expected and handles:
        out["penalty"] += 10
        out["warns"].append("\u062a\u0648\u06cc\u06cc\u062a\u0631 \u062b\u0628\u062a\u200c\u0634\u062f\u0647 \u0628\u0627 \u0644\u06cc\u0646\u06a9\u200c\u0647\u0627\u06cc \u0633\u0627\u06cc\u062a \u0646\u0645\u06cc\u200c\u062e\u0648\u0627\u0646\u062f")
    elif handles:
        out["facts"].append("\u062a\u0648\u06cc\u06cc\u062a\u0631 \u062f\u0631 \u0633\u0627\u06cc\u062a: @" + handles[0])
    else:
        out["penalty"] += 5
        out["warns"].append("\u0644\u06cc\u0646\u06a9 \u062a\u0648\u06cc\u06cc\u062a\u0631 \u062f\u0631 \u0633\u0627\u06cc\u062a \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f")
    if feat["approval"]:
        out["penalty"] += 15
        out["warns"].append("\u06a9\u062f \u0633\u0627\u06cc\u062a \u062f\u0631\u062e\u0648\u0627\u0633\u062a Approve \u06af\u0633\u062a\u0631\u062f\u0647 \u062f\u0627\u0631\u062f")
    if feat["eth_sign"]:
        out["penalty"] += 10
        out["warns"].append("\u06a9\u062f \u0633\u0627\u06cc\u062a \u0627\u0632 eth_sign \u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0645\u06cc\u200c\u06a9\u0646\u062f")
    out["facts"].append("\u0628\u062f\u0648\u0646 \u0644\u06cc\u0646\u06a9 \u062f\u0627\u0646\u0644\u0648\u062f \u0646\u0631\u0645\u200c\u0627\u0641\u0632\u0627\u0631/APK")
    out["facts"].append("\u0628\u062f\u0648\u0646 \u0641\u0631\u0645 \u0633\u06cc\u062f \u0641\u0631\u06cc\u0632/\u067e\u0631\u0627\u06cc\u0648\u062a\u200c\u06a9\u06cc")
    return out


def domain_age_days(host):
    rd = reg_domain(host)
    if rd in RDAP_CACHE:
        return RDAP_CACHE[rd]
    age = None
    try:
        r = requests.get(f"https://rdap.org/domain/{rd}", headers=HEADERS, timeout=20)
        if r.status_code == 200:
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    if d.tzinfo is None:
                        d = d.replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - d).days
                    break
    except Exception:
        pass
    RDAP_CACHE[rd] = age
    time.sleep(0.5)
    return age


def goplus_flags(addr):
    """Returns list of bad flags for an address (address + token security). None if service unreachable."""
    if addr in GOPLUS_CACHE:
        return GOPLUS_CACHE[addr]
    flags, reached = [], False
    try:
        d = get_json(f"{GOPLUS}/address_security/{addr}?chain_id=1", timeout=25)
        reached = True
        res = d.get("result") or {}
        flags += [k for k in BAD_ADDRESS_FLAGS if str(res.get(k)) == "1"]
    except Exception:
        pass
    time.sleep(1)
    for cid in GOPLUS_CHAINS:
        try:
            d = get_json(f"{GOPLUS}/token_security/{cid}?contract_addresses={addr}", timeout=25)
            reached = True
            info = (d.get("result") or {}).get(addr) or {}
            flags += [k for k in BAD_TOKEN_FLAGS if str(info.get(k)) == "1"]
        except Exception:
            pass
        time.sleep(1)
    GOPLUS_CACHE[addr] = sorted(set(flags)) if reached else None
    return GOPLUS_CACHE[addr]


def vt_check(host):
    """Returns (reject_reason or None, fact or None)."""
    if not VT_API_KEY:
        return None, None
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{reg_domain(host)}",
                         headers={"x-apikey": VT_API_KEY}, timeout=30)
        time.sleep(16)  # free key: 4 requests/minute
        if r.status_code != 200:
            return None, None
        st = r.json()["data"]["attributes"]["last_analysis_stats"]
        if st.get("malicious", 0) >= 1 or st.get("suspicious", 0) >= 2:
            return f"VirusTotal flags the domain (malicious={st.get('malicious')}, suspicious={st.get('suspicious')})", None
        return None, "VirusTotal: \u062f\u0627\u0645\u0646\u0647 \u067e\u0627\u06a9 \u0627\u0633\u062a"
    except Exception:
        return None, None


def gsb_check(url):
    if not GSB_API_KEY:
        return None, None
    try:
        body = {"client": {"clientId": "airdrop-scout", "clientVersion": "3.0"},
                "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                               "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": url}]}}
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                          json=body, timeout=25)
        if r.status_code != 200:
            return None, None
        if r.json().get("matches"):
            return "Google Safe Browsing flags the site", None
        return None, "Google Safe Browsing: \u067e\u0627\u06a9"
    except Exception:
        return None, None


def is_community_only(c):
    return c["sources"] and c["sources"] <= {"Reddit", "Medium", "Custom"}


def security_deep(c, feat):
    """Slower checks (network APIs). Returns (reject_reason or None, facts)."""
    facts = []
    host = domain(c["url"])
    free_host = any(host == h or host.endswith("." + h) for h in FREE_HOSTS)
    if free_host:
        if is_community_only(c):
            return "free-hosting site from a community-only source", facts
        facts.append("\u0633\u0646 \u062f\u0627\u0645\u0646\u0647 \u0642\u0627\u0628\u0644 \u0628\u0631\u0631\u0633\u06cc \u0646\u06cc\u0633\u062a (\u0647\u0627\u0633\u062a \u0631\u0627\u06cc\u06af\u0627\u0646)")
    else:
        age = domain_age_days(host)
        if age is None:
            if is_community_only(c):
                return "domain age unknown (community-only source)", facts
            facts.append("\u0633\u0646 \u062f\u0627\u0645\u0646\u0647 \u0646\u0627\u0645\u0634\u062e\u0635")
        else:
            if age < MIN_DOMAIN_AGE_DAYS:
                return f"domain too new ({age} days)", facts
            if is_community_only(c) and age < COMMUNITY_MIN_AGE_DAYS:
                return f"domain too new for a community-only source ({age} days)", facts
            facts.append(f"\u0633\u0646 \u062f\u0627\u0645\u0646\u0647: {age} \u0631\u0648\u0632")
    facts.append("\u0644\u06cc\u0633\u062a\u200c\u0647\u0627\u06cc \u0633\u06cc\u0627\u0647 (MetaMask \u0648 ScamSniffer): \u067e\u0627\u06a9")

    addrs = (feat or {}).get("addrs", [])[:3]
    if addrs:
        checked = 0
        for a in addrs:
            if a in BL["addrs"]:
                return f"contract {a[:10]}... is in the ScamSniffer blacklist", facts
            flags = goplus_flags(a)
            if flags:
                return f"contract {a[:10]}... flagged by GoPlus: {', '.join(flags)}", facts
            if flags is not None:
                checked += 1
        facts.append(f"{len(addrs)} \u0622\u062f\u0631\u0633 \u0642\u0631\u0627\u0631\u062f\u0627\u062f \u0631\u0648\u06cc \u0633\u0627\u06cc\u062a \u0628\u0631\u0631\u0633\u06cc \u0634\u062f (GoPlus): " +
                     ("\u067e\u0627\u06a9" if checked else "\u0633\u0631\u0648\u06cc\u0633 \u062f\u0631 \u062f\u0633\u062a\u0631\u0633 \u0646\u0628\u0648\u062f"))
    else:
        facts.append("\u0622\u062f\u0631\u0633 \u0642\u0631\u0627\u0631\u062f\u0627\u062f\u06cc \u0631\u0648\u06cc \u0635\u0641\u062d\u0647\u200c\u06cc \u0627\u0635\u0644\u06cc \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f")

    reason, fact = vt_check(host)
    if reason:
        return reason, facts
    if fact:
        facts.append(fact)
    reason, fact = gsb_check(c["url"])
    if reason:
        return reason, facts
    if fact:
        facts.append(fact)
    return None, facts


# ------------------------------------------------------------------ analysis
def cheap_reject(c):
    if c["category"].lower() in CAPITAL_CATEGORIES:
        return "needs capital (category)"
    if has_token(c["proto"]):
        return "token already exists"
    if not c["url"]:
        return "no official site to verify"
    r, _, _ = precheck_domain(c["url"])
    if r:
        return "SCAM-FILTER: " + r
    return None


def guess_layer(c, text):
    t = f"{c['category']} {c['description']} {text[:3000]}".lower()
    if "layer 2" in t or "rollup" in t or re.search(r"\bl2\b", t):
        return "L2"
    if c["category"].lower() == "chain" or "layer 1" in t or re.search(r"\bl1\b", t):
        return "L1"
    return "\u0627\u067e\u0644\u06cc\u06a9\u06cc\u0634\u0646 / \u067e\u0631\u0648\u062a\u06a9\u0644"


def community_share(text):
    m = re.search(r"(\d{1,2}(?:\.\d+)?)\s*%[^.]{0,60}(community|airdrop|users)", text)
    if m:
        return m.group(1) + "%"
    m = re.search(r"(community|airdrop)[^.]{0,60}?(\d{1,2}(?:\.\d+)?)\s*%", text)
    return (m.group(2) + "%") if m else None


def analyze(c, category_counts):
    reason = cheap_reject(c)
    if reason:
        return None, reason
    _, pre_penalty, pre_warns = precheck_domain(c["url"])
    page = fetch_page(c["url"])
    text = page["text"]
    if not page["ok"] or not text:
        return None, "site unreadable"

    sec = security_pre(c, page)
    if sec["reject"]:
        return None, "SCAM-FILTER: " + sec["reject"]

    if any(w in text for w in PAID_WORDS):
        return None, "paid/presale signal"
    if any(w in text for w in NO_AIRDROP_WORDS):
        return None, "site says no airdrop"
    capital_hits = sum(text.count(w) for w in CAPITAL_WORDS)
    free_hits = sum(text.count(w) for w in FREE_WORDS)
    confirmed = any(w in text for w in CONFIRM_WORDS)
    points = any(w in text for w in POINTS_WORDS)
    is_testnet = "testnet" in text or "devnet" in text or "testnet" in c["description"].lower() \
        or "GitHub" in c["sources"]
    if capital_hits >= 4 and free_hits <= 1:
        return None, "site looks capital-based"
    if STRICT_FREE and not (free_hits or points or confirmed):
        return None, "no free-task signal"
    if c["proto"] is None and not (confirmed or points):
        return None, "unknown project without airdrop signal"

    score = 0
    amount = c["amount"]
    if amount >= 20:
        score += 25
    elif amount >= 5:
        score += 18
    elif amount > 0:
        score += 10
    hits = [n for n in c["investors"] if any(t in n.lower() for t in TIER1_INVESTORS)]
    if hits:
        score += min(25, 12 + 4 * len(hits))
    if confirmed:
        score += 20
        status = "\u0646\u0634\u0627\u0646\u0647\u200c\u06cc \u0627\u06cc\u0631\u062f\u0631\u0627\u067e \u062f\u0631 \u0633\u0627\u06cc\u062a \u0631\u0633\u0645\u06cc \u062f\u06cc\u062f\u0647 \u0634\u062f (\u062a\u0627\u06cc\u06cc\u062f \u0646\u0647\u0627\u06cc\u06cc \u0628\u0627 \u062a\u0648\u06cc\u06cc\u062a\u0631 \u0631\u0633\u0645\u06cc)"
    elif points:
        score += 12
        status = "\u0628\u0631\u0646\u0627\u0645\u0647\u200c\u06cc \u067e\u0648\u06cc\u0646\u062a/\u062a\u0633\u06a9 \u062f\u0627\u0631\u062f (\u0627\u06cc\u0631\u062f\u0631\u0627\u067e \u062a\u0627\u06cc\u06cc\u062f \u0646\u0634\u062f\u0647)"
    else:
        status = "\u062a\u0627\u06cc\u06cc\u062f \u0646\u0634\u062f\u0647"
    if free_hits:
        score += 10
    if is_testnet:
        score += 8
    share = community_share(text)
    if share:
        score += 8
    cnt = category_counts.get(c["category"].lower(), 0)
    novel = bool(cnt and cnt <= 8)
    if novel:
        score += 10
    ts = c["fund_ts"]
    if ts:
        days = (datetime.now(timezone.utc).timestamp() - ts) / 86400
        score += 7 if days <= 120 else 3 if days <= 365 else 0
    elif c["origin"] in ("DefiLlama", "GitHub"):
        score += 7
    if c["gh_stars"] >= 100:
        score += 5
    extra_sources = max(0, len(c["sources"]) - 1)
    score += min(12, 6 * extra_sources)           # seen in several independent places
    score -= pre_penalty + sec["penalty"]
    score = max(0, min(score, 100))

    verdict = "\u0627\u0631\u0632\u0634 \u0648\u0642\u062a \u06af\u0630\u0627\u0634\u062a\u0646 \u0628\u0627\u0644\u0627" if score >= 75 else "\u0627\u0631\u0632\u0634 \u0628\u0631\u0631\u0633\u06cc \u062f\u0627\u0631\u062f" if score >= 60 else "\u0645\u062a\u0648\u0633\u0637"
    tok = has_token(c["proto"])
    return score, {
        **c, "score": score, "verdict": verdict, "status": status, "share": share,
        "novel": novel, "free": bool(free_hits), "testnet": is_testnet,
        "layer": guess_layer(c, text), "hits": hits, "feat": page["features"],
        "warns": pre_warns + sec["warns"], "sec_facts": sec["facts"],
        "token_status": "\u0647\u0646\u0648\u0632 \u062a\u0648\u06a9\u0646 \u0646\u062f\u0627\u0631\u062f" if tok is False else "\u0648\u0636\u0639\u06cc\u062a \u062a\u0648\u06a9\u0646 \u0646\u0627\u0645\u0634\u062e\u0635\u060c \u062f\u0633\u062a\u06cc \u0686\u06a9 \u06a9\u0646",
    }


def build_message(r):
    inv = "\u060c ".join(r["investors"][:6]) or "\u0646\u0627\u0645\u0634\u062e\u0635"
    srcs = "\u060c ".join(sorted(r["sources"])) or "\u0646\u0627\u0645\u0634\u062e\u0635"
    lines = [
        f"\U0001fa82 <b>{r['name']}</b>   (\u0627\u0645\u062a\u06cc\u0627\u0632 {r['score']}/100)",
        f"\U0001f4ca \u0646\u0638\u0631: {r['verdict']}",
        f"\U0001f52d \u067e\u06cc\u062f\u0627 \u0634\u062f\u0647 \u062f\u0631: {srcs}",
        f"\U0001f3f7 \u062d\u0648\u0632\u0647: {r['category'] or '\u0646\u0627\u0645\u0634\u062e\u0635'} | \u0644\u0627\u06cc\u0647: {r['layer']}"
        + (" | \U0001f9ea \u062a\u0633\u062a\u200c\u0646\u062a" if r["testnet"] else ""),
        f"\U0001f4b0 \u0622\u062e\u0631\u06cc\u0646 \u062c\u0630\u0628 \u0633\u0631\u0645\u0627\u06cc\u0647: {fmt_money(r['amount'])}"
        + (f" ({r['round']}) \u062f\u0631 {datetime.fromtimestamp(r['fund_ts'], timezone.utc):%Y-%m-%d}"
           if r["fund_ts"] else ""),
        f"\U0001f3e6 \u0633\u0631\u0645\u0627\u06cc\u0647\u200c\u06af\u0630\u0627\u0631\u0647\u0627: {inv}",
        f"\U0001f381 \u0627\u06cc\u0631\u062f\u0631\u0627\u067e: {r['status']}",
        f"\U0001fa99 \u062a\u0648\u06a9\u0646: {r['token_status']}",
        f"\U0001f465 \u0633\u0647\u0645 \u062c\u0627\u0645\u0639\u0647: {r['share'] or '\u067e\u06cc\u062f\u0627 \u0646\u0634\u062f'}",
        f"\U0001f195 \u0646\u0648\u0622\u0648\u0631\u06cc: {'\u062d\u0648\u0632\u0647\u200c\u06cc \u06a9\u0645\u200c\u0631\u0642\u06cc\u0628' if r['novel'] else '\u062d\u0648\u0632\u0647\u200c\u06cc \u0634\u0644\u0648\u063a\u200c\u062a\u0631'}",
        f"\U0001f193 \u0631\u0627\u06cc\u06af\u0627\u0646: {'\u0646\u0634\u0627\u0646\u0647\u200c\u06cc \u062a\u0633\u06a9 \u0631\u0627\u06cc\u06af\u0627\u0646 \u062f\u06cc\u062f\u0647 \u0634\u062f\u060c \u0628\u062f\u0648\u0646 \u0646\u0634\u0627\u0646\u0647\u200c\u06cc \u067e\u0631\u062f\u0627\u062e\u062a' if r['free'] else '\u0645\u0634\u062e\u0635 \u0646\u06cc\u0633\u062a'}",
        "",
        "\U0001f6e1 <b>\u0628\u0631\u0631\u0633\u06cc \u0627\u0645\u0646\u06cc\u062a\u06cc (\u0647\u0645\u0647 \u0642\u0628\u0648\u0644 \u0634\u062f):</b>",
    ]
    for f in r["sec_facts"] + r["deep_facts"]:
        lines.append(f"  \u2705 {f}")
    for w in r["warns"]:
        lines.append(f"  \u26a0\ufe0f {w}")
    lines.append("")
    if r["url"]:
        lines.append(f"\U0001f310 {r['url']}")
    if r["twitter"]:
        lines.append(f"\U0001f426 https://twitter.com/{r['twitter']}")
    if r["gh_url"]:
        lines.append(f"\U0001f4bb {r['gh_url']} (\u2b50 {r['gh_stars']}\u060c \u0633\u0627\u062e\u062a {r['gh_created']})")
    for outlet, title, link in (r.get("news") or [])[:2]:
        lines.append(f"\U0001f4f0 {outlet}: {link}")
    if r["source"]:
        lines.append(f"\U0001f50e \u0645\u0646\u0628\u0639 \u062c\u0630\u0628 \u0633\u0631\u0645\u0627\u06cc\u0647: {r['source']}")
    lines.append("\u26a0\ufe0f \u067e\u0627\u06a9 \u0628\u0648\u062f\u0646 \u062f\u0631 \u0627\u06cc\u0646 \u0628\u0631\u0631\u0633\u06cc\u200c\u0647\u0627 \u062a\u0636\u0645\u06cc\u0646 \u0646\u06cc\u0633\u062a. \u0644\u06cc\u0646\u06a9 \u0631\u0627 \u0645\u0633\u062a\u0642\u06cc\u0645 \u0628\u0627\u0632 \u0646\u06a9\u0646\u060c \u0627\u0648\u0644 \u0633\u0627\u06cc\u062a \u0631\u0633\u0645\u06cc \u0631\u0627 \u0627\u0632 \u062a\u0648\u06cc\u06cc\u062a\u0631 \u062e\u0648\u062f \u067e\u0631\u0648\u0698\u0647 \u062a\u0627\u06cc\u06cc\u062f \u06a9\u0646 \u0648 \u0641\u0642\u0637 \u0628\u0627 \u0648\u0644\u062a \u062c\u062f\u0627 \u0648 \u06a9\u0645\u200c\u0645\u0648\u062c\u0648\u062f\u06cc \u062a\u0633\u062a \u06a9\u0646. \u0647\u0631\u06af\u0632 \u0633\u06cc\u062f \u0641\u0631\u06cc\u0632 \u0646\u062f\u0647 \u0648 \u0647\u06cc\u0686 \u0647\u0632\u06cc\u0646\u0647\u200c\u0627\u06cc \u0628\u0631\u0627\u06cc \u0627\u06cc\u0631\u062f\u0631\u0627\u067e \u0646\u067e\u0631\u062f\u0627\u0632.")
    return "\n".join(lines)


# ------------------------------------------------------------------ main flows
def run_once():
    seen = load_state()
    load_blocklists()
    log("fetching DefiLlama data...")
    protocols = get_json("https://api.llama.fi/protocols")
    try:
        raises = get_json("https://api.llama.fi/raises").get("raises", [])
    except Exception as e:
        log("raises feed unavailable (now paid), using free fallback:", str(e)[:60])
        raises = []
    if not raises:
        for p in protocols:
            rs = p.get("raises")
            if isinstance(rs, list):
                for r in rs:
                    raises.append(convert_raise(r, p["name"], p))
    by_name = {p["name"].lower(): p for p in protocols}
    by_norm = {re.sub(r"[^a-z0-9]", "", p["name"].lower()): p for p in protocols}
    by_domain = {domain(p.get("url") or ""): p for p in protocols if p.get("url")}
    category_counts = Counter((p.get("category") or "").lower() for p in protocols)

    pool, dom_idx = {}, {}
    for src in (funding_candidates(raises, by_name), listing_candidates(protocols)):
        for c in src.values():
            add_cand(pool, dom_idx, c)
    if USE_GITHUB:
        log("scanning GitHub...")
        for c in github_candidates(by_domain).values():
            add_cand(pool, dom_idx, c)
    if USE_NEWS:
        log("scanning crypto news feeds...")
        for c in news_candidates(by_norm).values():
            add_cand(pool, dom_idx, c)
    if USE_COMMUNITY or EXTRA_FEEDS:
        log("scanning community feeds...")
        for c in community_candidates().values():
            add_cand(pool, dom_idx, c)
    log("sources per candidate:", dict(Counter(len(c["sources"]) for c in pool.values())))

    todo = [c for k, c in pool.items() if k not in seen]
    log(f"{len(todo)} new candidates; screening...")
    need = [c for c in todo if not c["fund_ts"] and c["proto"] and not cheap_reject(c)][:MAX_DETAIL]
    if need:
        log(f"reading funding history for {len(need)} projects (free endpoint)...")
        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(enrich_funding, need))
    urls = [c["url"] for c in todo if not cheap_reject(c)]
    log(f"reading {len(urls)} official sites (blacklisted/lookalike sites are never opened)...")
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(fetch_page, urls))

    passed, rejected, scams = [], Counter(), []
    for c in todo:
        score, res = analyze(c, category_counts)
        if score is None:
            rejected[res] += 1
            if res.startswith("SCAM-FILTER"):
                scams.append(f"{c['name']} ({res[13:]})")
        elif score >= MIN_SCORE:
            passed.append(res)
    log("rejected:", dict(rejected))
    if scams:
        log("blocked as scam/unsafe:", "; ".join(scams[:25]))

    passed.sort(key=lambda r: r["score"], reverse=True)
    log(f"{len(passed)} projects passed filters; running deep security checks...")
    sent, tried = 0, 0
    for r in passed:
        if sent >= MAX_PER_RUN or tried >= MAX_PER_RUN * 3:
            break
        tried += 1
        reason, facts = security_deep(r, r["feat"])
        if reason:
            log(f"deep security rejected {r['name']}: {reason}")
            seen.add(r["key"])
            continue
        r["deep_facts"] = facts
        msg = build_message(r)
        tg_send(msg)
        remember_message(msg)
        seen.add(r["key"])
        sent += 1
        time.sleep(1)
    save_state(seen)
    STATUS["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    STATUS["last_sent"] = sent
    log(f"done: {sent} sent")
    return sent


def check_text(url):
    if not url.startswith("http"):
        url = "https://" + url
    load_blocklists()
    host = domain(url)
    c = new_candidate(name=host, key=host, url=url, origin="manual")
    lines = [f"\u0628\u0631\u0631\u0633\u06cc: {url}", ""]
    reason, penalty, warns = precheck_domain(url)
    if reason:
        lines.append(f"\u274c \u062e\u0637\u0631\u0646\u0627\u06a9: {reason} (\u0633\u0627\u06cc\u062a \u0628\u0627\u0632 \u0646\u0634\u062f)")
        return "\n".join(lines)
    page = fetch_page(url)
    if not page["ok"]:
        lines.append("\u26a0\ufe0f \u0633\u0627\u06cc\u062a \u0628\u0627\u0632 \u0646\u0634\u062f \u06cc\u0627 \u067e\u0627\u0633\u062e \u0646\u062f\u0627\u062f")
        return "\n".join(lines)
    sec = security_pre(c, page)
    if sec["reject"]:
        lines.append(f"\u274c \u062e\u0637\u0631\u0646\u0627\u06a9: {sec['reject']}")
        return "\n".join(lines)
    deep_reason, facts = security_deep(c, page["features"])
    if deep_reason:
        lines.append(f"\u274c \u062e\u0637\u0631\u0646\u0627\u06a9: {deep_reason}")
        return "\n".join(lines)
    lines += ["\u2705 " + f for f in sec["facts"] + facts]
    lines += ["\u26a0\ufe0f " + w for w in warns + sec["warns"]]
    lines += ["", "\u0646\u062a\u06cc\u062c\u0647: \u0645\u0648\u0631\u062f \u062e\u0637\u0631\u0646\u0627\u06a9\u06cc \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f\u060c \u0648\u0644\u06cc \u0627\u06cc\u0646 \u062a\u0636\u0645\u06cc\u0646 \u0627\u0645\u0646\u06cc\u062a \u0646\u06cc\u0633\u062a."]
    return "\n".join(lines)


def check_url(url):
    print("\n" + check_text(url))


def run_locked(blocking=True):
    """Run one scan; never two at the same time. Returns number sent, or None if busy."""
    if not RUN_LOCK.acquire(blocking=blocking):
        return None
    try:
        return run_once()
    finally:
        RUN_LOCK.release()


HELP_TEXT = (
    "\u0633\u0644\u0627\u0645! \u0645\u0646 \u0631\u0628\u0627\u062a \u0627\u06cc\u0631\u062f\u0631\u0627\u067e \u0647\u0633\u062a\u0645 \u0648 \u0641\u0639\u0627\u0644\u0645.\n\n"
    "\u062f\u0633\u062a\u0648\u0631\u0647\u0627:\n"
    "/latest : \u0622\u062e\u0631\u06cc\u0646 \u067e\u0631\u0648\u0698\u0647\u200c\u0647\u0627\u06cc\u06cc \u06a9\u0647 \u0641\u0631\u0633\u062a\u0627\u062f\u0647\u200c\u0627\u0645\n"
    "/scan : \u0647\u0645\u06cc\u0646 \u0627\u0644\u0627\u0646 \u06cc\u06a9 \u0627\u0633\u06a9\u0646 \u062c\u062f\u06cc\u062f \u0627\u0646\u062c\u0627\u0645 \u0628\u062f\u0647\n"
    "/check \u0644\u06cc\u0646\u06a9 : \u0628\u0631\u0631\u0633\u06cc \u0627\u0645\u0646\u06cc\u062a\u06cc \u06cc\u06a9 \u0644\u06cc\u0646\u06a9\n"
    "/status : \u0648\u0636\u0639\u06cc\u062a \u0631\u0628\u0627\u062a\n\n"
    "\u062e\u0648\u062f\u0645 \u0647\u0645 \u0628\u0647\u200c\u0635\u0648\u0631\u062a \u062e\u0648\u062f\u06a9\u0627\u0631 \u0647\u0631 \u0686\u0646\u062f \u0633\u0627\u0639\u062a \u0686\u06a9 \u0645\u06cc\u200c\u06a9\u0646\u0645 \u0648 \u0641\u0642\u0637 \u0648\u0642\u062a\u06cc \u067e\u0631\u0648\u0698\u0647\u200c\u06cc \u062a\u0627\u06cc\u06cc\u062f\u0634\u062f\u0647 \u067e\u06cc\u062f\u0627 \u0634\u0648\u062f \u067e\u06cc\u0627\u0645 \u0645\u06cc\u200c\u0641\u0631\u0633\u062a\u0645."
)


def handle_command(text):
    cmd, _, arg = text.partition(" ")
    cmd = cmd.lower().split("@")[0]
    if cmd in ("/start", "/help"):
        tg_send(HELP_TEXT, html=False)
    elif cmd == "/status":
        tg_send(f"\u2705 \u0631\u0628\u0627\u062a \u0641\u0639\u0627\u0644 \u0627\u0633\u062a\n\u0622\u062e\u0631\u06cc\u0646 \u0627\u0633\u06a9\u0646: {STATUS['last_run'] or '\u0647\u0646\u0648\u0632 \u0627\u0646\u062c\u0627\u0645 \u0646\u0634\u062f\u0647'}\n"
                f"\u067e\u06cc\u0627\u0645\u200c\u0647\u0627\u06cc \u0622\u062e\u0631\u06cc\u0646 \u0627\u0633\u06a9\u0646: {STATUS['last_sent']}\n\u067e\u0631\u0648\u0698\u0647\u200c\u0647\u0627\u06cc \u062f\u06cc\u062f\u0647\u200c\u0634\u062f\u0647: {len(load_state())}", html=False)
    elif cmd == "/latest":
        try:
            data = json.loads(LAST_FILE.read_text(encoding="utf-8")) if LAST_FILE.exists() else []
        except Exception:
            data = []
        if not data:
            tg_send("\u0647\u0646\u0648\u0632 \u067e\u0631\u0648\u0698\u0647\u200c\u0627\u06cc \u0646\u0641\u0631\u0633\u062a\u0627\u062f\u0647\u200c\u0627\u0645. \u0628\u0627 /scan \u06cc\u06a9 \u0627\u0633\u06a9\u0646 \u062c\u062f\u06cc\u062f \u0628\u0632\u0646.", html=False)
        for m in data[-5:]:
            tg_send(m)
            time.sleep(1)
    elif cmd == "/scan":
        if RUN_LOCK.locked():
            tg_send("\u06cc\u06a9 \u0627\u0633\u06a9\u0646 \u062f\u0631 \u062d\u0627\u0644 \u0627\u0646\u062c\u0627\u0645 \u0627\u0633\u062a\u060c \u0686\u0646\u062f \u062f\u0642\u06cc\u0642\u0647 \u062f\u06cc\u06af\u0631 /latest \u0628\u0632\u0646.", html=False)
            return
        tg_send("\u0627\u0633\u06a9\u0646 \u0634\u0631\u0648\u0639 \u0634\u062f. \u0686\u0646\u062f \u062f\u0642\u06cc\u0642\u0647 \u0635\u0628\u0631 \u06a9\u0646...", html=False)

        def job():
            n = run_locked(blocking=False)
            if n == 0:
                tg_send("\u0627\u0633\u06a9\u0646 \u062a\u0645\u0627\u0645 \u0634\u062f. \u067e\u0631\u0648\u0698\u0647\u200c\u06cc \u062c\u062f\u06cc\u062f\u06cc \u06a9\u0647 \u0647\u0645\u0647\u200c\u06cc \u0641\u06cc\u0644\u062a\u0631\u0647\u0627 \u0631\u0627 \u0631\u062f \u06a9\u0646\u062f \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f.", html=False)
        threading.Thread(target=job, daemon=True).start()
    elif cmd == "/check":
        if not arg.strip():
            tg_send("\u0645\u062b\u0627\u0644: /check https://example.com", html=False)
            return

        def job():
            try:
                tg_send(check_text(arg.strip()), html=False)
            except Exception as e:
                tg_send(f"\u062e\u0637\u0627 \u062f\u0631 \u0628\u0631\u0631\u0633\u06cc: {e}", html=False)
        threading.Thread(target=job, daemon=True).start()
    else:
        tg_send(HELP_TEXT, html=False)


def telegram_listener():
    """Answers commands from YOU only (messages from any other chat are ignored)."""
    log("telegram commands active: /start /latest /scan /check /status")
    offset = None
    while True:
        try:
            r = requests.get(f"https://api.telegram.org/bot{TG_TOKEN}/getUpdates",
                             params={"timeout": 30, "offset": offset}, timeout=45)
            for u in r.json().get("result", []):
                offset = u["update_id"] + 1
                m = u.get("message") or {}
                if str(m.get("chat", {}).get("id")) != str(TG_CHAT_ID):
                    continue
                text = (m.get("text") or "").strip()
                if text.startswith("/"):
                    handle_command(text)
        except Exception as e:
            log("telegram listener error:", str(e)[:80])
            time.sleep(10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--check", metavar="URL", help="security-check a single link")
    args = ap.parse_args()
    if args.check:
        check_url(args.check)
        return
    if args.once:
        run_once()
        return
    if TG_TOKEN and TG_CHAT_ID:
        threading.Thread(target=telegram_listener, daemon=True).start()
    while True:
        try:
            run_locked(blocking=True)
        except Exception as e:
            log("run failed:", e)
        time.sleep(CHECK_EVERY_HOURS * 3600)


if __name__ == "__main__":
    sys.exit(main())
