#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fake200 - detect WAF fake-200 block pages / soft-404s that poison batch recon.

A WAF block page usually answers 200 on ANY path, and many CMS soft-404s do the
same with their site template. So before trusting a target's 200, fetch a few
random paths on the same origin and compare: a near-identical page means the
"200" is a wall, not a page.

Single-file CLI. Requires only `requests`.
"""

import argparse
import csv
import difflib
import io
import json
import re
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.stderr.write("fake200 needs requests: pip install requests\n")
    sys.exit(1)

__version__ = "0.1.0"

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

BODY_CAP = 200_000   # bytes read per response
SIM_CAP = 6_000      # chars fed into the similarity check
HIGH_SIM = 0.90      # >= -> FAKE200
MED_SIM = 0.70       # >= -> SUSPECT

# Vendor block-page markers. Only trusted when the same vendor page also shows
# up on a random baseline path (see classify), so a page merely *mentioning*
# "akamai" is not enough by itself.
VENDOR_SIGS = [
    ("cloudflare",     re.compile(r"(attention required|checking your browser|__cf_chl|cf-chl|please complete the security check)", re.I)),
    ("aliyun-waf",     re.compile(r"(errors\.aliyun\.com|yundun|aliyun[- ]?waf|您的访问请求被拦截)", re.I)),
    ("tencent-waf",    re.compile(r"(waf\.tencent|tencent[- ]?waf)", re.I)),
    ("safeline",       re.compile(r"(safeline|雷池)", re.I)),
    ("safedog",        re.compile(r"(safedog|安全狗)", re.I)),
    ("yunaq",          re.compile(r"(yunaq|创宇盾|知道创宇)", re.I)),
    ("baidu-yunjiasu", re.compile(r"(百度云加速|su\.baidu\.com)", re.I)),
    ("btpanel",        re.compile(r"(宝塔网站防火墙|bt\.cn)", re.I)),
    ("incapsula",      re.compile(r"(incapsula|_incap_)", re.I)),
    ("akamai",         re.compile(r"akamai", re.I)),
    ("f5",             re.compile(r"(the requested url was rejected|support\.f5\.com)", re.I)),
    ("modsecurity",    re.compile(r"(mod_security|modsecurity)", re.I)),
]

# Generic keywords: too ambiguous to stand alone -> SUSPECT, never FAKE200.
GENERIC_SIGS = [
    ("captcha", re.compile(r"captcha|验证码", re.I)),
    ("blocked", re.compile(r"(request blocked|access denied|请求被(拦截|拒绝)|访问被(拒绝|禁止))", re.I)),
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
DIGITS_RE = re.compile(r"\d+")
WS_RE = re.compile(r"\s+")
RAND_EXTS = ("", ".html", ".php", ".jsp", ".aspx")

TAGS = {"FAKE200": "[FAKE200]", "SUSPECT": "[SUSPECT]", "OK": "[ok]",
        "SKIP": "[skip]", "ERROR": "[error]"}

CSV_COLS = ["url", "status", "verdict", "sim", "vendor", "title", "note", "length"]


def safe_path(p):
    """Normalize a user-supplied I/O path and reject parent-directory escapes.

    I/O stays limited to the exact path the user named on the command line;
    traversal components ('..') are refused outright.
    """
    path = Path(p).expanduser()
    if ".." in path.parts:
        raise SystemExit(f"fake200: refusing path with '..': {p}")
    return path.resolve()


def rand_path():
    token = secrets.token_hex(8)
    return f"/f2k-{token}{secrets.choice(RAND_EXTS)}"


def normalize(body, cap=SIM_CAP):
    text = (body or "")[:cap].lower()
    text = DIGITS_RE.sub("#", text)
    return WS_RE.sub(" ", text)


def title_of(body):
    m = TITLE_RE.search(body or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def similarity(a, b, cap=SIM_CAP):
    a, b = a[:cap], b[:cap]
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def scan_vendor(body):
    for name, rx in VENDOR_SIGS:
        if rx.search(body):
            return name
    return ""


def scan_generic(body):
    return [name for name, rx in GENERIC_SIGS if rx.search(body)]


def classify(target, baselines, high=HIGH_SIM, med=MED_SIM):
    """Pure decision logic. target/baselines are dicts as returned by fetch()."""
    if not target.get("ok"):
        return {"verdict": "ERROR", "note": target.get("error") or "request failed",
                "vendor": "", "sim": None}
    if target.get("status") != 200:
        return {"verdict": "SKIP", "note": f"status={target.get('status')}",
                "vendor": "", "sim": None}

    body = target.get("body") or ""
    t_vendor = scan_vendor(body)
    ok_bases = [b for b in baselines if b.get("ok")]
    base200 = [b for b in ok_bases if b.get("status") == 200]
    base_vendors = {v for b in ok_bases if (v := scan_vendor(b.get("body") or ""))}

    best = None
    if base200:
        tn = normalize(body)
        best = max(similarity(tn, normalize(b.get("body") or "")) for b in base200)

    if t_vendor and t_vendor in base_vendors:
        return {"verdict": "FAKE200",
                "note": f"vendor={t_vendor} on target & baseline",
                "vendor": t_vendor,
                "sim": round(best, 2) if best is not None else None}
    if best is not None and best >= high:
        extra = f", vendor on baseline: {','.join(sorted(base_vendors))}" if base_vendors else ""
        return {"verdict": "FAKE200", "note": f"baseline also 200, sim={best:.2f}{extra}",
                "vendor": t_vendor, "sim": round(best, 2)}
    if best is not None and best >= med:
        return {"verdict": "SUSPECT",
                "note": f"baseline sim={best:.2f} (soft-404/shared template?)",
                "vendor": t_vendor, "sim": round(best, 2)}
    if t_vendor:
        return {"verdict": "SUSPECT", "note": f"vendor keyword on target only: {t_vendor}",
                "vendor": t_vendor, "sim": None}
    generic = scan_generic(body)
    if generic:
        return {"verdict": "SUSPECT", "note": f"keywords: {','.join(generic)}",
                "vendor": "", "sim": None}

    if base_vendors:
        note = "waf on baseline: " + ",".join(sorted(base_vendors)) + " (target differs)"
    elif base200:
        note = f"baseline differs (sim<={best:.2f})"
    elif ok_bases:
        note = "baseline status: " + ",".join(str(b.get("status")) for b in ok_bases)
    else:
        note = "no baseline reachable"
    return {"verdict": "OK", "note": note,
            "vendor": t_vendor or "",
            "sim": round(best, 2) if best is not None else None}


def fetch(session, url, timeout, verify):
    try:
        r = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
        body = r.content[:BODY_CAP].decode("utf-8", "replace")
        return {"ok": True, "status": r.status_code, "body": body, "url": str(r.url)}
    except requests.RequestException as e:
        return {"ok": False, "status": None, "body": "", "url": url,
                "error": type(e).__name__}


def check_target(session, url, args):
    p = urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    verify = not args.insecure
    target = fetch(session, url, args.timeout, verify)
    if target["ok"] and target["status"] == 200:
        bases = [fetch(session, origin + rand_path(), args.timeout, verify)
                 for _ in range(max(1, args.baselines))]
    else:
        bases = []
    out = {"url": url, "status": target.get("status"),
           "length": len(target.get("body") or ""),
           "title": title_of(target.get("body") or "")}
    out.update(classify(target, bases, high=args.threshold))
    return out


def load_targets(args):
    lines = list(args.targets)
    if args.file:
        text = safe_path(args.file).read_text(encoding="utf-8", errors="replace")
        lines.extend(text.splitlines())
    if "-" in lines:
        lines = [x for x in lines if x != "-"] + sys.stdin.read().splitlines()
    urls = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "://" not in s:
            s = f"{args.default_scheme}://{s}"
        urls.append(s)
    return urls


def format_row(r):
    tag = TAGS.get(r["verdict"], "[?]")
    status = "-" if r.get("status") is None else str(r["status"])
    return f"{tag:<10} {status:>3} {r.get('length') or 0:>8}  {r['url']}  | {r.get('note', '')}"


def to_csv(results):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for r in results:
        w.writerow([r.get(c, "") for c in CSV_COLS])
    return buf.getvalue()


EXAMPLES = """examples:
  python fake200.py https://target.com/admin
  python fake200.py -f urls.txt -t 20 -o result.json --csv result.csv
  cat urls.txt | python fake200.py -
  python fake200.py https://site.com --proxy http://127.0.0.1:8080 --insecure
"""


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fake200", description=__doc__.strip().splitlines()[0],
        epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="URLs (missing scheme => --default-scheme); '-' = stdin")
    ap.add_argument("-f", "--file", help="target list file, one URL per line (# comments ok)")
    ap.add_argument("-o", "--out", help="write full JSON results to file")
    ap.add_argument("--csv", dest="csv_out", help="write CSV results to file")
    ap.add_argument("-t", "--threads", type=int, default=10, help="concurrent targets (default 10)")
    ap.add_argument("--baselines", type=int, default=2, help="random baseline paths per target (default 2)")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout seconds (default 10)")
    ap.add_argument("--threshold", type=float, default=HIGH_SIM, help=f"similarity >= this => FAKE200 (default {HIGH_SIM})")
    ap.add_argument("--default-scheme", default="http", help="scheme added to scheme-less targets (default http)")
    ap.add_argument("--proxy", help="proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("-A", "--user-agent", default=DEFAULT_UA)
    ap.add_argument("-H", "--header", action="append", default=[], metavar="K: V",
                    help="extra header, repeatable")
    # --insecure is intentional: recon against self-signed/authorized targets
    # behind an intercepting proxy needs it.
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print FAKE200/SUSPECT/ERROR rows")
    ap.add_argument("--fail", action="store_true", help="exit code 2 if any FAKE200 found")
    ap.add_argument("-V", "--version", action="version", version=f"fake200 {__version__}")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    urls = load_targets(args)
    if not urls:
        ap.error("no targets")

    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    })
    for h in args.header:
        k, _, v = h.partition(":")
        session.headers[k.strip()] = v.strip()
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    adapter = requests.adapters.HTTPAdapter(pool_connections=max(1, args.threads),
                                            pool_maxsize=max(1, args.threads))
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = [ex.submit(check_target, session, u, args) for u in urls]
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            if not args.quiet or r["verdict"] in ("FAKE200", "SUSPECT", "ERROR"):
                print(format_row(r), flush=True)

    results.sort(key=lambda r: r["url"])
    n_fake = sum(1 for r in results if r["verdict"] == "FAKE200")
    n_susp = sum(1 for r in results if r["verdict"] == "SUSPECT")
    n_ok = sum(1 for r in results if r["verdict"] == "OK")
    print(f"\n{len(results)} targets | FAKE200={n_fake} SUSPECT={n_susp} OK={n_ok} "
          f"SKIP/ERROR={len(results) - n_fake - n_susp - n_ok}", file=sys.stderr)

    if args.out:
        payload = json.dumps(results, ensure_ascii=False, indent=2)
        safe_path(args.out).write_text(payload, encoding="utf-8")
    if args.csv_out:
        safe_path(args.csv_out).write_text(to_csv(results), encoding="utf-8")
    return 2 if (args.fail and n_fake) else 0


if __name__ == "__main__":
    sys.exit(main())
