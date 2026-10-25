# fake200

[![CI](https://github.com/wdfdsyhb/fake200/actions/workflows/tests.yml/badge.svg)](https://github.com/wdfdsyhb/fake200/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

> Verify each URL in a list with vendor fingerprints and a random-path baseline, separating real 200s from WAF block pages and CMS soft-404s.
>
> 🇨🇳 中文文档: [README.md](README.md)

## The problem

The most common trap in batch asset scanning: a WAF returns `200 + block page` for **any path**, and the script counts the block page as a valid hit; CMS soft-404s (a "page not found" served with 200) pollute results the same way. You only find out when you click through manually and see a page full of junk data.

## How it works

For each target URL (1 request) + a random-path baseline on the same origin (2 requests by default):

1. **Vendor fingerprints**: the response body is matched against 12 groups of known WAF block-page signatures (Cloudflare / Aliyun / Tencent / SafeLine / SafeDog / Yunaq / BaoTa / Baidu Cloud Accelerate / Incapsula / Akamai / F5 / ModSecurity). FAKE200 is only called when the target **and** the random-path baseline both match, so a page that merely mentions a vendor's name won't trigger a false positive;
2. **Random-path baseline**: request paths like `/f2k-<random>.html` that cannot exist on the same origin. A real site returns 404/403; a 200 that "looks like the target" means there's a wall;
3. **Similarity grading**: after normalization (strip digits, collapse whitespace, lowercase), compare against the baseline. `>= 0.90` → `FAKE200`; `0.70–0.90` → `SUSPECT` (usually CMS soft-404 / shared template); otherwise `OK`.

This is a heuristic — false positives and false negatives both happen. Manually verify important targets.

## Install & usage

```bash
pip install requests
python fake200.py https://target.com/admin            # single URL
python fake200.py -f urls.txt -t 20 -o result.json    # batch + concurrency + export
cat urls.txt | python fake200.py -                    # stdin
python fake200.py https://site.com --proxy http://127.0.0.1:8080 --insecure
```

Example output (real run):

```
[ok]       200      577  https://example.com  | baseline status: 404

1 targets | FAKE200=0 SUSPECT=0 OK=1 SKIP/ERROR=0
```

What a hit looks like:

```
[FAKE200]  200    51234  http://t1.com/admin  | vendor=cloudflare on target & baseline
[SUSPECT]  200    18220  http://t3.com/item/1 | baseline sim=0.82 (soft-404/shared template?)
```

## Verdicts

| verdict | meaning |
|---|---|
| `FAKE200` | High confidence: vendor fingerprint hits on both target and baseline, or baseline similarity >= 0.90 |
| `SUSPECT` | Suspected: similarity 0.70–0.90 (soft-404 / template page), or only the target matches keywords |
| `OK` | The 200 looks real (baseline is 404/403, or content clearly differs) |
| `SKIP` / `ERROR` | Non-200 status / network failure |

## How it relates to similar tools

- `wafw00f`: identifies the WAF type; doesn't answer "is this 200 of yours fake"
- `httpx`: liveness probing; counts block pages as alive by default
- `ffuf` / `gobuster` / `feroxbuster`: have built-in wildcard calibration, but only serve their own scans
- `fake200`: an independent layer of "result credibility checking"; input is any URL list (httpx output, crawler output, batch scan artifacts)

## Options

| option | default | description |
|---|---|---|
| `-t` | 10 | concurrency |
| `--baselines` | 2 | random baseline paths per target |
| `--threshold` | 0.90 | FAKE200 similarity threshold |
| `--timeout` | 10 | per-request timeout (seconds) |
| `--proxy` / `--insecure` | - | use a proxy / skip TLS verification |
| `-o` / `--csv` | - | export JSON / CSV |
| `-q` | - | only output FAKE200 / SUSPECT / ERROR |
| `--fail` | - | exit code 2 when FAKE200 is found, for scripts |

## Limitations

- Block pages that are purely client-rendered with no body signatures can't be detected; most JS challenge pages still carry server-side markers in the source and can be caught
- Similarity is based on the first 6000 normalized characters; very long pages are compared by their head only
- Each target costs an extra `--baselines` requests; watch your traffic on large batches
- Sends no payloads, GET probing only

## Authorized use only

Use only against assets you are authorized to test. I take no responsibility for abuse.

## Recon toolkit

- [scan-diff](https://github.com/wdfdsyhb/scan-diff) — snapshot diff, keeps an eye on new assets each scan turns up
- [fw-diff](https://github.com/wdfdsyhb/fw-diff) — firmware rootfs diff for version comparison and forensics

## License

MIT
