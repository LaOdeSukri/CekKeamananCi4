#!/usr/bin/env python3
"""
sukri.py
Audit non-destruktif untuk aplikasi CI4 / web lokal.
Hasil: CSV dengan status keamanan tiap route.

Fitur:
 - Auto crawl jika tidak ada urls.txt
 - Cek status HTTP & header keamanan
 - Analisis form (file upload, XSS refleksi, SQLi indikasi)
 - Output CSV: route, url, status, severity, issues, link
"""

import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import time, json, os, sys, argparse
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===== Default Config =====
DEFAULT_BASE = "http://localhost:8080"
DEFAULT_INPUT = "urls.txt"
DEFAULT_OUTPUT = "audit_output.csv"
DEFAULT_TIMEOUT = 10
MAX_WORKERS = 10
MAX_CRAWL_PAGES = 50
MAX_CRAWL_DEPTH = 2

USER_AGENT = "CI4RoutesAudit/1.0"
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

REFLECT_PAYLOAD = "<ci4_routes_reflect_TEST_123>"
SQLI_PAYLOAD = "' OR '1'='1' --test"

SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql", "syntax error", "sqlstate", "odbc", "sqlite",
    "ora-", "mysql_fetch", "pdoexception", "you have an error in your sql syntax"
]

# ===== Colors =====
C_OK = "\033[92m"
C_WARN = "\033[93m"
C_ERR = "\033[91m"
C_INFO = "\033[94m"
C_RST = "\033[0m"


def full_url(base, path):
    if not path:
        return base
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urlparse.urljoin(base.rstrip('/')+'/', path.lstrip('/'))


def load_urls_from_file(fname):
    if not os.path.exists(fname):
        return []
    with open(fname, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f.readlines()
                 if l.strip() and not l.strip().startswith("#")]
    return lines


def fetch(url, timeout=DEFAULT_TIMEOUT):
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None


def check_headers(r):
    hdr = {k.lower(): v for k, v in r.headers.items()}
    findings = {
        "x-content-type-options": ('x-content-type-options' in hdr and 'nosniff' in hdr.get('x-content-type-options', '').lower()),
        "x-frame-options": ('x-frame-options' in hdr),
        "strict-transport-security": ('strict-transport-security' in hdr),
        "content-security-policy": ('content-security-policy' in hdr),
        "referrer-policy": ('referrer-policy' in hdr)
    }
    return findings, hdr


def analyze_forms(page_url, html, timeout=DEFAULT_TIMEOUT, active=False):
    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    results = []
    for form in forms:
        form_info = {
            "action": form.get("action") or "",
            "method": (form.get("method") or "get").lower(),
            "inputs": [],
            "has_file": False,
            "reflect_vuln": False,
            "sqli_flag": False,
            "notes": []
        }
        target = urlparse.urljoin(page_url, form_info["action"])
        form_info["target_url"] = target
        inputs = form.find_all(["input", "textarea", "select"])
        input_names = []
        for inp in inputs:
            itype = (inp.get("type") or "").lower()
            iname = inp.get("name") or inp.get("id") or ""
            form_info["inputs"].append({"name": iname, "type": itype})
            if itype == "file":
                form_info["has_file"] = True
            if iname:
                input_names.append(iname)

        if active:
            test_ref = {n: REFLECT_PAYLOAD for n in input_names} if input_names else {"q": REFLECT_PAYLOAD}
            test_sqli = {n: SQLI_PAYLOAD for n in input_names} if input_names else {"q": SQLI_PAYLOAD}
            try:
                if form_info["method"] == "post":
                    r_ref = session.post(target, data=test_ref, timeout=timeout)
                    r_sql = session.post(target, data=test_sqli, timeout=timeout)
                else:
                    r_ref = session.get(target, params=test_ref, timeout=timeout)
                    r_sql = session.get(target, params=test_sqli, timeout=timeout)
            except Exception as e:
                form_info["notes"].append(f"Request failed: {e}")
                results.append(form_info)
                continue

            body_ref = (r_ref.text or "").lower()
            body_sql = (r_sql.text or "").lower()

            if REFLECT_PAYLOAD.lower() in body_ref:
                form_info["reflect_vuln"] = True
                form_info["notes"].append("Reflected payload found in response")

            for sig in SQL_ERROR_SIGNATURES:
                if sig in body_sql:
                    form_info["sqli_flag"] = True
                    form_info["notes"].append("SQL error signature found in response")
                    break

        results.append(form_info)
    return results


def analyze_route(base, path, timeout=DEFAULT_TIMEOUT, active=False):
    url = full_url(base, path)
    entry = {"route": path, "url": url, "status": None,
             "headers_ok": None, "headers": {}, "forms": [], "issues": [], "severity": "Aman"}
    r = fetch(url, timeout=timeout)
    if r is None:
        entry["issues"].append("Gagal koneksi / timeout")
        entry["severity"] = "Berbahaya"
        return entry

    entry["status"] = r.status_code
    hdr_ok, hdrs = check_headers(r)
    entry["headers_ok"] = all(hdr_ok.values())
    entry["headers"] = hdrs
    entry["forms"] = analyze_forms(url, r.text or "", timeout=timeout, active=active)

    if not entry["headers_ok"]:
        entry["issues"].append("Missing security headers")

    for f in entry["forms"]:
        if f.get("reflect_vuln"):
            entry["issues"].append(f"Reflected XSS -> {f.get('target_url')}")
        if f.get("sqli_flag"):
            entry["issues"].append(f"Possible SQL issue -> {f.get('target_url')}")
        if f.get("has_file"):
            entry["issues"].append(f"File upload input -> {f.get('target_url')}")

    # Severity
    if any("SQL" in i or "XSS" in i for i in entry["issues"]):
        entry["severity"] = "Berbahaya"
    elif entry["issues"]:
        entry["severity"] = "Tidak Aman"
    else:
        entry["severity"] = "Aman"

    return entry


def crawl_site(base, max_pages=MAX_CRAWL_PAGES, max_depth=MAX_CRAWL_DEPTH):
    visited, to_visit = set(), [(base, 0)]
    results = []
    while to_visit and len(results) < max_pages:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        r = fetch(url)
        if not r:
            continue
        results.append(url)
        soup = BeautifulSoup(r.text, "lxml")
        for a in soup.find_all("a", href=True):
            nxt = full_url(base, a["href"])
            if nxt.startswith(base):
                to_visit.append((nxt, depth + 1))
    return results


def write_csv(fname, results):
    rows = []
    for r in results:
        rows.append({
            "route": r.get("route"),
            "url": r.get("url"),
            "status": r.get("status"),
            "severity": r.get("severity"),
            "issues": "; ".join(r.get("issues") or []),
            "link": r.get("url")
        })
    df = pd.DataFrame(rows)
    df.to_csv(fname, index=False, encoding="utf-8-sig")
    print(C_INFO + f"[i] CSV saved -> {fname}" + C_RST)


def main():
    ap = argparse.ArgumentParser(description="CI4 Routes Auditor -> CSV (dev/stage only).")
    ap.add_argument("--base", "-b", default=DEFAULT_BASE, help="BASE URL (contoh: http://localhost:8080)")
    ap.add_argument("--input", "-i", default=DEFAULT_INPUT, help="Input file (urls.txt). Jika tidak ada: auto-crawl")
    ap.add_argument("--output", "-o", default=DEFAULT_OUTPUT, help="Output CSV file path")
    ap.add_argument("--workers", "-w", type=int, default=MAX_WORKERS, help="Parallel workers")
    ap.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT, help="Request timeout (detik)")
    ap.add_argument("--active", action="store_true", help="Enable active tests (reflected XSS / SQLi) — dev/stage only")
    ap.add_argument("--max-pages", type=int, default=MAX_CRAWL_PAGES, help="Max pages to crawl (if no input file)")
    ap.add_argument("--max-depth", type=int, default=MAX_CRAWL_DEPTH, help="Max crawl depth")
    ap.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verify (useful untuk dev self-signed)")
    args = ap.parse_args()

    session.verify = not args.no_ssl_verify
    urls = load_urls_from_file(args.input)

    if urls:
        print(C_INFO + f"[i] Loaded {len(urls)} entries from {args.input}" + C_RST)
    else:
        print(C_INFO + "[i] No input file found, auto crawling..." + C_RST)
        urls = crawl_site(args.base, max_pages=args.max_pages, max_depth=args.max_depth)

    if not urls:
        print(C_ERR + "[!] Tidak ada URL untuk diuji." + C_RST)
        sys.exit(1)

    print(C_INFO + f"[i] Mulai uji {len(urls)} halaman dengan {args.workers} workers..." + C_RST)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        futures = {exe.submit(analyze_route, args.base, u, args.timeout, args.active): u for u in urls}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            status = res.get("status") or "ERR"
            severity = res.get("severity") or "?"
            if severity == "Aman":
                print(C_OK + f"[OK] {res.get('route')} -> {status}" + C_RST)
            elif severity == "Tidak Aman":
                print(C_WARN + f"[!] {res.get('route')} -> {status}" + C_RST)
            else:
                print(C_ERR + f"[X] {res.get('route')} -> {status}" + C_RST)

    write_csv(args.output, results)


if __name__ == "__main__":
    main()
