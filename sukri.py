#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PT. 4z3s Technology
4z3stehnology@gmail.com
https://4z3s-technology.blogspot.com/

Production-ready CI4 site auditor (CSV output).

Ringkasan:
 - Baca daftar URL dari urls.txt (satu route/URL per baris). Jika tidak ada, auto-crawl dari BASE_URL.
 - Analisis pasif (default): cek status, header security, cookie attrs, forms (list inputs, file uploads, CSRF token exist),
   redirect eksternal detection.
 - Mode aktif (--active): tambahan test reflected payload + simple SQL error signature checks (NON-DESTRUCTIVE payloads).
 - Multi-threaded (ThreadPoolExecutor).
 - Output CSV tunggal dengan kolom: Alamat, Status, Keterangan, Issues, Has_Forms, Form_Links, Redirects, Link
 - Konfigurasi lewat CLI args.
 - Designed for dev/staging only.
"""

import argparse
import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import time, os, sys, csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

# Optional colorama for nicer console output (fallback to plain)
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    C_OK = Fore.GREEN
    C_WARN = Fore.YELLOW
    C_ERR = Fore.RED
    C_INFO = Fore.CYAN
    C_RST = Style.RESET_ALL
except Exception:
    C_OK = C_WARN = C_ERR = C_INFO = C_RST = ""

# ---------- Defaults ----------
DEFAULT_BASE = "http://localhost:8080"
DEFAULT_INPUT = "urls.txt"
DEFAULT_OUTPUT = "report.csv"
USER_AGENT = "CI4RoutesAudit/production-1.1"
TIMEOUT = 8
MAX_WORKERS = 8
MAX_CRAWL_PAGES = 200
MAX_CRAWL_DEPTH = 2
# --------------------------------

# Active payloads (only when --active)
REFLECT_PAYLOAD = "<ci4_routes_reflect_TEST_123>"
SQLI_PAYLOADS = [
    "' OR '1'='1' --ci4test",
    "\" OR \"1\"=\"1\" --ci4test",
    "' OR 1=1 --ci4test",
]
SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql", "syntax error", "sqlstate", "odbc", "sqlite", "ora-", "mysql_fetch", "pdoexception",
    "internal server error", "warning: pg_", "you have an error in your sql syntax", "sql error"
]
COMMON_CSRF_NAMES = ["csrf", "csrf_token", "csrf_test_name", "_token", "token", "__requestverificationtoken"]

# requests session
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})
session.cookies = requests.cookies.RequestsCookieJar()

# ---------- Utilities ----------
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
        lines = [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith("#")]
    return lines

def is_same_host(a, b):
    try:
        return urlparse.urlparse(a).netloc == urlparse.urlparse(b).netloc
    except Exception:
        return False

# ---------- Crawler ----------
def crawl_site(base_url, max_pages=MAX_CRAWL_PAGES, max_depth=MAX_CRAWL_DEPTH):
    print(C_INFO + f"[i] Auto-crawl starting from {base_url} (max_pages={max_pages}, max_depth={max_depth})" + C_RST)
    to_visit = deque([(base_url, 0)])
    visited = set()
    discovered = []
    while to_visit and len(discovered) < max_pages:
        url, depth = to_visit.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = session.get(url, timeout=TIMEOUT)
            html = r.text or ""
        except Exception:
            continue
        # store path (relative) if same host
        if is_same_host(base_url, url):
            p = urlparse.urlparse(url).path or "/"
            if p not in discovered:
                discovered.append(p)
        # find links
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            link = urlparse.urljoin(url, a['href'])
            if link.startswith(base_url) and link not in visited:
                to_visit.append((link, depth + 1))
    print(C_INFO + f"[i] Auto-crawl found {len(discovered)} routes" + C_RST)
    return discovered

# ---------- Analysis helpers ----------
def check_security_headers(resp):
    hdr = {k.lower(): v for k, v in resp.headers.items()}
    findings = {
        "x-content-type-options": ('x-content-type-options' in hdr and 'nosniff' in hdr.get('x-content-type-options','').lower()),
        "x-frame-options": ('x-frame-options' in hdr),
        "strict-transport-security": ('strict-transport-security' in hdr),
        "content-security-policy": ('content-security-policy' in hdr),
        "referrer-policy": ('referrer-policy' in hdr)
    }
    missing = [k for k,v in findings.items() if not v]
    return findings, missing, hdr

def check_cookies(resp):
    """
    Robustly obtain Set-Cookie values, with fallback.
    """
    set_cookie_vals = []
    # try raw headers (http.client.HTTPMessage has get_all)
    try:
        raw = getattr(resp.raw, "headers", None)
        if raw and hasattr(raw, "get_all"):
            vals = raw.get_all("Set-Cookie") or []
            set_cookie_vals = vals
    except Exception:
        set_cookie_vals = []

    # fallback to resp.headers['Set-Cookie']
    if not set_cookie_vals:
        sc = resp.headers.get('Set-Cookie')
        if sc:
            set_cookie_vals = [sc]

    issues = []
    for sc in set_cookie_vals:
        lower = (sc or "").lower()
        if 'httponly' not in lower:
            issues.append("Cookie tanpa HttpOnly")
        if resp.url.startswith("https") and 'secure' not in lower:
            issues.append("Cookie tanpa Secure")
        if 'samesite' not in lower:
            issues.append("Cookie tanpa SameSite")
    if not set_cookie_vals:
        # Many pages legitimately don't set cookies; only report that cookie tidak ada as informational
        issues.append("Tidak ada Set-Cookie")
    return issues, set_cookie_vals

def is_external_location(base, location_url):
    try:
        base_host = urlparse.urlparse(base).netloc
        loc_host = urlparse.urlparse(location_url).netloc
        return (loc_host and loc_host != base_host)
    except Exception:
        return False

def extract_forms(page_url, html):
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        enctype = (form.get("enctype") or "")
        fields = []
        has_file = False
        csrf = False
        for inp in form.find_all(["input","textarea","select"]):
            typ = (inp.get("type") or "").lower()
            name = inp.get("name") or inp.get("id") or ""
            if inp.name == "textarea":
                typ = "textarea"
            if inp.name == "select":
                typ = "select"
            fields.append({"name": name, "type": typ})
            if typ == "file" or ("multipart" in enctype.lower()):
                has_file = True
            if typ == "hidden" and name:
                if any(k in name.lower() for k in COMMON_CSRF_NAMES):
                    csrf = True
        forms.append({
            "action": urlparse.urljoin(page_url, action),
            "method": method,
            "enctype": enctype,
            "inputs": fields,
            "has_file": has_file,
            "csrf_detected": csrf
        })
    return forms

# ---------- Active tests (only when --active) ----------
def active_test_reflect(target_url, form_inputs, method="get"):
    try:
        if form_inputs:
            data = {n: REFLECT_PAYLOAD for n in form_inputs}
        else:
            data = {"q": REFLECT_PAYLOAD}
        if method == "post":
            r = session.post(target_url, data=data, timeout=TIMEOUT)
        else:
            r = session.get(target_url, params=data, timeout=TIMEOUT)
        if REFLECT_PAYLOAD.lower() in (r.text or "").lower():
            return True, r
    except Exception:
        pass
    return False, None

def active_test_sqli(target_url, form_inputs, method="get"):
    findings = []
    for payload in SQLI_PAYLOADS:
        try:
            if form_inputs:
                data = {n: payload for n in form_inputs}
            else:
                data = {"q": payload}
            if method == "post":
                r = session.post(target_url, data=data, timeout=TIMEOUT)
            else:
                r = session.get(target_url, params=data, timeout=TIMEOUT)
            body = (r.text or "").lower()
            for sig in SQL_ERROR_SIGNATURES:
                if sig in body:
                    findings.append({"payload": payload, "signature": sig})
                    break
            if findings:
                break
        except Exception:
            continue
    return findings

# ---------- Main route analysis ----------
def analyze_route(base_url, path_or_url, active=False):
    url = full_url(base_url, path_or_url)
    entry = {
        "route": path_or_url,
        "url": url,
        "status": None,
        "issues": [],
        "has_forms": False,
        "form_links": [],
        "redirects": [],
        "raw_headers": {},
    }
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        entry["status"] = "ERR"
        entry["issues"].append(f"Gagal koneksi: {e}")
        entry["keterangan"] = "Berbahaya"
        return entry

    entry["status"] = r.status_code

    # redirects history
    if r.history:
        for h in r.history:
            loc = h.headers.get('Location') or h.headers.get('location') or ""
            full_loc = urlparse.urljoin(h.url, loc) if loc else ""
            external = is_external_location(base_url, full_loc) if full_loc else False
            entry["redirects"].append({"from": h.url, "to": full_loc, "external": external})
            if external:
                entry["issues"].append(f"Redirect eksternal -> {full_loc}")

    # header checks
    hdr_ok, missing_headers, hdrs = check_security_headers(r)
    entry["raw_headers"] = hdrs
    if missing_headers:
        entry["issues"].append("Missing headers: " + ", ".join(missing_headers))

    # cookie checks
    cookie_issues, set_cookie_vals = check_cookies(r)
    # report cookie issues but treat "Tidak ada Set-Cookie" as informational (do not escalate)
    for ci in cookie_issues:
        if ci != "Tidak ada Set-Cookie":
            entry["issues"].append(ci)

    # form extraction
    forms = extract_forms(url, r.text or "")
    entry["has_forms"] = len(forms) > 0
    for f in forms:
        entry["form_links"].append(f.get("action") or "")
        if f.get("has_file"):
            entry["issues"].append(f"Form upload file -> {f.get('action')}")
        if not f.get("csrf_detected"):
            entry["issues"].append(f"Form mungkin tanpa CSRF token -> {f.get('action')}")

    # active tests (only if explicitly enabled)
    if active:
        for f in forms:
            inputs = [inp.get("name") for inp in f.get("inputs") if inp.get("name")]
            # reflected XSS check
            reflected, _ = active_test_reflect(f.get("action"), inputs, method=f.get("method"))
            if reflected:
                entry["issues"].append(f"Reflected payload ditemukan -> {f.get('action')}")
            # SQLi heuristics
            sqli_find = active_test_sqli(f.get("action"), inputs, method=f.get("method"))
            if sqli_find:
                for ff in sqli_find:
                    entry["issues"].append(f"SQL error signature '{ff.get('signature')}' untuk payload '{ff.get('payload')}' -> {f.get('action')}")
    else:
        # passive: look for obvious SQL error strings in response (non-invasive)
        body = (r.text or "").lower()
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body:
                entry["issues"].append(f"SQL error signature in response: {sig}")

    # categorize into Keterangan: Aman / Tidak Aman / Berbahaya
    keterangan = "Aman"
    if isinstance(entry["status"], int):
        if entry["status"] >= 500 or (400 <= entry["status"] < 500):
            keterangan = "Berbahaya"
    else:
        keterangan = "Berbahaya"

    # count important issues
    critical_indicators = 0
    for it in entry["issues"]:
        low = it.lower()
        if "reflected" in low or "sql error" in low or "sql error signature" in low:
            critical_indicators += 2
        if "redirect eksternal" in low:
            critical_indicators += 1
        if "form upload file" in low:
            critical_indicators += 1
        if "missing headers" in low:
            critical_indicators += 1
        if "gagal koneksi" in low:
            critical_indicators += 2

    if critical_indicators >= 3:
        keterangan = "Berbahaya"
    elif 1 <= critical_indicators < 3:
        keterangan = "Tidak Aman"
    else:
        if isinstance(entry["status"], int) and entry["status"] == 200 and missing_headers:
            if len(missing_headers) > 2:
                keterangan = "Tidak Aman"

    entry["keterangan"] = keterangan
    return entry

# ---------- CSV output ----------
def write_csv(output_file, rows):
    headers = ["Alamat", "Status", "Keterangan", "Issues", "Has_Forms", "Form_Links", "Redirects", "Link"]
    with open(output_file, "w", newline="", encoding="utf-8-sig") as csvfile:
        w = csv.writer(csvfile)
        w.writerow(headers)
        for r in rows:
            issues_txt = " | ".join(r.get("issues") or [])
            form_links_txt = " | ".join(r.get("form_links") or [])
            redirects_txt = " | ".join([f"{d.get('from')}-> {d.get('to')}" for d in (r.get("redirects") or [])])
            w.writerow([
                r.get("route"),
                r.get("status"),
                r.get("keterangan"),
                issues_txt,
                "Yes" if r.get("has_forms") else "No",
                form_links_txt,
                redirects_txt,
                r.get("url"),
            ])
    print(C_OK + f"[+] CSV saved to {output_file}" + C_RST)

# ---------- CLI / Main ----------
def main():
    ap = argparse.ArgumentParser(description="CI4 Routes Auditor -> CSV (dev/stage only).")
    ap.add_argument("--base", "-b", default=DEFAULT_BASE, help="BASE URL (contoh: http://localhost:8080)")
    ap.add_argument("--input", "-i", default=DEFAULT_INPUT, help="Input file (urls.txt). Jika tidak ada: auto-crawl")
    ap.add_argument("--output", "-o", default=DEFAULT_OUTPUT, help="Output CSV file path")
    ap.add_argument("--workers", "-w", type=int, default=MAX_WORKERS, help="Parallel workers")
    ap.add_argument("--timeout", "-t", type=int, default=TIMEOUT, help="Request timeout (detik)")
    ap.add_argument("--active", action="store_true", help="Enable active tests (reflected XSS / SQLi) — dev/stage only")
    ap.add_argument("--max-pages", type=int, default=MAX_CRAWL_PAGES, help="Max pages to crawl (if no input file)")
    ap.add_argument("--max-depth", type=int, default=MAX_CRAWL_DEPTH, help="Max crawl depth")
    ap.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verify (useful untuk dev self-signed)")
    args = ap.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout
    session.verify = not args.no_ssl_verify

    # Load URLs: prefer input file
    urls = load_urls_from_file(args.input)
    if urls:
        print(C_INFO + f"[i] Loaded {len(urls)} entries from {args.input}" + C_RST)
    else:
        discovered = crawl_site(args.base, max_pages=args.max_pages, max_depth=args.max_depth)
        if not discovered:
            print(C_ERR + "[!] Tidak menemukan halaman saat auto-crawl dan input file kosong. Keluar." + C_RST)
            sys.exit(1)
        urls = discovered

    # Normalize tasks
    tasks = [u for u in urls]

    # Run analysis in parallel
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(analyze_route, args.base, t, args.active): t for t in tasks}
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"route": t, "url": full_url(args.base, t), "status": "ERR",
                       "issues": [f"Internal error: {e}"], "has_forms": False, "form_links": [], "redirects": [], "keterangan": "Berbahaya"}
            results.append(res)
            # brief console output
            status = res.get("status")
            kat = res.get("keterangan")
            if kat == "Aman":
                print(C_OK + f"[Aman] {res.get('route')} -> {status}" + C_RST)
            elif kat == "Tidak Aman":
                print(C_WARN + f"[Tidak Aman] {res.get('route')} -> {status}" + C_RST)
            else:
                print(C_ERR + f"[Berbahaya] {res.get('route')} -> {status}" + C_RST)

    # write CSV
    write_csv(args.output, results)

if __name__ == "__main__":
    main()
