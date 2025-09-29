#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ci4_audit_prod.py
Production-ready CI4 site auditor (CSV output).
"""

import argparse
import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse
import os, csv
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

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

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
        return [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith("#")]

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
        if is_same_host(base_url, url):
            p = urlparse.urlparse(url).path or "/"
            if p not in discovered:
                discovered.append(p)
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            link = urlparse.urljoin(url, a['href'])
            if link.startswith(base_url) and link not in visited:
                to_visit.append((link, depth + 1))
    print(C_INFO + f"[i] Auto-crawl found {len(discovered)} routes" + C_RST)
    return discovered

# ---------- Checks ----------
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
    set_cookie_vals = resp.headers.get("Set-Cookie", "")
    issues = []
    if set_cookie_vals:
        lower = set_cookie_vals.lower()
        if 'httponly' not in lower:
            issues.append("Cookie tanpa HttpOnly")
        if resp.url.startswith("https") and 'secure' not in lower:
            issues.append("Cookie tanpa Secure")
        if 'samesite' not in lower:
            issues.append("Cookie tanpa SameSite")
    return issues, [set_cookie_vals] if set_cookie_vals else []

def extract_forms(page_url, html):
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        enctype = (form.get("enctype") or "")
        has_file, csrf = False, False
        for inp in form.find_all(["input","textarea","select"]):
            typ = (inp.get("type") or "").lower()
            name = inp.get("name") or inp.get("id") or ""
            if typ == "file" or ("multipart" in enctype.lower()):
                has_file = True
            if typ == "hidden" and name and any(k in name.lower() for k in COMMON_CSRF_NAMES):
                csrf = True
        forms.append({
            "action": urlparse.urljoin(page_url, action),
            "method": method,
            "enctype": enctype,
            "has_file": has_file,
            "csrf_detected": csrf
        })
    return forms

# ---------- Analysis ----------
def analyze_route(base_url, path_or_url, active=False):
    url = full_url(base_url, path_or_url)
    entry = {"route": path_or_url, "url": url, "status": None, "issues": [], "has_forms": False,
             "form_links": [], "redirects": []}
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        entry.update(status="ERR", issues=[f"Gagal koneksi: {e}"], keterangan="Berbahaya")
        return entry

    entry["status"] = r.status_code
    hdr_ok, missing_headers, hdrs = check_security_headers(r)
    if missing_headers:
        entry["issues"].append("Missing headers: " + ", ".join(missing_headers))
    cookie_issues, _ = check_cookies(r)
    entry["issues"].extend(cookie_issues)

    forms = extract_forms(url, r.text or "")
    entry["has_forms"] = len(forms) > 0
    for f in forms:
        entry["form_links"].append(f.get("action") or "")
        if f.get("has_file"):
            entry["issues"].append(f"Form upload file -> {f.get('action')}")
        if not f.get("csrf_detected"):
            entry["issues"].append(f"Form mungkin tanpa CSRF token -> {f.get('action')}")

    # kategori
    keterangan = "Aman"
    if isinstance(entry["status"], int):
        if entry["status"] >= 400:
            keterangan = "Berbahaya"
        elif missing_headers or cookie_issues:
            keterangan = "Tidak Aman"
    entry["keterangan"] = keterangan
    return entry

# ---------- CSV ----------
def write_csv(output_file, rows):
    headers = ["Alamat", "Status", "Keterangan", "Issues", "Has_Forms", "Form_Links", "Redirects", "Link"]
    with open(output_file, "w", newline="", encoding="utf-8-sig") as csvfile:
        w = csv.writer(csvfile)
        w.writerow(headers)
        for r in rows:
            issues_txt = " | ".join(r.get("issues") or [])
            forms_txt = " | ".join(r.get("form_links") or [])
            redirects_txt = " | ".join([f"{red['from']} -> {red['to']}" for red in r.get("redirects") or []])
            w.writerow([
                r.get("route"), r.get("status"), r.get("keterangan"),
                issues_txt, "Ya" if r.get("has_forms") else "Tidak",
                forms_txt, redirects_txt, r.get("url")
            ])

# ---------- Runner ----------
def main():
    parser = argparse.ArgumentParser(description="CI4 Auditor (Production Ready)")
    parser.add_argument("--base", default=DEFAULT_BASE, help="Base URL (default: localhost:8080)")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="File daftar URL (default: urls.txt)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV file (default: report.csv)")
    args = parser.parse_args()

    urls = load_urls_from_file(args.input)
    if not urls:
        urls = crawl_site(args.base)

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(analyze_route, args.base, u): u for u in urls}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(C_ERR + f"[!] Error menganalisis {futures[future]}: {e}" + C_RST)

    write_csv(args.output, results)
    print(C_OK + f"[✓] Audit selesai, hasil tersimpan di {args.output}" + C_RST)

if __name__ == "__main__":
    main()
