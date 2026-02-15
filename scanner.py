#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import requests

DEFAULT_TIMEOUT = 10
UA = "mini-web-scanner/1.0 (+github.com/ikpehlivan)"
ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System\.Data\.SqlClient\.",
    r"Unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ORA-\d{5}",
]

REDACT_HEADERS = {"authorization", "cookie", "set-cookie"}

SEC_HEADERS = {
    "content-security-policy": "Missing CSP (consider a baseline policy)",
    "x-content-type-options": "Missing X-Content-Type-Options (set to nosniff)",
    "x-frame-options": "Missing X-Frame-Options (DENY/SAMEORIGIN) or use CSP frame-ancestors",
    "referrer-policy": "Missing Referrer-Policy",
    "permissions-policy": "Missing Permissions-Policy",
    "strict-transport-security": "Missing HSTS (only for HTTPS)",
}

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
    "/admin", "/phpinfo.php", "/server-status", "/.well-known/security.txt"
]

@dataclass
class Finding:
    type: str
    severity: str
    title: str
    evidence: str
    url: str
    extra: Optional[Dict] = None

def normalize_url(u: str) -> str:
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    p = urlparse(u)
    # drop fragments
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))

def load_payloads(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]

def safe_headers(h: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in h.items():
        if k.lower() in REDACT_HEADERS:
            out[k] = "***redacted***"
        else:
            out[k] = v
    return out

def req(session: requests.Session, method: str, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        r = session.request(method, url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, **kwargs)
        return r, None
    except requests.RequestException as e:
        return None, str(e)

def check_security_headers(url: str, r: requests.Response) -> List[Finding]:
    findings = []
    headers = {k.lower(): v for k, v in r.headers.items()}
    for hk, msg in SEC_HEADERS.items():
        if hk not in headers:
            # HSTS only meaningful on HTTPS
            if hk == "strict-transport-security" and urlparse(url).scheme != "https":
                continue
            findings.append(Finding(
                type="misconfig",
                severity="low",
                title=f"Missing security header: {hk}",
                evidence=msg,
                url=url,
                extra={"response_headers": safe_headers(dict(r.headers))}
            ))
    return findings

def mutate_query(url: str, new_params: Dict[str, str]) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    qd = dict(q)
    qd.update(new_params)
    new_q = urlencode(list(qd.items()), doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, ""))

def check_reflected_xss(session: requests.Session, url: str, xss_payloads: List[str]) -> List[Finding]:
    p = urlparse(url)
    if not p.query:
        return []

    findings = []
    baseline_r, err = req(session, "GET", url, headers={"User-Agent": UA})
    if err or baseline_r is None:
        return [Finding("error", "info", "Request failed", err or "unknown", url)]

    baseline_body = baseline_r.text[:200000]  # cap
    params = dict(parse_qsl(p.query, keep_blank_values=True))

    for k in list(params.keys())[:8]:  # keep it quick
        for payload in xss_payloads[:8]:
            test_url = mutate_query(url, {k: payload})
            r, err = req(session, "GET", test_url, headers={"User-Agent": UA})
            if err or r is None:
                continue
            body = r.text[:200000]
            # Heuristic: payload reflected and not in baseline
            if payload in body and payload not in baseline_body:
                findings.append(Finding(
                    type="xss",
                    severity="medium",
                    title="Possible reflected XSS",
                    evidence=f"Parameter '{k}' reflected payload.",
                    url=test_url,
                    extra={"param": k, "payload": payload}
                ))
                break
        if findings:
            break
    return findings

def check_sqli_errors(session: requests.Session, url: str, sqli_payloads: List[str]) -> List[Finding]:
    p = urlparse(url)
    if not p.query:
        return []

    findings = []
    baseline_r, err = req(session, "GET", url, headers={"User-Agent": UA})
    if err or baseline_r is None:
        return [Finding("error", "info", "Request failed", err or "unknown", url)]
    baseline = baseline_r.text[:200000]

    params = dict(parse_qsl(p.query, keep_blank_values=True))
    regexes = [re.compile(pat, re.IGNORECASE) for pat in ERROR_PATTERNS]

    for k in list(params.keys())[:8]:
        for payload in sqli_payloads[:8]:
            test_url = mutate_query(url, {k: params.get(k, "") + payload})
            r, err = req(session, "GET", test_url, headers={"User-Agent": UA})
            if err or r is None:
                continue
            body = r.text[:200000]
            if body == baseline:
                continue
            if any(rx.search(body) for rx in regexes):
                findings.append(Finding(
                    type="sqli",
                    severity="medium",
                    title="Possible SQL injection (error-based)",
                    evidence=f"DB error pattern detected after injecting into '{k}'.",
                    url=test_url,
                    extra={"param": k, "payload": payload}
                ))
                break
        if findings:
            break
    return findings

def check_sensitive_paths(session: requests.Session, base_url: str) -> List[Finding]:
    findings = []
    p = urlparse(base_url)
    root = urlunparse((p.scheme, p.netloc, "", "", "", ""))
    for path in SENSITIVE_PATHS:
        u = root + path
        r, err = req(session, "GET", u, headers={"User-Agent": UA})
        if err or r is None:
            continue
        if r.status_code in (200, 206):
            snippet = (r.text or "")[:200].replace("\n", "\\n")
            findings.append(Finding(
                type="exposure",
                severity="high" if path in ("/.env", "/.git/config") else "low",
                title=f"Sensitive path accessible: {path}",
                evidence=f"HTTP {r.status_code} response. Snippet: {snippet}",
                url=u
            ))
    return findings

def scan_one(url: str, xss_payloads: List[str], sqli_payloads: List[str]) -> Dict:
    session = requests.Session()
    session.verify = True  # keep safe default
    session.headers.update({"User-Agent": UA})

    results = {
        "target": url,
        "timestamp": int(time.time()),
        "findings": [],
        "meta": {"note": "Heuristic scanner. Validate findings manually."}
    }

    r, err = req(session, "GET", url)
    if err or r is None:
        results["findings"].append(asdict(Finding("error", "info", "Request failed", err or "unknown", url)))
        return results

    findings: List[Finding] = []
    findings += check_security_headers(url, r)
    findings += check_reflected_xss(session, url, xss_payloads)
    findings += check_sqli_errors(session, url, sqli_payloads)
    findings += check_sensitive_paths(session, url)

    results["findings"] = [asdict(f) for f in findings]
    return results

def parse_args():
    ap = argparse.ArgumentParser(description="Mini Web Security Scanner (headers, reflected XSS, basic SQLi, sensitive paths)")
    ap.add_argument("-u", "--url", help="Target URL (with optional query string)")
    ap.add_argument("-l", "--list", help="File with target URLs (one per line)")
    ap.add_argument("-o", "--out", default="report.json", help="Output JSON report file")
    ap.add_argument("--xss", default="payloads/xss.txt", help="XSS payload file")
    ap.add_argument("--sqli", default="payloads/sqli.txt", help="SQLi payload file")
    return ap.parse_args()

def main():
    args = parse_args()
    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        p = Path(args.list)
        targets += [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

    if not targets:
        print("Provide -u or -l", file=sys.stderr)
        sys.exit(2)

    targets = [normalize_url(t) for t in targets]
    xss_payloads = load_payloads(args.xss)
    sqli_payloads = load_payloads(args.sqli)

    all_results = []
    for t in targets[:20]:  # limit for 1-day project
        res = scan_one(t, xss_payloads, sqli_payloads)
        all_results.append(res)
        # quick console summary
        fcount = len(res.get("findings", []))
        print(f"[+] {t} -> {fcount} finding(s)")

    Path(args.out).write_text(json.dumps(all_results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved report: {args.out}")

if __name__ == "__main__":
    main()
