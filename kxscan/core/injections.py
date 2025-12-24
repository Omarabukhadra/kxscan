from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
]
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "';--",
]

def with_param(url, key, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    new_query = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))

def reflect_test(session, url, payload):
    try:
        r = session.get(url, timeout=10, allow_redirects=True, verify=False)
        if r.status_code == 200 and payload in r.text:
            return True
    except requests.RequestException:
        pass
    return False

def simple_xss_checks(session, url):
    findings = []
    p = urlparse(url)
    if not p.query:
        return findings
    for k, _ in parse_qsl(p.query, keep_blank_values=True):
        for pl in XSS_PAYLOADS:
            test_url = with_param(url, k, pl)
            if reflect_test(session, test_url, pl):
                findings.append({
                    "type": "xss_reflection",
                    "parameter": k,
                    "payload": pl,
                    "url": test_url
                })
                break
    return findings

def simple_sqli_checks(session, url):
    findings = []
    p = urlparse(url)
    if not p.query:
        return findings
    error_signatures = [
        "You have an error in your SQL syntax",
        "Warning: mysql_fetch",
        "pg_query():",
        "SQLite3::query()",
        "SQLSTATE[",
        "ORA-01756",
        "Unclosed quotation mark after the character string"
    ]
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        for pl in SQLI_PAYLOADS:
            test_url = with_param(url, k, pl)
            try:
                r = session.get(test_url, timeout=10, allow_redirects=True, verify=False)
                body_lower = r.text.lower()
                if any(sig.lower() in body_lower for sig in error_signatures):
                    findings.append({
                        "type": "sqli_error_based",
                        "parameter": k,
                        "payload": pl,
                        "url": test_url
                    })
                    break
            except requests.RequestException:
                pass
    return findings
