from dataclasses import dataclass

REQUIRED = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Permissions-Policy"
]

@dataclass
class HeaderIssue:
    header: str
    present: bool
    details: str

def check_security_headers(response):
    issues = []
    hdrs = {k.lower(): v for k, v in response.headers.items()}
    for h in REQUIRED:
        if h.lower() not in hdrs:
            issues.append(HeaderIssue(header=h, present=False, details="Missing"))
        else:
            val = hdrs[h.lower()]
            if h == "X-Content-Type-Options" and val.lower() != "nosniff":
                issues.append(HeaderIssue(header=h, present=True, details=f"Unexpected value: {val}"))
            if h == "X-Frame-Options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                issues.append(HeaderIssue(header=h, present=True, details=f"Weak value: {val}"))
    return issues
