import json
from datetime import datetime
from pathlib import Path

def print_color(txt, color="reset"):
    colors = {
        "green": "\033[92m", "yellow": "\033[93m",
        "red": "\033[91m", "blue": "\033[94m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color,'')}{txt}{colors['reset']}")

def summarize(console, url, header_issues, xss, sqli):
    print_color(f"\n=== {url} ===", "blue")
    if header_issues:
        print_color(f"- Security headers issues: {len(header_issues)}", "yellow")
        for i in header_issues:
            print_color(f"  • {i.header}: {i.details}", "yellow")
    else:
        print_color("- Security headers look OK", "green")

    if xss:
        print_color(f"- XSS findings: {len(xss)}", "red")
        for f in xss:
            print_color(f"  • Param `{f['parameter']}` reflected payload", "red")
    else:
        print_color("- No reflected XSS detected (basic checks)", "green")

    if sqli:
        print_color(f"- SQLi (error-based) signatures: {len(sqli)}", "red")
        for f in sqli:
            print_color(f"  • Param `{f['parameter']}` error-based indicator", "red")
    else:
        print_color("- No SQL error signatures detected (basic checks)", "green")

def save_json_report(results, out_dir="reports"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = Path(out_dir) / f"kxscan_report_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    return str(path)
