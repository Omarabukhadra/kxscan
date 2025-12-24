import argparse
import warnings
import requests
from tqdm import tqdm
from kxscan.core.crawler import Crawler
from kxscan.core.headers import check_security_headers
from kxscan.core.injections import simple_xss_checks, simple_sqli_checks
from kxscan.core.report import summarize, save_json_report

# تجاهل تحذيرات SSL لأننا نستخدم verify=False في طلبات التدريب
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def main():
    parser = argparse.ArgumentParser(
        prog="kxscan",
        description="KXScan — ماسح ثغرات ويب خفيف (تعليمي): كرول بسيط + فحوصات رؤوس الحماية + XSS/SQLi الأساسية."
    )
    parser.add_argument("url", help="رابط البداية (مثال: https://example.com)")
    parser.add_argument("--max-pages", type=int, default=30, help="أقصى عدد صفحات للزحف")
    parser.add_argument("--timeout", type=int, default=10, help="مهلة الطلبات بالثواني")
    parser.add_argument("--no-crawl", action="store_true", help="عدم الزحف والاكتفاء بالرابط المُدخل")
    parser.add_argument("--report-json", action="store_true", help="حفظ تقرير JSON")
    args = parser.parse_args()

    start_url = args.url.rstrip("/")
    session = requests.Session()
    session.headers.update({"User-Agent": "KXScan/1.0"})
    results = {"target": start_url, "items": []}

    # لاحظ استخدام underscore هنا بدل الشرطات
    targets = [start_url]
    if not args.no_crawl:
        crawler = Crawler(start_url, max_pages=args.max_pages, timeout=args.timeout)
        targets = crawler.crawl()

    for url in tqdm(targets, desc="Scanning", unit="url"):
        item = {"url": url, "headers": [], "xss": [], "sqli": []}
        try:
            r = session.get(url, timeout=args.timeout, allow_redirects=True, verify=False)
            item["status"] = r.status_code

            # فحص رؤوس الحماية
            hdr_issues = check_security_headers(r)
            item["headers"] = [i.__dict__ for i in hdr_issues]

            # فحوصات حقن أساسية على باراميترات GET
            item["xss"] = simple_xss_checks(session, url)
            item["sqli"] = simple_sqli_checks(session, url)

            summarize(True, url, hdr_issues, item["xss"], item["sqli"])

        except requests.RequestException as e:
            item["error"] = str(e)

        results["items"].append(item)

    if args.report_json:
        path = save_json_report(results)
        print(f"\n[+] تم حفظ تقرير JSON: {path}")

if __name__ == "__main__":
    main()
