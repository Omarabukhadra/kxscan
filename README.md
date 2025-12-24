# KXScan — Lightweight Web Vulnerability Scanner (Educational)

## التثبيت
\`\`\`bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
\`\`\`

## التشغيل
\`\`\`bash
python -m kxscan.cli https://example.com --max-pages 20 --report-json
python -m kxscan.cli "https://testphp.vulnweb.com/listproducts.php?cat=1" --no-crawl --report-json
\`\`\`

## خريطة الطريق
- تقارير HTML
- دعم POST forms
- تحسين محرك الزحف
