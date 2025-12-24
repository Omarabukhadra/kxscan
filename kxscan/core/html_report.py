from pathlib import Path
from jinja2 import Template

TPL = """
<!doctype html>
<html lang="ar">
<head>
<meta charset="utf-8">
<title>تقرير KXScan</title>
<style>
body{font-family:sans-serif;background:#0f111a;color:#e5e9f0;padding:20px}
h1,h2{color:#88c0d0}
.card{background:#2e3440;padding:15px;margin-bottom:12px;border-radius:8px}
.bad{color:#bf616a}
.good{color:#a3be8c}
.muted{color:#d8dee9}
code{background:#3b4252;padding:2px 4px;border-radius:4px}
ul{margin-top:6px}
</style>
</head>
<body>
<h1>تقرير KXScan</h1>
<p>الهدف: <code>{{ data["target"] }}</code></p>

{% for item in data["items"] %}
<div class="card">
  <h2>{{ item["url"] }} — الحالة: {{ item["status"] if "status" in item else "N/A" }}</h2>

  <h3>رؤوس الحماية</h3>
  {% if item["headers"] %}
    <ul>
    {% for h in item["headers"] %}
      <li class="{{ 'bad' if (not h.present) or ('Missing' in h.details) else 'muted' }}">
        {{ h.header }} — {{ h.details }}
      </li>
    {% endfor %}
    </ul>
  {% else %}
    <p class="good">لا توجد مشاكل ظاهرة في الرؤوس.</p>
  {% endif %}

  <h3>XSS (GET)</h3>
  {% if item["xss"] %}
    <ul>
    {% for f in item["xss"] %}
      <li class="bad">انعكاس بايلود في البارامتر <code>{{ f.parameter }}</code></li>
    {% endfor %}
    </ul>
  {% else %}
    <p class="good">لا يوجد انعكاس XSS (فحوصات أساسية)</p>
  {% endif %}

  <h3>SQLi (GET)</h3>
  {% if item["sqli"] %}
    <ul>
    {% for f in item["sqli"] %}
      <li class="bad">مؤشرات أخطاء SQL في <code>{{ f.parameter }}</code></li>
    {% endfor %}
    </ul>
  {% else %}
    <p class="good">لا توجد مؤشرات أخطاء SQL (فحوصات أساسية)</p>
  {% endif %}

  <h3>نماذج POST</h3>
  <p class="muted">عدد النماذج المُكتشفة: {{ item["forms_count"] if "forms_count" in item else 0 }}</p>

  <h4>XSS (POST)</h4>
  {% if "post" in item and item["post"] and item["post"]["xss"] %}
    <ul>
    {% for f in item["post"]["xss"] %}
      <li class="bad">شكل POST إلى <code>{{ f.action }}</code> انعكس فيه بايلود على الحقل <code>{{ f.field }}</code></li>
    {% endfor %}
    </ul>
  {% else %}
    <p class="good">لا يوجد انعكاس XSS عبر POST (أساسي)</p>
  {% endif %}

  <h4>SQLi (POST)</h4>
  {% if "post" in item and item["post"] and item["post"]["sqli"] %}
    <ul>
    {% for f in item["post"]["sqli"] %}
      <li class="bad">شكل POST إلى <code>{{ f.action }}</code> أظهر مؤشرات خطأ SQL عند الحقل <code>{{ f.field }}</code></li>
    {% endfor %}
    </ul>
  {% else %}
    <p class="good">لا توجد مؤشرات أخطاء SQL عبر POST (أساسي)</p>
  {% endif %}
</div>
{% endfor %}
</body>
</html>
"""

def render_html(data, out_dir="reports"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    html = Template(TPL).render(data=data)
    path = Path(out_dir) / "kxscan_report.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
