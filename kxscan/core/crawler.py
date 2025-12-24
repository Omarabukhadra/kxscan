import re
from urllib.parse import urljoin, urldefrag, urlparse
import requests
from bs4 import BeautifulSoup

class Crawler:
    def __init__(self, base_url, max_pages=50, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.found = set()

    def same_domain(self, url):
        p = urlparse(url)
        return p.netloc == self.parsed_base.netloc or p.netloc == ""

    def normalize(self, url):
        url = urljoin(self.base_url + "/", url)
        url = urldefrag(url)[0]
        return url

    def extract_links(self, html, current_url):
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for tag in soup.find_all(["a", "link", "script"]):
            attr = "href" if tag.name in ("a", "link") else "src"
            href = tag.get(attr)
            if not href:
                continue
            url = self.normalize(href)
            if self.same_domain(url):
                links.add(url)
        return links

    def crawl(self):
        queue = [self.base_url]
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            try:
                r = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
                self.visited.add(url)
                self.found.add(url)
                if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", ""):
                    for link in self.extract_links(r.text, url):
                        if link not in self.visited:
                            queue.append(link)
            except requests.RequestException:
                self.visited.add(url)
        return list(self.found)
