import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import List, Dict
import sys

class WebSecurityScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.visited_urls = set()
        self.vulnerabilities = []

    def normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > 2 or url in self.visited_urls:
            return

        try:
            response = requests.get(url, timeout=5)
            self.visited_urls.add(url)

            soup = BeautifulSoup(response.text, 'html.parser')
            for link_tag in soup.find_all('a', href=True):
                link = urljoin(url, link_tag['href'])
                if self.base_url in link:
                    self.crawl(link, depth + 1)
        except requests.RequestException:
            pass

    def check_sql_injection(self, url: str) -> None:
        test_payloads = ["'", "\"", "1' OR '1'='1", "\" OR \"1\"=\"1"]
        for payload in test_payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if "sql" in response.text.lower() or "syntax" in response.text.lower():
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "url": test_url
                    })
            except requests.RequestException:
                continue

    def check_xss(self, url: str) -> None:
        xss_payload = "<script>alert('xss')</script>"
        test_url = f"{url}?q={xss_payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if xss_payload in response.text:
                self.vulnerabilities.append({
                    "type": "XSS",
                    "url": test_url
                })
        except requests.RequestException:
            pass

    def check_sensitive_info(self, url: str) -> None:
        try:
            response = requests.get(url, timeout=5)
            keywords = ["password", "secret", "api_key", "token"]
            for keyword in keywords:
                if keyword in response.text.lower():
                    self.vulnerabilities.append({
                        "type": "Sensitive Information Disclosure",
                        "url": url,
                        "keyword": keyword
                    })
        except requests.RequestException:
            pass

    def scan(self) -> List[Dict]:
        self.crawl(self.base_url)
        for url in self.visited_urls:
            self.check_sql_injection(url)
            self.check_xss(url)
            self.check_sensitive_info(url)
        return self.vulnerabilities

    def report_vulnerability(self, vulnerability: Dict) -> None:
        print(f"[!] Vulnerability Found: {vulnerability['type']} at {vulnerability['url']}")
        if 'keyword' in vulnerability:
            print(f"    Keyword: {vulnerability['keyword']}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    found_vulnerabilities = scanner.scan()

    if found_vulnerabilities:
        print("\nScan Complete. Vulnerabilities Found:\n")
        for vuln in found_vulnerabilities:
            scanner.report_vulnerability(vuln)
    else:
        print("Scan Complete. No vulnerabilities found.")
