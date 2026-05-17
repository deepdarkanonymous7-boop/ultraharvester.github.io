"""
Web & Asset Discovery Module
Web crawling, SSL certs via crt.sh, Wayback Machine,
Shodan/Censys, IP range & ASN lookup
"""

import re
import time
import random
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from ..utils.logger import get_logger

logger = get_logger("ultraharvester.web")


class WebDiscovery:
    def __init__(self, domain: str, config=None):
        self.domain = domain
        self.config = config
        self.crawled_pages: List[Dict] = []
        self.ssl_certs: List[Dict] = []
        self.wayback_urls: List[str] = []
        self.shodan_data: Dict = {}
        self.censys_data: Dict = {}
        self.ip_info: Dict = {}
        self.asn_info: Dict = {}
        self.technologies: List[str] = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; UltraHarvester/1.0)",
        })
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings()

    def run(self) -> Dict:
        logger.info(f"[Web] Starting web discovery for {self.domain}")
        self._resolve_ip()
        self._crawl_website()
        self._get_ssl_certs()
        self._wayback_machine()
        self._ip_asn_lookup()
        self._shodan_lookup()
        self._censys_lookup()
        logger.info(f"[Web] Found {len(self.crawled_pages)} pages, {len(self.ssl_certs)} certs, {len(self.wayback_urls)} wayback URLs")
        return {
            "crawled_pages": self.crawled_pages,
            "ssl_certs": self.ssl_certs,
            "wayback_urls": self.wayback_urls[:100],
            "shodan": self.shodan_data,
            "censys": self.censys_data,
            "ip_info": self.ip_info,
            "asn_info": self.asn_info,
        }

    def _resolve_ip(self):
        try:
            import socket
            self.ip = socket.gethostbyname(self.domain)
            logger.info(f"[Web] Resolved {self.domain} -> {self.ip}")
        except Exception:
            self.ip = None

    def _crawl_website(self):
        logger.info(f"[Web] Crawling {self.domain}...")
        max_depth = self.config.max_depth if self.config else 2
        visited: Set[str] = set()
        to_visit = [f"https://{self.domain}", f"http://{self.domain}"]

        def crawl_url(url: str, depth: int):
            if depth > max_depth or url in visited or len(visited) > 100:
                return
            visited.add(url)
            try:
                time.sleep(random.uniform(0.5, 1.0))
                r = self.session.get(url, timeout=8, allow_redirects=True)
                page_data = {
                    "url": url,
                    "status": r.status_code,
                    "title": "",
                    "links": [],
                    "forms": [],
                    "content_type": r.headers.get("Content-Type", ""),
                    "server": r.headers.get("Server", ""),
                    "x_powered_by": r.headers.get("X-Powered-By", ""),
                    "security_headers": self._check_security_headers(r.headers),
                }
                if "text/html" in r.headers.get("Content-Type", ""):
                    soup = BeautifulSoup(r.text, "html.parser")
                    title_tag = soup.find("title")
                    if title_tag:
                        page_data["title"] = title_tag.get_text(strip=True)

                    links = []
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        full_url = urljoin(url, href)
                        parsed = urlparse(full_url)
                        if self.domain in parsed.netloc:
                            links.append(full_url)
                    page_data["links"] = links[:20]

                    forms = []
                    for form in soup.find_all("form"):
                        forms.append({
                            "action": form.get("action", ""),
                            "method": form.get("method", "get"),
                            "fields": [inp.get("name", "") for inp in form.find_all("input")],
                        })
                    page_data["forms"] = forms

                    if depth < max_depth:
                        for link in links[:10]:
                            if link not in visited:
                                to_visit.append((link, depth + 1))

                self.crawled_pages.append(page_data)
            except Exception as e:
                logger.debug(f"Crawl error ({url}): {e}")

        queue = [(url, 0) for url in to_visit]
        for item in queue[:50]:
            if isinstance(item, tuple):
                crawl_url(*item)
            else:
                crawl_url(item, 0)
            if len(self.crawled_pages) >= 30:
                break

    def _check_security_headers(self, headers) -> Dict:
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "X-Frame-Options": "Clickjacking",
            "X-Content-Type-Options": "MIME sniff",
            "Content-Security-Policy": "CSP",
            "X-XSS-Protection": "XSS",
            "Referrer-Policy": "Referrer",
            "Permissions-Policy": "Permissions",
        }
        result = {}
        for header, name in security_headers.items():
            result[name] = header in headers
        return result

    def _get_ssl_certs(self):
        logger.info(f"[Web] Fetching SSL certificates from crt.sh...")
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                seen = set()
                for cert in data[:100]:
                    cert_id = cert.get("id")
                    if cert_id in seen:
                        continue
                    seen.add(cert_id)
                    self.ssl_certs.append({
                        "id": cert_id,
                        "issuer": cert.get("issuer_name", ""),
                        "common_name": cert.get("common_name", ""),
                        "name_value": cert.get("name_value", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", ""),
                        "entry_timestamp": cert.get("entry_timestamp", ""),
                    })
                logger.info(f"[Web] Found {len(self.ssl_certs)} SSL certificates")
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")

    def _wayback_machine(self):
        logger.info(f"[Web] Fetching Wayback Machine URLs...")
        try:
            r = requests.get(
                f"http://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{self.domain}/*",
                    "output": "text",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "500",
                },
                timeout=20
            )
            if r.status_code == 200:
                urls = [line.strip() for line in r.text.splitlines() if line.strip()]
                self.wayback_urls = list(set(urls))
                logger.info(f"[Web] Wayback Machine: {len(self.wayback_urls)} unique URLs")
        except Exception as e:
            logger.debug(f"Wayback Machine error: {e}")

    def _ip_asn_lookup(self):
        if not self.ip:
            return
        logger.info(f"[Web] Looking up IP/ASN info for {self.ip}...")
        try:
            r = requests.get(f"https://ipapi.co/{self.ip}/json/", timeout=8)
            if r.status_code == 200:
                data = r.json()
                self.ip_info = {
                    "ip": self.ip,
                    "city": data.get("city", ""),
                    "region": data.get("region", ""),
                    "country": data.get("country_name", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("org", ""),
                    "latitude": data.get("latitude", ""),
                    "longitude": data.get("longitude", ""),
                    "timezone": data.get("timezone", ""),
                }
        except Exception as e:
            logger.debug(f"IP lookup error: {e}")

        try:
            r = requests.get(f"https://api.hackertarget.com/aslookup/?q={self.ip}", timeout=8)
            if r.status_code == 200:
                self.asn_info = {"raw": r.text.strip()}
        except Exception as e:
            logger.debug(f"ASN lookup error: {e}")

    def _shodan_lookup(self):
        if not self.config or not self.config.shodan_api_key:
            logger.debug("[Web] No Shodan API key configured")
            return
        logger.info(f"[Web] Querying Shodan...")
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{self.ip}",
                params={"key": self.config.shodan_api_key},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                self.shodan_data = {
                    "ip": data.get("ip_str", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "os": data.get("os", ""),
                    "country": data.get("country_name", ""),
                    "city": data.get("city", ""),
                    "hostnames": data.get("hostnames", []),
                    "ports": data.get("ports", []),
                    "vulns": list(data.get("vulns", {}).keys()),
                    "tags": data.get("tags", []),
                    "services": [
                        {
                            "port": s.get("port"),
                            "transport": s.get("transport"),
                            "product": s.get("product", ""),
                            "version": s.get("version", ""),
                            "banner": str(s.get("data", ""))[:200],
                        }
                        for s in data.get("data", [])[:20]
                    ],
                }
                logger.info(f"[Web] Shodan: {len(self.shodan_data.get('ports', []))} ports, {len(self.shodan_data.get('vulns', []))} vulns")
        except Exception as e:
            logger.debug(f"Shodan error: {e}")

    def _censys_lookup(self):
        if not self.config or not self.config.censys_api_id:
            logger.debug("[Web] No Censys API key configured")
            return
        logger.info(f"[Web] Querying Censys...")
        try:
            r = requests.get(
                f"https://search.censys.io/api/v2/hosts/{self.ip}",
                auth=(self.config.censys_api_id, self.config.censys_api_secret),
                timeout=10
            )
            if r.status_code == 200:
                data = r.json().get("result", {})
                self.censys_data = {
                    "ip": data.get("ip", ""),
                    "services": data.get("services", []),
                    "autonomous_system": data.get("autonomous_system", {}),
                    "location": data.get("location", {}),
                    "labels": data.get("labels", []),
                }
                logger.info(f"[Web] Censys: {len(self.censys_data.get('services', []))} services")
        except Exception as e:
            logger.debug(f"Censys error: {e}")
