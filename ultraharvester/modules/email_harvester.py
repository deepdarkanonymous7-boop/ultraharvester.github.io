"""
Email & People Harvester Module
Collects emails from Google, Bing, DuckDuckGo, Yahoo
SMTP verification, LinkedIn/Twitter/GitHub profile search
"""

import re
import time
import smtplib
import asyncio
import socket
import random
from typing import List, Dict, Set, Optional
from urllib.parse import quote_plus, urlparse

import requests
from bs4 import BeautifulSoup

from ..utils.logger import get_logger

logger = get_logger("ultraharvester.emails")

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


class EmailHarvester:
    def __init__(self, domain: str, config=None):
        self.domain = domain
        self.config = config
        self.found_emails: Set[str] = set()
        self.verified_emails: List[Dict] = []
        self.profiles: List[Dict] = []
        self.employees: List[str] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
        })
        if config and config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}

    def run(self) -> Dict:
        logger.info(f"[Emails] Starting email harvesting for {self.domain}")
        self._harvest_google()
        self._harvest_bing()
        self._harvest_duckduckgo()
        self._harvest_yahoo()
        self._harvest_common_formats()
        for email in list(self.found_emails)[:30]:
            result = self._verify_smtp(email)
            self.verified_emails.append(result)
        self._search_profiles()
        self._search_employees()
        logger.info(f"[Emails] Found {len(self.found_emails)} emails, {len(self.verified_emails)} verified")
        return {
            "emails": list(self.found_emails),
            "verified": self.verified_emails,
            "profiles": self.profiles,
            "employees": self.employees,
        }

    def _search_engine(self, url: str, params: dict) -> str:
        try:
            time.sleep(random.uniform(1.5, 3.0))
            r = self.session.get(url, params=params, timeout=10)
            return r.text
        except Exception as e:
            logger.debug(f"Search engine error: {e}")
            return ""

    def _extract_emails(self, text: str) -> Set[str]:
        found = set()
        for m in EMAIL_RE.finditer(text):
            email = m.group().lower()
            if self.domain in email:
                found.add(email)
        return found

    def _harvest_google(self):
        logger.info("[Emails] Searching Google...")
        queries = [
            f'site:{self.domain} "@{self.domain}"',
            f'"{self.domain}" email contact',
            f'intext:"@{self.domain}" filetype:html',
        ]
        for query in queries:
            html = self._search_engine(
                "https://www.google.com/search",
                {"q": query, "num": 100, "hl": "en"}
            )
            emails = self._extract_emails(html)
            self.found_emails.update(emails)
            logger.debug(f"Google found {len(emails)} emails for query: {query}")

    def _harvest_bing(self):
        logger.info("[Emails] Searching Bing...")
        queries = [
            f'site:{self.domain} "@{self.domain}"',
            f'"{self.domain}" "contact" email',
        ]
        for query in queries:
            html = self._search_engine(
                "https://www.bing.com/search",
                {"q": query, "count": 50}
            )
            emails = self._extract_emails(html)
            self.found_emails.update(emails)

    def _harvest_duckduckgo(self):
        logger.info("[Emails] Searching DuckDuckGo...")
        query = f'site:{self.domain} "@{self.domain}"'
        html = self._search_engine(
            "https://html.duckduckgo.com/html/",
            {"q": query}
        )
        emails = self._extract_emails(html)
        self.found_emails.update(emails)

    def _harvest_yahoo(self):
        logger.info("[Emails] Searching Yahoo...")
        query = f'site:{self.domain} "@{self.domain}"'
        html = self._search_engine(
            "https://search.yahoo.com/search",
            {"p": query, "n": 50}
        )
        emails = self._extract_emails(html)
        self.found_emails.update(emails)

    def _harvest_common_formats(self):
        logger.info("[Emails] Generating common email formats...")
        common_prefixes = [
            "info", "contact", "admin", "support", "hello", "mail",
            "office", "hr", "sales", "security", "webmaster", "postmaster",
            "abuse", "noreply", "no-reply", "legal", "privacy", "help",
        ]
        for prefix in common_prefixes:
            self.found_emails.add(f"{prefix}@{self.domain}")

    def _verify_smtp(self, email: str) -> Dict:
        result = {
            "email": email,
            "valid_format": bool(EMAIL_RE.match(email)),
            "domain_exists": False,
            "smtp_valid": False,
            "disposable": False,
            "risk_score": 0,
        }
        try:
            import dns.resolver
            domain = email.split("@")[1]
            mx_records = dns.resolver.resolve(domain, "MX")
            if mx_records:
                result["domain_exists"] = True
                mx_host = str(list(mx_records)[0].exchange).rstrip(".")
                try:
                    smtp = smtplib.SMTP(timeout=5)
                    smtp.connect(mx_host, 25)
                    smtp.helo("ultraharvester.local")
                    smtp.mail("probe@ultraharvester.local")
                    code, _ = smtp.rcpt(email)
                    smtp.quit()
                    result["smtp_valid"] = (code == 250)
                except Exception:
                    pass
        except Exception:
            pass

        disposable_domains = {
            "mailinator.com", "guerrillamail.com", "tempmail.com",
            "throwam.com", "yopmail.com", "10minutemail.com",
        }
        domain = email.split("@")[1] if "@" in email else ""
        result["disposable"] = domain in disposable_domains

        score = 0
        if result["valid_format"]: score += 20
        if result["domain_exists"]: score += 30
        if result["smtp_valid"]: score += 40
        if not result["disposable"]: score += 10
        result["risk_score"] = score

        return result

    def _search_profiles(self):
        logger.info("[Emails] Searching social profiles...")
        platforms = {
            "linkedin": f"https://www.google.com/search?q=site:linkedin.com+\"{self.domain}\"",
            "twitter": f"https://www.google.com/search?q=site:twitter.com+\"{self.domain}\"",
            "github": f"https://www.google.com/search?q=site:github.com+\"{self.domain}\"",
        }
        for platform, url in platforms.items():
            try:
                time.sleep(random.uniform(1.0, 2.0))
                r = self.session.get(url, timeout=10)
                soup = BeautifulSoup(r.text, "html.parser")
                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if platform in href and "google.com" not in href:
                        clean = urlparse(href).path
                        if clean and len(clean) > 2:
                            links.append(href)
                if links:
                    self.profiles.append({
                        "platform": platform,
                        "domain": self.domain,
                        "results": links[:10],
                    })
            except Exception as e:
                logger.debug(f"Profile search error ({platform}): {e}")

    def _search_employees(self):
        logger.info("[Emails] Searching employee names...")
        query = f'site:linkedin.com/in "{self.domain}" employee'
        try:
            time.sleep(random.uniform(2.0, 3.5))
            r = self.session.get(
                "https://www.google.com/search",
                params={"q": query, "num": 50},
                timeout=10
            )
            soup = BeautifulSoup(r.text, "html.parser")
            name_re = re.compile(r"([A-Z][a-z]+ [A-Z][a-z]+)")
            names = set()
            for text in soup.stripped_strings:
                matches = name_re.findall(text)
                for name in matches:
                    common = {"Google", "LinkedIn", "Search", "See More", "Sign In"}
                    if name not in common:
                        names.add(name)
            self.employees = list(names)[:30]
        except Exception as e:
            logger.debug(f"Employee search error: {e}")
