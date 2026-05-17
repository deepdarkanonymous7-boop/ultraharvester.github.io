"""
Leak & Breach Checker Module
HaveIBeenPwned API, GitHub credential leaks,
Pastebin monitoring, paste site search
"""

import re
import time
import random
import hashlib
from typing import List, Dict, Optional, Set

import requests

from ..utils.logger import get_logger

logger = get_logger("ultraharvester.leaks")


class LeakChecker:
    def __init__(self, domain: str, emails: List[str] = None, config=None):
        self.domain = domain
        self.emails = emails or []
        self.config = config
        self.breaches: List[Dict] = []
        self.pastes: List[Dict] = []
        self.github_leaks: List[Dict] = []
        self.pastebin_mentions: List[Dict] = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "UltraHarvester-SecurityScanner/1.0",
            "hibp-api-key": (config.hibp_api_key or "") if config else "",
        })

    def run(self) -> Dict:
        logger.info(f"[Leaks] Starting leak check for {self.domain}")
        self._check_hibp_domain()
        for email in self.emails[:20]:
            self._check_hibp_email(email)
        self._search_github_leaks()
        self._search_pastebin()
        self._search_paste_sites()
        logger.info(
            f"[Leaks] Found {len(self.breaches)} breaches, {len(self.github_leaks)} GitHub leaks, {len(self.pastes)} pastes"
        )
        return {
            "breaches": self.breaches,
            "pastes": self.pastes,
            "github_leaks": self.github_leaks,
            "pastebin_mentions": self.pastebin_mentions,
            "summary": {
                "total_breaches": len(self.breaches),
                "total_pastes": len(self.pastes),
                "github_exposures": len(self.github_leaks),
                "emails_checked": len(self.emails[:20]),
            }
        }

    def _check_hibp_domain(self):
        logger.info(f"[Leaks] Checking HaveIBeenPwned for domain {self.domain}...")
        api_key = self.config.hibp_api_key if self.config else None
        if not api_key:
            logger.info("[Leaks] No HIBP API key — using public endpoint (limited)")

        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{self.domain}"
        headers = {"hibp-api-key": api_key} if api_key else {}
        try:
            r = self.session.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for email_user, breach_names in data.items():
                    self.breaches.append({
                        "email": f"{email_user}@{self.domain}",
                        "breaches": breach_names,
                        "source": "hibp-domain",
                    })
                logger.info(f"[Leaks] HIBP domain: {len(self.breaches)} emails breached")
            elif r.status_code == 401:
                logger.warning("[Leaks] HIBP API key required for domain breach lookup")
            elif r.status_code == 404:
                logger.info("[Leaks] No breaches found for this domain")
        except Exception as e:
            logger.debug(f"HIBP domain error: {e}")

    def _check_hibp_email(self, email: str):
        api_key = self.config.hibp_api_key if self.config else None
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"hibp-api-key": api_key} if api_key else {}
        try:
            time.sleep(1.6)
            r = self.session.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for breach in data:
                    self.breaches.append({
                        "email": email,
                        "breach_name": breach.get("Name", ""),
                        "breach_date": breach.get("BreachDate", ""),
                        "data_classes": breach.get("DataClasses", []),
                        "pwn_count": breach.get("PwnCount", 0),
                        "description": breach.get("Description", "")[:200],
                        "is_verified": breach.get("IsVerified", False),
                        "source": "hibp-email",
                    })
            elif r.status_code == 404:
                logger.debug(f"[Leaks] {email}: no breaches found")
            elif r.status_code == 429:
                logger.warning("[Leaks] HIBP rate limit hit, slowing down...")
                time.sleep(5)
        except Exception as e:
            logger.debug(f"HIBP email error ({email}): {e}")

    def _check_password_range(self, password_hash_prefix: str) -> List[str]:
        try:
            r = self.session.get(
                f"https://api.pwnedpasswords.com/range/{password_hash_prefix}",
                timeout=10
            )
            if r.status_code == 200:
                return r.text.splitlines()
        except Exception:
            pass
        return []

    def check_password_breached(self, password: str) -> Dict:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        results = self._check_password_range(prefix)
        for line in results:
            if ":" in line:
                hash_suffix, count = line.split(":", 1)
                if hash_suffix == suffix:
                    return {"breached": True, "count": int(count), "hash": sha1}
        return {"breached": False, "count": 0, "hash": sha1}

    def _search_github_leaks(self):
        logger.info(f"[Leaks] Searching GitHub for credential leaks...")
        queries = [
            f'"{self.domain}" password',
            f'"{self.domain}" api_key OR api-key OR apikey',
            f'"{self.domain}" secret OR token',
            f'"{self.domain}" smtp OR database OR db',
            f'"@{self.domain}" password',
        ]
        session = requests.Session()
        session.headers.update({"User-Agent": "UltraHarvester/1.0"})

        github_token = None
        if self.config:
            github_token = getattr(self.config, "github_token", None)
        if github_token:
            session.headers["Authorization"] = f"token {github_token}"

        for query in queries[:3]:
            try:
                time.sleep(random.uniform(2.0, 4.0))
                r = session.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 10},
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get("items", []):
                        self.github_leaks.append({
                            "query": query,
                            "repository": item.get("repository", {}).get("full_name", ""),
                            "file_name": item.get("name", ""),
                            "path": item.get("path", ""),
                            "url": item.get("html_url", ""),
                            "score": item.get("score", 0),
                        })
                elif r.status_code == 403:
                    logger.warning("[Leaks] GitHub API rate limit — add a token for higher limits")
                    break
                elif r.status_code == 422:
                    logger.debug(f"[Leaks] GitHub query invalid: {query}")
            except Exception as e:
                logger.debug(f"GitHub search error: {e}")

    def _search_pastebin(self):
        logger.info(f"[Leaks] Searching Pastebin for mentions...")
        try:
            r = requests.get(
                f"https://psbdmp.ws/api/search/{self.domain}",
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                for paste in data.get("data", [])[:20]:
                    self.pastebin_mentions.append({
                        "id": paste.get("id", ""),
                        "title": paste.get("title", ""),
                        "time": paste.get("time", ""),
                        "url": f"https://pastebin.com/{paste.get('id', '')}",
                        "source": "pastebin",
                    })
        except Exception as e:
            logger.debug(f"Pastebin search error: {e}")

    def _search_paste_sites(self):
        logger.info(f"[Leaks] Searching paste sites via Google...")
        paste_sites = ["pastebin.com", "paste.ee", "ghostbin.com", "hastebin.com", "gist.github.com"]
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 UltraHarvester"})

        for site in paste_sites[:3]:
            query = f'site:{site} "{self.domain}"'
            try:
                time.sleep(random.uniform(2.0, 3.5))
                r = session.get(
                    "https://www.google.com/search",
                    params={"q": query, "num": 10},
                    timeout=10
                )
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("/url?q="):
                        href = href.split("/url?q=")[1].split("&")[0]
                    if site in href:
                        self.pastes.append({
                            "url": href,
                            "site": site,
                            "query": query,
                        })
            except Exception as e:
                logger.debug(f"Paste site search error ({site}): {e}")
