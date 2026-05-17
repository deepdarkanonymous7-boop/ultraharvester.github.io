"""
DNS & Domain Enumeration Module
Subdomain brute-force + passive, DNS records, zone transfer,
reverse DNS, WHOIS, PassiveDNS history
"""

import socket
import concurrent.futures
import time
import re
import json
from typing import List, Dict, Set, Optional

import requests
import dns.resolver
import dns.zone
import dns.query
import dns.reversename

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

from ..utils.logger import get_logger

logger = get_logger("ultraharvester.dns")

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "vpn", "m", "mobile", "api", "dev", "staging", "test", "beta",
    "blog", "cdn", "static", "assets", "img", "images", "media", "upload",
    "download", "files", "docs", "help", "support", "admin", "portal",
    "login", "secure", "shop", "store", "pay", "payment", "checkout",
    "app", "apps", "auth", "oauth", "sso", "ldap", "remote", "git",
    "gitlab", "github", "jira", "confluence", "jenkins", "ci", "monitor",
    "status", "metrics", "grafana", "prometheus", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "redis", "mongo", "solr",
    "fw", "firewall", "proxy", "gateway", "router", "switch",
    "intranet", "internal", "corp", "office", "extranet",
    "owa", "exchange", "autodiscover", "lyncdiscover", "teams",
    "sharepoint", "onedrive", "skype",
    "crm", "erp", "hr", "finance", "accounting",
    "backup", "bk", "archive", "old", "legacy",
    "v1", "v2", "v3", "new", "demo", "sandbox",
    "cpanel", "whm", "plesk", "webmin", "phpmyadmin",
    "mx", "mx1", "mx2", "relay", "smtp2", "imap",
    "ssh", "sftp", "ansible", "puppet", "chef",
    "docker", "k8s", "kubernetes", "vault",
    "research", "partner", "partners", "affiliate", "affiliates",
    "news", "press", "media", "marketing", "ad", "ads",
    "forum", "community", "wiki", "kb",
    "us", "eu", "asia", "uk", "de", "fr", "es", "it", "nl",
    "east", "west", "north", "south", "us-east", "us-west",
    "aws", "azure", "gcp", "cloud", "s3",
    "vpn1", "vpn2", "jump", "bastion",
]


class DNSEnumerator:
    def __init__(self, domain: str, config=None):
        self.domain = domain
        self.config = config
        self.subdomains: List[Dict] = []
        self.records: Dict = {}
        self.zone_transfer: List[str] = []
        self.reverse_dns: List[Dict] = []
        self.whois_data: Dict = {}
        self.passive_dns: List[Dict] = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    def run(self) -> Dict:
        logger.info(f"[DNS] Starting DNS enumeration for {self.domain}")
        self._get_dns_records()
        self._enumerate_subdomains()
        self._check_zone_transfer()
        self._reverse_dns_lookup()
        self._whois_lookup()
        self._passive_dns()
        logger.info(f"[DNS] Found {len(self.subdomains)} subdomains, {len(self.records)} record types")
        return {
            "subdomains": self.subdomains,
            "records": self.records,
            "zone_transfer": self.zone_transfer,
            "reverse_dns": self.reverse_dns,
            "whois": self.whois_data,
            "passive_dns": self.passive_dns,
        }

    def _get_dns_records(self):
        logger.info("[DNS] Fetching DNS records...")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                records = []
                for rdata in answers:
                    records.append(str(rdata))
                if records:
                    self.records[rtype] = records
                    logger.debug(f"[DNS] {rtype}: {records}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception as e:
                logger.debug(f"DNS record error ({rtype}): {e}")

        self._check_spf_dmarc()

    def _check_spf_dmarc(self):
        try:
            answers = self.resolver.resolve(self.domain, "TXT")
            spf = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    spf.append(txt)
            if spf:
                self.records["SPF"] = spf
        except Exception:
            pass

        try:
            answers = self.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
            dmarc = [str(r).strip('"') for r in answers]
            if dmarc:
                self.records["DMARC"] = dmarc
        except Exception:
            pass

    def _enumerate_subdomains(self):
        logger.info("[DNS] Enumerating subdomains...")
        wordlist = COMMON_SUBDOMAINS
        if self.config and self.config.subdomain_wordlist:
            try:
                with open(self.config.subdomain_wordlist) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            except Exception:
                pass

        threads = self.config.threads if self.config else 20
        found: Set[str] = set()

        def check(sub: str):
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = self.resolver.resolve(fqdn, "A")
                ips = [str(r) for r in answers]
                found.add(fqdn)
                return {"subdomain": fqdn, "ips": ips, "source": "brute"}
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(check, sub): sub for sub in wordlist}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    self.subdomains.append(result)
                    logger.debug(f"[DNS] Found subdomain: {result['subdomain']}")

        self._passive_subdomains(found)

    def _passive_subdomains(self, already_found: Set[str]):
        logger.info("[DNS] Passive subdomain enumeration...")
        sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
        ]
        for url in sources:
            try:
                r = requests.get(url, timeout=10)
                if "crt.sh" in url:
                    data = r.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(self.domain) and sub not in already_found:
                                try:
                                    ips = [str(r2) for r2 in self.resolver.resolve(sub, "A")]
                                    self.subdomains.append({"subdomain": sub, "ips": ips, "source": "crt.sh"})
                                    already_found.add(sub)
                                except Exception:
                                    self.subdomains.append({"subdomain": sub, "ips": [], "source": "crt.sh"})
                                    already_found.add(sub)
                elif "hackertarget" in url:
                    for line in r.text.splitlines():
                        parts = line.split(",")
                        if len(parts) == 2:
                            sub, ip = parts[0].strip(), parts[1].strip()
                            if sub not in already_found:
                                self.subdomains.append({"subdomain": sub, "ips": [ip], "source": "hackertarget"})
                                already_found.add(sub)
            except Exception as e:
                logger.debug(f"Passive sub error ({url}): {e}")

    def _check_zone_transfer(self):
        logger.info("[DNS] Checking for DNS zone transfer (AXFR)...")
        ns_records = self.records.get("NS", [])
        for ns in ns_records:
            ns = ns.rstrip(".")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=5))
                for name in z.nodes:
                    self.zone_transfer.append(f"{name}.{self.domain}")
                logger.warning(f"[DNS] Zone transfer SUCCESSFUL on {ns}!")
            except Exception:
                pass
        if not self.zone_transfer:
            logger.info("[DNS] Zone transfer not allowed (expected)")

    def _reverse_dns_lookup(self):
        logger.info("[DNS] Performing reverse DNS lookups...")
        all_ips = []
        for sub in self.subdomains[:20]:
            all_ips.extend(sub.get("ips", []))
        all_ips = list(set(all_ips))[:30]
        for ip in all_ips:
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(rev_name, "PTR")
                for rdata in answers:
                    self.reverse_dns.append({"ip": ip, "hostname": str(rdata).rstrip(".")})
            except Exception:
                pass

    def _whois_lookup(self):
        logger.info("[DNS] Performing WHOIS lookup...")
        if not HAS_WHOIS:
            logger.debug("python-whois not installed")
            return
        try:
            w = whois.whois(self.domain)
            self.whois_data = {
                "domain_name": str(w.domain_name or ""),
                "registrar": str(w.registrar or ""),
                "creation_date": str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "updated_date": str(w.updated_date or ""),
                "name_servers": [str(ns) for ns in (w.name_servers or [])],
                "status": str(w.status or ""),
                "emails": [str(e) for e in (w.emails or [])] if isinstance(w.emails, list) else [str(w.emails or "")],
                "dnssec": str(w.dnssec or ""),
                "org": str(w.org or ""),
                "country": str(w.country or ""),
            }
        except Exception as e:
            logger.debug(f"WHOIS error: {e}")
            self.whois_data = {"error": str(e)}

    def _passive_dns(self):
        logger.info("[DNS] Checking PassiveDNS history...")
        try:
            r = requests.get(
                f"https://api.hackertarget.com/dnslookup/?q={self.domain}",
                timeout=10
            )
            for line in r.text.splitlines():
                parts = line.split(" ")
                if len(parts) >= 2:
                    self.passive_dns.append({
                        "type": parts[0] if len(parts) > 2 else "A",
                        "value": parts[-1],
                    })
        except Exception as e:
            logger.debug(f"PassiveDNS error: {e}")
