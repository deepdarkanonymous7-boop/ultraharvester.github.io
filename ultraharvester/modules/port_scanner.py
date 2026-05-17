"""
Port Scanner & Service Detection Module
Nmap-style scanning, banner grabbing, web tech detection, CMS detection
"""

import socket
import concurrent.futures
import re
import time
from typing import List, Dict, Optional, Tuple

import requests
from bs4 import BeautifulSoup

from ..utils.logger import get_logger

logger = get_logger("ultraharvester.ports")

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "ISAKMP", 514: "Syslog", 587: "SMTP", 631: "IPP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2181: "Zookeeper", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5000: "Flask/UPnP", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic", 8000: "HTTP-Alt",
    8008: "HTTP-Alt", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "PHP-FPM", 9090: "Openfire", 9200: "Elasticsearch", 9300: "ES-Cluster",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB", 50070: "Hadoop",
}

WEB_TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Joomla": [r"Joomla!", r"/components/com_", r"joomla"],
    "Drupal": [r"Drupal", r"/sites/default/files", r"drupal"],
    "Magento": [r"Magento", r"/skin/frontend/", r"mage"],
    "PrestaShop": [r"PrestaShop", r"/modules/prestafraud"],
    "Laravel": [r"laravel_session", r"laravel"],
    "Django": [r"csrfmiddlewaretoken", r"django"],
    "React": [r"react", r"__REACT_DEVTOOLS"],
    "Vue.js": [r"vue\.js", r"__vue__"],
    "Angular": [r"ng-version", r"angular"],
    "jQuery": [r"jquery", r"jQuery"],
    "Bootstrap": [r"bootstrap", r"Bootstrap"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static"],
    "Nuxt.js": [r"__NUXT__", r"nuxt"],
    "Express": [r"X-Powered-By: Express"],
    "Nginx": [r"nginx", r"Server: nginx"],
    "Apache": [r"Apache", r"Server: Apache"],
    "IIS": [r"Microsoft-IIS", r"X-Powered-By: ASP.NET"],
    "Cloudflare": [r"cloudflare", r"CF-RAY"],
    "AWS": [r"AmazonS3", r"x-amz-"],
    "Google Cloud": [r"goog-", r"X-Google-"],
    "Shopify": [r"cdn.shopify.com", r"Shopify"],
    "Wix": [r"wix.com", r"Wix"],
    "Squarespace": [r"squarespace", r"Squarespace"],
    "Ghost": [r"ghost", r"Ghost"],
    "Gatsby": [r"gatsby", r"___gatsby"],
    "PHP": [r"X-Powered-By: PHP", r"\.php"],
    "ASP.NET": [r"ASP.NET", r"ASPNETCORE"],
    "Spring": [r"spring", r"Spring Framework"],
    "Tomcat": [r"Apache Tomcat", r"Coyote"],
}


class PortScanner:
    def __init__(self, target: str, config=None):
        self.target = target
        self.config = config
        self.open_ports: List[Dict] = []
        self.web_technologies: List[str] = []
        self.cms_detected: Optional[str] = None
        self.banners: List[Dict] = []
        self.threads = config.threads if config else 50

        port_range = config.port_range if config else "1-1000"
        self.port_list = self._parse_port_range(port_range)

    def run(self) -> Dict:
        logger.info(f"[Ports] Starting port scan on {self.target}")
        self._resolve_target()
        self._scan_ports()
        self._grab_banners()
        self._detect_web_technologies()
        logger.info(f"[Ports] Found {len(self.open_ports)} open ports")
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "banners": self.banners,
            "web_technologies": self.web_technologies,
            "cms": self.cms_detected,
        }

    def _parse_port_range(self, port_range: str) -> List[int]:
        ports = []
        for part in port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _resolve_target(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            logger.info(f"[Ports] Resolved {self.target} -> {self.ip}")
        except Exception:
            self.ip = self.target

    def _scan_single_port(self, port: int) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                return {"port": port, "state": "open", "service": service}
        except Exception:
            pass
        return None

    def _scan_ports(self):
        logger.info(f"[Ports] Scanning {len(self.port_list)} ports with {self.threads} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_single_port, p): p for p in self.port_list}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    self.open_ports.append(result)
                    logger.debug(f"[Ports] Open: {result['port']}/{result['service']}")
        self.open_ports.sort(key=lambda x: x["port"])

    def _grab_banner(self, port: int, service: str) -> Optional[str]:
        probes = {
            "HTTP": b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n",
            "HTTPS": None,
            "FTP": None,
            "SMTP": None,
            "SSH": None,
            "default": b"\r\n",
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, port))
            if service in probes and probes[service]:
                sock.send(probes[service])
            elif service not in probes:
                sock.send(probes["default"])
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:500] if banner else None
        except Exception:
            return None

    def _grab_banners(self):
        logger.info("[Ports] Grabbing service banners...")
        for port_info in self.open_ports[:20]:
            port = port_info["port"]
            service = port_info["service"]
            banner = self._grab_banner(port, service)
            if banner:
                self.banners.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                })
                port_info["banner"] = banner[:100]

    def _detect_web_technologies(self):
        logger.info("[Ports] Detecting web technologies...")
        web_ports = [p for p in self.open_ports if p["service"] in ("HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt")]
        if not web_ports:
            web_ports = [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]

        detected: set = set()
        for port_info in web_ports[:3]:
            port = port_info["port"]
            scheme = "https" if "443" in str(port) or "HTTPS" in port_info["service"] else "http"
            url = f"{scheme}://{self.target}:{port}" if port not in (80, 443) else f"{scheme}://{self.target}"
            try:
                r = requests.get(url, timeout=8, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0 UltraHarvester"})
                content = r.text.lower()
                headers_str = str(r.headers).lower()
                combined = content + headers_str

                for tech, patterns in WEB_TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern.lower(), combined):
                            detected.add(tech)
                            break

                for cms in ["WordPress", "Joomla", "Drupal", "Magento", "PrestaShop", "Shopify", "Wix"]:
                    if cms in detected:
                        self.cms_detected = cms
                        break

            except Exception as e:
                logger.debug(f"Web tech detection error ({url}): {e}")

        self.web_technologies = sorted(detected)
        logger.info(f"[Ports] Technologies detected: {', '.join(self.web_technologies) or 'none'}")
