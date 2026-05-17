"""
AI & Automation Engine
Risk scoring, auto-correlation, PDF/HTML report generation,
Telegram/Slack notifications
"""

import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..utils.logger import get_logger

logger = get_logger("ultraharvester.ai")


RISK_WEIGHTS = {
    "zone_transfer": 90,
    "open_rdp": 85,
    "open_smb": 80,
    "breach_found": 75,
    "github_leak": 70,
    "paste_mention": 65,
    "email_verified": 40,
    "subdomain_many": 35,
    "missing_hsts": 30,
    "missing_csp": 25,
    "missing_x_frame": 20,
    "smtp_open": 15,
    "ftp_open": 50,
    "telnet_open": 70,
    "cms_detected": 20,
    "shodan_vulns": 80,
}


class AIEngine:
    def __init__(self, config=None):
        self.config = config
        self.risk_score = 0
        self.risk_findings: List[Dict] = []
        self.correlations: List[Dict] = []
        self.summary: str = ""

    def run(self, scan_data: Dict) -> Dict:
        logger.info("[AI] Running AI analysis and risk scoring...")
        self._calculate_risk(scan_data)
        self._correlate_findings(scan_data)
        self._generate_summary(scan_data)
        self._send_notifications(scan_data)
        return {
            "risk_score": self.risk_score,
            "risk_level": self._risk_level(self.risk_score),
            "findings": self.risk_findings,
            "correlations": self.correlations,
            "summary": self.summary,
        }

    def _calculate_risk(self, data: Dict):
        score = 0
        findings = []

        dns = data.get("dns", {})
        if dns.get("zone_transfer"):
            score += RISK_WEIGHTS["zone_transfer"]
            findings.append({
                "severity": "CRITICAL",
                "category": "DNS",
                "title": "DNS Zone Transfer Allowed",
                "description": "The DNS server allows zone transfers, exposing all DNS records.",
                "remediation": "Restrict zone transfers to authorized secondary nameservers only.",
                "cvss": 9.1,
            })

        ports = data.get("ports", {})
        open_ports = [p["port"] for p in ports.get("open_ports", [])]

        dangerous_ports = {
            23: ("Telnet Port Open", "CRITICAL", 70, "Telnet transmits credentials in cleartext. Disable and use SSH."),
            21: ("FTP Port Open", "HIGH", 50, "FTP transmits credentials in cleartext. Use SFTP instead."),
            3389: ("RDP Exposed", "HIGH", 85, "RDP is exposed to the internet. Use VPN or restrict access."),
            445: ("SMB Port Open", "HIGH", 80, "SMB exposed can lead to ransomware attacks. Restrict access."),
            1433: ("MSSQL Exposed", "HIGH", 75, "Database port exposed to internet."),
            3306: ("MySQL Exposed", "HIGH", 75, "Database port exposed to internet."),
            5432: ("PostgreSQL Exposed", "HIGH", 75, "Database port exposed to internet."),
            27017: ("MongoDB Exposed", "CRITICAL", 85, "MongoDB often has no auth by default when exposed."),
            6379: ("Redis Exposed", "CRITICAL", 85, "Redis often has no auth by default when exposed."),
            9200: ("Elasticsearch Exposed", "HIGH", 80, "Elasticsearch may expose sensitive data without auth."),
            11211: ("Memcached Exposed", "HIGH", 70, "Memcached has no built-in authentication."),
        }

        for port, (title, severity, weight, remediation) in dangerous_ports.items():
            if port in open_ports:
                score += weight
                findings.append({
                    "severity": severity,
                    "category": "Ports",
                    "title": title,
                    "description": f"Port {port} is open and accessible.",
                    "remediation": remediation,
                    "cvss": round(weight / 10, 1),
                })

        leaks = data.get("leaks", {})
        if leaks.get("breaches"):
            score += RISK_WEIGHTS["breach_found"]
            findings.append({
                "severity": "HIGH",
                "category": "Breach",
                "title": f"Email Breaches Found ({len(leaks['breaches'])})",
                "description": f"Found {len(leaks['breaches'])} email addresses in known data breaches.",
                "remediation": "Force password resets for affected accounts and enable MFA.",
                "cvss": 7.5,
            })

        if leaks.get("github_leaks"):
            score += RISK_WEIGHTS["github_leak"]
            findings.append({
                "severity": "HIGH",
                "category": "Code Exposure",
                "title": f"Credentials Exposed on GitHub ({len(leaks['github_leaks'])})",
                "description": "Sensitive information found in public GitHub repositories.",
                "remediation": "Rotate all exposed credentials immediately and use .gitignore properly.",
                "cvss": 7.0,
            })

        if leaks.get("pastes") or leaks.get("pastebin_mentions"):
            paste_count = len(leaks.get("pastes", [])) + len(leaks.get("pastebin_mentions", []))
            score += RISK_WEIGHTS["paste_mention"]
            findings.append({
                "severity": "MEDIUM",
                "category": "Paste Sites",
                "title": f"Mentions on Paste Sites ({paste_count})",
                "description": "Domain or related data found on public paste sites.",
                "remediation": "Review paste content and rotate any exposed credentials.",
                "cvss": 6.5,
            })

        web = data.get("web", {})
        for page in web.get("crawled_pages", [])[:5]:
            sec_headers = page.get("security_headers", {})
            if not sec_headers.get("HSTS"):
                score += RISK_WEIGHTS["missing_hsts"]
                findings.append({
                    "severity": "MEDIUM",
                    "category": "HTTP Security",
                    "title": "Missing HSTS Header",
                    "description": "HTTP Strict Transport Security header is not set.",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
                    "cvss": 5.0,
                })
                break

        shodan = web.get("shodan", {})
        if shodan.get("vulns"):
            score += RISK_WEIGHTS["shodan_vulns"]
            findings.append({
                "severity": "CRITICAL",
                "category": "Vulnerabilities",
                "title": f"Known CVEs Detected ({len(shodan['vulns'])})",
                "description": f"Shodan detected vulnerabilities: {', '.join(shodan['vulns'][:5])}",
                "remediation": "Apply security patches immediately.",
                "cvss": 9.0,
            })

        self.risk_score = min(100, score)
        self.risk_findings = sorted(findings, key=lambda x: x.get("cvss", 0), reverse=True)

    def _risk_level(self, score: int) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        if score >= 20: return "LOW"
        return "INFO"

    def _correlate_findings(self, data: Dict):
        emails = data.get("emails", {})
        dns = data.get("dns", {})
        leaks = data.get("leaks", {})

        email_list = emails.get("emails", [])
        subdomains = [s["subdomain"] for s in dns.get("subdomains", [])]
        breached_emails = [b["email"] for b in leaks.get("breaches", [])]

        if email_list and subdomains:
            self.correlations.append({
                "type": "email-subdomain",
                "title": "Email ↔ Subdomain Correlation",
                "description": f"Found {len(email_list)} emails and {len(subdomains)} subdomains for {data.get('target', '')}",
                "entities": {"emails": email_list[:5], "subdomains": subdomains[:5]},
            })

        breached_set = set(breached_emails)
        overlap = [e for e in email_list if e in breached_set]
        if overlap:
            self.correlations.append({
                "type": "email-breach",
                "title": "Active Emails in Breaches",
                "description": f"{len(overlap)} currently-active email(s) found in breach databases",
                "entities": {"emails": overlap[:10]},
                "severity": "HIGH",
            })

        subdomains_from_certs = [c["common_name"] for c in data.get("web", {}).get("ssl_certs", [])]
        new_subs = [s for s in subdomains_from_certs if s not in subdomains and data.get("target", "") in s]
        if new_subs:
            self.correlations.append({
                "type": "cert-subdomain",
                "title": "Subdomains Found via SSL Certificates",
                "description": f"{len(new_subs)} additional subdomains discovered via crt.sh",
                "entities": {"subdomains": new_subs[:10]},
            })

    def _generate_summary(self, data: Dict):
        target = data.get("target", "unknown")
        email_count = len(data.get("emails", {}).get("emails", []))
        sub_count = len(data.get("dns", {}).get("subdomains", []))
        port_count = len(data.get("ports", {}).get("open_ports", []))
        breach_count = len(data.get("leaks", {}).get("breaches", []))
        doc_count = len(data.get("metadata", {}).get("documents", []))

        self.summary = (
            f"UltraHarvester scan of '{target}' completed. "
            f"Discovered: {email_count} email addresses, {sub_count} subdomains, "
            f"{port_count} open ports, {breach_count} breach records, {doc_count} public documents. "
            f"Overall risk score: {self.risk_score}/100 ({self._risk_level(self.risk_score)}). "
            f"Key findings: {len(self.risk_findings)} security issues identified."
        )

        if self.config and self.config.openai_api_key:
            self._ai_summary(data)

    def _ai_summary(self, data: Dict):
        try:
            import openai
            client = openai.OpenAI(api_key=self.config.openai_api_key)
            prompt = f"""You are a cybersecurity analyst. Summarize this OSINT scan data for {data.get('target')}:

Risk Score: {self.risk_score}/100
Key Findings: {json.dumps([f['title'] for f in self.risk_findings[:5]], indent=2)}
Emails found: {len(data.get('emails', {}).get('emails', []))}
Subdomains: {len(data.get('dns', {}).get('subdomains', []))}
Open ports: {len(data.get('ports', {}).get('open_ports', []))}
Breaches: {len(data.get('leaks', {}).get('breaches', []))}

Write a concise 3-paragraph executive summary with: 1) attack surface overview, 2) critical risks, 3) recommended actions."""

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500
            )
            self.summary = response.choices[0].message.content
        except Exception as e:
            logger.debug(f"OpenAI summary error: {e}")

    def _send_notifications(self, data: Dict):
        if not self.config:
            return
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            self._send_telegram(data)
        if self.config.slack_webhook_url:
            self._send_slack(data)

    def _send_telegram(self, data: Dict):
        logger.info("[AI] Sending Telegram notification...")
        try:
            import requests as req
            risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(
                self._risk_level(self.risk_score), "⚪"
            )
            msg = (
                f"🔍 *UltraHarvester Scan Complete*\n\n"
                f"🎯 Target: `{data.get('target', 'N/A')}`\n"
                f"{risk_emoji} Risk: *{self._risk_level(self.risk_score)}* ({self.risk_score}/100)\n\n"
                f"📧 Emails: {len(data.get('emails', {}).get('emails', []))}\n"
                f"🌐 Subdomains: {len(data.get('dns', {}).get('subdomains', []))}\n"
                f"🔌 Open Ports: {len(data.get('ports', {}).get('open_ports', []))}\n"
                f"🔑 Breaches: {len(data.get('leaks', {}).get('breaches', []))}\n"
                f"⚠️ Issues: {len(self.risk_findings)}"
            )
            req.post(
                f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage",
                json={"chat_id": self.config.telegram_chat_id, "text": msg, "parse_mode": "Markdown"},
                timeout=10
            )
            logger.info("[AI] Telegram notification sent")
        except Exception as e:
            logger.debug(f"Telegram error: {e}")

    def _send_slack(self, data: Dict):
        logger.info("[AI] Sending Slack notification...")
        try:
            import requests as req
            risk_level = self._risk_level(self.risk_score)
            color_map = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "warning", "LOW": "good", "INFO": "good"}
            payload = {
                "attachments": [{
                    "color": color_map.get(risk_level, "good"),
                    "title": "UltraHarvester Scan Complete",
                    "fields": [
                        {"title": "Target", "value": data.get("target", "N/A"), "short": True},
                        {"title": "Risk Level", "value": f"{risk_level} ({self.risk_score}/100)", "short": True},
                        {"title": "Emails", "value": str(len(data.get("emails", {}).get("emails", []))), "short": True},
                        {"title": "Subdomains", "value": str(len(data.get("dns", {}).get("subdomains", []))), "short": True},
                        {"title": "Open Ports", "value": str(len(data.get("ports", {}).get("open_ports", []))), "short": True},
                        {"title": "Breaches", "value": str(len(data.get("leaks", {}).get("breaches", []))), "short": True},
                    ],
                    "footer": "UltraHarvester",
                    "ts": int(time.time()),
                }]
            }
            req.post(self.config.slack_webhook_url, json=payload, timeout=10)
            logger.info("[AI] Slack notification sent")
        except Exception as e:
            logger.debug(f"Slack error: {e}")
