"""
Core Scanner — orchestrates all modules
"""

import time
from datetime import datetime
from typing import Dict, List, Optional

from ..utils.logger import get_logger, setup_logger
from ..utils.config import Config
from ..utils.output import OutputManager

logger = get_logger("ultraharvester.scanner")


class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.target = config.target or config.domain
        self.results: Dict = {
            "target": self.target,
            "scan_start": datetime.now().isoformat(),
            "scan_end": None,
            "duration_seconds": None,
            "modules_run": [],
            "emails": {},
            "dns": {},
            "ports": {},
            "metadata": {},
            "leaks": {},
            "web": {},
            "ai": {},
        }
        self.output = OutputManager(config.output_dir, self.target)
        self.start_time = None

    def run(self) -> Dict:
        self.start_time = time.time()
        logger.info(f"[Scanner] Starting scan of {self.target}")
        logger.info(f"[Scanner] Modules: {', '.join(self.config.modules)}")

        modules = self.config.modules

        if "emails" in modules:
            self._run_emails()

        if "dns" in modules:
            self._run_dns()

        if "ports" in modules:
            self._run_ports()

        if "metadata" in modules:
            self._run_metadata()

        if "leaks" in modules:
            self._run_leaks()

        if "web" in modules:
            self._run_web()

        if "ai" in modules:
            self._run_ai()

        self.results["scan_end"] = datetime.now().isoformat()
        self.results["duration_seconds"] = round(time.time() - self.start_time, 2)

        self._save_outputs()
        return self.results

    def _run_emails(self):
        try:
            logger.info("[Scanner] ── Email Harvesting ──")
            from ..modules.email_harvester import EmailHarvester
            harvester = EmailHarvester(self.target, self.config)
            self.results["emails"] = harvester.run()
            self.results["modules_run"].append("emails")
        except Exception as e:
            logger.error(f"[Scanner] Email module error: {e}")
            self.results["emails"] = {"error": str(e)}

    def _run_dns(self):
        try:
            logger.info("[Scanner] ── DNS Enumeration ──")
            from ..modules.dns_enum import DNSEnumerator
            enumerator = DNSEnumerator(self.target, self.config)
            self.results["dns"] = enumerator.run()
            self.results["modules_run"].append("dns")
        except Exception as e:
            logger.error(f"[Scanner] DNS module error: {e}")
            self.results["dns"] = {"error": str(e)}

    def _run_ports(self):
        try:
            logger.info("[Scanner] ── Port Scanning ──")
            from ..modules.port_scanner import PortScanner
            scanner = PortScanner(self.target, self.config)
            self.results["ports"] = scanner.run()
            self.results["modules_run"].append("ports")
        except Exception as e:
            logger.error(f"[Scanner] Port module error: {e}")
            self.results["ports"] = {"error": str(e)}

    def _run_metadata(self):
        try:
            logger.info("[Scanner] ── Metadata Extraction ──")
            from ..modules.metadata import MetadataExtractor
            extractor = MetadataExtractor(self.target, self.config)
            self.results["metadata"] = extractor.run()
            self.results["modules_run"].append("metadata")
        except Exception as e:
            logger.error(f"[Scanner] Metadata module error: {e}")
            self.results["metadata"] = {"error": str(e)}

    def _run_leaks(self):
        try:
            logger.info("[Scanner] ── Leak Detection ──")
            from ..modules.leak_checker import LeakChecker
            emails = self.results.get("emails", {}).get("emails", [])
            checker = LeakChecker(self.target, emails, self.config)
            self.results["leaks"] = checker.run()
            self.results["modules_run"].append("leaks")
        except Exception as e:
            logger.error(f"[Scanner] Leak module error: {e}")
            self.results["leaks"] = {"error": str(e)}

    def _run_web(self):
        try:
            logger.info("[Scanner] ── Web Discovery ──")
            from ..modules.web_discovery import WebDiscovery
            discovery = WebDiscovery(self.target, self.config)
            self.results["web"] = discovery.run()
            self.results["modules_run"].append("web")
        except Exception as e:
            logger.error(f"[Scanner] Web module error: {e}")
            self.results["web"] = {"error": str(e)}

    def _run_ai(self):
        try:
            logger.info("[Scanner] ── AI Analysis ──")
            from ..modules.ai_engine import AIEngine
            engine = AIEngine(self.config)
            self.results["ai"] = engine.run(self.results)
            self.results["modules_run"].append("ai")
        except Exception as e:
            logger.error(f"[Scanner] AI module error: {e}")
            self.results["ai"] = {"error": str(e)}

    def _save_outputs(self):
        logger.info("[Scanner] Saving outputs...")
        formats = self.config.output_formats
        saved_files = {}

        if "json" in formats:
            saved_files["json"] = self.output.save_json(self.results)
        if "csv" in formats:
            saved_files["csv"] = self.output.save_csv(self.results)
        if "html" in formats:
            saved_files["html"] = self.output.save_html(self.results)
        if "pdf" in formats:
            saved_files["pdf"] = self.output.save_pdf(self.results)

        self.results["output_files"] = saved_files
        self.output.print_summary(self.results)
        logger.info(f"[Scanner] Scan complete in {self.results['duration_seconds']}s")
