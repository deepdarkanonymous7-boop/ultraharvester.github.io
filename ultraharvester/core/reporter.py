"""
Report Generator — creates PDF and HTML reports from scan data
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict

from ..utils.logger import get_logger
from ..utils.output import OutputManager

logger = get_logger("ultraharvester.reporter")


class Reporter:
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir

    def generate(self, data: Dict, formats: list = None) -> Dict:
        if formats is None:
            formats = ["json", "html", "pdf"]
        target = data.get("target", "unknown")
        output = OutputManager(self.output_dir, target)
        saved = {}
        if "json" in formats:
            saved["json"] = output.save_json(data)
        if "csv" in formats:
            saved["csv"] = output.save_csv(data)
        if "html" in formats:
            saved["html"] = output.save_html(data)
        if "pdf" in formats:
            saved["pdf"] = output.save_pdf(data)
        logger.info(f"[Reporter] Generated: {list(saved.keys())}")
        return saved

    def load_json(self, path: str) -> Dict:
        with open(path) as f:
            return json.load(f)
