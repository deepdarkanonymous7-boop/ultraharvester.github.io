"""
Metadata & Document Discovery Module
Search public docs (PDF, DOCX, XLSX), extract metadata,
automated Google Dorks
"""

import re
import io
import time
import random
import concurrent.futures
from typing import List, Dict, Optional
from urllib.parse import urlparse, quote_plus

import requests
from bs4 import BeautifulSoup

from ..utils.logger import get_logger

logger = get_logger("ultraharvester.metadata")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
]

GOOGLE_DORKS = [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:doc OR filetype:docx',
    'site:{domain} filetype:xls OR filetype:xlsx',
    'site:{domain} filetype:ppt OR filetype:pptx',
    'site:{domain} filetype:txt',
    'site:{domain} filetype:xml',
    'site:{domain} filetype:sql',
    'site:{domain} filetype:log',
    'site:{domain} filetype:bak',
    'site:{domain} filetype:conf OR filetype:cfg',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:password',
    'site:{domain} inurl:config',
    'site:{domain} inurl:backup',
    'site:{domain} intitle:"index of"',
    'site:{domain} "not for public release"',
    'site:{domain} "confidential" OR "internal use"',
    'site:{domain} inurl:wp-config',
    'site:{domain} inurl:.git',
    'site:{domain} inurl:phpinfo.php',
    'site:{domain} "error" OR "exception" OR "stack trace"',
    '"@{domain}" filetype:xls',
    '"@{domain}" email contact list',
    'site:{domain} inurl:api key OR token OR secret',
]


class MetadataExtractor:
    def __init__(self, domain: str, config=None):
        self.domain = domain
        self.config = config
        self.documents: List[Dict] = []
        self.dork_results: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml",
        })
        if config and config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}

    def run(self) -> Dict:
        logger.info(f"[Metadata] Starting document & metadata search for {self.domain}")
        self._run_dorks()
        self._discover_documents()
        self._extract_metadata()
        logger.info(f"[Metadata] Found {len(self.documents)} documents, {len(self.dork_results)} dork results")
        return {
            "documents": self.documents,
            "dork_results": self.dork_results,
        }

    def _search(self, query: str) -> List[str]:
        links = []
        try:
            time.sleep(random.uniform(2.0, 4.0))
            r = self.session.get(
                "https://www.google.com/search",
                params={"q": query, "num": 20},
                timeout=10
            )
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/url?q="):
                    href = href.split("/url?q=")[1].split("&")[0]
                parsed = urlparse(href)
                if parsed.scheme in ("http", "https") and "google.com" not in href:
                    links.append(href)
        except Exception as e:
            logger.debug(f"Search error: {e}")
        return links

    def _run_dorks(self):
        logger.info(f"[Metadata] Running {len(GOOGLE_DORKS)} Google Dorks...")
        for dork_template in GOOGLE_DORKS[:12]:
            query = dork_template.format(domain=self.domain)
            links = self._search(query)
            if links:
                self.dork_results.append({
                    "dork": query,
                    "results": links[:5],
                    "count": len(links),
                })
                logger.debug(f"[Metadata] Dork '{query}' -> {len(links)} results")

    def _discover_documents(self):
        logger.info("[Metadata] Discovering public documents...")
        doc_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"]
        doc_urls = []
        for ext in doc_extensions:
            query = f"site:{self.domain} filetype:{ext}"
            links = self._search(query)
            for url in links:
                if f".{ext}" in url.lower() or ext in url.lower():
                    doc_urls.append({"url": url, "type": ext.upper()})

        self.documents = doc_urls

    def _extract_metadata(self):
        logger.info("[Metadata] Extracting document metadata...")
        for doc in self.documents[:10]:
            url = doc["url"]
            doc_type = doc["type"]
            try:
                time.sleep(random.uniform(0.5, 1.5))
                r = self.session.get(url, timeout=15, stream=True)
                content = b""
                for chunk in r.iter_content(chunk_size=8192):
                    content += chunk
                    if len(content) > 5 * 1024 * 1024:
                        break

                meta = {}
                if doc_type == "PDF":
                    meta = self._extract_pdf_metadata(content)
                elif doc_type in ("DOC", "DOCX"):
                    meta = self._extract_docx_metadata(content)
                elif doc_type in ("XLS", "XLSX"):
                    meta = self._extract_xlsx_metadata(content)

                doc["metadata"] = meta
                if meta:
                    logger.info(f"[Metadata] Extracted from {url}: {list(meta.keys())}")
            except Exception as e:
                logger.debug(f"Metadata extraction error ({url}): {e}")
                doc["metadata"] = {}

    def _extract_pdf_metadata(self, content: bytes) -> Dict:
        meta = {}
        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(io.BytesIO(content))
            info = reader.metadata
            if info:
                meta = {
                    "author": str(info.get("/Author", "")),
                    "creator": str(info.get("/Creator", "")),
                    "producer": str(info.get("/Producer", "")),
                    "title": str(info.get("/Title", "")),
                    "subject": str(info.get("/Subject", "")),
                    "creation_date": str(info.get("/CreationDate", "")),
                    "modification_date": str(info.get("/ModDate", "")),
                    "pages": len(reader.pages),
                }
        except Exception as e:
            logger.debug(f"PDF parse error: {e}")
        return {k: v for k, v in meta.items() if v and v != "None"}

    def _extract_docx_metadata(self, content: bytes) -> Dict:
        meta = {}
        try:
            from docx import Document
            doc = Document(io.BytesIO(content))
            core = doc.core_properties
            meta = {
                "author": str(core.author or ""),
                "title": str(core.title or ""),
                "subject": str(core.subject or ""),
                "company": str(getattr(core, "company", "") or ""),
                "created": str(core.created or ""),
                "modified": str(core.modified or ""),
                "last_modified_by": str(core.last_modified_by or ""),
                "revision": str(core.revision or ""),
            }
        except Exception as e:
            logger.debug(f"DOCX parse error: {e}")
        return {k: v for k, v in meta.items() if v and v != "None"}

    def _extract_xlsx_metadata(self, content: bytes) -> Dict:
        meta = {}
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
            props = wb.properties
            meta = {
                "creator": str(props.creator or ""),
                "title": str(props.title or ""),
                "description": str(props.description or ""),
                "subject": str(props.subject or ""),
                "company": str(getattr(props, "company", "") or ""),
                "created": str(props.created or ""),
                "modified": str(props.modified or ""),
                "last_modified_by": str(props.lastModifiedBy or ""),
            }
        except Exception as e:
            logger.debug(f"XLSX parse error: {e}")
        return {k: v for k, v in meta.items() if v and v != "None"}
