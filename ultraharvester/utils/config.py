import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    target: str = ""
    domain: str = ""
    output_dir: str = "./output"
    output_formats: list = field(default_factory=lambda: ["json", "html"])
    threads: int = 10
    timeout: int = 10
    delay: float = 1.0
    verbose: bool = False
    proxy: Optional[str] = None

    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    hibp_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    modules: list = field(default_factory=lambda: [
        "emails", "dns", "ports", "metadata", "leaks", "web", "ai"
    ])

    port_range: str = "1-1000"
    subdomain_wordlist: Optional[str] = None
    max_depth: int = 3
    user_agent: str = "Mozilla/5.0 (compatible; UltraHarvester/1.0)"

    @classmethod
    def from_file(cls, path: str) -> "Config":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls()
        cfg.shodan_api_key = os.getenv("SHODAN_API_KEY")
        cfg.censys_api_id = os.getenv("CENSYS_API_ID")
        cfg.censys_api_secret = os.getenv("CENSYS_API_SECRET")
        cfg.hibp_api_key = os.getenv("HIBP_API_KEY")
        cfg.openai_api_key = os.getenv("OPENAI_API_KEY")
        cfg.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        cfg.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")
        cfg.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        cfg.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        return cfg

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
