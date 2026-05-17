<div align="center">

```
██╗   ██╗██╗  ████████╗██████╗  █████╗ ██╗  ██╗ █████╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗
██║   ██║██║  ╚══██╔══╝██╔══██╗██╔══██╗██║  ██║██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██║   ██║██║     ██║   ██████╔╝███████║███████║███████║██████╔╝██║   ██║█████╗  ███████╗   ██║   █████╗  ██████╔╝
██║   ██║██║     ██║   ██╔══██╗██╔══██║██╔══██║██╔══██║██╔══██╗╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
╚██████╔╝███████╗██║   ██║  ██║██║  ██║██║  ██║██║  ██║██║  ██║ ╚████╔╝ ███████╗███████║   ██║   ███████╗██║  ██║
 ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

# UltraHarvester

**All-in-one OSINT reconnaissance framework for security professionals**

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-64748b?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-22c55e?style=flat-square)

</div>

---

UltraHarvester is a full-scope OSINT framework that brings together email harvesting, DNS enumeration, port scanning, metadata extraction, breach detection, and web reconnaissance under a single command-line tool and web dashboard. Built for penetration testers and security researchers who need more than TheHarvester can offer.

---

## ⚠️ Legal Notice

This tool is intended **exclusively** for authorized security assessments.  
Only run UltraHarvester against systems and domains you own or have written permission to test.  
The author takes no responsibility for any misuse or damage caused by this software.

---

## What it does

| Module | Capabilities |
|--------|-------------|
| 📧 **Email Harvester** | Scrapes Google, Bing, DuckDuckGo, Yahoo · SMTP verification · Employee & profile discovery via LinkedIn, Twitter, GitHub |
| 🌐 **DNS Enumeration** | Subdomain brute-force (200+ prefixes) + passive recon via crt.sh · Full DNS records (A, MX, TXT, NS, CNAME, SPF, DMARC) · Zone transfer detection · WHOIS |
| 🔌 **Port Scanner** | Multi-threaded TCP scanning · Banner grabbing · Service & technology fingerprinting · CMS detection (WordPress, Joomla, Drupal, Magento…) |
| 🗂️ **Metadata Extractor** | 25+ Google Dorks · Discovers public PDFs, DOCXs, XLSXs · Extracts author, company, revision history, dates |
| 🔑 **Leak Checker** | HaveIBeenPwned domain & email lookup · GitHub credential exposure search · Pastebin monitoring · k-anonymity password check |
| 🖼️ **Web Discovery** | Recursive crawler · crt.sh SSL enumeration · Wayback Machine history · Shodan / Censys integration · IP geolocation & ASN lookup |
| 🤖 **AI Engine** | Risk scoring 0–100 · Finding correlation · GPT-4 executive summary · Telegram & Slack alerts |
| 📊 **Output** | JSON · CSV · HTML · PDF · Interactive web dashboard · Relation graph (domain → subdomain → email → person) |

---

## Requirements

- Python **3.9** or higher
- pip / pip3

The following API keys are optional but unlock additional modules:

- **Shodan** — service intelligence and CVE data
- **HaveIBeenPwned** — breach detection
- **OpenAI** — GPT-4 executive summary
- **Telegram / Slack** — real-time notifications

---

## Installation

**Option 1 — Virtual environment (recommended)**

```bash
git clone https://github.com/yourusername/ultraharvester
cd ultraharvester

python3 -m venv venv
source venv/bin/activate       # Linux / macOS
venv\Scripts\activate.bat      # Windows

pip install -r requirements.txt
pip install -e .
```

**Option 2 — Run directly**

```bash
pip install -r requirements.txt
python main.py --help
```

**Option 3 — System-wide**

```bash
pip install -e /path/to/ultraharvester
```

---

## Configuration

Copy the example env file and add your API keys:

```bash
cp .env.example .env
nano .env
```

Or set them as environment variables:

```bash
export SHODAN_API_KEY="your_key"
export HIBP_API_KEY="your_key"
export OPENAI_API_KEY="your_key"
export TELEGRAM_BOT_TOKEN="your_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

Using a YAML config file:

```bash
cp config.example.yaml myconfig.yaml
ultraharvester scan example.com --config myconfig.yaml
```

---

## Usage

**Full scan**

```bash
ultraharvester scan example.com
# short alias
uh scan example.com
```

**Select modules and output format**

```bash
ultraharvester scan example.com -m emails,dns,ports -f json,html,pdf
```

**Custom threads, port range and proxy**

```bash
ultraharvester scan example.com --ports 1-65535 -t 100 --proxy http://127.0.0.1:8080
```

**Module-specific commands**

```bash
ultraharvester dns example.com
ultraharvester emails example.com
ultraharvester portscan example.com --ports 1-65535
ultraharvester report output/scan_*.json -f html,pdf
```

**Web dashboard**

```bash
ultraharvester web
# then open http://localhost:5000
```

---

## Flags

| Flag | Description |
|------|-------------|
| `-m` | Modules to run: `emails,dns,ports,metadata,leaks,web,ai` |
| `-o` | Output directory (default: `./output/`) |
| `-f` | Export formats: `json,csv,html,pdf` |
| `-t` | Threads for port scanning (default: 50) |
| `--ports` | Port range — e.g. `1-65535` or `80,443,8080` |
| `--proxy` | Proxy URL, supports HTTP and SOCKS5 |
| `--config` | Path to YAML config file |
| `--shodan-key` | Shodan API key (overrides `.env`) |
| `--hibp-key` | HaveIBeenPwned API key (overrides `.env`) |
| `--openai-key` | OpenAI API key (overrides `.env`) |
| `-v` | Verbose output |

---

## Sample output

```
╔══════════════════════════════════════════════════════════╗
║           UltraHarvester — Scan Summary                 ║
╠══════════════════════════════════════════════════════════╣
║ Module          │ Findings  │ Status                    ║
╠══════════════════════════════════════════════════════════╣
║ emails          │    47     │ ✓                         ║
║ dns             │   132     │ ✓                         ║
║ ports           │    12     │ ✓                         ║
║ metadata        │    28     │ ✓                         ║
║ leaks           │     8     │ ✓                         ║
║ web             │   215     │ ✓                         ║
║ ai              │     5     │ ✓                         ║
╠══════════════════════════════════════════════════════════╣
║ TOTAL           │   447     │                           ║
╚══════════════════════════════════════════════════════════╝

Risk Level: HIGH (72/100)
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ImportError` on startup | `pip install -r requirements.txt` |
| DNS resolution errors | `pip install dnspython` |
| PDF generation fails | `pip install reportlab` |
| Slow scans | Lower threads `-t 10` · limit ports `--ports 80,443` · fewer modules `-m emails,dns` |
| Search engine rate limiting | Use a proxy `--proxy http://127.0.0.1:8080` or Tor `--proxy socks5://127.0.0.1:9050` |

---

## Contributing

1. Fork this repository
2. Create your branch — `git checkout -b feature/my-feature`
3. Commit your changes — `git commit -m "Add my feature"`
4. Push — `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

Released under the **MIT License** — see the [LICENSE](LICENSE) file.

---

<div align="center">
<sub>Built for security professionals · Use responsibly</sub>
</div>
