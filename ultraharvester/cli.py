"""
UltraHarvester CLI — colorized command-line interface
"""

import sys
import os
import json
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

try:
    import pyfiglet
    HAS_FIGLET = True
except ImportError:
    HAS_FIGLET = False

console = Console()

BANNER_TEXT = "UltraHarvester"
VERSION = "1.0.0"

BANNER_COLORS = ["green", "bright_green", "cyan"]


def print_banner():
    console.print()
    if HAS_FIGLET:
        fig = pyfiglet.figlet_format(BANNER_TEXT, font="slant")
        console.print(fig, style="bold green")
    else:
        console.print(f"[bold green]{'='*60}[/bold green]")
        console.print(f"[bold bright_green]  {BANNER_TEXT} v{VERSION}[/bold bright_green]")
        console.print(f"[bold green]{'='*60}[/bold green]")

    info = Table.grid(padding=1)
    info.add_column(style="cyan", justify="right")
    info.add_column(style="white")
    info.add_row("Version:", f"[bold green]{VERSION}[/bold green]")
    info.add_row("Author:", "[bright_white]UltraHarvester Team[/bright_white]")
    info.add_row("Purpose:", "[yellow]Advanced OSINT Information Gathering[/yellow]")
    info.add_row("Warning:", "[red]Use only on targets you own or have written permission to test[/red]")
    console.print(Panel(info, border_style="green", title="[bold green]OSINT Framework[/bold green]"))
    console.print()


@click.group()
@click.version_option(VERSION)
def cli():
    """UltraHarvester — Advanced OSINT Information Gathering Framework"""
    pass


@cli.command()
@click.argument("target")
@click.option("-m", "--modules", default="all",
              help="Modules to run: all, emails, dns, ports, metadata, leaks, web, ai (comma-separated)")
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("-f", "--formats", default="json,html",
              help="Output formats: json,csv,html,pdf (comma-separated)")
@click.option("-t", "--threads", default=20, help="Number of threads")
@click.option("--timeout", default=10, help="Request timeout in seconds")
@click.option("--ports", "port_range", default="1-1000", help="Port range to scan (e.g. 1-1000,8080,8443)")
@click.option("--wordlist", default=None, help="Custom subdomain wordlist file")
@click.option("--proxy", default=None, help="Proxy URL (e.g. http://127.0.0.1:8080)")
@click.option("--config", "config_file", default=None, help="YAML config file path")
@click.option("--shodan-key", envvar="SHODAN_API_KEY", default=None, help="Shodan API key")
@click.option("--hibp-key", envvar="HIBP_API_KEY", default=None, help="HaveIBeenPwned API key")
@click.option("--openai-key", envvar="OPENAI_API_KEY", default=None, help="OpenAI API key for AI report")
@click.option("--telegram-token", envvar="TELEGRAM_BOT_TOKEN", default=None)
@click.option("--telegram-chat", envvar="TELEGRAM_CHAT_ID", default=None)
@click.option("--slack-webhook", envvar="SLACK_WEBHOOK_URL", default=None)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose output")
@click.option("--no-banner", is_flag=True, default=False, help="Skip banner")
def scan(target, modules, output, formats, threads, timeout, port_range, wordlist,
         proxy, config_file, shodan_key, hibp_key, openai_key,
         telegram_token, telegram_chat, slack_webhook, verbose, no_banner):
    """
    Run a full OSINT scan against TARGET.

    Examples:\n
      ultraharvester scan example.com\n
      ultraharvester scan example.com -m emails,dns,ports\n
      ultraharvester scan example.com -f json,html,pdf -o /tmp/results\n
      ultraharvester scan example.com --ports 1-65535 --threads 100
    """
    if not no_banner:
        print_banner()

    from .utils.config import Config
    from .utils.logger import setup_logger

    log_level = "DEBUG" if verbose else "INFO"
    log_file = str(Path(output) / "ultraharvester.log")
    setup_logger("ultraharvester", level=log_level, log_file=log_file)

    if config_file:
        cfg = Config.from_file(config_file)
    else:
        cfg = Config.from_env()

    cfg.target = target
    cfg.domain = target
    cfg.output_dir = output
    cfg.output_formats = [f.strip() for f in formats.split(",")]
    cfg.threads = threads
    cfg.timeout = timeout
    cfg.port_range = port_range
    cfg.verbose = verbose
    if wordlist:
        cfg.subdomain_wordlist = wordlist
    if proxy:
        cfg.proxy = proxy
    if shodan_key:
        cfg.shodan_api_key = shodan_key
    if hibp_key:
        cfg.hibp_api_key = hibp_key
    if openai_key:
        cfg.openai_api_key = openai_key
    if telegram_token:
        cfg.telegram_bot_token = telegram_token
    if telegram_chat:
        cfg.telegram_chat_id = telegram_chat
    if slack_webhook:
        cfg.slack_webhook_url = slack_webhook

    if modules == "all":
        cfg.modules = ["emails", "dns", "ports", "metadata", "leaks", "web", "ai"]
    else:
        cfg.modules = [m.strip() for m in modules.split(",")]

    console.print(f"[bold green]▶ Target:[/bold green] [white]{target}[/white]")
    console.print(f"[bold green]▶ Modules:[/bold green] [white]{', '.join(cfg.modules)}[/white]")
    console.print(f"[bold green]▶ Output:[/bold green] [white]{output}[/white]")
    console.print()

    try:
        from .core.scanner import Scanner
        scanner = Scanner(cfg)
        results = scanner.run()
        ai_data = results.get("ai", {})
        risk_score = ai_data.get("risk_score", 0)
        risk_level = ai_data.get("risk_level", "UNKNOWN")
        risk_colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green", "INFO": "cyan"}
        color = risk_colors.get(risk_level, "white")
        console.print()
        console.print(Panel(
            f"[bold {color}]Risk Level: {risk_level}[/bold {color}]\n"
            f"[white]Score: {risk_score}/100[/white]\n\n"
            f"[dim]{ai_data.get('summary', '')}[/dim]",
            title="[bold green]AI Risk Assessment[/bold green]",
            border_style=color
        ))
        output_files = results.get("output_files", {})
        if output_files:
            console.print("\n[bold green]Output files:[/bold green]")
            for fmt, path in output_files.items():
                if path:
                    console.print(f"  [cyan]{fmt.upper()}:[/cyan] {path}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Scan error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option("-o", "--output", default="./output")
@click.option("-t", "--threads", default=30)
def dns(target, output, threads):
    """Quick DNS enumeration only."""
    print_banner()
    from .utils.config import Config
    from .utils.logger import setup_logger
    from .modules.dns_enum import DNSEnumerator
    from .utils.output import OutputManager
    setup_logger("ultraharvester", level="INFO")
    cfg = Config(target=target, domain=target, output_dir=output, threads=threads)
    enumerator = DNSEnumerator(target, cfg)
    results = enumerator.run()
    out = OutputManager(output, target)
    out.save_json({"dns": results})
    out.print_summary({"dns": results})


@cli.command()
@click.argument("target")
@click.option("-o", "--output", default="./output")
@click.option("-t", "--threads", default=50)
@click.option("--ports", "port_range", default="1-1000")
def portscan(target, output, threads, port_range):
    """Quick port scan only."""
    print_banner()
    from .utils.config import Config
    from .utils.logger import setup_logger
    from .modules.port_scanner import PortScanner
    from .utils.output import OutputManager
    setup_logger("ultraharvester", level="INFO")
    cfg = Config(target=target, domain=target, output_dir=output, threads=threads, port_range=port_range)
    scanner = PortScanner(target, cfg)
    results = scanner.run()
    out = OutputManager(output, target)
    out.save_json({"ports": results})
    out.print_summary({"ports": results})


@cli.command()
@click.argument("target")
@click.option("-o", "--output", default="./output")
def emails(target, output):
    """Quick email harvesting only."""
    print_banner()
    from .utils.config import Config
    from .utils.logger import setup_logger
    from .modules.email_harvester import EmailHarvester
    from .utils.output import OutputManager
    setup_logger("ultraharvester", level="INFO")
    cfg = Config(target=target, domain=target, output_dir=output)
    harvester = EmailHarvester(target, cfg)
    results = harvester.run()
    out = OutputManager(output, target)
    out.save_json({"emails": results})
    out.print_summary({"emails": results})


@cli.command()
@click.argument("json_file")
@click.option("-f", "--formats", default="html,pdf")
@click.option("-o", "--output", default="./output")
def report(json_file, formats, output):
    """Generate report from an existing JSON results file."""
    print_banner()
    from .core.reporter import Reporter
    reporter = Reporter(output)
    data = reporter.load_json(json_file)
    fmt_list = [f.strip() for f in formats.split(",")]
    saved = reporter.generate(data, fmt_list)
    console.print("[bold green]Reports generated:[/bold green]")
    for fmt, path in saved.items():
        if path:
            console.print(f"  [cyan]{fmt.upper()}:[/cyan] {path}")


@cli.command()
def web():
    """Launch the web dashboard."""
    print_banner()
    console.print("[bold green]Starting UltraHarvester Web Dashboard...[/bold green]")
    try:
        from .web.app import create_app
        app = create_app()
        host = os.getenv("UH_HOST", "0.0.0.0")
        port = int(os.getenv("UH_PORT", "5000"))
        console.print(f"[green]Dashboard running at:[/green] [link]http://localhost:{port}[/link]")
        app.run(host=host, port=port, debug=False)
    except ImportError as e:
        console.print(f"[red]Error starting web dashboard: {e}[/red]")
        console.print("[yellow]Make sure Flask is installed: pip install flask flask-socketio[/yellow]")


@cli.command()
def config():
    """Show current configuration and API key status."""
    print_banner()
    from .utils.config import Config
    cfg = Config.from_env()
    table = Table(title="[bold green]Configuration Status[/bold green]", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Status", style="green")
    checks = [
        ("SHODAN_API_KEY", cfg.shodan_api_key),
        ("HIBP_API_KEY", cfg.hibp_api_key),
        ("OPENAI_API_KEY", cfg.openai_api_key),
        ("TELEGRAM_BOT_TOKEN", cfg.telegram_bot_token),
        ("SLACK_WEBHOOK_URL", cfg.slack_webhook_url),
    ]
    for key, val in checks:
        status = "[green]✓ Set[/green]" if val else "[red]✗ Not set[/red]"
        table.add_row(key, status)
    console.print(table)


def main():
    cli()


if __name__ == "__main__":
    main()
