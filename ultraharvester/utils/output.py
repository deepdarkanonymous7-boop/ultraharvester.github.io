import json
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table

console = Console()


class OutputManager:
    def __init__(self, output_dir: str = "./output", target: str = ""):
        self.output_dir = Path(output_dir)
        self.target = target.replace(".", "_").replace("/", "_")
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _filepath(self, ext: str) -> Path:
        fname = f"ultraharvester_{self.target}_{self.timestamp}.{ext}"
        return self.output_dir / fname

    def save_json(self, data: Dict) -> str:
        path = self._filepath("json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[green]✓ JSON saved:[/green] {path}")
        return str(path)

    def save_csv(self, data: Dict) -> str:
        path = self._filepath("csv")
        rows = []
        for module, findings in data.items():
            if isinstance(findings, list):
                for item in findings:
                    if isinstance(item, dict):
                        row = {"module": module}
                        row.update(item)
                        rows.append(row)
                    else:
                        rows.append({"module": module, "value": str(item)})
        if rows:
            fieldnames = list({k for r in rows for k in r.keys()})
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        console.print(f"[green]✓ CSV saved:[/green] {path}")
        return str(path)

    def save_html(self, data: Dict) -> str:
        from jinja2 import Environment, BaseLoader
        path = self._filepath("html")
        template_str = self._html_template()
        env = Environment(loader=BaseLoader())
        tmpl = env.from_string(template_str)
        html = tmpl.render(
            data=data,
            target=self.target,
            timestamp=self.timestamp,
            title="UltraHarvester Report"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green]✓ HTML saved:[/green] {path}")
        return str(path)

    def save_pdf(self, data: Dict) -> str:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                             Table as RLTable, TableStyle, HRFlowable)
            path = self._filepath("pdf")
            doc = SimpleDocTemplate(str(path), pagesize=A4,
                                    rightMargin=2*cm, leftMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)
            styles = getSampleStyleSheet()
            story = []
            title_style = ParagraphStyle("title", parent=styles["Title"],
                                          textColor=colors.HexColor("#00ff88"),
                                          fontSize=24, spaceAfter=12)
            story.append(Paragraph("UltraHarvester Report", title_style))
            story.append(Paragraph(f"Target: {self.target}", styles["Normal"]))
            story.append(Paragraph(f"Generated: {self.timestamp}", styles["Normal"]))
            story.append(Spacer(1, 0.5*cm))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#00ff88")))
            story.append(Spacer(1, 0.5*cm))

            for module, findings in data.items():
                if not findings:
                    continue
                story.append(Paragraph(f"Module: {module.upper()}", styles["Heading2"]))
                if isinstance(findings, list):
                    for item in findings[:50]:
                        story.append(Paragraph(f"• {str(item)[:200]}", styles["Normal"]))
                elif isinstance(findings, dict):
                    for k, v in list(findings.items())[:20]:
                        story.append(Paragraph(f"• {k}: {str(v)[:150]}", styles["Normal"]))
                story.append(Spacer(1, 0.3*cm))

            doc.build(story)
            console.print(f"[green]✓ PDF saved:[/green] {path}")
            return str(path)
        except ImportError:
            console.print("[yellow]⚠ reportlab not installed — skipping PDF[/yellow]")
            return ""

    def print_summary(self, data: Dict):
        table = Table(title="[bold green]UltraHarvester — Scan Summary[/bold green]",
                      show_header=True, header_style="bold cyan")
        table.add_column("Module", style="cyan", width=20)
        table.add_column("Findings", style="yellow", justify="right")
        table.add_column("Status", style="green")
        total = 0
        for module, findings in data.items():
            count = len(findings) if isinstance(findings, (list, dict)) else 0
            total += count
            status = "✓" if count > 0 else "—"
            table.add_row(module, str(count), status)
        table.add_section()
        table.add_row("[bold]TOTAL[/bold]", f"[bold]{total}[/bold]", "")
        console.print(table)

    def _html_template(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} - {{ target }}</title>
<style>
  :root { --green: #00ff88; --dark: #0a0a0f; --card: #111118; --border: #1e1e2e; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--dark); color: #e0e0e0; font-family: 'Courier New', monospace; padding: 2rem; }
  h1 { color: var(--green); font-size: 2rem; margin-bottom: 0.5rem; }
  .meta { color: #888; font-size: 0.85rem; margin-bottom: 2rem; }
  .module { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
            margin-bottom: 1.5rem; padding: 1.5rem; }
  .module h2 { color: var(--green); margin-bottom: 1rem; font-size: 1.1rem; text-transform: uppercase; }
  .badge { display:inline-block; background:#1a2a1a; color:var(--green); border-radius:4px;
           padding:0.2rem 0.6rem; font-size:0.75rem; margin:0.25rem 0.25rem 0.25rem 0; }
  .item { border-bottom: 1px solid var(--border); padding: 0.5rem 0; font-size: 0.85rem; }
  .item:last-child { border: none; }
  .kv { display:flex; gap:1rem; }
  .kv .key { color:var(--green); min-width:140px; }
  .kv .val { color:#ccc; word-break:break-all; }
  .grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(200px,1fr)); gap:1rem; }
  .stat { background:#0a1a0a; border:1px solid #1e3a1e; border-radius:6px; padding:1rem; text-align:center; }
  .stat .num { font-size:2rem; color:var(--green); font-weight:bold; }
  .stat .lbl { font-size:0.75rem; color:#888; margin-top:0.25rem; }
</style>
</head>
<body>
<h1>🔍 UltraHarvester Report</h1>
<div class="meta">Target: <b>{{ target }}</b> &nbsp;|&nbsp; Generated: {{ timestamp }}</div>

<div class="grid" style="margin-bottom:2rem">
{% for module, findings in data.items() %}
<div class="stat">
  <div class="num">{{ findings|length if findings is iterable else 0 }}</div>
  <div class="lbl">{{ module }}</div>
</div>
{% endfor %}
</div>

{% for module, findings in data.items() %}
{% if findings %}
<div class="module">
  <h2>{{ module }}</h2>
  {% if findings is mapping %}
    {% for k, v in findings.items() %}
    <div class="item"><div class="kv"><span class="key">{{ k }}</span><span class="val">{{ v }}</span></div></div>
    {% endfor %}
  {% elif findings is iterable %}
    {% for item in findings %}
    {% if item is mapping %}
      <div class="item">
      {% for k, v in item.items() %}<span class="badge">{{ k }}: {{ v }}</span>{% endfor %}
      </div>
    {% else %}
      <div class="item">{{ item }}</div>
    {% endif %}
    {% endfor %}
  {% endif %}
</div>
{% endif %}
{% endfor %}
</body>
</html>"""
