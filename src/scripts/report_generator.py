from typing import Any, Dict, List
"""
report_generator.py
===================
Converts the detected_devices.json output into human-readable reports:
  - Console summary (colored)
  - CSV spreadsheet
  - HTML report with sortable tables
  - Syslog / JSON-lines for SIEM forwarding

Usage:
    python report_generator.py --input detected_devices.json \
                               --format html --output report.html
    python report_generator.py --input detected_devices.json \
                               --format csv  --output devices.csv
    python report_generator.py --input detected_devices.json \
                               --format syslog
"""

import csv
import json
import sys
import os
import logging
import argparse
from datetime import datetime

logger = logging.getLogger(__name__)

# ANSI colors for terminal output
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

CONFIDENCE_COLOR = {"HIGH": GREEN, "MEDIUM": YELLOW, "LOW": RED, "NONE": RED}

# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

def report_console(devices: List[Dict[str, Any]]):
    medical = [d for d in devices if d.get("device_type") == "medical"]
    ot      = [d for d in devices if d.get("device_type") == "ot"]
    unknown = [d for d in devices if d.get("device_type") not in ("medical", "ot")]

    def _section(title: str, devs: list, color: str):
        print(f"\n{BOLD}{color}{'='*80}{RESET}")
        print(f"{BOLD}{color}  {title.upper()}  ({len(devs)} devices){RESET}")
        print(f"{BOLD}{color}{'='*80}{RESET}")
        if not devs:
            print(f"  {YELLOW}(none){RESET}")
            return
        hdr = f"{'IP':<18} {'MAC':<18} {'Vendor':<22} {'Model':<30} {'Firmware':<18} {'Conf':<6} {'Hostname'}"
        print(f"{BOLD}{hdr}{RESET}")
        print("─" * 130)
        for d in devs:
            conf = d.get("confidence", "NONE")
            cc = CONFIDENCE_COLOR.get(conf, "")
            fw = (d.get("firmware") or "")[:17]
            print(
                f"{d.get('ip',''):<18} "
                f"{d.get('mac',''):<18} "
                f"{d.get('vendor',''):<22} "
                f"{d.get('model',''):<30} "
                f"{fw:<18} "
                f"{cc}{conf:<6}{RESET} "
                f"{d.get('hostname','')}"
            )

    print(f"\n{BOLD}Zeek Device Detection Report — {datetime.utcnow().isoformat()}Z{RESET}")
    print(f"Total devices: {len(devices)}")
    _section("Medical Devices", medical, CYAN)
    _section("OT / Infrastructure Devices", ot, YELLOW)
    _section("Unknown / Unclassified", unknown, RED)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def report_csv(devices: List[Dict[str, Any]], output_path: str):
    COLUMNS = [
        "ip", "mac", "hostname", "vendor", "model", "firmware",
        "device_type", "confidence", "confidence_score",
        "open_ports", "protocols", "first_seen", "last_seen", "notes",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for d in devices:
            row = {k: d.get(k, "") for k in COLUMNS}
            if isinstance(row["open_ports"], list):
                row["open_ports"] = ",".join(str(p) for p in row["open_ports"])
            if isinstance(row["protocols"], list):
                row["protocols"] = ",".join(row["protocols"])
            writer.writerow(row)
    print(f"CSV report written → {output_path}  ({len(devices)} rows)")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Zeek Device Detection Report</title>
<style>
  :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d;
           --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950;
           --yellow: #d29922; --red: #f85149; --purple: #bc8cff; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, 
          BlinkMacSystemFont, "Segoe UI", monospace; padding: 24px; }}
  h1 {{ color: var(--accent); margin-bottom: 4px; font-size: 1.6rem; }}
  .meta {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{ background: var(--card); border: 1px solid var(--border);
           border-radius: 8px; padding: 12px 20px; min-width: 140px; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.8rem; color: #8b949e; margin-top: 2px; }}
  .medical {{ color: var(--green); }}
  .ot {{ color: var(--yellow); }}
  .unknown {{ color: var(--red); }}
  section {{ margin-bottom: 32px; }}
  h2 {{ border-left: 3px solid var(--accent); padding-left: 10px;
        margin-bottom: 12px; font-size: 1.1rem; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.82rem; }}
  th {{ background: #1c2128; color: #8b949e; padding: 8px 12px;
        text-align: left; white-space: nowrap; cursor: pointer;
        border-bottom: 1px solid var(--border); user-select: none; }}
  th:hover {{ color: var(--accent); }}
  td {{ padding: 7px 12px; border-bottom: 1px solid #21262d;
        vertical-align: top; white-space: nowrap; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            font-size: 0.72rem; font-weight: 600; }}
  .HIGH   {{ background: #1a3a25; color: var(--green); }}
  .MEDIUM {{ background: #3a2a0a; color: var(--yellow); }}
  .LOW    {{ background: #3a1a1a; color: var(--red); }}
  .NONE   {{ background: #2a1a1a; color: var(--red); }}
  .med    {{ color: var(--green); }}
  .ot_cls {{ color: var(--yellow); }}
  input#search {{ background: var(--card); border: 1px solid var(--border);
                  color: var(--text); padding: 8px 14px; border-radius: 6px;
                  width: 320px; margin-bottom: 16px; font-size: 0.9rem; }}
  .firmware {{ font-family: monospace; color: #79c0ff; }}
  .port {{ display: inline-block; background: #1c2128; border-radius: 3px;
           padding: 1px 5px; margin: 1px; font-size: 0.72rem; }}
</style>
</head>
<body>
<h1>🔍 Zeek Device Detection Report</h1>
<div class="meta">Generated {timestamp} &nbsp;|&nbsp; {total} devices detected</div>
<div class="stats">
  <div class="stat"><div class="stat-num">{total}</div><div class="stat-label">Total Devices</div></div>
  <div class="stat"><div class="stat-num medical">{medical}</div><div class="stat-label">Medical</div></div>
  <div class="stat"><div class="stat-num ot">{ot}</div><div class="stat-label">OT / Infra</div></div>
  <div class="stat"><div class="stat-num unknown">{unknown}</div><div class="stat-label">Unclassified</div></div>
  <div class="stat"><div class="stat-num">{high}</div><div class="stat-label">High Confidence</div></div>
</div>
<input type="text" id="search" placeholder="Filter by IP, vendor, model..." oninput="filterTable()">
{sections}
<script>
function sortTable(table, col) {{
  const rows = Array.from(table.querySelectorAll('tbody tr'));
  const asc = table.dataset.sortCol == col && table.dataset.sortDir == 'asc';
  rows.sort((a,b)=>{{
    const x=a.cells[col]?.innerText||'', y=b.cells[col]?.innerText||'';
    return asc ? y.localeCompare(x) : x.localeCompare(y);
  }});
  table.dataset.sortCol=col; table.dataset.sortDir=asc?'desc':'asc';
  const tbody=table.querySelector('tbody');
  rows.forEach(r=>tbody.appendChild(r));
}}
document.querySelectorAll('th').forEach((th,i)=>{{
  th.onclick=()=>sortTable(th.closest('table'),i);
}});
function filterTable() {{
  const q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(row=>{{
    row.style.display=row.innerText.toLowerCase().includes(q)?'':'none';
  }});
}}
</script>
</body>
</html>
"""

SECTION_TEMPLATE = """
<section>
<h2>{title} <span style="color:#8b949e;font-size:0.8rem">({count})</span></h2>
<div class="table-wrap">
<table>
<thead><tr>
  <th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Model</th>
  <th>Firmware</th><th>Type</th><th>Confidence</th><th>Ports</th><th>Protocols</th><th>Last Seen</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</section>
"""

ROW_TEMPLATE = """<tr>
  <td><code>{ip}</code></td>
  <td><code>{mac}</code></td>
  <td>{hostname}</td>
  <td>{vendor}</td>
  <td>{model}</td>
  <td class="firmware">{firmware}</td>
  <td class="{dtype_cls}">{device_type}</td>
  <td><span class="badge {confidence}">{confidence}</span></td>
  <td>{ports}</td>
  <td>{protocols}</td>
  <td>{last_seen}</td>
</tr>"""


def _make_section(title: str, devices: List[Dict[str, Any]]) -> str:
    rows = []
    for d in devices:
        ports_html = "".join(
            f'<span class="port">{p}</span>'
            for p in (d.get("open_ports") or [])[:10]
        )
        protos = ", ".join((d.get("protocols") or [])[:5])
        rows.append(ROW_TEMPLATE.format(
            ip=d.get("ip", ""),
            mac=d.get("mac", ""),
            hostname=d.get("hostname", ""),
            vendor=d.get("vendor", ""),
            model=d.get("model", ""),
            firmware=d.get("firmware", ""),
            dtype_cls="med" if d.get("device_type") == "medical" else "ot_cls",
            device_type=d.get("device_type", "unknown"),
            confidence=d.get("confidence", "NONE"),
            ports=ports_html,
            protocols=protos,
            last_seen=d.get("last_seen", ""),
        ))
    return SECTION_TEMPLATE.format(
        title=title,
        count=len(devices),
        rows="\n".join(rows),
    )


def report_html(devices: List[Dict[str, Any]], output_path: str):
    medical = [d for d in devices if d.get("device_type") == "medical"]
    ot      = [d for d in devices if d.get("device_type") == "ot"]
    unknown = [d for d in devices if d.get("device_type") not in ("medical", "ot")]
    high    = [d for d in devices if d.get("confidence") == "HIGH"]

    sections = (
        _make_section("🏥 Medical Devices", medical) +
        _make_section("⚙️  OT / Infrastructure Devices", ot) +
        _make_section("❓ Unclassified Devices", unknown)
    )

    html = HTML_TEMPLATE.format(
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        total=len(devices),
        medical=len(medical),
        ot=len(ot),
        unknown=len(unknown),
        high=len(high),
        sections=sections,
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"HTML report written → {output_path}")


# ---------------------------------------------------------------------------
# Syslog / JSON-lines
# ---------------------------------------------------------------------------

def report_syslog(devices: List[Dict[str, Any]]):
    """Print JSON-lines to stdout for SIEM/syslog forwarding."""
    for d in devices:
        event = {
            "event": "device_detected",
            "timestamp": d.get("last_seen"),
            "ip": d.get("ip"),
            "mac": d.get("mac"),
            "hostname": d.get("hostname"),
            "vendor": d.get("vendor"),
            "model": d.get("model"),
            "firmware": d.get("firmware"),
            "device_type": d.get("device_type"),
            "confidence": d.get("confidence"),
        }
        print(json.dumps(event))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate device detection reports")
    parser.add_argument("--input", default="detected_devices.json",
                        help="Input JSON from detector")
    parser.add_argument("--format", choices=["console", "csv", "html", "syslog"],
                        default="console")
    parser.add_argument("--output", default="",
                        help="Output file (for csv/html formats)")
    parser.add_argument("--min-confidence", choices=["HIGH","MEDIUM","LOW","NONE"],
                        default="NONE", help="Filter by minimum confidence level")
    args = parser.parse_args()

    with open(args.input) as fh:
        devices = json.load(fh)

    CONF_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    min_rank = CONF_RANK[args.min_confidence]
    devices = [d for d in devices
               if CONF_RANK.get(d.get("confidence", "NONE"), 0) >= min_rank]

    if args.format == "console":
        report_console(devices)
    elif args.format == "csv":
        out = args.output or "devices.csv"
        report_csv(devices, out)
    elif args.format == "html":
        out = args.output or "report.html"
        report_html(devices, out)
    elif args.format == "syslog":
        report_syslog(devices)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
