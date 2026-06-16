"""
Report Generator Module
Generates vulnerability scan reports in TXT and HTML formats.
"""

import os
import json
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#8B0000",
    "HIGH": "#cc0000",
    "MEDIUM": "#e67e00",
    "LOW": "#b8a000",
    "INFO": "#2c7be5",
}


def _severity_score(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def generate_txt_report(host: str, open_ports: list, version_findings: list,
                         config_findings: list, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"vuln_report_{host.replace('.', '_')}_{timestamp}.txt")

    all_findings = version_findings + config_findings
    counts = _severity_score(all_findings)

    with open(filename, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("       VULNERABILITY SCANNER — SCAN REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Target   : {host}\n")
        f.write(f"Scanned  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Tool     : VulnScanner v1.0\n")
        f.write("-" * 70 + "\n\n")

        f.write("SUMMARY\n")
        f.write("-" * 30 + "\n")
        f.write(f"Open Ports Found : {len(open_ports)}\n")
        f.write(f"Total Findings   : {len(all_findings)}\n")
        f.write(f"  CRITICAL : {counts['CRITICAL']}\n")
        f.write(f"  HIGH     : {counts['HIGH']}\n")
        f.write(f"  MEDIUM   : {counts['MEDIUM']}\n")
        f.write(f"  LOW      : {counts['LOW']}\n")
        f.write(f"  INFO     : {counts['INFO']}\n\n")

        f.write("OPEN PORTS\n")
        f.write("-" * 30 + "\n")
        if open_ports:
            for p in open_ports:
                line = f"  Port {p['port']:5d} | {p['service']:<15}"
                if p.get("risk"):
                    line += f" | ⚠ {p['risk']}"
                f.write(line + "\n")
        else:
            f.write("  No open ports found.\n")
        f.write("\n")

        f.write("VERSION FINDINGS\n")
        f.write("-" * 30 + "\n")
        high_version = [v for v in version_findings if v["severity"] == "HIGH"]
        if high_version:
            for v in high_version:
                f.write(f"  [{v['severity']}] Port {v['port']} ({v['service']})\n")
                f.write(f"    Issue  : {v['vulnerability']}\n")
                f.write(f"    Banner : {v['banner'][:80]}\n\n")
        else:
            f.write("  No outdated software version issues found.\n\n")

        f.write("CONFIGURATION FINDINGS\n")
        f.write("-" * 30 + "\n")
        config_high = sorted(
            [c for c in config_findings if c["severity"] != "INFO"],
            key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)
        )
        if config_high:
            for c in config_high:
                f.write(f"  [{c['severity']}] {c['check']}\n")
                f.write(f"    Issue  : {c['issue']}\n")
                if c.get("detail"):
                    f.write(f"    Detail : {c['detail'][:80]}\n")
                f.write("\n")
        else:
            f.write("  No configuration issues found.\n\n")

        f.write("=" * 70 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 70 + "\n")

    print(f"[✔] TXT report saved: {filename}")
    return filename


def generate_html_report(host: str, open_ports: list, version_findings: list,
                          config_findings: list, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"vuln_report_{host.replace('.', '_')}_{timestamp}.html")

    all_findings = version_findings + config_findings
    counts = _severity_score(all_findings)

    def badge(sev):
        color = SEVERITY_COLOR.get(sev, "#888")
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold;">{sev}</span>'

    rows_ports = ""
    for p in open_ports:
        risk_cell = f'<span style="color:#cc0000">⚠ {p["risk"]}</span>' if p.get("risk") else '<span style="color:green">OK</span>'
        rows_ports += f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{risk_cell}</td></tr>\n"

    rows_version = ""
    for v in version_findings:
        if v["severity"] == "HIGH":
            rows_version += f"<tr><td>{badge(v['severity'])}</td><td>{v['port']} ({v['service']})</td><td>{v['vulnerability']}</td></tr>\n"

    rows_config = ""
    for c in sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99)):
        if c.get("severity") != "INFO" and "check" in c:
            rows_config += f"<tr><td>{badge(c['severity'])}</td><td>{c['check']}</td><td>{c['issue']}</td></tr>\n"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Report — {host}</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #f4f6fa; color: #222; margin: 0; padding: 20px; }}
  .card {{ background: #fff; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  h1 {{ color: #1a237e; }} h2 {{ color: #333; border-bottom: 2px solid #e0e0e0; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; }} th {{ background: #1a237e; color: #fff; padding: 10px; text-align: left; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }} tr:hover {{ background: #f9f9f9; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-top: 10px; }}
  .sev-box {{ text-align: center; border-radius: 8px; padding: 12px; color: #fff; }}
  .footer {{ text-align: center; color: #888; font-size: 0.85em; margin-top: 20px; }}
</style>
</head>
<body>
<div class="card">
  <h1>🛡 Vulnerability Scan Report</h1>
  <p><strong>Target:</strong> {host} &nbsp;|&nbsp; <strong>Scanned:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; <strong>Tool:</strong> VulnScanner v1.0</p>
  <div class="summary-grid">
    <div class="sev-box" style="background:#8B0000">CRITICAL<br><big>{counts['CRITICAL']}</big></div>
    <div class="sev-box" style="background:#cc0000">HIGH<br><big>{counts['HIGH']}</big></div>
    <div class="sev-box" style="background:#e67e00">MEDIUM<br><big>{counts['MEDIUM']}</big></div>
    <div class="sev-box" style="background:#b8a000">LOW<br><big>{counts['LOW']}</big></div>
    <div class="sev-box" style="background:#2c7be5">INFO<br><big>{counts['INFO']}</big></div>
  </div>
</div>

<div class="card">
  <h2>Open Ports ({len(open_ports)} found)</h2>
  <table><tr><th>Port</th><th>Service</th><th>Risk</th></tr>
  {rows_ports if rows_ports else '<tr><td colspan="3">No open ports found.</td></tr>'}
  </table>
</div>

<div class="card">
  <h2>Software Version Findings</h2>
  <table><tr><th>Severity</th><th>Port / Service</th><th>Finding</th></tr>
  {rows_version if rows_version else '<tr><td colspan="3">No outdated version issues detected.</td></tr>'}
  </table>
</div>

<div class="card">
  <h2>Configuration Findings</h2>
  <table><tr><th>Severity</th><th>Check</th><th>Issue</th></tr>
  {rows_config if rows_config else '<tr><td colspan="3">No configuration issues detected.</td></tr>'}
  </table>
</div>

<div class="footer">Generated by VulnScanner v1.0 | For authorized use only</div>
</body></html>"""

    with open(filename, "w") as f:
        f.write(html)

    print(f"[✔] HTML report saved: {filename}")
    return filename


def generate_json_report(host: str, open_ports: list, version_findings: list,
                          config_findings: list, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"vuln_report_{host.replace('.', '_')}_{timestamp}.json")

    report = {
        "meta": {
            "target": host,
            "scanned_at": datetime.now().isoformat(),
            "tool": "VulnScanner v1.0",
        },
        "open_ports": open_ports,
        "version_findings": version_findings,
        "config_findings": config_findings,
        "summary": _severity_score(version_findings + config_findings),
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[✔] JSON report saved: {filename}")
    return filename
