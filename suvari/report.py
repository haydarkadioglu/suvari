"""
Report Generator — converts scan results into a Markdown report.
Inspired by Shannon's executive report format.
"""

from datetime import datetime
from .workspace import Workspace
from .tools.runner import clean_ansi


REPORT_TEMPLATE = """# 🐎 Suvari Pentest Report

**Target:** {target_url}
**Date:** {date}
**Status:** {status}

---

## 📊 Summary

| Metric | Value |
|--------|-------|
| Total Findings | {total} |
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |

---

## 🔍 Reconnaissance Results

### Technology (whatweb)
```
{whatweb}
```

### HTTP Headers
```
{headers}
```

### Open Ports (nmap)
```
{nmap}
```

---

## 🛡️ Scan Results

{scan_results}

---

## 🧠 AI Analysis

{analysis}

---

## 💥 Exploitation Attempts

{exploit_results}

---

## ✅ Remediation Recommendations

{remediation}

---

*Report auto-generated: {date}*
"""


class ReportGenerator:
    """Generates Markdown reports from scan results."""

    def __init__(self, workspace: Workspace, target_url: str):
        self.ws = workspace
        self.target_url = target_url

    def generate(self, context: dict) -> str:
        """Generate and save the report."""

        recon_results = context.get("recon_results", {})

        scan_results = context.get("scan_results", {})
        scan_text = ""
        for tool, output in scan_results.items():
            if isinstance(output, str) and output:
                scan_text += f"### {tool}\n```\n{output[:1000]}\n```\n\n"

        analysis = context.get("analysis", {})
        vulns = analysis.get("vulnerabilities", [])
        summary = analysis.get("summary", {})

        analysis_text = ""
        for v in vulns:
            analysis_text += f"- **[{v.get('severity','?')}]** {v.get('type','?')}: {v.get('description','')[:200]}\n"

        if not vulns:
            analysis_text = "*AI analysis complete — no significant vulnerabilities detected.*"

        exploit_data = context.get("exploit_results", {})
        exploits = exploit_data.get("exploits", [])
        exploit_text = ""
        for e in exploits:
            icon = "✅" if e.get("success") else "❌"
            exploit_text += f"- {icon} **{e.get('vuln_type','?')}** ({e.get('tool','?')})\n"
        if not exploits:
            exploit_text = "*No exploitation attempted.*"

        remediation_text = ""
        for v in vulns[:5]:
            remediation_text += f"- **{v.get('type','?')}**: {v.get('remediation','')}\n"
        if not remediation_text:
            remediation_text = "*No remediation suggestions.*"

        report = REPORT_TEMPLATE.format(
            target_url=self.target_url,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            status="✅ Complete" if not context.get("error") else f"❌ Error: {context.get('error')}",
            total=summary.get("total", 0),
            critical=summary.get("critical", 0),
            high=summary.get("high", 0),
            medium=summary.get("medium", 0),
            low=summary.get("low", 0),
            whatweb=str(recon_results.get("whatweb", ""))[:500],
            headers=str(recon_results.get("headers", ""))[:500],
            nmap=str(recon_results.get("nmap", ""))[:500],
            scan_results=scan_text,
            analysis=analysis_text,
            exploit_results=exploit_text,
            remediation=remediation_text,
        )

        report_path = self.ws.path / "report.md"
        report_path.write_text(report)
        return report
