"""
Report Generator — converts scan results into a Markdown report.
Inspired by Shannon's executive report format.
"""

from datetime import datetime
from .workspace import Workspace
from .tools.runner import clean_ansi


REPORT_TEMPLATE = """# [SUVARI] Suvari Pentest Report

**Target:** {target_url}
**Date:** {date}
**Status:** {status}

---

## [STATS] Summary

| Metric | Value |
|--------|-------|
| Total Findings | {total} |
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |

---

## [SEARCH] Reconnaissance Results

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

## [SCAN]️ Scan Results

{scan_results}

---

## [AI] AI Analysis

{analysis}

---

## [EXP] Exploitation Attempts

{exploit_results}

---

## [OK] Remediation Recommendations

{remediation}

---

*Report auto-generated: {date}*
"""


class ReportGenerator:
    """Generates reports in multiple formats (Markdown, JSON, HTML, XML)."""

    def __init__(self, workspace: Workspace, target_url: str, report_format: str = "markdown"):
        self.ws = workspace
        self.target_url = target_url
        self.report_format = report_format
    
    def generate(self, context: dict) -> str:
        """Generate and save the report in the specified format."""
        
        if self.report_format == "json":
            report = self._generate_json(context)
        elif self.report_format == "html":
            report = self._generate_html(context)
        elif self.report_format == "xml":
            report = self._generate_xml(context)
        else:
            report = self._generate_markdown(context)
        
        report_path = self.ws.path / f"report.{self.report_format}"
        report_path.write_text(report)
        return report
    
    def _generate_markdown(self, context: dict) -> str:
        """Generate Markdown report."""
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
            icon = "[OK]" if e.get("success") else "[ERR]"
            exploit_text += f"- {icon} **{e.get('vuln_type','?')}** ({e.get('tool','?')})\n"
        if not exploits:
            exploit_text = "*No exploitation attempted.*"

        remediation_text = ""
        for v in vulns[:5]:
            remediation_text += f"- **{v.get('type','?')}**: {v.get('remediation','')}\n"
        if not remediation_text:
            remediation_text = "*No remediation suggestions.*"

        return REPORT_TEMPLATE.format(
            target_url=self.target_url,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            status="[OK] Complete" if not context.get("error") else f"[ERR] Error: {context.get('error')}",
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
    
    def _generate_json(self, context: dict) -> str:
        """Generate JSON report."""
        import json
        
        analysis = context.get("analysis", {})
        vulns = analysis.get("vulnerabilities", [])
        summary = analysis.get("summary", {})
        
        report_data = {
            "target": self.target_url,
            "date": datetime.now().isoformat(),
            "status": "complete" if not context.get("error") else "error",
            "error": context.get("error"),
            "summary": summary,
            "vulnerabilities": vulns,
            "recon": {
                "technology": context.get("recon_results", {}).get("whatweb", ""),
                "headers": context.get("recon_results", {}).get("headers", ""),
                "ports": context.get("recon_results", {}).get("nmap", ""),
            },
            "scan_results": context.get("scan_results", {}),
            "exploitation": context.get("exploit_results", {}),
            "attack_chains": context.get("attack_chains", []),
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_html(self, context: dict) -> str:
        """Generate HTML report."""
        analysis = context.get("analysis", {})
        vulns = analysis.get("vulnerabilities", [])
        summary = analysis.get("summary", {})
        
        vuln_rows = ""
        for v in vulns:
            sev_color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "info": "green"}.get(v.get("severity", "").lower(), "gray")
            vuln_rows += f"<tr><td style='color:{sev_color}'><b>[{v.get('severity','?')}]</b></td><td>{v.get('type','?')}</td><td>{v.get('description','')[:200]}</td></tr>\n"
        
        if not vuln_rows:
            vuln_rows = "<tr><td colspan='3'>No vulnerabilities found</td></tr>"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Suvari Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #f1c40f; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #333; color: white; }}
        .summary {{ background: #f9f9f9; padding: 15px; border-radius: 5px; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>[SUVARI] Pentest Report</h1>
    <p><b>Target:</b> {self.target_url}</p>
    <p><b>Date:</b> {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total: {summary.get("total", 0)} | Critical: {summary.get("critical", 0)} | High: {summary.get("high", 0)} | Medium: {summary.get("medium", 0)} | Low: {summary.get("low", 0)}</p>
    </div>
    
    <h2>Vulnerabilities</h2>
    <table>
        <tr><th>Severity</th><th>Type</th><th>Description</th></tr>
        {vuln_rows}
    </table>
    
    <h2>Reconnaissance</h2>
    <pre>{str(context.get("recon_results", {}).get("whatweb", ""))[:1000]}</pre>
    
    <p><i>Report generated by Suvari AI Pentester</i></p>
</body>
</html>"""
        return html
    
    def _generate_xml(self, context: dict) -> str:
        """Generate XML report."""
        import xml.etree.ElementTree as ET
        from xml.dom import minidom
        
        root = ET.Element("suvari_report")
        ET.SubElement(root, "target").text = self.target_url
        ET.SubElement(root, "date").text = datetime.now().isoformat()
        ET.SubElement(root, "status").text = "complete" if not context.get("error") else "error"
        
        if context.get("error"):
            ET.SubElement(root, "error").text = context.get("error")
        
        analysis = context.get("analysis", {})
        vulns = analysis.get("vulnerabilities", [])
        summary = analysis.get("summary", {})
        
        summary_elem = ET.SubElement(root, "summary")
        for key, value in summary.items():
            ET.SubElement(summary_elem, key).text = str(value)
        
        vulns_elem = ET.SubElement(root, "vulnerabilities")
        for v in vulns:
            vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
            ET.SubElement(vuln_elem, "severity").text = v.get("severity", "")
            ET.SubElement(vuln_elem, "type").text = v.get("type", "")
            ET.SubElement(vuln_elem, "description").text = v.get("description", "")
            ET.SubElement(vuln_elem, "location").text = v.get("location", "")
            ET.SubElement(vuln_elem, "remediation").text = v.get("remediation", "")
        
        xml_str = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(xml_str)
        return dom.toprettyxml(indent="  ")
