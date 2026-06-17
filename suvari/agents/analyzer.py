"""
Analyzer Agent — AI-powered analysis of scan results.
Inspired by Shannon's vulnerability analysis + exploitation pipeline.
"""

from .base import BaseAgent


ANALYZER_PROMPT = """You are a senior penetration testing analyst. Analyze the scan results and identify confirmed vulnerabilities.

Target: {target_url}

## Recon Results
{recon_data}

## Scan Results
{scan_data}

For each potential vulnerability:
1. Assess if it's exploitable
2. Rate severity (CRITICAL / HIGH / MEDIUM / LOW)
3. Suggest exploitation approach
4. Estimate confidence (confirmed / likely / possible)

Return JSON:
{{
  "vulnerabilities": [
    {{
      "type": "SQL Injection",
      "location": "/search.php?id=1",
      "severity": "CRITICAL",
      "confidence": "confirmed",
      "description": "Parameter 'id' is injectable...",
      "exploit_hint": "sqlmap -u '...' --batch --dbs",
      "remediation": "Use prepared statements"
    }}
  ],
  "summary": {{
    "total": 3,
    "critical": 1,
    "high": 1,
    "medium": 1
  }}
}}

Only include findings that have actual evidence in the scan data.
"""


class AnalyzerAgent(BaseAgent):
    """AI analysis of scan results — identifies real vulnerabilities."""

    def run(self, context: dict) -> dict:
        url = context["target_url"]
        recon_results = context.get("recon_results", {})
        scan_results = context.get("scan_results", {})

        self.log("🧠 AI analyzing results...")

        recon_text = "\n\n".join([
            f"=== {k} ===\n{v[:1000]}"
            for k, v in recon_results.items()
            if isinstance(v, str)
        ])

        scan_text = "\n\n".join([
            f"=== {k} ===\n{v[:2000]}"
            for k, v in scan_results.items()
            if isinstance(v, str)
        ])

        try:
            analysis = self.llm.chat_json(
                messages=[{"role": "user", "content": ANALYZER_PROMPT.format(
                    target_url=url,
                    recon_data=recon_text[:2000],
                    scan_data=scan_text[:4000],
                )}],
                temperature=0.1,
            )
            self.ws.save_json("analysis", "findings", analysis)
            summary = analysis.get("summary", {})
            self.log(f"  📊 {summary.get('total', 0)} findings detected")
            return analysis
        except Exception as e:
            self.log(f"  ⚠️ Analysis error: {e}")
            return {
                "vulnerabilities": [],
                "error": str(e),
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0},
            }
