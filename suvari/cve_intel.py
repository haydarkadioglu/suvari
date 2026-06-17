"""
CVE Intelligence — looks up vulnerabilities for detected technologies.
Uses searchsploit (local) and CVE APIs.
"""

import subprocess
import json
import re
from typing import Optional
from .llm import LLMClient


# Tech patterns to extract version info
VERSION_PATTERNS = [
    (r"(Apache[^\d]*(\d+\.\d+(?:\.\d+)?))", "apache"),
    (r"(nginx[^\d]*(\d+\.\d+(?:\.\d+)?))", "nginx"),
    (r"(OpenSSH[^\d]*(\d+[_\d.]+))", "openssh"),
    (r"(Apache-Coyote[^\d]*(\d+\.\d+))", "tomcat"),
    (r"(IIS[^\d]*(\d+\.\d+))", "iis"),
    (r"(PHP[^\d]*(\d+\.\d+(?:\.\d+)?))", "php"),
    (r"(MySQL[^\d]*(\d+\.\d+(?:\.\d+)?))", "mysql"),
    (r"(WordPress[^\d]*(\d+\.\d+(?:\.\d+)?))", "wordpress"),
    (r"(Drupal[^\d]*(\d+\.\d+(?:\.\d+)?))", "drupal"),
    (r"(OpenSSL[^\d]*(\d+\.\d+(?:\.\d+)?))", "openssl"),
]


def extract_versions(recon_results: dict) -> list:
    """Extract technology+version pairs from recon output."""
    versions = []
    text = str(recon_results)

    for pattern, tech_name in VERSION_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            versions.append({"technology": tech_name, "version": match[1].replace("_", "."), "matched": match[0].strip()})

    return versions


def query_searchsploit(technology: str, version: str) -> list:
    """Query local searchsploit for exploits."""
    results = []
    try:
        query = f"{technology} {version}"
        out = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True, text=True, timeout=30
        )
        if out.returncode == 0 and out.stdout:
            data = json.loads(out.stdout)
            for entry in data.get("RESULTS_EXPLOIT", [])[:5]:
                results.append({
                    "title": entry.get("Title", ""),
                    "path": entry.get("Path", ""),
                    "type": "exploit",
                })
    except Exception:
        pass
    return results


def query_cve_api(technology: str, version: str) -> list:
    """Query CVE database for known vulnerabilities."""
    results = []
    try:
        # Try cve.circl.lu API
        import httpx
        resp = httpx.get(
            f"https://cve.circl.lu/api/search/{technology}/{version}",
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            for cve in data[:5]:
                results.append({
                    "id": cve.get("id", ""),
                    "summary": cve.get("summary", "")[:200],
                    "cvss": cve.get("cvss", "N/A"),
                    "cpe": cve.get("vulnerable_configuration", [{}])[0].get("id", "") if cve.get("vulnerable_configuration") else "",
                })
    except Exception:
        pass

    if not results:
        # Fallback: try NVD API
        try:
            import httpx
            keyword = f"{technology} {version}"
            resp = httpx.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5",
                timeout=10,
                headers={"User-Agent": "Suvari/1.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", [])[:5]:
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_score = "N/A"
                    if "cvssMetricV31" in metrics:
                        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    results.append({
                        "id": cve.get("id", ""),
                        "summary": cve.get("descriptions", [{}])[0].get("value", "")[:200],
                        "cvss": cvss_score,
                    })
        except Exception:
            pass

    return results


def generate_exploit(technology: str, version: str, cve_id: str, summary: str, llm) -> str:
    """Use LLM to generate exploit code for a specific CVE."""
    prompt = f"""Generate a working proof-of-concept exploit for the following vulnerability:

Technology: {technology}
Version: {version}
CVE: {cve_id}
Description: {summary}

Requirements:
1. Python3 script using requests library
2. Must verify the vulnerability exists (check banner/response)
3. Print clear output showing success/failure
4. Safe - no destructive actions, no DoS
5. Include usage instructions in comments

Return ONLY the Python code, no explanation."""
    try:
        response = llm.chat(messages=[{"role": "user", "content": prompt}], temperature=0.3, max_tokens=2048)
        return response
    except Exception:
        return "# Failed to generate exploit"
