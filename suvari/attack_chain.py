"""
Attack Chain — connects findings into exploit chains.
Inspired by HexStrike's attack chain discovery.
"""

import json
from typing import Optional
from .llm import LLMClient


class AttackChain:
    """Connects vulnerabilities into multi-step attack chains."""

    # Rule-based chain templates: [finding_types] → chain description
    CHAIN_RULES = [
        {
            "name": "Credential Theft via CORS + CSRF",
            "requires": ["cors", "session", "login"],
            "steps": [
                "1. CORS misconfiguration allows cross-origin requests",
                "2. Attacker hosts malicious page on evil.com",
                "3. Victim visits evil.com while authenticated",
                "4. JavaScript reads sensitive data via CORS",
                "5. Session cookie stolen / CSRF token extracted",
            ],
            "impact": "Account takeover via credential theft",
        },
        {
            "name": "Database Compromise via .env + Exposed Port",
            "requires": [".env", "database", "port"],
            "steps": [
                "1. .env file exposes database credentials",
                "2. Database port (3306/5432) is publicly accessible",
                "3. Attacker connects using leaked credentials",
                "4. Data exfiltration / ransomware",
            ],
            "impact": "Full database compromise",
        },
        {
            "name": "RCE via File Upload + Missing Auth",
            "requires": ["upload", "auth", "path"],
            "steps": [
                "1. File upload endpoint has no authentication",
                "2. No file type validation",
                "3. Attacker uploads webshell",
                "4. Webshell accessed via exposed uploads directory",
            ],
            "impact": "Remote code execution on server",
        },
        {
            "name": "WAF Bypass + SQL Injection",
            "requires": ["waf", "sql"],
            "steps": [
                "1. WAF detected (CloudFlare/ModSecurity)",
                "2. SQL injection endpoint identified",
                "3. Use WAF bypass techniques (comment injection, encoding)",
                "4. Execute SQL injection to extract data",
            ],
            "impact": "Data extraction via SQL injection",
        },
        {
            "name": "CloudFlare Bypass via Subdomain + Direct IP",
            "requires": ["cloudflare", "subdomain", "ip"],
            "steps": [
                "1. Target behind CloudFlare",
                "2. Subdomain enumeration reveals real IP",
                "3. Direct IP access bypasses WAF",
                "4. Attack server directly without CloudFlare protection",
            ],
            "impact": "Bypass WAF/CDN protection",
        },
        {
            "name": "Session Hijacking via XSS + Missing HttpOnly",
            "requires": ["xss", "httponly", "session"],
            "steps": [
                "1. XSS vulnerability found on page",
                "2. Session cookie missing HttpOnly flag",
                "3. Attacker injects JavaScript to steal cookie",
                "4. Session cookie used to impersonate user",
            ],
            "impact": "Account takeover via session hijacking",
        },
        {
            "name": "SMB Relay Attack",
            "requires": ["smb", "responder", "auth"],
            "steps": [
                "1. SMB signing disabled",
                "2. Responder captures NTLM hashes",
                "3. Relay captured hashes to other services",
                "4. Lateral movement within network",
            ],
            "impact": "Network-wide lateral movement",
        },
    ]

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm

    def discover(self, findings: list, recon_data: dict = None) -> list:
        """Discover attack chains from findings and recon data."""
        if not findings:
            return []

        # Extract keywords from findings
        finding_text = " ".join([
            f"{v.get('type','')} {v.get('location','')} {v.get('description','')}"
            for v in findings
        ]).lower()

        # Extract keywords from recon
        recon_text = ""
        if recon_data:
            recon_text = " ".join(str(v) for v in recon_data.values()).lower()

        combined = finding_text + " " + recon_text

        # Match against rule-based chains
        chains = []
        matched = set()
        for rule in self.CHAIN_RULES:
            required = rule["requires"]
            match_count = sum(1 for kw in required if kw in combined)
            if match_count >= len(required) * 0.6:  # 60% match threshold
                chains.append({
                    "chain": rule["name"],
                    "confidence": f"{match_count}/{len(required)} indicators",
                    "steps": rule["steps"],
                    "impact": rule["impact"],
                    "matched_indicators": [kw for kw in required if kw in combined],
                    "missing_indicators": [kw for kw in required if kw not in combined],
                })
                matched.add(rule["name"])

        # AI-enhanced chain discovery (if LLM available)
        if self.llm and len(chains) < 3:
            ai_chains = self._ai_discover(findings, combined)
            for c in ai_chains:
                if c["chain"] not in matched:
                    chains.append(c)
                    matched.add(c["chain"])

        return chains[:5]

    def _ai_discover(self, findings: list, context: str) -> list:
        """Use AI to discover novel attack chains."""
        try:
            prompt = f"""Given these findings, identify possible attack chains (connections between vulnerabilities):

{json.dumps([{'type': v.get('type'), 'severity': v.get('severity'), 'location': v.get('location')} for v in findings[:5]], indent=2)}

Context: {context[:1000]}

For each chain, provide:
- Chain name
- Steps (numbered)
- Impact

Return as JSON array: [{{"chain": "name", "steps": ["step1","step2"], "impact": "description"}}]
"""
            response = self.llm.chat(messages=[{"role": "user", "content": prompt}], temperature=0.3, max_tokens=1024)
            # Try to parse JSON from response
            text = response.strip()
            if text.startswith("```"): text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"): text = text[:-3].strip()
            if text.startswith("json"): text = text[4:].strip()
            if text.startswith("["):
                return json.loads(text)
        except Exception:
            pass
        return []
