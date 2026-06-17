"""
Tool Runner — executes Kali Linux tools via subprocess.
Docker-free, lightweight sandbox inspired by PentAGI's architecture.
"""

import subprocess
import shutil
import re
from pathlib import Path
from typing import Optional


# ANSI escape sequence cleaner
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def clean_ansi(text: str) -> str:
    """Remove ANSI escape sequences from tool output."""
    return _ANSI_RE.sub('', text)


class ToolRunner:
    """Execute security tools and collect output."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def run(self, cmd: list, timeout: int = 120, workdir: Optional[Path] = None) -> str:
        """Run a command, return stdout+stderr."""
        if self.verbose:
            print(f"  ⚡ {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=workdir,
            )
            output = clean_ansi(result.stdout + result.stderr)
            return output.strip() if output else "(empty)"
        except subprocess.TimeoutExpired:
            return f"(TIMEOUT after {timeout}s)"
        except FileNotFoundError:
            return f"(tool not found: {cmd[0]})"
        except Exception as e:
            return f"(error: {e})"

    def check_tool(self, name: str) -> bool:
        """Check if a tool is installed."""
        return shutil.which(name) is not None

    def available_tools(self) -> dict:
        """List available security tools on the system."""
        tools = {
            # Network scanning
            "nmap": "Port scanning & service detection",
            "masscan": "High-speed port scanning",
            "rustscan": "Ultra-fast port scanner",
            # Web discovery
            "whatweb": "Technology fingerprinting",
            "httpx": "HTTP probing & tech detection",
            "gobuster": "Directory/subdomain brute force",
            "ffuf": "Web fuzzing",
            "feroxbuster": "Recursive content discovery",
            "dirb": "Web content scanner",
            "dirsearch": "Advanced directory discovery",
            "katana": "Web crawler with JS support",
            "hakrawler": "Fast web endpoint discovery",
            # Vulnerability scanning
            "nuclei": "Vulnerability scanner (4000+ templates)",
            "nikto": "Web server scanner",
            "wpscan": "WordPress scanner",
            "jaeles": "Advanced vulnerability scanner",
            "dalfox": "XSS scanner with DOM analysis",
            "xsstrike": "XSS detection suite",
            # Exploitation
            "sqlmap": "SQL injection automation",
            "hydra": "Password brute force (50+ protocols)",
            "john": "John the Ripper password cracker",
            "hashcat": "GPU-accelerated password recovery",
            "netexec": "Network exploitation framework",
            "metasploit": "Metasploit framework",
            # OSINT & recon
            "subfinder": "Passive subdomain discovery",
            "amass": "Subdomain enumeration & OSINT",
            "theharvester": "Email/subdomain OSINT",
            "dnsenum": "DNS enumeration",
            "dnsrecon": "DNS reconnaissance",
            "fierce": "DNS reconnaissance",
            "gau": "Get All URLs from sources",
            "waybackurls": "Historical URL discovery",
            "arjun": "HTTP parameter discovery",
            "paramspider": "Parameter mining",
            # SMB & Windows
            "enum4linux": "SMB enumeration",
            "smbmap": "SMB share enumeration",
            "responder": "LLMNR/NBT-NS poisoning",
            "rpcclient": "RPC null session testing",
            # Cloud
            "trivy": "Container/filesystem vulnerability scanner",
            "prowler": "AWS security assessment",
            # Web application
            "wafw00f": "WAF fingerprinting",
            "dotdotpwn": "Directory traversal fuzzing",
            # Utilities
            "curl": "HTTP requests & scripting",
            "jq": "JSON processor",
        }
        return {name: desc for name, desc in tools.items() if self.check_tool(name)}
