"""
Tool Runner — executes Kali Linux tools via subprocess.
Docker-free, lightweight sandbox inspired by PentAGI's architecture.
"""

import subprocess
import shutil
from pathlib import Path
from typing import Optional


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
            output = result.stdout + result.stderr
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
            "nmap": "Port scanning",
            "whatweb": "Technology detection",
            "nuclei": "Vulnerability scanner",
            "nikto": "Web server scanner",
            "gobuster": "Directory/subdomain brute force",
            "ffuf": "Fuzzing",
            "sqlmap": "SQL injection",
            "wpscan": "WordPress scanner",
            "curl": "HTTP requests",
            "subfinder": "Subdomain discovery",
            "httpx": "HTTP probing",
            "dnsx": "DNS probing",
            "katana": "Web crawler",
        }
        return {name: desc for name, desc in tools.items() if self.check_tool(name)}
