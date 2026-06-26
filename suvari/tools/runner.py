"""
Tool Runner — executes Kali Linux tools via subprocess.
Docker-free, lightweight sandbox inspired by PentAGI's architecture.
"""

import subprocess
import shutil
import re
from pathlib import Path
from typing import Optional, Callable

# Critical patterns to preserve from truncation
_CRITICAL_PATTERNS = re.compile(
    r'\[?(critical|high|CRITICAL|HIGH|cve-\d{4}|vulnerability|VULNERABILITY|exposed|EXPOSED|sql\s*inj|XSS|rce|RCE|LFI|SSRF)\]?',
    re.IGNORECASE
)


# ANSI escape sequence cleaner
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def clean_ansi(text: str) -> str:
    """Remove ANSI escape sequences from tool output."""
    return _ANSI_RE.sub('', text)


class ToolRunner:
    """Execute security tools with result caching (max 100 per session)."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._cache = {}  # Instance-level cache, not shared across sessions
        self._MAX_CACHE = 100

    def run(self, cmd: list, timeout: int = 120, workdir: Optional[Path] = None,
            max_output_len: int = 50_000) -> str:
        """Run a command with caching. Same cmd+target -> cached result.
        
        max_output_len: if output exceeds this, smart-truncate preserving critical lines.
        """
        # Create cache key from command and working directory
        cache_key = (tuple(cmd), str(workdir))
        if cache_key in self._cache:
            if self.verbose:
                print(f"  [cache] reused: {' '.join(cmd)[:80]}")
            return self._cache[cache_key]

        # Evict oldest if cache is full
        if len(self._cache) >= self._MAX_CACHE:
            self._cache.pop(next(iter(self._cache)))
        if self.verbose:
            print(f"  [exec] {' '.join(cmd)[:120]}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=workdir,
            )
            output = clean_ansi(result.stdout + result.stderr)
            output = self._smart_truncate(output, max_output_len) if len(output) > max_output_len else output
            self._cache[cache_key] = output
            return output.strip() if output else "(empty)"
        except subprocess.TimeoutExpired:
            self._cache[cache_key] = f"(TIMEOUT after {timeout}s)"
            return self._cache[cache_key]
        except FileNotFoundError:
            self._cache[cache_key] = f"(tool not found: {cmd[0]})"
            return self._cache[cache_key]
        except Exception as e:
            self._cache[cache_key] = f"(error: {e})"
            return self._cache[cache_key]

    def _smart_truncate(self, text: str, max_len: int) -> str:
        """Truncate text but preserve critical lines (CVEs, vulnerabilities, etc.)."""
        lines = text.splitlines(keepends=False)
        if not lines or len(text) <= max_len:
            return text

        # Identify critical lines
        critical_lines = []
        normal_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                normal_lines.append(line)
            elif _CRITICAL_PATTERNS.search(stripped):
                critical_lines.append(line)
            else:
                normal_lines.append(line)

        # Always preserve critical lines at the top
        # Then head + tail of normal lines
        head = normal_lines[:20]  # first 20 normal lines
        tail = normal_lines[-10:]  # last 10 normal lines
        mid_note = f"... [truncated: {len(normal_lines) - len(head) - len(tail)} normal lines] ..."

        selected = critical_lines + [""] + head + [mid_note] + tail
        result = "\n".join(selected)

        # If still too long, hard truncate keeping critical lines + head only
        if len(result) > max_len:
            result = "\n".join(critical_lines) + "\n... [hard truncation: output too large for Analyzer] ..."

        return result

    def run_priority(self, cmd: list, timeout: int = 120, workdir: Optional[Path] = None,
                     priority_callback: Optional[Callable[[str], None]] = None) -> str:
        """Run a command and optionally stream partial results via callback.
        
        Useful for long-running tools — callback gets each line as it arrives.
        """
        cache_key = (tuple(cmd), str(workdir))
        if cache_key in self._cache:
            if self.verbose:
                print(f"  [cache] reused: {' '.join(cmd)[:80]}")
            return self._cache[cache_key]

        if len(self._cache) >= self._MAX_CACHE:
            self._cache.pop(next(iter(self._cache)))
        if self.verbose:
            print(f"  [exec] {' '.join(cmd)[:120]}")

        output_parts = []
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=workdir,
            )
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    clean = clean_ansi(line)
                    output_parts.append(clean)
                    if priority_callback and _CRITICAL_PATTERNS.search(clean):
                        priority_callback(clean.strip())
            proc.wait(timeout=timeout)
            output = "".join(output_parts)
            self._cache[cache_key] = output
            return output.strip() if output else "(empty)"
        except subprocess.TimeoutExpired:
            if proc:
                proc.kill()
            self._cache[cache_key] = "(TIMEOUT)"
            return self._cache[cache_key]
        except FileNotFoundError:
            self._cache[cache_key] = f"(tool not found: {cmd[0]})"
            return self._cache[cache_key]
        except Exception as e:
            self._cache[cache_key] = f"(error: {e})"
            return self._cache[cache_key]

    def check_tool(self, name: str) -> bool:
        """Check if a tool is installed."""
        return shutil.which(name) is not None

    def available_tools(self) -> dict:
        """List available security tools on the system."""
        tools = {
            # ─── Network scanning ───
            "nmap": "Port scanning & service detection",
            "masscan": "High-speed port scanning",
            "rustscan": "Ultra-fast port scanner",
            "unicornscan": "Next-gen port scanner",
            "zmap": "Internet-wide port scanner",
            "arp-scan": "ARP discovery & fingerprinting",

            # ─── Web discovery ───
            "whatweb": "Technology fingerprinting",
            "httpx": "HTTP probing & tech detection",
            "gobuster": "Directory/subdomain brute force",
            "ffuf": "Web fuzzing",
            "feroxbuster": "Recursive content discovery",
            "dirb": "Web content scanner",
            "dirsearch": "Advanced directory discovery",
            "katana": "Web crawler with JS support",
            "hakrawler": "Fast web endpoint discovery",
            "wfuzz": "Web fuzzer",
            "recon-ng": "Web reconnaissance framework",

            # ─── Vulnerability scanning ───
            "nuclei": "Vulnerability scanner (4000+ templates)",
            "nikto": "Web server scanner",
            "wpscan": "WordPress scanner",
            "jaeles": "Advanced vulnerability scanner",
            "dalfox": "XSS scanner with DOM analysis",
            "xsstrike": "XSS detection suite",
            "skipfish": "Web app security scanner",
            "wapiti": "Web app vulnerability scanner",
            "arachni": "Web app security scanner framework",
            "zaproxy": "OWASP ZAP web scanner",

            # ─── Exploitation ───
            "sqlmap": "SQL injection automation",
            "hydra": "Password brute force (50+ protocols)",
            "john": "John the Ripper password cracker",
            "hashcat": "GPU-accelerated password recovery",
            "netexec": "Network exploitation framework",
            "metasploit": "Metasploit framework (msfconsole)",
            "msfvenom": "Payload generator",
            "searchsploit": "Exploit-DB local search",
            "exploitdb": "Exploit database",
            "medusa": "Parallel brute force",
            "ncrack": "Network authentication cracking",
            "crowbar": "SSH/OpenVPN brute force",

            # ─── Sniffing & MITM ───
            "responder": "LLMNR/NBT-NS poisoning",
            "ettercap": "MITM framework",
            "bettercap": "MITM & network monitoring",
            "tcpdump": "Packet capture",
            "tshark": "Wireshark CLI packet analyzer",
            "wireshark": "Packet analyzer (GUI)",
            "driftnet": "Image capture from network",
            "dnschef": "DNS proxy",
            "tcpreplay": "Packet replay",
            "tcpflow": "TCP flow recorder",

            # ─── SMB & Windows ───
            "enum4linux": "SMB enumeration",
            "smbmap": "SMB share enumeration",
            "rpcclient": "RPC null session testing",
            "impacket": "Windows protocol suite",
            "psexec": "Remote execution via SMB",
            "mimikatz": "Windows credential extraction",
            "crackmapexec": "Windows/AD exploitation (legacy)",

            # ─── OSINT & recon ───
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
            "maltego": "OSINT & link analysis (GUI)",
            "dmitry": "Deepmagic information gathering",
            "sublist3r": "Subdomain enumeration",

            # ─── Wireless ───
            "aircrack-ng": "Wireless security tools",
            "kismet": "Wireless network detector",
            "reaver": "WPS brute force",
            "bully": "WPS brute force alternative",

            # ─── Forensics ───
            "binwalk": "Firmware analysis",
            "foremost": "File carving",
            "volatility": "Memory forensics",
            "strings": "Extract strings from binaries",
            "exiftool": "Metadata extraction",
            "steghide": "Steganography",
            "outguess": "Steganography",
            "audacity": "Audio analysis",
            "pcapfix": "PCAP repair",

            # ─── Cloud ───
            "trivy": "Container/filesystem vulnerability scanner",
            "s3scanner": "AWS S3 bucket finder",

            # ─── Password ───
            "cewl": "Custom wordlist generator",
            "crunch": "Wordlist generator",
            "rsmangler": "Wordlist mangler",
            "rarcrack": "RAR/ZIP password cracker",
            "fcrackzip": "ZIP password cracker",
            "pdfcrack": "PDF password cracker",

            # ─── Web application ───
            "wafw00f": "WAF fingerprinting",
            "dotdotpwn": "Directory traversal fuzzing",
            "xsser": "XSS testing framework",
            "commix": "Command injection tester",
            "beef": "Browser exploitation framework",
            "webshell": "Webshell tools",

            # ─── Database ───
            "sqldict": "SQL Server dictionary attack",
            "mdb-sql": "MDB file query",

            # ─── Utilities ───
            "curl": "HTTP requests & scripting",
            "jq": "JSON processor",
            "socat": "Bidirectional data relay",
            "proxychains": "Proxy routing",
            "sbd": "Netcat alternative with encryption",
            "pwntools": "Exploit development library",
            "openssl": "SSL/TLS testing",
            "sslscan": "SSL/TLS scanner",
            "sslyze": "SSL configuration analyzer",
            "ike-scan": "IPsec VPN scanner",
            "snmpcheck": "SNMP enumerator",
            "onesixtyone": "SNMP brute force",
            "stunnel4": "SSL tunnel",
        }
        return {name: desc for name, desc in tools.items() if self.check_tool(name)}
