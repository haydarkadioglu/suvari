


   

import subprocess

import shutil

import re

from pathlib import Path

from typing import Optional, Callable

_CRITICAL_PATTERNS = re.compile(

    r'\[?(critical|high|CRITICAL|HIGH|cve-\d{4}|vulnerability|VULNERABILITY|exposed|EXPOSED|sql\s*inj|XSS|rce|RCE|LFI|SSRF)\]?',

    re.IGNORECASE

)

_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def clean_ansi(text: str) -> str:

                                                        

    return _ANSI_RE.sub('', text)

class ToolRunner:

                                                                           

    def __init__(self, verbose: bool = False, proxy_url: Optional[str] = None,

                 custom_headers: Optional[dict] = None, custom_cookies: Optional[dict] = None,

                 rate_limit: Optional[int] = None, user_agent: Optional[str] = None):

        self.verbose = verbose

        self._cache = {}

        self._MAX_CACHE = 100

        self.proxy_url = proxy_url

        self.custom_headers = custom_headers or {}

        self.custom_cookies = custom_cookies or {}

        self.rate_limit = rate_limit

        self.user_agent = user_agent

        self._env = None

        self._setup_proxy_env()

    def _setup_proxy_env(self):

                                                                       

        if self.proxy_url:

            import os

            self._env = os.environ.copy()

            self._env['HTTP_PROXY'] = self.proxy_url

            self._env['HTTPS_PROXY'] = self.proxy_url

    def run(self, cmd: list, timeout: int = 120, workdir: Optional[Path] = None,

            max_output_len: int = 50_000) -> str:

        


           

        cache_key = (tuple(cmd), str(workdir))

        if cache_key in self._cache:

            if self.verbose:

                print(f"  [cache] reused: {' '.join(cmd)[:80]}")

            return self._cache[cache_key]

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

                env=self._env,

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

    def build_tool_args(self, base_cmd: list, target: str, extra_args: Optional[list] = None) -> list:

        


           

        cmd = base_cmd.copy()

        for key, value in self.custom_headers.items():

            if 'curl' in cmd[0] or 'httpx' in cmd[0]:

                cmd.extend(['-H', f'{key}: {value}'])

            elif 'nuclei' in cmd[0]:

                cmd.extend(['-header', f'{key}: {value}'])

            elif 'gobuster' in cmd[0] or 'ffuf' in cmd[0]:

                cmd.extend(['-H', f'{key}: {value}'])

        if self.custom_cookies:

            cookie_str = '; '.join([f'{k}={v}' for k, v in self.custom_cookies.items()])

            if 'curl' in cmd[0]:

                cmd.extend(['-b', cookie_str])

            elif 'httpx' in cmd[0]:

                cmd.extend(['-cookie', cookie_str])

            elif 'nuclei' in cmd[0]:

                cmd.extend(['-cookie', f'{cookie_str}'])

            elif 'gobuster' in cmd[0] or 'ffuf' in cmd[0]:

                cmd.extend(['-b', cookie_str])

        if self.user_agent:

            if 'curl' in cmd[0]:

                cmd.extend(['-A', self.user_agent])

            elif 'httpx' in cmd[0]:

                cmd.extend(['-user-agent', self.user_agent])

            elif 'nuclei' in cmd[0]:

                cmd.extend(['-user-agent', self.user_agent])

            elif 'gobuster' in cmd[0] or 'ffuf' in cmd[0]:

                cmd.extend(['-a', self.user_agent])

        if self.rate_limit:

            if 'nuclei' in cmd[0]:

                cmd.extend(['-rate-limit', str(self.rate_limit)])

            elif 'httpx' in cmd[0]:

                cmd.extend(['-rate-limit', str(self.rate_limit)])

            elif 'gobuster' in cmd[0]:

                cmd.extend(['-d', str(int(1000 / self.rate_limit))])

            elif 'ffuf' in cmd[0]:

                cmd.extend(['-t', '1'])

        if target and target not in cmd:

            cmd.append(target)

        if extra_args:

            cmd.extend(extra_args)

        return cmd

    def _smart_truncate(self, text: str, max_len: int) -> str:

                                                                                      

        lines = text.splitlines(keepends=False)

        if not lines or len(text) <= max_len:

            return text

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

        head = normal_lines[:20]

        tail = normal_lines[-10:]

        mid_note = f"... [truncated: {len(normal_lines) - len(head) - len(tail)} normal lines] ..."

        selected = critical_lines + [""] + head + [mid_note] + tail

        result = "\n".join(selected)

        if len(result) > max_len:

            result = "\n".join(critical_lines) + "\n... [hard truncation: output too large for Analyzer] ..."

        return result

    def run_priority(self, cmd: list, timeout: int = 120, workdir: Optional[Path] = None,

                     priority_callback: Optional[Callable[[str], None]] = None) -> str:

        


           

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

                                           

        return shutil.which(name) is not None

    def available_tools(self) -> dict:

                                                          

        tools = {

            "nmap": "Port scanning & service detection",

            "masscan": "High-speed port scanning",

            "rustscan": "Ultra-fast port scanner",

            "unicornscan": "Next-gen port scanner",

            "zmap": "Internet-wide port scanner",

            "arp-scan": "ARP discovery & fingerprinting",

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

            "enum4linux": "SMB enumeration",

            "smbmap": "SMB share enumeration",

            "rpcclient": "RPC null session testing",

            "impacket": "Windows protocol suite",

            "psexec": "Remote execution via SMB",

            "mimikatz": "Windows credential extraction",

            "crackmapexec": "Windows/AD exploitation (legacy)",

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

            "aircrack-ng": "Wireless security tools",

            "kismet": "Wireless network detector",

            "reaver": "WPS brute force",

            "bully": "WPS brute force alternative",

            "binwalk": "Firmware analysis",

            "foremost": "File carving",

            "volatility": "Memory forensics",

            "strings": "Extract strings from binaries",

            "exiftool": "Metadata extraction",

            "steghide": "Steganography",

            "outguess": "Steganography",

            "audacity": "Audio analysis",

            "pcapfix": "PCAP repair",

            "trivy": "Container/filesystem vulnerability scanner",

            "s3scanner": "AWS S3 bucket finder",

            "cewl": "Custom wordlist generator",

            "crunch": "Wordlist generator",

            "rsmangler": "Wordlist mangler",

            "rarcrack": "RAR/ZIP password cracker",

            "fcrackzip": "ZIP password cracker",

            "pdfcrack": "PDF password cracker",

            "wafw00f": "WAF fingerprinting",

            "dotdotpwn": "Directory traversal fuzzing",

            "xsser": "XSS testing framework",

            "commix": "Command injection tester",

            "beef": "Browser exploitation framework",

            "webshell": "Webshell tools",

            "sqldict": "SQL Server dictionary attack",

            "mdb-sql": "MDB file query",

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

    def run_custom_command(self, command: str, timeout: int = 120, workdir: Optional[Path] = None,

                           max_output_len: int = 50_000) -> dict:

        



           

        import shlex

        try:

            cmd_list = shlex.split(command)

        except ValueError as e:

            return {

                "stdout": "",

                "stderr": f"Command parsing error: {e}",

                "returncode": -1,

                "command": command,

                "error": str(e)

            }

        if self.verbose:

            print(f"  [agent-exec] {command[:120]}")

        try:

            result = subprocess.run(

                cmd_list,

                capture_output=True,

                text=True,

                timeout=timeout,

                cwd=workdir,

                env=self._env,

            )

            stdout = clean_ansi(result.stdout)

            stderr = clean_ansi(result.stderr)

            output = stdout + stderr

            if len(output) > max_output_len:

                output = self._smart_truncate(output, max_output_len)

            return {

                "stdout": stdout,

                "stderr": stderr,

                "returncode": result.returncode,

                "command": command,

                "output": output.strip() if output else ""

            }

        except subprocess.TimeoutExpired:

            return {

                "stdout": "",

                "stderr": "",

                "returncode": -1,

                "command": command,

                "error": f"TIMEOUT after {timeout}s",

                "output": f"(TIMEOUT after {timeout}s)"

            }

        except FileNotFoundError as e:

            return {

                "stdout": "",

                "stderr": f"Tool not found: {cmd_list[0] if cmd_list else 'unknown'}",

                "returncode": -1,

                "command": command,

                "error": str(e),

                "output": f"(tool not found: {cmd_list[0] if cmd_list else 'unknown'})"

            }

        except Exception as e:

            return {

                "stdout": "",

                "stderr": f"Execution error: {e}",

                "returncode": -1,

                "command": command,

                "error": str(e),

                "output": f"(error: {e})"

            }
