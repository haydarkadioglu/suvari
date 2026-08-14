


   

from typing import Optional

from .bus import FindingsBus

from pathlib import Path

from rich.console import Console

from rich.progress import Progress, SpinnerColumn, TextColumn

from .llm import LLMClient

from .workspace import Workspace

from .tools.runner import ToolRunner

from .agents.recon import ReconAgent

from .agents.scanner import ScannerAgent

from .agents.analyzer import AnalyzerAgent

from .agents.exploiter import ExploiterAgent

from .report import ReportGenerator

from .state import PipelineState

from .prompt_loader import PromptLoader

from .core import Planner, Reflector

from .scan_logger import ScanLogger

from .mode import ScanMode

console = Console()

class SuvariOrchestrator:

                                                                                 

    PHASES = [

        ("recon", " Reconnaissance", "Target analysis"),

        ("scan", " Vulnerability Scan", "Security scanning"),

        ("analyze", " AI Analysis", "LLM-powered analysis"),

        ("exploit", " Exploitation", "Proof of concept"),

        ("report", " Report", "Report generation"),

    ]

    def __init__(self, target_url: str, workspace: Workspace, provider: str = "openai",

                 model: Optional[str] = None, recon_only: bool = False, fast: bool = False,

                 verbose: bool = False, scan_mode: ScanMode = ScanMode.GUIDED,

                 parallel: int = 3, chain_mode: bool = False,

                 login_creds: Optional[str] = None, browser_type: str = "chromium",

                 source_dir: Optional[Path] = None, server_scan: bool = False,

                 proxy_url: Optional[str] = None, custom_headers: Optional[dict] = None,

                 custom_cookies: Optional[dict] = None, rate_limit: Optional[int] = None,

                 timeout: int = 300, scope_file: Optional[str] = None,

                 user_agent: Optional[str] = None, report_format: str = "markdown"):

        self.target_url = target_url

        self.ws = workspace

        self.recon_only = recon_only

        self.fast = fast

        self.verbose = verbose

        self.mode = scan_mode

        self.parallel = parallel

        self.chain_mode = chain_mode

        self.login_creds = login_creds

        self.browser_type = browser_type

        self.source_dir = source_dir

        self.server_scan = server_scan

        self.proxy_url = proxy_url

        self.custom_headers = custom_headers or {}

        self.custom_cookies = custom_cookies or {}

        self.rate_limit = rate_limit

        self.timeout = timeout

        self.scope_file = scope_file

        self.user_agent = user_agent

        self.report_format = report_format

        self.state = PipelineState(workspace.path)

        self.logger = ScanLogger(workspace.path)

        self.logger.info("suvari", f"Scan started: {target_url} (provider={provider}, fast={fast})")

        self.llm = LLMClient(provider=provider, model=model)

        self.tools = ToolRunner(

            verbose=verbose,

            proxy_url=proxy_url,

            custom_headers=self.custom_headers,

            custom_cookies=self.custom_cookies,

            rate_limit=rate_limit,

            user_agent=user_agent,

        )

        self.prompts = PromptLoader(target_url, fast)

        self.planner = Planner(self.llm, self.tools, self.prompts)

        self.reflector = Reflector(self.llm)

        self.recon_agent = ReconAgent("recon", self.llm, self.ws, self.tools, verbose)

        self.scanner_agent = ScannerAgent("scanner", self.llm, self.ws, self.tools, verbose)

        self.analyzer_agent = AnalyzerAgent("analyzer", self.llm, self.ws, self.tools, verbose)

        self.exploiter_agent = ExploiterAgent("exploiter", self.llm, self.ws, self.tools, verbose)

        self.reporter = ReportGenerator(self.ws, self.target_url, report_format)

        self.context = {"target_url": target_url, "fast": fast, "source_dir": source_dir,

                        "mode": scan_mode, "server_scan": server_scan, "parallel": parallel,

                        "login_creds": login_creds, "browser_type": browser_type,

                        "recon_done": [], "proxy_url": proxy_url,

                        "custom_headers": self.custom_headers,

                        "custom_cookies": self.custom_cookies,

                        "rate_limit": rate_limit, "timeout": timeout,

                        "scope_file": scope_file, "user_agent": user_agent,

                        "report_format": report_format}

        self.bus = FindingsBus()

        self.bus.subscribe("port", self._on_port_found)

        self.bus.subscribe("cve", self._on_cve_found)

        self.bus.subscribe("vuln", self._on_vuln_found)

    def run(self):

                                             

        is_resume = self.state.has_partial_run()

        if is_resume:

            done = ", ".join(self.state.completed)

            console.print(f"[yellow] Resuming scan — already completed: {done}[/yellow]")

        avail = self.tools.available_tools()

        console.print(f"[bold]Available Tools:[/bold] {', '.join(avail.keys()) or '(none)'}")

        if not avail:

            console.print("[yellow]No Kali tools found. Only curl and AI analysis will work.[/yellow]")

        console.print("")

        phases = self.PHASES

        if self.recon_only:

            phases = [self.PHASES[0]]

        if is_resume:

            remaining = self.state.resume_from(phases)

            if not remaining:

                console.print("[green]All phases already completed! Showing report.[/green]")

                self._show_results()

                return

            skipped = [p[1] for p in phases if p[0] in self.state.completed]

            if skipped:

                console.print(f"[dim]Skipping completed: {', '.join(skipped)}[/dim]")

            phases = remaining

        if not is_resume:

            self.state.start(self.target_url)

        with Progress(

            SpinnerColumn(),

            TextColumn("[progress.description]{task.description}"),

            console=console,

        ) as progress:

            for phase_id, phase_name, phase_desc in phases:

                task = progress.add_task(f"{phase_name} — {phase_desc}", total=None)

                self.state.phase_start(phase_id)

                try:

                    plan = self.planner.decide(

                        phase=phase_id, completed=self.state.completed, last_results=self.context)

                    action = plan.get("next_action", phase_id)

                    if self.verbose:

                        console.print(f"  [dim]Plan: {plan.get('reasoning', '')[:100]}[/dim]")

                    self._run_phase(phase_id)

                    if phase_id != "report":

                        phase_output = self._get_phase_output(phase_id)

                        reflection = self.reflector.analyze(

                            last_action=phase_id, tool=action, output=phase_output,

                            target_url=self.target_url)

                        for finding in reflection.get("findings", []):

                            self.planner.add_knowledge(finding)

                        if self.verbose:

                            s = reflection.get("success", False)

                            f = len(reflection.get("findings", []))

                            console.print(f"  [dim]Reflection: {'OK' if s else '?'} {f} findings[/dim]")

                    self.state.phase_complete(phase_id)

                except Exception as e:

                    console.print(f"\n[red][ERR] {phase_name} error: {e}[/red]")

                    self.context["error"] = str(e)

                    self.state.set_error(str(e))

                    break

                finally:

                    progress.remove_task(task)

        self._show_results()

    def _on_port_found(self, agent: str, finding: dict):

                                         

        port = finding.get("detail", "")

        self.logger.info("bus", f"Port from {agent}: {port}")

    def _on_cve_found(self, agent: str, finding: dict):

                                        

        cve = finding.get("cve_id", finding.get("detail", ""))

        self.logger.info("bus", f"CVE from {agent}: {cve}")

        if finding.get("severity") in ("CRITICAL", "HIGH"):

            self.context.setdefault("critical_cves", []).append(finding)

    def _on_vuln_found(self, agent: str, finding: dict):

                                                  

        vtype = finding.get("type", "")

        sev = finding.get("severity", "")

        self.logger.info("bus", f"Vuln from {agent}: [{sev}] {vtype}")

        if sev in ("CRITICAL", "HIGH") and agent != "delegated":

            from .agents.exploiter import ExploiterAgent

            from .workspace import Workspace

            sub_ws = Workspace(f"bus-{vtype[:15]}")

            sub = ExploiterAgent("delegated", self.llm, sub_ws, self.tools)

            sub.run({"target_url": self.target_url, "analysis": {"vulnerabilities": [finding]}})

    def _get_phase_output(self, phase_id: str) -> str:

        return self.ws.get_phase_output(phase_id)[:2000]

    def _show_results(self):

        console.print("\n[bold green]Scan complete![/bold green]")

        report_path = self.ws.path / "report.md"

        console.print(f"[bold]Report:[/bold] {report_path}")

        rt = self.context.get("recon_results", {}).get("_recon_time", "")

        st = self.context.get("scan_results", {}).get("_total_time", "")

        if rt or st:

            console.print(f"[dim]  Recon: {rt} | Scan: {st}[/dim]")

        analysis = self.context.get("analysis", {})

        summary = analysis.get("summary", {})

        if summary.get("total", 0) > 0:

            console.print(f"\n[red] {summary['total']} vulnerabilities found![/red]")

            parts = []

            for sev, icon in [("critical", "[CRIT]"), ("high", "[WARN]"), ("medium", "[INFO]"), ("low", "[INFO]"), ("info", "[INFO]")]:

                if summary.get(sev, 0) > 0:

                    parts.append(f"{icon} {sev.title()}: {summary[sev]}")

            console.print(f"  {' | '.join(parts)}")

        else:

            console.print("[green]No significant vulnerabilities detected.[/green]")

        self._suggest_next_targets()

    def _suggest_next_targets(self):

                                                                                  

        console = Console()

        analysis = self.context.get("analysis", {})

        vulns = analysis.get("vulnerabilities", [])

        suggestions = []

        vuln_types = set(v.get("type", "").lower() for v in vulns)

        if "cors" in vuln_types:

            suggestions.append("[cors] CORS open - try CSRF + auth bypass chain")

        if "xss" in vuln_types:

            suggestions.append("[xss] XSS found - try session stealing, phishing")

        if "sql" in " ".join(vuln_types):

            suggestions.append("[sqli] SQL injection - try data extraction via sqlmap")

        if "exposure" in vuln_types or "env" in vuln_types:

            suggestions.append("[config] Sensitive file exposed - check for credentials and API keys")

        if "clickjacking" in vuln_types:

            suggestions.append("[clickjack] Clickjacking - try frame-based phishing PoC")

        techs = str(self.context.get("browser_info", {}).get("tech", []))

        techs += str(self.context.get("recon_results", {}).get("whatweb", ""))

        if techs and "wordpress" in techs.lower():

            suggestions.append("[cms] WordPress - try wpscan for plugin CVEs and user enum")

        if any("header" in v.get("type", "").lower() or "missing" in v.get("type", "").lower() for v in vulns):

            suggestions.append("[header] Security headers missing - try HSTS bypass, cookie injection")

        if suggestions:

            console.print("\n[bold yellow]Next steps:[/bold yellow]")

            for s in suggestions[:5]:

                console.print(f"  {s}")

    def _run_phase(self, phase_id: str):

                                                                             

        self.logger.info("phase", f"Starting: {phase_id}")

        if phase_id == "recon":

            console.print(f"  {self.target_url}")

            self.context["recon_results"] = self.recon_agent.run(self.context)

            self.context["recon_done"] = ["whatweb", "headers", "nmap", "robots", "common_paths"]

            self.logger.info("phase", "Recon complete")

        elif phase_id == "scan":

            console.print("  [Agent Orchestrator] Starting intelligent scan pipeline...")

            from .agents.orchestrator import AgentOrchestrator

            orchestrator = AgentOrchestrator(

                llm=self.llm,

                workspace=self.ws,

                tools=self.tools,

                verbose=self.verbose,

                context=self.context,

                target_url=self.target_url

            )

            self.context["scan_results"] = orchestrator.run_scan_pipeline()

            scan_results = self.context.get("scan_results", {})

            vulnerabilities = scan_results.get("vulnerabilities", [])

            for vuln in vulnerabilities[:3]:

                if vuln.get("severity") in ("CRITICAL", "HIGH"):

                    sub_ws = Workspace(f"delegated-{vuln.get('type','')[:20]}")

                    sub = ExploiterAgent("delegated", self.llm, sub_ws, self.tools)

                    sub.run({"target_url": self.target_url, "analysis": {"vulnerabilities": [vuln]}})

            self.logger.info("phase", "Agent-based scan complete")

        elif phase_id == "analyze":

            if self.context.get("user_suggestions"):

                self.context["analysis_context"] = f"User specifically asked to check: {self.context['user_suggestions']}"

            self.context["analysis"] = self.analyzer_agent.run(self.context)

            analysis = self.context.get("analysis", {})

            vulnerabilities = analysis.get("vulnerabilities", [])

            for vuln in vulnerabilities[:3]:

                if vuln.get("severity", "") in ("CRITICAL", "HIGH"):

                    from .agents.exploiter import ExploiterAgent

                    from .workspace import Workspace

                    sub_ws = Workspace(f"delegated-{vuln.get('type','')[:20]}")

                    sub = ExploiterAgent("delegated", self.llm, sub_ws, self.tools)

                    sub.run({"target_url": self.target_url, "analysis": {"vulnerabilities": [vuln]}})

            from .attack_chain import AttackChain

            chainer = AttackChain(self.llm)

            chains = chainer.discover(vulnerabilities, self.context.get("recon_results"))

            if chains:

                self.context["attack_chains"] = chains

                console.print(f"  Attack chains: {len(chains)} found")

                for c in chains:

                    console.print(f"    [{c.get('confidence','?')}] {c['chain']}")

            sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for v in vulnerabilities:

                s = v.get("severity", "low").lower()

                if s in sev_count:

                    sev_count[s] += 1

            analysis["summary"] = {

                "total": len(vulnerabilities),

                **sev_count,

            }

            self.context["analysis"] = analysis

            self.logger.info("phase", f"Analysis complete: {analysis['summary']['total']} findings")

        elif phase_id == "exploit":

            self.context["exploit_results"] = self.exploiter_agent.run(self.context)

        elif phase_id == "report":

            report = self.reporter.generate(self.context)

            console.print(f"\nReport generated ({len(report)} chars)")

            self.logger.info("phase", "Report generated")

    def _try_default_logins(self, browser) -> Optional[str]:

                                                     

        defaults = [

            ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),

            ("admin", "123456"), ("root", "root"), ("test", "test"),

            ("user", "user"), ("guest", "guest"),

        ]

        for username, password in defaults:

            try:

                result = browser.login_form(self.target_url, username, password)

                if result.get("success"):

                    return f"{username}:{password}"

            except Exception:

                continue

        return None

    def _run_browser(self) -> dict:

                                                       

        result = {"title": "", "status": 0, "tech": [], "forms": 0, "scripts": 0, "dom_xss": []}

        console = Console()

        try:

            from .browser import BrowserAgent

            with BrowserAgent(browser_type=self.browser_type) as browser:

                page_info = browser.navigate(self.target_url)

                if page_info.get("status", 0) in (200, 301, 302, 403):

                    forms = page_info.get("forms", [])

                    login_form = any("password" in str(f) for f in forms)

                    result = {

                        "title": page_info.get("title", ""),

                        "status": page_info.get("status", 0),

                        "tech": page_info.get("client_tech", []),

                        "forms": len(forms),

                        "scripts": len(page_info.get("scripts", [])),

                        "dom_xss": [],

                    }

                    console.print(f"  Page: {page_info.get('title', '?')} ({page_info.get('status', '?')})")

                    if page_info.get("client_tech"):

                        console.print(f"  Tech: {', '.join(page_info['client_tech'])}")

                    if login_form:

                        defaults = self._try_default_logins(browser)

                        if defaults:

                            console.print(f"  Default login: {defaults}")

                        elif self.login_creds:

                            creds = self.login_creds.split(":", 1)

                            if browser.login_form(self.target_url, creds[0], creds[1]).get("success"):

                                console.print("  Login OK")

                    dom_xss = browser.check_dom_xss(self.target_url)

                    if dom_xss:

                        result["dom_xss"] = dom_xss

                        console.print(f"  DOM XSS: {len(dom_xss)}")

                    browser.screenshot(str(self.ws.path / "browser_screenshot.png"))

        except ImportError:

            console.print("  Browser: pip install playwright")

        except Exception as e:

            console.print(f"  Browser: {e}")

        return result

    def _run_cve_intel(self) -> list:

                                                       

        console = Console()

        findings = []

        try:

            from .cve_intel import extract_versions, query_cve_api, generate_exploit

            recon_results = self.context.get("recon_results", {})

            tech_versions = extract_versions(recon_results)

            for tv in tech_versions[:3]:

                cves = query_cve_api(tv["technology"], tv["version"])

                for cve in cves[:2]:

                    findings.append({

                        "type": f"CVE: {cve.get('id', '?')}", "location": f"{tv['technology']} {tv['version']}",

                        "severity": "CRITICAL" if str(cve.get('cvss', '0')).startswith(("9", "10")) else "HIGH",

                        "description": cve.get("summary", "")[:200], "cve_id": cve.get("id", ""),

                    })

            if findings:

                console.print(f"  CVE: {len(findings)} known vulns")

                top = findings[0]

                tv = tech_versions[0] if tech_versions else {}

                if top.get("cve_id") and tv:

                    exploit = generate_exploit(

                        tv.get("technology", ""), tv.get("version", ""),

                        top["cve_id"], top["description"], self.llm)

                    if exploit and not exploit.startswith("# Failed"):

                        (self.ws.path / f"exploit_{top['cve_id']}.py").write_text(exploit)

                        console.print(f"  Exploit saved")

        except Exception:

            pass

        return findings

    def _run_causal_chain(self) -> dict:

                                                                          

        from .chain import CausalChain

        console = Console()

        console.print("  Causal chain: reasoning step by step")

        try:

            chain = CausalChain(self.target_url, self.llm, self.tools, self.ws, max_steps=8)

            results = chain.run()

            if results.get("vulnerabilities"):

                console.print(f"  Chain: {len(results['vulnerabilities'])} findings")

            return results

        except Exception as e:

            console.print(f"  Chain error: {e}")

            return {}

    def _run_smart_scan(self) -> dict:

                                                                             

        from .agents.scanner import ScannerAgent

        from .chain import CausalChain

        console = Console()

        console.print("  Phase A: AI-driven tool selection")

        scanner = ScannerAgent("scanner", self.llm, self.ws, self.tools, verbose=False)

        if self.context.get("fast"):

            console.print("  [dim]Fast mode: nuclei (high/med) + curl endpoints[/dim]")

            scan_results = scanner.run({**self.context, "fast": True, "tool_limit": 3}) or {}

        else:

            scan_results = scanner.run(self.context) or {}

        if self.chain_mode:

            console.print("  Phase B: Causal graph analysis")

            try:

                chain = CausalChain(self.target_url, self.llm, self.tools, self.ws, max_steps=6)

                chain_results = chain.run()

                if chain_results.get("vulnerabilities"):

                    existing = scan_results.setdefault("vulnerabilities", [])

                    existing.extend(chain_results["vulnerabilities"])

                    console.print(f"  Chain added {len(chain_results['vulnerabilities'])} findings")

            except Exception as e:

                console.print(f"  Chain: {e}")

        vulns = scan_results.get("vulnerabilities", [])

        if vulns:

            critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")

            high = sum(1 for v in vulns if v.get("severity") == "HIGH")

            console.print(f"  Phase C: {critical} critical, {high} high findings - delegating exploitation")

        return scan_results

    def _run_scanner(self) -> dict:

                                              

        console = Console()

        if self.chain_mode:

            from .chain import ScanChain

            try:

                chain = ScanChain(self.target_url, self.llm, self.tools, self.ws, fast=self.fast)

                findings = chain.run()

                return {"chain_findings": findings, "_total_time": "chain"}

            except Exception as e:

                console.print(f"  Chain: {e}")

                return {"_total_time": "chain_error"}

        return self.scanner_agent.run(self.context)
