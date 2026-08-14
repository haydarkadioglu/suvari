


   

from typing import Dict, List, Optional, Any

from rich.console import Console

from ..llm import LLMClient

from ..workspace import Workspace

from ..tools.runner import ToolRunner

from .base import BaseAgent, AgentManager

from .recon import ReconAgent

from .scanner import ScannerAgent

from .analyzer import AnalyzerAgent

from .exploiter import ExploiterAgent

from .bugbounty import BugBountyAgent

from .infiltrator import InfiltratorAgent

console = Console()

class AgentOrchestrator:

    








       

    AGENT_REGISTRY = {

        "recon": {

            "class": ReconAgent,

            "category": "discovery",

            "description": "Target reconnaissance and information gathering",

            "dependencies": [],

            "parallel_safe": True,

        },

        "bugbounty": {

            "class": BugBountyAgent,

            "category": "hunting",

            "description": "Bug bounty focused subdomain/URL discovery",

            "dependencies": [],

            "parallel_safe": True,

        },

        "infiltrator": {

            "class": InfiltratorAgent,

            "category": "authentication",

            "description": "Auto-registration and login to gain authorized access",

            "dependencies": ["recon"],

            "parallel_safe": False,

            "conditional": True,

        },

        "scanner": {

            "class": ScannerAgent,

            "category": "vuln_detection",

            "description": "Vulnerability scanning with multiple tools",

            "dependencies": ["recon"],

            "parallel_safe": False,

        },

        "analyzer": {

            "class": AnalyzerAgent,

            "category": "analysis",

            "description": "AI-powered analysis of scan results",

            "dependencies": ["recon", "scanner"],

            "parallel_safe": False,

        },

        "exploiter": {

            "class": ExploiterAgent,

            "category": "exploitation",

            "description": "Vulnerability verification and proof collection",

            "dependencies": ["analyzer"],

            "parallel_safe": False,

        },

    }

    def __init__(

        self,

        llm: LLMClient,

        workspace: Workspace,

        tools: ToolRunner,

        verbose: bool = False,

        context: Optional[Dict] = None,

        target_url: str = "",

    ):

        self.llm = llm

        self.ws = workspace

        self.tools = tools

        self.verbose = verbose

        self.context = context or {}

        self.target_url = target_url

        self.manager = AgentManager()

        self.agent_results: Dict[str, Dict] = {}

        self.findings_bus: List[Dict] = []

    def log(self, msg: str):

                                                     

        if self.verbose:

            console.print(f"  [orchestrator] {msg}")

    def _should_run_agent(self, agent_name: str) -> bool:

        


           

        agent_meta = self.AGENT_REGISTRY.get(agent_name, {})

        deps = agent_meta.get("dependencies", [])

        for dep in deps:

            if dep not in self.agent_results:

                self.log(f"Skipping {agent_name}: dependency {dep} not completed")

                return False

        if agent_meta.get("conditional", False):

            if not self._check_agent_conditions(agent_name):

                self.log(f"Skipping {agent_name}: conditions not met")

                return False

        if agent_name in ["bugbounty", "exploiter", "infiltrator"]:

            try:

                decision = self._ai_decide_agent(agent_name)

                if not decision.get("should_run", True):

                    self.log(f"AI decided to skip {agent_name}: {decision.get('reason', 'N/A')}")

                    return False

            except Exception as e:

                self.log(f"AI decision failed for {agent_name}, using default: {e}")

        return True

    def _check_agent_conditions(self, agent_name: str) -> bool:

        


           

        if agent_name == "infiltrator":

            if "recon" in self.agent_results:

                recon_result = self.agent_results["recon"]

                recon_output = recon_result.get("whatweb", "") + recon_result.get("nmap", "")

                login_indicators = ["login", "signin", "auth", "register", "signup", "form"]

                has_login_page = any(indicator in recon_output.lower() for indicator in login_indicators)

                if has_login_page:

                    self.log(f"Infiltrator conditions met: login/register forms detected")

                    return True

                return True

            return False

        return True

    def _ai_decide_agent(self, agent_name: str) -> Dict:

        


           

        context_summary = {

            "target_url": self.target_url,

            "completed_agents": list(self.agent_results.keys()),

            "findings_count": len(self.findings_bus),

            "available_tools": list(self.tools.available_tools().keys())[:10],

        }

        if "recon" in self.agent_results:

            recon = self.agent_results["recon"]

            context_summary["tech_stack"] = recon.get("whatweb", "")[:200]

            context_summary["open_ports"] = recon.get("nmap", "")[:200]

        if "scanner" in self.agent_results:

            scan = self.agent_results["scanner"]

            vulns = scan.get("vulnerabilities", [])

            context_summary["vuln_count"] = len(vulns)

            if vulns:

                context_summary["critical_vulns"] = [

                    v.get("type") for v in vulns 

                    if v.get("severity") in ("CRITICAL", "HIGH")

                ][:5]

        prompt = f"""You are deciding whether to run the '{agent_name}' agent.
Context:
- Target: {self.target_url}
- Completed agents: {context_summary['completed_agents']}
- Available tools: {', '.join(context_summary['available_tools'])}
- Findings so far: {context_summary['findings_count']}
Task Description:
{self.AGENT_REGISTRY[agent_name]['description']}
Return JSON:
{ 
    "should_run": true/false,
    "reason": "Brief explanation",
    "priority": "high/medium/low"
} """

        response = self.llm.chat(

            messages=[{"role": "user", "content": prompt}],

            temperature=0.3,

            max_tokens=300,

        )

        import json

        try:

            cleaned = response.strip()

            if "```json" in cleaned:

                cleaned = cleaned.split("```json")[1].split("```")[0].strip()

            elif "```" in cleaned:

                cleaned = cleaned.split("```")[1].split("```")[0].strip()

            result = json.loads(cleaned)

            return {

                "should_run": result.get("should_run", True),

                "reason": result.get("reason", "No reason provided"),

                "priority": result.get("priority", "medium"),

            }

        except Exception as e:

            self.log(f"Failed to parse AI decision: {e}")

            return {"should_run": True, "reason": "Parse error, defaulting to run", "priority": "medium"}

    def _run_agent(self, agent_name: str) -> Dict:

                                                   

        agent_meta = self.AGENT_REGISTRY.get(agent_name)

        if not agent_meta:

            raise ValueError(f"Unknown agent: {agent_name}")

        agent_class = agent_meta["class"]

        agent_ws = Workspace(f"{self.ws.path.stem}/{agent_name}")

        if agent_name == "infiltrator":

            console.print(f"  [bold cyan]▶ Running {agent_name} agent (async)...[/bold cyan]")

            import asyncio

            from suvari.core.config import Config

            config = Config()

            infiltrator = InfiltratorAgent(config)

            try:

                result = asyncio.run(infiltrator.execute(self.target_url, {**self.context, **self.agent_results}))

            except Exception as e:

                console.print(f"  [red]✗ {agent_name} failed: {e}[/red]")

                return {"error": str(e), "success": False}

            self.agent_results[agent_name] = result

            if result.get("success"):

                console.print(f"  [green]✓ {agent_name} gained authorized access![/green]")

                self.context["auth_cookies"] = result.get("cookies", [])

                self.context["auth_token"] = result.get("token")

                self.context["credentials"] = result.get("credentials", {})

            else:

                console.print(f"  [yellow]⊘ {agent_name} could not gain access (anonymous scanning)[/yellow]")

            return result

        agent = agent_class(

            name=agent_name,

            llm=self.llm,

            workspace=agent_ws,

            tools=self.tools,

            verbose=self.verbose,

            manager=self.manager,

        )

        run_context = {**self.context, **self.agent_results}

        run_context["target_url"] = self.target_url

        console.print(f"  [bold cyan]▶ Running {agent_name} agent...[/bold cyan]")

        result = agent.run(run_context)

        self.agent_results[agent_name] = result

        if isinstance(result, dict):

            vulnerabilities = result.get("vulnerabilities", [])

            for vuln in vulnerabilities:

                self.findings_bus.append({

                    "source": agent_name,

                    "finding": vuln,

                })

        return result

    def _get_parallel_groups(self) -> List[List[str]]:

        


           

        parallel_group = []

        sequential_list = []

        for name, meta in self.AGENT_REGISTRY.items():

            if meta["parallel_safe"] and not meta["dependencies"]:

                parallel_group.append(name)

            else:

                sequential_list.append(name)

        groups = []

        if parallel_group:

            groups.append(parallel_group)

        for agent in sequential_list:

            groups.append([agent])

        return groups

    def run_scan_pipeline(self) -> Dict:

        



           

        console.print("\n[bold magenta]🤖 Agent Orchestrator Starting[/bold magenta]")

        console.print(f"  Target: {self.target_url}")

        console.print(f"  Available agents: {', '.join(self.AGENT_REGISTRY.keys())}")

        total_start = __import__('time').time()

        execution_groups = self._get_parallel_groups()

        for group_idx, agent_group in enumerate(execution_groups):

            console.print(f"\n  [dim]Phase {group_idx + 1}: Running {len(agent_group)} agent(s)[/dim]")

            agents_to_run = [

                name for name in agent_group 

                if self._should_run_agent(name)

            ]

            if not agents_to_run:

                console.print("  [yellow]⊘ All agents in this group skipped[/yellow]")

                continue

            if len(agents_to_run) > 1:

                from concurrent.futures import ThreadPoolExecutor, as_completed

                console.print(f"  [cyan]⟳ Running in parallel: {', '.join(agents_to_run)}[/cyan]")

                with ThreadPoolExecutor(max_workers=len(agents_to_run)) as executor:

                    futures = {

                        executor.submit(self._run_agent, name): name 

                        for name in agents_to_run

                    }

                    for future in as_completed(futures):

                        agent_name = futures[future]

                        try:

                            result = future.result()

                            console.print(f"  [green]✓ {agent_name} completed[/green]")

                        except Exception as e:

                            console.print(f"  [red]✗ {agent_name} failed: {e}[/red]")

                            self.agent_results[f"{agent_name}_error"] = str(e)

            else:

                agent_name = agents_to_run[0]

                try:

                    result = self._run_agent(agent_name)

                    console.print(f"  [green]✓ {agent_name} completed[/green]")

                except Exception as e:

                    console.print(f"  [red]✗ {agent_name} failed: {e}[/red]")

                    self.agent_results[f"{agent_name}_error"] = str(e)

        total_time = __import__('time').time() - total_start

        combined_results = {

            "_total_time": f"{total_time:.1f}s",

            "_agents_run": list(self.agent_results.keys()),

            "_findings_count": len(self.findings_bus),

            "_agent_manager_summary": self.manager.summary(),

        }

        for agent_name, result in self.agent_results.items():

            if isinstance(result, dict):

                for key, value in result.items():

                    if not key.startswith("_"):

                        combined_results[f"{agent_name}_{key}"] = value

        all_vulnerabilities = []

        for agent_name, result in self.agent_results.items():

            if isinstance(result, dict):

                vulns = result.get("vulnerabilities", [])

                for vuln in vulns:

                    vuln["_source"] = agent_name

                    all_vulnerabilities.append(vuln)

        combined_results["vulnerabilities"] = all_vulnerabilities

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for vuln in all_vulnerabilities:

            sev = vuln.get("severity", "low").lower()

            if sev in severity_counts:

                severity_counts[sev] += 1

        combined_results["summary"] = {

            "total": len(all_vulnerabilities),

            **severity_counts,

        }

        console.print(f"\n[bold green]✓ Agent pipeline complete in {combined_results['_total_time']}[/bold green]")

        console.print(f"  Total vulnerabilities: {combined_results['summary']['total']}")

        console.print(f"  Critical: {severity_counts['critical']}, High: {severity_counts['high']}, Medium: {severity_counts['medium']}")

        return combined_results
