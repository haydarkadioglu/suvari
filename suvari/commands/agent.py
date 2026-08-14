



   

import typer

from rich.console import Console

from rich.panel import Panel

from rich.markdown import Markdown

from rich.prompt import Prompt

from typing import Optional

import json

import sys

import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from suvari.llm import LLMClient

from suvari.tools.runner import ToolRunner

from suvari.config import load_config

console = Console()

def run_agent_command(target: str, model: Optional[str] = None):

                                                  

    llm = LLMClient(model=model)

    runner = ToolRunner()

    system_prompt = f"""
You are Suvari, an autonomous Penetration Testing Agent. 
The user is your Commander. You do NOT just give advice; you EXECUTE commands.
Available Tools (via Python subprocess):
- nmap, masscan (Recon)
- nuclei, httpx (Web Scanning)
- sqlmap, hydra (Exploitation/Bruteforce)
- gobuster, dirb (Directory Fuzzing)
- searchsploit, msfvenom (Exploit Dev)
- jq, grep, curl (Data Processing)
Rules:
1. When the user gives an order (e.g., "Scan the target"), you MUST generate the exact CLI command to run.
2. Return your response in this JSON format ONLY:
   { 
     "thought": "Brief analysis of user request",
     "action": "execute_tool", 
     "command": "the exact shell command to run (e.g., 'nmap -sV {target}')",
     "reason": "Why this tool/command was chosen"
   } 
   If no tool is needed (e.g., user asks "who are you"), set action to "reply" and put text in "response".
3. After execution, you will receive the tool output. Summarize findings clearly.
4. Be concise, professional, and focused on security findings.
5. Target: {target}
Context:
You have full access to the system's security tools. Execute safely but effectively.
"""



    console.print(Panel.fit(f"[bold green]🤖 Suvari Agent Mode Initialized[/bold green]\nTarget: [cyan]{target}[/cyan]\nModel: {model or 'default'}\n\nType commands like 'Scan ports', 'Check for SQLi', 'Fuzz directories'.\nType 'exit' to quit.", border_style="green"))



    conversation_history = [

        {"role": "system", "content": system_prompt},

        {"role": "user", "content": f"Target acquired: {target}. Waiting for orders."}

    ]



    while True:

        try:

                               

            user_input = Prompt.ask("\n[bold blue]Commander[/bold blue]")

            

            if user_input.lower() in ["exit", "quit", "q"]:

                console.print("[yellow]Agent session terminated.[/yellow]")

                break

            

            if not user_input.strip():

                continue



                                       

            conversation_history.append({"role": "user", "content": user_input})



                                    

            with console.status("[bold green]AI is planning execution...", spinner="dots"):

                response_text = llm.chat(

                    messages=conversation_history,

                    temperature=0.2,                                                

                    max_tokens=1000

                )



                                                   

            try:

                                                                

                clean_json = response_text.replace("```json", "").replace("```", "").strip()

                ai_decision = json.loads(clean_json)

            except json.JSONDecodeError:

                                                             

                console.print(f"[red]Error parsing AI plan. Raw output:[/red] {response_text}")

                conversation_history.append({"role": "assistant", "content": response_text})

                continue



            action = ai_decision.get("action", "reply")

            

            if action == "reply":

                                   

                console.print(Panel(Markdown(ai_decision.get("response", "")), title="AI Response", border_style="blue"))

                conversation_history.append({"role": "assistant", "content": response_text})

                continue



            elif action == "execute_tool":

                command = ai_decision.get("command", "")

                reason = ai_decision.get("reason", "")

                thought = ai_decision.get("thought", "")



                console.print(f"\n[bold yellow]🧠 AI Thought:[/bold yellow] {thought}")

                console.print(f"[bold yellow]🎯 Reason:[/bold yellow] {reason}")

                console.print(f"[bold red]⚡ Executing:[/bold red] {command}\n")



                                     

                try:

                                                    

                                                                                                        

                                                                                                         

                                                                

                    

                    result = runner.run_custom_command(command, timeout=120)

                    

                    output_summary = result.get("stdout", "") + result.get("stderr", "")

                    exit_code = result.get("returncode", 1)

                    

                    if exit_code != 0:

                        console.print(f"[red]Command failed with exit code {exit_code}[/red]")

                    

                                                                     

                    if len(output_summary) > 4000:

                        output_summary = output_summary[:4000] + "\n... [Output truncated]"



                                               

                    analysis_prompt = f"The command `{command}` finished (Exit Code: {exit_code}).\nOutput:\n{output_summary}\n\nSummarize the security findings. What should we do next?"

                    

                    conversation_history.append({

                        "role": "assistant", 

                        "content": f"Executed: {command}\nOutput received."

                    })

                    conversation_history.append({

                        "role": "user",

                        "content": analysis_prompt

                    })



                    with console.status("[bold green]AI is analyzing results...", spinner="dots"):

                        analysis_response = llm.chat(

                            messages=conversation_history,

                            temperature=0.3,

                            max_tokens=1500

                        )

                    

                    console.print(Panel(Markdown(analysis_response), title="🔍 Analysis Report", border_style="green"))

                    

                                                  

                    conversation_history.append({"role": "assistant", "content": analysis_response})



                except Exception as e:

                    error_msg = f"Execution error: {str(e)}"

                    console.print(f"[red]{error_msg}[/red]")

                    conversation_history.append({"role": "user", "content": f"Error executing command: {error_msg}"})



            else:

                console.print(f"[yellow]Unknown action type: {action}[/yellow]")



        except KeyboardInterrupt:

            console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/yellow]")

        except Exception as e:

            console.print(f"[red]Critical Error: {e}[/red]")

