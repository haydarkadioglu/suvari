"""
suvari.commands.pilot - Human-in-the-Loop Interactive AI Agent
Kullanıcı yönlendirmeli, AI destekli gerçek zamanlı penetrasyon testi kokpiti.
"""
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.markdown import Markdown
from typing import Optional, List, Dict, Any
import json
import subprocess
import shlex
import os
import sys

# Parent dizini path'e ekle (geliştirme aşamasında)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from suvari.llm import LLMClient

console = Console()

class PilotSession:
    def __init__(self, target: str, config: dict):
        self.target = target
        self.config = config
        self.llm = LLMClient(provider=config.get("provider", "deepseek"), model=config.get("model"))
        self.history = []  # Komut geçmişi
        self.findings = [] # Bulunan zafiyetler
        
        # Sistem prompt'u: Rol tanımı
        self.system_prompt = f"""
Sen 'Suvari Pilot', bir siber güvenlik uzmanı asistanısın. 
Hedef: {target}
Görevin: Kullanıcıya interaktif olarak penetration testi adımları önermek, 
komutları oluşturmak, çalıştırmak ve sonuçları analiz etmektir.

KURALLAR:
1. Asla izinsiz otomatik saldırı başlatma. Her komut için kullanıcı onayı al.
2. Önerdiğin her adım için 'thought' (analiz), 'suggestion' (öneri), 'command' (shell komutu) ve 'risk_level' alanlarını JSON olarak döndür.
3. Eğer önceki bir komutun çıktısı varsa, onu analiz ederek sonraki adımı öner.
4. Tool kullanımı: nmap, nuclei, sqlmap, gobuster, hydra, curl, jq vb. Kali araçlarını kullan.
5. Çıktı formatı SADECE geçerli bir JSON objesi olmalı. Başka açıklama yapma.
JSON Şeması:
{{
  "thought": "Kısa analiz",
  "suggestion": "Kullanıcıya gösterilecek öneri metni",
  "command": "Çalıştırılacak tam shell komutu (veya null eğer sadece sohbet ise)",
  "risk_level": "low|medium|high"
}}
"""

    def get_ai_suggestion(self, user_input: str, last_output: Optional[str] = None) -> dict:
        """AI'dan sonraki adım için öneri iste."""
        context_msg = f"Hedef: {self.target}\n"
        if last_output:
            context_msg += f"\nSon Komut Çıktısı (Özet):\n{last_output[:3000]}...\n" # Token limiti için kısalt
        
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"{context_msg}\nKullanıcı: {user_input}"}
        ]
        
        try:
            response = self.llm.chat(messages, temperature=0.2) # Düşük temp, daha deterministik
            # JSON parsing denemesi
            # Bazen AI markdown içine alır, temizleyelim
            clean_resp = response.replace("```json", "").replace("```", "").strip()
            return json.loads(clean_resp)
        except Exception as e:
            console.print(f"[red]AI Parsing Hatası: {e}[/red]")
            return {
                "thought": "AI yanıtı parse edilemedi.",
                "suggestion": "Bir hata oluştu. Lütfen manuel komut girin.",
                "command": None,
                "risk_level": "low"
            }

    def execute_command(self, cmd: str) -> str:
        """Komutu güvenli şekilde çalıştır ve çıktıyı döndür."""
        console.print(f"\n[bold yellow]⚡ Komut Çalıştırılıyor:[/bold yellow] {cmd}")
        try:
            process = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            stdout, stderr = process.communicate(timeout=120) # 2 dk timeout
            
            if process.returncode != 0:
                console.print(f"[red]Hata Kodu: {process.returncode}[/red]")
            
            output = stdout if stdout else stderr
            return output if output else "Komut başarılı ancak çıktı yok."
            
        except subprocess.TimeoutExpired:
            process.kill()
            return "HATA: Komut zaman aşımına uğradı (120s)."
        except Exception as e:
            return f"HATA: {str(e)}"

    def run(self):
        """Ana Pilot Döngüsü."""
        console.print(Panel.fit(
            f"[bold green]🛡️  SUVARİ PİLOT MODU[/bold green]\nHedef: {self.target}\nÇıkmak için 'exit', 'quit' veya Ctrl+C yazın.",
            border_style="green"
        ))
        
        last_output = None
        user_input = "Taramaya başlamak için bir strateji öner." # İlk tetikleyici

        while True:
            # 1. AI Önerisi Al
            with console.status("[bold blue]AI düşünüyor...", spinner="dots"):
                ai_response = self.get_ai_suggestion(user_input, last_output)
            
            suggestion = ai_response.get("suggestion", "")
            command = ai_response.get("command")
            thought = ai_response.get("thought", "")
            risk = ai_response.get("risk_level", "unknown")

            # 2. Öneriyi Göster
            console.print("\n" + "="*50)
            console.print(f"[bold cyan]🧠 AI Analizi:[/bold cyan] {thought}")
            console.print(f"[bold magenta]💡 Öneri:[/bold magenta] {suggestion}")
            
            if command:
                risk_color = "green" if risk == "low" else "orange3" if risk == "medium" else "red"
                console.print(f"[{risk_color}]⚠️ Risk Seviyesi: {risk.upper()}[/{risk_color}]")
                console.print(Panel(
                    Syntax(command, "bash", theme="monokai", line_numbers=True),
                    title="Önerilen Komut",
                    border_style="yellow"
                ))
                
                # 3. Kullanıcı Onayı / Düzenleme
                choice = Prompt.ask(
                    "Ne yapmak istersiniz?",
                    choices=["run", "edit", "skip", "manual", "exit"],
                    default="run"
                )
                
                if choice == "exit":
                    break
                elif choice == "skip":
                    last_output = None
                    user_input = "Başka bir önerin var mı?"
                    continue
                elif choice == "manual":
                    manual_cmd = Prompt.ask("Manuel komut girin")
                    command = manual_cmd
                elif choice == "edit":
                    console.print("[dim]Komutu düzenlemek için yapıştırın (boş bırakıp enter'a basarsanız iptal edilir):[/dim]")
                    edited_cmd = Prompt.ask("Yeni Komut", default=command)
                    if not edited_cmd:
                        user_input = "Komut iptal edildi, başka öner."
                        continue
                    command = edited_cmd

                # 4. Komutu Çalıştır
                output = self.execute_command(command)
                
                # Çıktıyı kaydet ve özetle
                self.history.append({"cmd": command, "output": output})
                
                # Büyük çıktıları panel içinde göster
                if len(output) > 2000:
                    console.print(Panel(output[:2000] + "\n... (çıktı kısaltıldı, loglarda tam hali var)", title="Komut Çıktısı (Özet)", border_style="blue"))
                else:
                    console.print(Panel(output, title="Komut Çıktısı", border_style="blue"))
                
                last_output = output
                user_input = "Bu çıktıya göre sonraki adım ne olmalı?"
                
            else:
                # Komut yoksa sadece sohbet
                console.print("[dim]AI sadece bilgi verdi, komut önermedi.[/dim]")
                user_input = Prompt.ask("Sırada ne var? (Sorunuz veya 'öneri' yazın)")

        console.print("[bold green]✅ Pilot oturumu sonlandırıldı.[/bold green]")

# CLI Komutu Tanımı
app = typer.Typer()

@app.command()
def pilot(target: str, model: Optional[str] = None):
    """
    İnsan-AI işbirliğiyle interaktif penetrasyon testi kokpiti.
    AI komut önerir, kullanıcı onaylar/düzenler ve çalıştırır.
    Chat'ten farklı olarak tam kontrol sizdedir, AI sadece asistandır.
    """
    config = {} 
    if model:
        config['model'] = model
        
    session = PilotSession(target, config)
    try:
        session.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Kullanıcı tarafından kesildi.[/yellow]")

if __name__ == "__main__":
    app()
