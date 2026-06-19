"""
Config — Suvari configuration management.
Provider, model and API keys are configured interactively and saved to
~/.config/suvari/config.json + .env
"""

import os
import json
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".config" / "suvari"
CONFIG_FILE = CONFIG_DIR / "config.json"
ENV_FILE = CONFIG_DIR / ".env"

PROVIDERS = {
    "anthropic": {
        "name": "Anthropic (Claude)",
        "models": ["claude-sonnet-4-20250514", "claude-sonnet-4", "claude-3-5-sonnet-latest"],
        "env_key": "ANTHROPIC_API_KEY",
        "default_model": "claude-sonnet-4-20250514",
    },
    "deepseek": {
        "name": "DeepSeek",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "env_key": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
    },
    "gemini": {
        "name": "Google Gemini",
        "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
        "env_key": "GEMINI_API_KEY",
        "default_model": "gemini-2.5-flash",
    },
    "openrouter": {
        "name": "OpenRouter",
        "models": [
            "anthropic/claude-sonnet-4", "deepseek/deepseek-chat",
            "google/gemini-2.5-flash", "qwen/qwen-2.5-72b",
        ],
        "env_key": "OPENROUTER_API_KEY",
        "default_model": "deepseek/deepseek-chat",
    },
    "ollama": {
        "name": "Ollama (local)",
        "models": ["llama3", "qwen2.5", "mistral", "deepseek-r1"],
        "env_key": None,
        "default_model": "llama3",
    },
}


def load_config() -> dict:
    """Load current config."""
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(config: dict):
    """Save config to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def save_env(key: str, value: str):
    """Save an API key to the .env file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    env_vars = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip()
    env_vars[key] = value
    lines = [f"{k}={v}" for k, v in env_vars.items()]
    ENV_FILE.write_text("\n".join(lines) + "\n")
    os.environ[key] = value
    print(f"  [OK] {key} saved to {ENV_FILE}")


def get_env(key: str) -> Optional[str]:
    """Get an API key: first from .env, then from environment."""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k.strip() == key:
                    return v.strip()
    return os.environ.get(key)


def configure_interactive():
    """Interactive configuration wizard."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table

    console = Console()

    console.print(Panel.fit(
        "[bold yellow][SUVARI] Suvari Configuration[/bold yellow]\n"
        "Let's set up your provider, model, and API keys.\n"
        "[dim]Settings are saved to ~/.config/suvari/[/dim]",
        border_style="yellow",
    ))

    # ── Pick provider ──
    table = Table(show_header=False, box=None)
    table.add_column("#", style="dim", width=3)
    table.add_column("Provider", style="cyan")
    table.add_column("Models", style="white")
    table.add_column("API Key", style="yellow")

    provider_keys = list(PROVIDERS.keys())
    for i, (key, info) in enumerate(PROVIDERS.items(), 1):
        models = ", ".join(info["models"][:3])
        models += "..." if len(info["models"]) > 3 else ""
        env = info["env_key"] or "—"
        has_key = get_env(info["env_key"]) if info["env_key"] else False
        env_str = f"{env} [OK]" if has_key else (env or "—")
        table.add_row(str(i), info["name"], models, env_str)

    console.print(table)
    console.print("")

    while True:
        choice = Prompt.ask(
            "[bold]Pick a provider[/bold] (1-5)",
            choices=["1", "2", "3", "4", "5"],
        )
        provider_key = provider_keys[int(choice) - 1]
        provider_info = PROVIDERS[provider_key]
        break

    console.print(f"\n  Selected: [cyan]{provider_info['name']}[/cyan]")

    # ── Pick model ──
    models = provider_info["models"]
    if len(models) > 1:
        console.print("\n[bold]Available models:[/bold]")
        for i, m in enumerate(models, 1):
            console.print(f"  {i}. {m}")
        model_choice = Prompt.ask(
            "Pick a model",
            choices=[str(i) for i in range(1, len(models) + 1)],
            default="1",
        )
        model = models[int(model_choice) - 1]
    else:
        model = models[0]

    console.print(f"  Model: [green]{model}[/green]")

    # ── API key (if needed) ──
    env_key = provider_info["env_key"]
    if env_key:
        current_key = get_env(env_key)
        if current_key:
            masked = current_key[:8] + "***" + current_key[-4:]
            console.print(f"\n  Current {env_key}: [dim]{masked}[/dim]")
            if not Confirm.ask("Change it?", default=False):
                api_key = current_key
            else:
                api_key = Prompt.ask(
                    f"[bold]{env_key}[/bold] (input is hidden)",
                    password=True,
                )
        else:
            console.print(f"\n  [yellow][WARN] {env_key} is not set[/yellow]")
            api_key = Prompt.ask(
                f"[bold]{env_key}[/bold] (press Enter to skip)",
                password=True,
                default="",
            )

        if api_key:
            save_env(env_key, api_key)
    else:
        console.print(f"\n  [dim]Ollama doesn't need an API key — it runs locally.[/dim]")

    # ── Save config ──
    config = load_config()
    config["provider"] = provider_key
    config["model"] = model
    save_config(config)

    console.print(f"\n[bold green][OK] Configuration complete![/bold green]")
    console.print(f"  Config: {CONFIG_FILE}")
    console.print(f"  Env:    {ENV_FILE}")
    console.print(f"\n[dim]Now you can simply run:[/dim]")
    console.print(f"  [bold]python suvari.py scan https://example.com[/bold]")
