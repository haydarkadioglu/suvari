"""
Prompt Loader — loads and renders Jinja2 prompt templates from prompt files.
Inspired by Shannon's modular prompt structure and LuaN1aoAgent's Jinja2 templates.
"""

from pathlib import Path
from typing import Optional
from jinja2 import Environment, FileSystemLoader, StrictUndefined

PROMPT_DIR = Path(__file__).parent / "prompts"


class PromptLoader:
    """Loads and renders prompt templates from the prompts/ directory."""

    def __init__(self, target_url: str, fast: bool = False):
        self.env = Environment(
            loader=FileSystemLoader(str(PROMPT_DIR)),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.globals = {
            "target_url": target_url,
            "fast": fast,
        }

    def render(self, phase: str, **kwargs) -> str:
        """Render a prompt template for a given phase.

        Phase maps to prompts/{phase}/system.txt.
        Shared fragments from prompts/shared/ are included automatically.
        """
        # Load phase-specific prompt
        template_path = f"{phase}/system.txt"
        try:
            template = self.env.get_template(template_path)
        except Exception as e:
            raise FileNotFoundError(
                f"Prompt not found: {template_path} ({e})"
            )

        # Merge globals with kwargs
        context = {**self.globals, **kwargs}

        return template.render(**context)

    def render_with_shared(self, phase: str, **kwargs) -> str:
        """Render a prompt with shared fragments prepended."""
        parts = []

        # Shared fragments (if they exist)
        for shared_file in ["_rules", "_target_context"]:
            try:
                shared_template = self.env.get_template(f"shared/{shared_file}.txt")
                context = {**self.globals, **kwargs}
                parts.append(shared_template.render(**context))
            except Exception:
                pass  # shared fragment might not exist

        # Phase-specific prompt
        parts.append(self.render(phase, **kwargs))

        return "\n\n".join(parts)
