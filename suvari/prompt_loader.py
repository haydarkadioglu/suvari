


   

from pathlib import Path

from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined

PROMPT_DIR = Path(__file__).parent / "prompts"

class PromptLoader:

                                                                         

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

        



           

        template_path = f"{phase}/system.txt"

        try:

            template = self.env.get_template(template_path)

        except Exception as e:

            raise FileNotFoundError(

                f"Prompt not found: {template_path} ({e})"

            )

        context = {**self.globals, **kwargs}

        return template.render(**context)

    def render_with_shared(self, phase: str, **kwargs) -> str:

                                                              

        parts = []

        for shared_file in ["_rules", "_target_context"]:

            try:

                shared_template = self.env.get_template(f"shared/{shared_file}.txt")

                context = {**self.globals, **kwargs}

                parts.append(shared_template.render(**context))

            except Exception:

                pass

        parts.append(self.render(phase, **kwargs))

        return "\n\n".join(parts)
