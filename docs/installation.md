# Installation

## Requirements

- Python 3.10+
- Kali Linux (or any Linux with security tools)
- Internet access for LLM API calls
- No Docker required (optional for vulnerable test targets)

## Setup

```bash
git clone https://github.com/haydarkadioglu/suvari.git
cd suvari
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install --with-deps
# Or for specific browsers:
python -m playwright install chromium firefox webkit
python suvari.py configure
```

The `configure` command will prompt for:
1. **Provider** — OpenAI, Anthropic, DeepSeek, Gemini, OpenRouter, or Ollama
2. **Model** — specific model name (e.g. gpt-4o, deepseek-chat, claude-sonnet-4)
3. **API key** — will be saved to `~/.config/suvari/.env`

## Provider Setup

| Provider | Env Variable | Default Model |
|----------|-------------|---------------|
| OpenAI | `OPENAI_API_KEY` | gpt-4o |
| Anthropic | `ANTHROPIC_API_KEY` | claude-sonnet-4 |
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat |
| Google Gemini | `GEMINI_API_KEY` | gemini-2.5-flash |
| OpenRouter | `OPENROUTER_API_KEY` | openai/gpt-4o |
| Ollama (local) | *(none)* | llama3 |

You can also set API keys manually:

```bash
export DEEPSEEK_API_KEY=sk-...
python suvari.py scan https://example.com
```

## Verify Installation

```bash
source .venv/bin/activate
python suvari.py --help
python suvari.py recon https://example.com
```
