# Providers

Suvari supports multiple LLM providers. Configure via `python suvari.py configure` or edit `~/.config/suvari/config.json`.

## Supported

| Provider | Models | API Key Env Var |
|----------|--------|-----------------|
| deepseek | deepseek-chat, deepseek-reasoner | DEEPSEEK_API_KEY |
| anthropic | claude-sonnet-4, claude-3-5-sonnet | ANTHROPIC_API_KEY |
| gemini | gemini-2.0-flash, gemini-2.0-pro | GEMINI_API_KEY |
| openrouter | any (deepseek/deepseek-chat, etc.) | OPENROUTER_API_KEY |
| ollama | local models (llama3, mistral, etc.) | (none, uses localhost) |

## Custom Provider

Add to `~/.config/suvari/config.json`:
```json
{
  "custom_providers": {
    "myprovider": {
      "base_url": "https://api.myprovider.com/v1",
      "models": ["model-name"],
      "env_key": "MY_API_KEY"
    }
  }
}
```

Then use: `--provider myprovider --model model-name`
