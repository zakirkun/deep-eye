# Deep Eye Quick Start Guide

## Installation

1. **Install Python Dependencies:**
```powershell
pip install -r requirements.txt
```

2. **Configure AI Providers:**
```powershell
# Copy example config
Copy-Item config\config.example.yaml config\config.yaml

# Edit config.yaml and add your API keys
notepad config\config.yaml
```

## Basic Usage

### Simple Scan
```powershell
python deep_eye.py -u https://example.com
```

### Full Scan with AI
```powershell
python deep_eye.py -u https://example.com --ai-provider openai --full-scan
```

### Reconnaissance Mode
```powershell
python deep_eye.py -u https://example.com --recon --output report.html
```

## Configuration

### AI Providers Setup

#### OpenAI (GPT-4)
1. Get API key from https://platform.openai.com/api-keys
2. Add to config.yaml:
```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "sk-your-key-here"
    model: "gpt-4o"
```

#### Claude (Anthropic)
1. Get API key from https://console.anthropic.com/
2. Add to config.yaml:
```yaml
ai_providers:
  claude:
    enabled: true
    api_key: "sk-ant-your-key-here"
    model: "claude-3-5-sonnet-20241022"
```

#### Grok (xAI)
1. Get API key from https://console.x.ai/
2. Add to config.yaml:
```yaml
ai_providers:
  grok:
    enabled: true
    api_key: "xai-your-key-here"
```

#### OLLAMA (Local)
1. Install OLLAMA from https://ollama.ai/
2. Pull a model: `ollama pull llama2`
3. Add to config.yaml:
```yaml
ai_providers:
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    model: "llama2"
```

#### OpenRouter
1. Get API key from https://openrouter.ai/settings/keys
2. Add to config.yaml:
```yaml
ai_providers:
  openrouter:
    enabled: true
    api_key: "sk-your-key-here"
    model: "openai/gpt-4o"
```

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | Target URL | `-u https://example.com` |
| `-d, --depth` | Crawl depth | `-d 3` |
| `-t, --threads` | Number of threads | `-t 10` |
| `--ai-provider` | AI provider | `--ai-provider openai` |
| `--recon` | Enable reconnaissance | `--recon` |
| `--full-scan` | Enable all tests | `--full-scan` |
| `--quick-scan` | Quick scan only | `--quick-scan` |
| `-o, --output` | Output file | `-o report.pdf` |
| `--format` | Report format | `--format html` |
| `--proxy` | Proxy URL | `--proxy http://127.0.0.1:8080` |

## Examples

### 1. Basic Website Scan
```powershell
python deep_eye.py -u https://testsite.com
```

### 2. Deep Scan with Custom Depth
```powershell
python deep_eye.py -u https://testsite.com -d 5 -t 15
```

### 3. Full Reconnaissance + Scan
```powershell
python deep_eye.py -u https://testsite.com --recon --full-scan --format pdf -o full_report.pdf
```

### 4. Scan Through Proxy
```powershell
python deep_eye.py -u https://testsite.com --proxy http://127.0.0.1:8080
```

### 5. Using Different AI Provider
```powershell
python deep_eye.py -u https://testsite.com --ai-provider claude --full-scan
```

## Troubleshooting

### Import Errors
Install missing dependencies:
```powershell
pip install -r requirements.txt --upgrade
```

### AI Provider Errors
- Check API keys in `config/config.yaml`
- Verify API key has sufficient credits
- Check network connectivity

### SSL Errors
Disable SSL verification (not recommended for production):
Edit config.yaml:
```yaml
scanner:
  verify_ssl: false
```

## Legal Notice

⚠️ **IMPORTANT**: Only use Deep Eye on systems you own or have explicit permission to test. Unauthorized security testing is illegal.

## Support

For issues and questions:
- GitHub Issues: https://github.com/zakirkun/deep-eye/issues
- Documentation: See README.md
