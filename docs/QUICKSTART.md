# Deep Eye Quick Start Guide

## Installation

1. **Install Python Dependencies:**
```powershell
pip install -r requirements.txt
```

2. **Install Browser Automation (Optional - for Advanced Testing):**
```powershell
# Install Playwright for browser-based testing
playwright install chromium

# Install Browser Use for AI-powered browser automation (recommended)
# Browser Use: https://browser-use.com (71.8k+ GitHub stars)
pip install browser-use langchain-openai
```

3. **Configure AI Providers:**
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

#### Google Gemini
1. Get API key from https://makersuite.google.com/app/apikey
2. Add to config.yaml:
```yaml
ai_providers:
  gemini:
    enabled: true
    api_key: "your-gemini-api-key-here"
    model: "gemini-1.5-flash"  # or gemini-1.5-pro
```

**Gemini Models:**
- `gemini-1.5-flash` - Fast and cost-effective (recommended)
- `gemini-1.5-pro` - Most capable, better reasoning
- `gemini-pro` - Balanced performance

## Advanced Features

### Browser-Based Testing with AI
Enable AI-powered browser automation using **Browser Use** ([browser-use.com](https://browser-use.com)) for intelligent client-side testing:

```yaml
# config/config.yaml
advanced:
  enable_javascript_rendering: true  # Enable AI browser automation
  screenshot_enabled: true           # Capture screenshots as base64
```

**Browser Use Features**:
- ✅ **AI-Powered Testing**: Uses GPT-4 to intelligently interact with web pages
- ✅ **Smart Detection**: AI understands context and finds vulnerabilities automatically
- ✅ **Form Interaction**: Automatically fills forms and triggers actions
- ✅ **Error Recognition**: AI can read and understand SQL/JavaScript errors
- ✅ **Adaptive**: Handles dynamic content and complex web applications
- ✅ **Hidden Element Discovery**: AI finds and tests hidden inputs, forms, and elements
- ✅ **Fallback**: Automatically falls back to Playwright if Browser Use unavailable

This enables:
- **AI-Driven XSS Testing**: AI navigates pages and tests for XSS intelligently
- **SQL Error Detection**: AI reads page content and identifies database errors
- **Hidden Element Testing**: Discover and evaluate hidden fields, forms, and sensitive data
- **Real Browser Testing**: Execute JavaScript and test DOM-based vulnerabilities
- **Screenshot Evidence**: Automatically capture proof-of-concept screenshots
- **DOM XSS Detection**: Test for DOM-based XSS vulnerabilities
- **Clickjacking Tests**: Verify X-Frame-Options protection

### Enhanced HTML Reports
HTML reports now include:
- **Interactive Charts**: Severity distribution and vulnerability type charts (Chart.js)
- **DataTables**: Sortable, searchable vulnerability tables
- **Filtering**: Filter by severity and vulnerability type
- **Expandable Details**: View full vulnerability details inline
- **Screenshot Evidence**: View captured screenshots directly in report

### Real-Time State Tracking
Monitor pentest progress in real-time with:
- Current phase tracking (Recon, Crawling, Scanning, etc.)
- Live vulnerability counts by severity
- Attack statistics and success rates
- URLs discovered and tested
- Time elapsed per phase

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | Target URL | `-u https://example.com` |
| `-c, --config` | Config file path | `-c myconfig.yaml` |
| `-v, --verbose` | Verbose output | `-v` |
| `--no-banner` | Disable banner | `--no-banner` |

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

### 5. Browser-Based Advanced Testing
```powershell
# Enable browser automation in config.yaml first
# Then run:
python deep_eye.py -u https://testsite.com -v
```

### 6. Generate HTML Report with Charts
```powershell
# Reports are automatically generated based on config.yaml
# Output will include:
# - Interactive charts
# - Sortable data tables
# - Screenshot evidence
# - Filtering capabilities
python deep_eye.py -u https://testsite.com
```

### 7. Test Hidden Elements with AI
```powershell
# Browser Use AI will automatically:
# - Discover hidden input fields
# - Find display:none elements
# - Detect sensitive data in hidden fields
# - Test for hidden element manipulation
# - Capture evidence screenshots
python deep_eye.py -u https://testsite.com -v
```

### 8. Update CVE Intelligence Database (Experimental)
```powershell
# Scrape latest CVEs from NVD and build intelligence database
python scripts/update_cve_database.py

# This will:
# - Download CVEs from National Vulnerability Database (NVD)
# - Store in SQLite database (data/cve_intelligence.db)
# - Generate exploit patterns
# - Enable CVE-based payload generation
```

### 9. Subdomain Discovery & Scanning (Experimental)
```powershell
# Enable in config.yaml first
# Then Deep Eye will automatically:
# - Discover subdomains via Certificate Transparency
# - DNS bruteforce with common names
# - Verify subdomain liveness
# - Scan each subdomain for vulnerabilities
# - Aggregate results in main report
python deep_eye.py -u https://example.com -v
```

## Configuration Examples

### Enable All Advanced Features
```yaml
# config/config.yaml
scanner:
  enable_recon: true
  full_scan: true
  default_threads: 10
  default_depth: 5

advanced:
  enable_javascript_rendering: true
  screenshot_enabled: true

reporting:
  default_format: "html"
```

### Context-Aware Payload Generation with CVE Matching
```yaml
vulnerability_scanner:
  payload_generation:
    use_ai: true
    context_aware: true  # Detect tech stack and WAF
    cve_database: true   # Match with CVE database

experimental:
  enable_cve_matching: true  # Enable CVE-based payload generation
```

### Experimental: Subdomain Scanning
```yaml
experimental:
  enable_subdomain_scanning: true   # Discover and scan all subdomains
  aggressive_subdomain_enum: true   # Use aggressive enumeration
  max_subdomains_to_scan: 50        # Limit subdomains to scan
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

### Browser Automation Errors
If browser tests fail:
```powershell
# Reinstall Browser Use and Playwright
pip install browser-use langchain-openai --upgrade
playwright install chromium --force

# Verify OpenAI API key is configured in config.yaml
# Browser Use requires OpenAI for AI-powered testing

# Or disable browser testing
# Edit config.yaml:
advanced:
  enable_javascript_rendering: false
```

**Note**: Browser Use requires OpenAI API key. If not configured, it will automatically fallback to standard Playwright browser automation.

### Report Generation Issues
- Ensure output directory exists (default: `reports/`)
- Check file permissions
- For HTML reports, ensure internet connection (loads CDN resources)

## Experimental Features

### CVE Intelligence System

Deep Eye includes a CVE intelligence system that matches detected technologies with real-world CVE exploits:

**Step 1: Build CVE Database**
```powershell
# Run the CVE database updater
python scripts/update_cve_database.py

# This creates data/cve_intelligence.db with:
# - 8 common web vulnerability CVE patterns
# - 36 exploit payloads
# - 21 technology mappings
# - Severity classifications (CRITICAL, HIGH, MEDIUM)
```

**Step 2: Enable CVE Matching**
```yaml
# config/config.yaml
experimental:
  enable_cve_matching: true
  cve_database_path: "data/cve_intelligence.db"

vulnerability_scanner:
  payload_generation:
    cve_database: true  # Use CVE-based payloads
```

**How It Works:**
1. Deep Eye detects technologies (PHP, MySQL, WordPress, etc.)
2. CVE Matcher queries database for relevant CVEs
3. Extracts exploit payloads from matched CVEs
4. Prioritizes CVE-based payloads (real-world exploits first)
5. Falls back to generic payloads if no CVE match

### Subdomain Discovery & Scanning

Automatically discover and scan all subdomains of target domain:

**Enable Subdomain Scanning:**
```yaml
# config/config.yaml
experimental:
  enable_subdomain_scanning: true    # Enable subdomain discovery
  aggressive_subdomain_enum: true    # Use aggressive enumeration
  max_subdomains_to_scan: 50         # Limit concurrent scans
```

**Discovery Methods:**
- ✅ **Certificate Transparency** - Query crt.sh for SSL certificates
- ✅ **DNS Bruteforce** - Test 100+ common subdomain patterns
- ✅ **Liveness Verification** - Verify HTTP/HTTPS accessibility
- ✅ **Parallel Scanning** - Scan multiple subdomains concurrently
- ✅ **Aggregate Reporting** - Combine all results in main report

**Example Output:**
```
🔍 Discovering subdomains for: example.com
  ✓ Found: www.example.com
  ✓ Found: api.example.com
  ✓ Found: admin.example.com
  ✓ Found: dev.example.com

🎯 Scanning 4 subdomains...
  ✓ www.example.com: 5 vulnerabilities
  ✓ api.example.com: 12 vulnerabilities
  ✓ admin.example.com: 8 vulnerabilities
  ✓ dev.example.com: 3 vulnerabilities

Total: 28 vulnerabilities across all subdomains
```

## Performance Tips

1. **Adjust Thread Count**: Balance speed vs. server load
   ```yaml
   scanner:
     default_threads: 10  # Increase for faster scans
   ```

2. **Use Caching**: Payload cache speeds up repeated scans

3. **Limit Depth**: Reduce crawl depth for faster scans
   ```yaml
   scanner:
     default_depth: 3  # Decrease for speed
   ```

4. **Quick Scan Mode**: Test main URL only
   ```yaml
   scanner:
     quick_scan: true
   ```

5. **Limit Subdomain Scans**: Control subdomain scanning scope
   ```yaml
   experimental:
     max_subdomains_to_scan: 20  # Scan only top 20 subdomains
   ```

## Legal Notice

⚠️ **IMPORTANT**: Only use Deep Eye on systems you own or have explicit permission to test. Unauthorized security testing is illegal.

## Support

For issues and questions:
- GitHub Issues: https://github.com/zakirkun/deep-eye/issues
- Documentation: See README.md
