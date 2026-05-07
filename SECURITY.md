# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Deep Eye, please report it responsibly:

1. **Do NOT open a public issue** with exploit details
2. Use [GitHub Security Advisories](https://github.com/zakirkun/deep-eye/security/advisories/new) (preferred)
3. Or email the maintainer directly

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Safe Usage Guidelines

Deep Eye is a powerful security testing tool. Follow these guidelines to protect yourself and others:

### Environment Isolation

- **Always run in an isolated environment** (VM, container, or dedicated machine)
- Never run on your primary development machine where you store credentials or sensitive projects
- Use a dedicated Python virtual environment: `python -m venv deep-eye-venv`

### API Key Management

- Create **dedicated API keys** with spending limits for use with Deep Eye
- Never reuse API keys from production systems
- Revoke keys when not actively scanning
- API keys are stored in plaintext in `config/config.yaml` -- ensure this file has restricted permissions (`chmod 600`)

### OAST Callback Configuration

- Configure `scanner.oast_callback_url` in your `config.yaml` with a server you control (e.g., Burp Collaborator, interact.sh)
- XSS and XXE payloads use this URL for out-of-band detection
- Never scan production targets with unconfigured callback URLs

### Notification Channels

- Vulnerability evidence sent to Slack/Discord webhooks is sanitized, but may still contain fragments of target responses
- Only configure webhooks for channels with appropriate access controls
- Consider disabling notifications (`notifications.enabled: false`) when scanning sensitive targets

### Plugin System

- The plugin system (`plugin_manager.enabled`) is **disabled by default** for security
- Plugins execute with full access to the host OS -- only load plugins you have reviewed
- Never point `plugin_directory` to a world-writable path
- Never download plugins from untrusted sources

### ML Model Files

- The anomaly detector can save/load `.pkl` (pickle) model files
- **Never load pickle files from untrusted sources** -- they can execute arbitrary code
- If cloning a fork, verify no `.pkl` files exist in `data/` before running
- Consider setting `ml_detection.save_model: false` unless you need model persistence

### Scan Data Hygiene

- Scan results in `data/deep_eye.db` may contain sensitive target data (credentials, tokens, error messages)
- Reduce `database.auto_cleanup_days` from the default 30 to an appropriate retention period
- Delete `data/`, `logs/`, and `reports/` after completing an engagement

## Legal Disclaimer

- Only scan systems you own or have **explicit written authorization** to test
- Unauthorized scanning may violate local laws (CFAA, Computer Misuse Act, etc.)
- Deep Eye generates aggressive payloads (SQL injection, XSS, command injection) that will appear in target access logs
- You are solely responsible for ensuring compliance with applicable laws and regulations

## Known Security Considerations

| Area | Status | Notes |
|------|--------|-------|
| Plugin sandboxing | Not implemented | Plugins run with full OS access; keep disabled unless needed |
| Dependency pinning | Partial | `requirements.txt` uses `>=` floors without upper bounds |
| SSL verification | Configurable | `verify_ssl: false` disables TLS validation globally, including for AI API calls |
| Notification sanitization | Implemented | Evidence is redacted before webhook transmission |
| Session ID validation | Implemented | Collaborative scanner validates session ID format |
| OAST callback | Configurable | Users must set their own callback server |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | Yes      |
| < 1.3   | No       |
