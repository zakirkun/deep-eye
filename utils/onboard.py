"""
Deep Eye Onboarding Wizard
Interactive setup when config.yaml doesn't exist.
"""

import yaml
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt

console = Console()

PROVIDERS = {
    "1": {
        "key": "openai",
        "name": "OpenAI (GPT-4o)",
        "needs_key": True,
        "default_model": "gpt-4o",
    },
    "2": {
        "key": "claude",
        "name": "Claude (Anthropic)",
        "needs_key": True,
        "default_model": "claude-3-5-sonnet-20241022",
    },
    "3": {
        "key": "gemini",
        "name": "Google Gemini",
        "needs_key": True,
        "default_model": "gemini-1.5-flash",
    },
    "4": {
        "key": "grok",
        "name": "Grok (xAI)",
        "needs_key": True,
        "default_model": "grok-beta",
    },
    "5": {
        "key": "ollama",
        "name": "OLLAMA (Local)",
        "needs_key": False,
        "default_model": "llama2",
        "base_url": "http://localhost:11434",
    },
    "6": {
        "key": "openrouter",
        "name": "OpenRouter",
        "needs_key": True,
        "default_model": "openai/gpt-4o",
    },
    "7": {
        "key": "mistral",
        "name": "Mistral AI",
        "needs_key": True,
        "default_model": "mistral-large-latest",
    },
    "8": {
        "key": "groq",
        "name": "Groq",
        "needs_key": True,
        "default_model": "llama-3.1-70b-versatile",
    },
    "9": {
        "key": "litellm",
        "name": "LiteLLM (Proxy)",
        "needs_key": True,
        "default_model": "gpt-4o",
        "base_url": "http://localhost:4000",
    },
    "10": {
        "key": "lmstudio",
        "name": "LM Studio (Local)",
        "needs_key": False,
        "default_model": "local-model",
        "base_url": "http://localhost:1234/v1",
    },
    "11": {
        "key": "requesty",
        "name": "Requesty",
        "needs_key": True,
        "default_model": "openai/gpt-4o-mini",
    },
}


def run_onboard(config_path: str) -> dict:
    """
    Run interactive onboarding wizard.
    Returns the generated config dict and writes config file.
    """
    console.print(Panel(
        "[bold cyan]Welcome to Deep Eye Setup[/bold cyan]\n\n"
        "No configuration file found. Let's set one up.\n"
        "This wizard will create your config.yaml with essential settings.",
        border_style="cyan"
    ))

    # --- AI Provider ---
    console.print("\n[bold]Select your AI provider:[/bold]\n")
    for num, info in PROVIDERS.items():
        console.print(f"  [{num}] {info['name']}")

    choice = Prompt.ask(
        "\nProvider number",
        choices=list(PROVIDERS.keys()),
        default="1"
    )
    provider = PROVIDERS[choice]
    provider_key = provider["key"]

    # API key
    api_key = ""
    base_url = provider.get("base_url", "")
    if provider["needs_key"]:
        api_key = Prompt.ask(f"\n{provider['name']} API key")
        if not api_key.strip():
            console.print("[yellow]Warning: Empty API key. You can set it later in config.yaml[/yellow]")
            api_key = f"your-{provider_key}-api-key-here"
    elif "base_url" in provider:
        base_url = Prompt.ask(
            f"\n{provider['name']} base URL",
            default=provider["base_url"]
        )

    # Model
    model = Prompt.ask(
        f"\nModel name",
        default=provider["default_model"]
    )

    # --- Scanner Settings ---
    console.print("\n[bold]Scanner Settings:[/bold]\n")

    threads = IntPrompt.ask("Threads (1-50)", default=5)
    threads = max(1, min(50, threads))

    depth = IntPrompt.ask("Crawl depth (1-10)", default=2)
    depth = max(1, min(10, depth))

    full_scan = Confirm.ask("Enable full scan mode?", default=False)
    enable_recon = Confirm.ask("Enable reconnaissance?", default=True)

    # --- Report Format ---
    console.print("\n[bold]Report format:[/bold]")
    console.print("  [1] HTML (interactive, recommended)")
    console.print("  [2] PDF")
    console.print("  [3] JSON")

    fmt_choice = Prompt.ask("Format", choices=["1", "2", "3"], default="1")
    fmt_map = {"1": "html", "2": "pdf", "3": "json"}
    report_format = fmt_map[fmt_choice]

    # --- Build Config ---
    provider_config = {
        "enabled": True,
        "api_key": api_key,
        "model": model,
        "temperature": 0.7,
        "max_tokens": 2000,
        "timeout": 30,
    }
    if not provider["needs_key"]:
        del provider_config["api_key"]
    if base_url:
        provider_config["base_url"] = base_url

    config = {
        "ai_providers": {
            provider_key: provider_config
        },
        "scanner": {
            "target_url": "",
            "default_threads": threads,
            "default_depth": depth,
            "max_urls": 100,
            "timeout": 10,
            "scan_url_timeout": 30,
            "user_agent": "Deep-Eye/1.4",
            "follow_redirects": True,
            "verify_ssl": True,
            "max_retries": 3,
            "enable_recon": enable_recon,
            "full_scan": full_scan,
            "quick_scan": False,
            "ai_provider": provider_key,
        },
        "vulnerability_scanner": {
            "enabled_checks": [
                "sql_injection",
                "xss",
                "command_injection",
                "ssrf",
                "xxe",
                "path_traversal",
                "csrf",
                "open_redirect",
                "cors_misconfiguration",
                "security_misconfiguration",
                "lfi",
                "rfi",
                "ssti",
                "crlf_injection",
                "host_header_injection",
                "information_disclosure",
                "jwt_vulnerabilities",
            ],
            "payload_generation": {
                "use_ai": True,
                "context_aware": True,
                "cve_database": False,
            },
        },
        "reporting": {
            "enabled": True,
            "output_directory": "reports",
            "default_format": report_format,
        },
        "logging": {
            "level": "INFO",
            "log_to_file": True,
            "log_file": "logs/deep_eye.log",
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_second": 5,
            "burst_size": 10,
        },
        "database": {
            "enabled": True,
            "type": "sqlite",
            "path": "data/deep_eye.db",
        },
    }

    # --- Write File ---
    output_path = Path(config_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        f.write("# Deep Eye Configuration\n")
        f.write("# Generated by setup wizard\n")
        f.write("# Full reference: config/config.example.yaml\n\n")
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    console.print(f"\n[bold green]Config saved to: {config_path}[/bold green]")
    console.print("Edit this file to add more providers or tweak settings.")
    console.print("Full reference: config/config.example.yaml\n")

    return config
