"""Deep Eye interactive config setup wizard."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt

console = Console()

PROVIDERS = {
    "1": {
        "key": "openai",
        "name": "OpenAI (GPT-4o / GPT-4.1 / o-series)",
        "needs_key": True,
        "default_model": "gpt-4o",
    },
    "2": {
        "key": "claude",
        "name": "Claude (Anthropic Sonnet 4)",
        "needs_key": True,
        "default_model": "claude-sonnet-4-20250514",
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
        "base_url": "https://api.x.ai/v1",
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
        "base_url": "https://openrouter.ai/api/v1",
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
        "base_url": "https://api.groq.com/openai/v1",
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
    "12": {
        "key": "orcarouter",
        "name": "OrcaRouter",
        "needs_key": True,
        "default_model": "openai/gpt-4o",
        "base_url": "https://api.orcarouter.ai/v1",
    },
    "13": {
        "key": "nvidia_nim",
        "name": "NVIDIA NIM",
        "needs_key": True,
        "default_model": "nvidia/nemotron-3-ultra-550b-a55b",
        "base_url": "https://integrate.api.nvidia.com/v1",
    },
    "14": {
        "key": "cheaperinference",
        "name": "Cheaper Inference",
        "needs_key": True,
        "default_model": "gpt-5.4-mini",
        "base_url": "https://api.cheaperinference.com/v1",
    },
}

CORE_CHECKS = [
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
    "ldap_injection",
]

STANDARD_EXTRA = [
    "api_security",
    "cors_csp",
    "jwt_deep",
    "graphql_deep",
    "idor",
    "ssrf_cloud",
    "waf_fingerprint",
    "secret_scanning",
    "open_redirect_deep",
    "hpp_pollution",
    "http_method_override",
    "host_header_deep",
    "crlf_header_inject_deep",
    "ssti_engines",
    "stored_xss",
    "email_injection",
]

FULL_EXTRA = STANDARD_EXTRA + [
    "api_bola_deep",
    "websocket_deep",
    "sse_injection",
    "cloud_misconfig",
    "php_webshell",
    "nosql_injection",
    "http_smuggling",
    "race_condition",
    "log4shell",
    "oauth_testing",
    "mass_assignment",
    "prototype_pollution",
    "directory_bruteforce",
    "port_scanner",
    "saml_attacks",
    "subdomain_takeover",
    "cache_poisoning",
    "cache_deception",
    "h2_smuggle",
    "supply_chain_js",
    "authentication",
    "business_logic",
    "file_upload",
    "websocket",
]


def run_onboard(config_path: str, force: bool = False) -> dict:
    """Interactive setup. Writes config_path and returns config dict."""
    path = Path(config_path)
    if path.exists() and not force:
        if not Confirm.ask(
            f"[yellow]{config_path} already exists. Overwrite?[/yellow]",
            default=False,
        ):
            console.print("[dim]Keeping existing config.[/dim]")
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}

    console.print(
        Panel(
            "[bold cyan]Deep Eye Setup Wizard[/bold cyan]\n\n"
            "Answer a few questions to create config.yaml.\n"
            "Full knobs stay in config/config.example.yaml.",
            border_style="cyan",
        )
    )

    ai_providers, primary = _wizard_providers()
    scanner = _wizard_scanner(primary)
    checks = _wizard_checks()
    report_format = _wizard_report()
    experimental = _wizard_experimental()
    mobile = _wizard_mobile()
    oast_url = scanner.get("oast_callback_url") or ""

    config: Dict[str, Any] = {
        "ai_providers": ai_providers,
        "scanner": scanner,
        "vulnerability_scanner": {
            "enabled_checks": checks,
            "payload_generation": {
                "use_ai": True,
                "context_aware": True,
                "cve_database": bool(experimental.get("enable_cve_matching")),
                "use_payload_obfuscation": False,
            },
            "testing": {
                "thorough_mode": scanner.get("full_scan", False),
                "time_based_detection_delay": 5,
                "blind_injection_attempts": 3,
            },
        },
        "reporting": {
            "enabled": True,
            "output_directory": "reports",
            "default_format": report_format,
            "formats": [report_format],
            "dedupe": True,
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
        "scope": {"enabled": False},
        "oast": {
            "enabled": bool(oast_url),
            "host": "0.0.0.0",
            "port": 9999,
            "callback_url": oast_url,
        },
        "experimental": experimental,
        "mobile": mobile,
        "secrets_scanner": {"enabled": True},
        "plugin_manager": {"enabled": False},
        "notifications": {"enabled": False},
    }

    if scanner.get("enable_recon"):
        config["reconnaissance"] = {
            "enabled_modules": [
                "subdomain_enumeration",
                "dns_records",
                "whois_lookup",
                "technology_detection",
                "ssl_certificate_info",
                "osint_gathering",
            ]
        }
        config["osint"] = {
            "enabled": True,
            "google_dorking": True,
            "email_harvesting": True,
            "metadata_extraction": True,
            "github_search": True,
            "certificate_transparency": True,
            "hibp_api_key": "",
        }

    write_config(config_path, config)
    _print_summary(config_path, config)
    return config


def write_config(config_path: str, config: Dict[str, Any]) -> None:
    output_path = Path(config_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Deep Eye Configuration\n")
        f.write("# Generated by setup wizard (python deep_eye.py --setup)\n")
        f.write("# Full reference: config/config.example.yaml\n\n")
        yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def _wizard_providers() -> tuple:
    console.print("\n[bold]1) AI provider[/bold]\n")
    for num, info in PROVIDERS.items():
        console.print(f"  [{num}] {info['name']}")

    choice = Prompt.ask(
        "\nPrimary provider number",
        choices=list(PROVIDERS.keys()),
        default="1",
    )
    primary_info = PROVIDERS[choice]
    primary_key = primary_info["key"]

    ai_providers: Dict[str, Any] = {}
    for num, info in PROVIDERS.items():
        ai_providers[info["key"]] = {
            "enabled": False,
            "model": info["default_model"],
            "temperature": 0.7,
            "max_tokens": 2000,
            "timeout": 60 if info["key"] in ("ollama", "lmstudio", "litellm") else 30,
        }
        if info.get("base_url"):
            ai_providers[info["key"]]["base_url"] = info["base_url"]
        if info["needs_key"]:
            ai_providers[info["key"]]["api_key"] = f"your-{info['key']}-api-key-here"

    primary_cfg = _configure_one_provider(primary_info)
    primary_cfg["enabled"] = True
    ai_providers[primary_key] = primary_cfg

    if Confirm.ask("Configure additional AI providers (failover)?", default=False):
        for num, info in PROVIDERS.items():
            if info["key"] == primary_key:
                continue
            if Confirm.ask(f"  Enable {info['name']}?", default=False):
                cfg = _configure_one_provider(info)
                cfg["enabled"] = True
                ai_providers[info["key"]] = cfg

    return ai_providers, primary_key


def _configure_one_provider(provider: Dict[str, Any]) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "enabled": False,
        "model": provider["default_model"],
        "temperature": 0.7,
        "max_tokens": 2000,
        "timeout": 30,
    }
    base_url = provider.get("base_url", "")
    if provider["needs_key"]:
        api_key = Prompt.ask(
            f"{provider['name']} API key (blank = placeholder)",
            password=True,
            default="",
        )
        if not (api_key or "").strip():
            console.print(
                f"[yellow]Placeholder key for {provider['key']} — edit config later[/yellow]"
            )
            api_key = f"your-{provider['key']}-api-key-here"
        cfg["api_key"] = api_key.strip()
    if "base_url" in provider:
        base_url = Prompt.ask(
            f"{provider['name']} base URL",
            default=provider.get("base_url") or "",
        )
    if base_url:
        cfg["base_url"] = base_url
    cfg["model"] = Prompt.ask("Model", default=provider["default_model"])
    return cfg


def _wizard_scanner(primary_provider: str) -> Dict[str, Any]:
    console.print("\n[bold]2) Scanner[/bold]\n")
    target = Prompt.ask("Default target URL (blank ok)", default="").strip()
    threads = max(1, min(50, IntPrompt.ask("Threads (1-50)", default=5)))
    depth = max(1, min(10, IntPrompt.ask("Crawl depth (1-10)", default=2)))
    max_urls = max(10, min(10000, IntPrompt.ask("Max URLs", default=200)))

    console.print("\nScan mode:")
    console.print("  [1] Quick  — core checks, shallow crawl")
    console.print("  [2] Standard — recon + common modules")
    console.print("  [3] Full — broad enabled_checks")
    mode = Prompt.ask("Mode", choices=["1", "2", "3"], default="2")
    full_scan = mode == "3"
    quick_scan = mode == "1"
    enable_recon = mode != "1" and Confirm.ask("Enable reconnaissance?", default=True)

    oast = Prompt.ask(
        "OAST callback URL (Burp Collaborator / interact.sh, blank = off)",
        default="",
    ).strip()

    proxy = Prompt.ask("HTTP proxy (e.g. http://127.0.0.1:8080, blank = none)", default="").strip()
    verify_ssl = Confirm.ask("Verify SSL certificates?", default=True)

    return {
        "target_url": target,
        "default_threads": threads,
        "default_depth": depth,
        "max_urls": max_urls,
        "timeout": 10,
        "scan_url_timeout": 60,
        "user_agent": "Deep-Eye/1.4 (Security Scanner)",
        "follow_redirects": True,
        "verify_ssl": verify_ssl,
        "max_retries": 3,
        "enable_recon": enable_recon,
        "full_scan": full_scan,
        "quick_scan": quick_scan,
        "ai_provider": primary_provider,
        "oast_callback_url": oast,
        "proxy": proxy,
        "custom_headers": {},
        "cookies": {},
    }


def _wizard_checks() -> List[str]:
    console.print("\n[bold]3) Vulnerability checks preset[/bold]")
    console.print("  [1] Core only")
    console.print("  [2] Standard (recommended)")
    console.print("  [3] Full module set")
    preset = Prompt.ask("Preset", choices=["1", "2", "3"], default="2")
    if preset == "1":
        return list(CORE_CHECKS)
    if preset == "2":
        return list(dict.fromkeys(CORE_CHECKS + STANDARD_EXTRA))
    return list(dict.fromkeys(CORE_CHECKS + FULL_EXTRA))


def _wizard_report() -> str:
    console.print("\n[bold]4) Report format[/bold]")
    console.print("  [1] HTML  [2] PDF  [3] JSON  [4] HTML+JSON")
    fmt = Prompt.ask("Format", choices=["1", "2", "3", "4"], default="1")
    return {"1": "html", "2": "pdf", "3": "json", "4": "html"}[fmt]


def _wizard_experimental() -> Dict[str, Any]:
    console.print("\n[bold]5) Optional intelligence[/bold]")
    cve = Confirm.ask("Enable CVE matching / enrichment?", default=False)
    return {
        "enable_subdomain_scanning": False,
        "aggressive_subdomain_enum": True,
        "max_subdomains_to_scan": 50,
        "enable_cve_matching": cve,
        "cve_database_path": "data/cve_intelligence.db",
        "auto_update_cve_db": False,
        "cve_lookback_days": 365,
    }


def _wizard_mobile() -> Dict[str, Any]:
    console.print("\n[bold]6) Mobile / Frida (optional)[/bold]")
    enabled = Confirm.ask("Enable mobile analysis section?", default=False)
    if not enabled:
        return {
            "enabled": False,
            "platform": "android",
            "package": "",
            "artifact": "",
            "use_ai": True,
            "script_output_dir": "reports/frida_scripts",
            "try_attach": False,
            "spawn": False,
            "device": "",
        }
    platform = Prompt.ask("Platform", choices=["android", "ios"], default="android")
    package = Prompt.ask("Package / bundle id", default="").strip()
    artifact = Prompt.ask("APK / IPA / Info.plist path", default="").strip()
    return {
        "enabled": True,
        "platform": platform,
        "package": package,
        "artifact": artifact,
        "use_ai": True,
        "script_output_dir": "reports/frida_scripts",
        "try_attach": False,
        "spawn": False,
        "device": "",
    }


def _print_summary(config_path: str, config: Dict[str, Any]) -> None:
    sc = config.get("scanner") or {}
    checks = (config.get("vulnerability_scanner") or {}).get("enabled_checks") or []
    console.print(f"\n[bold green]Config saved:[/bold green] {config_path}")
    console.print(f"  AI primary : {sc.get('ai_provider')}")
    console.print(f"  Target     : {sc.get('target_url') or '(set later with -u)'}")
    console.print(f"  Threads    : {sc.get('default_threads')}  depth={sc.get('default_depth')}")
    console.print(f"  Checks     : {len(checks)}")
    console.print(f"  Report     : {(config.get('reporting') or {}).get('default_format')}")
    console.print(f"  CVE match  : {(config.get('experimental') or {}).get('enable_cve_matching')}")
    console.print(f"  Mobile     : {(config.get('mobile') or {}).get('enabled')}")
    console.print("\n[dim]Edit file anytime. Reference: config/config.example.yaml[/dim]")
    console.print("[dim]Re-run wizard: python deep_eye.py --setup[/dim]\n")


# Non-interactive builder for tests / CI
def build_config(
    provider_key: str = "openai",
    api_key: str = "test-key",
    model: Optional[str] = None,
    target_url: str = "",
    threads: int = 5,
    depth: int = 2,
    preset: str = "standard",
    report_format: str = "html",
    enable_recon: bool = True,
    enable_cve: bool = False,
    oast_callback_url: str = "",
) -> Dict[str, Any]:
    """Build config dict without prompts (tests / automation)."""
    info = next((p for p in PROVIDERS.values() if p["key"] == provider_key), PROVIDERS["1"])
    model = model or info["default_model"]
    pcfg: Dict[str, Any] = {
        "enabled": True,
        "model": model,
        "temperature": 0.7,
        "max_tokens": 2000,
        "timeout": 30,
    }
    if info["needs_key"]:
        pcfg["api_key"] = api_key
    if info.get("base_url"):
        pcfg["base_url"] = info["base_url"]

    if preset == "core":
        checks = list(CORE_CHECKS)
    elif preset == "full":
        checks = list(dict.fromkeys(CORE_CHECKS + FULL_EXTRA))
    else:
        checks = list(dict.fromkeys(CORE_CHECKS + STANDARD_EXTRA))

    return {
        "ai_providers": {provider_key: pcfg},
        "scanner": {
            "target_url": target_url,
            "default_threads": threads,
            "default_depth": depth,
            "max_urls": 200,
            "timeout": 10,
            "scan_url_timeout": 60,
            "user_agent": "Deep-Eye/1.4 (Security Scanner)",
            "follow_redirects": True,
            "verify_ssl": True,
            "max_retries": 3,
            "enable_recon": enable_recon,
            "full_scan": preset == "full",
            "quick_scan": preset == "core",
            "ai_provider": provider_key,
            "oast_callback_url": oast_callback_url,
            "proxy": "",
            "custom_headers": {},
            "cookies": {},
        },
        "vulnerability_scanner": {
            "enabled_checks": checks,
            "payload_generation": {
                "use_ai": True,
                "context_aware": True,
                "cve_database": enable_cve,
            },
        },
        "reporting": {
            "enabled": True,
            "output_directory": "reports",
            "default_format": report_format,
            "dedupe": True,
        },
        "logging": {"level": "INFO", "log_to_file": True, "log_file": "logs/deep_eye.log"},
        "experimental": {
            "enable_cve_matching": enable_cve,
            "cve_database_path": "data/cve_intelligence.db",
        },
        "mobile": {"enabled": False, "platform": "android", "package": "", "artifact": ""},
        "oast": {"enabled": bool(oast_callback_url), "callback_url": oast_callback_url},
    }
