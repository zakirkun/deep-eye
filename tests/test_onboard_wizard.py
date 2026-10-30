"""Interactive / non-interactive config setup wizard tests."""
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def test_build_config_standard():
    from utils.onboard import build_config

    cfg = build_config(
        provider_key="openai",
        api_key="sk-test",
        target_url="https://example.com",
        preset="standard",
        enable_cve=True,
        oast_callback_url="https://cb.oast.example",
    )
    assert cfg["scanner"]["ai_provider"] == "openai"
    assert cfg["scanner"]["target_url"] == "https://example.com"
    assert cfg["ai_providers"]["openai"]["enabled"] is True
    assert cfg["ai_providers"]["openai"]["api_key"] == "sk-test"
    checks = cfg["vulnerability_scanner"]["enabled_checks"]
    assert "sql_injection" in checks
    assert "jwt_deep" in checks
    assert cfg["experimental"]["enable_cve_matching"] is True
    assert cfg["oast"]["callback_url"] == "https://cb.oast.example"


def test_build_config_core_vs_full():
    from utils.onboard import build_config

    core = build_config(preset="core")
    full = build_config(preset="full")
    assert len(full["vulnerability_scanner"]["enabled_checks"]) > len(
        core["vulnerability_scanner"]["enabled_checks"]
    )
    assert "api_bola_deep" in full["vulnerability_scanner"]["enabled_checks"]
    assert "api_bola_deep" not in core["vulnerability_scanner"]["enabled_checks"]


def test_write_config_roundtrip(tmp_path):
    from utils.onboard import build_config, write_config

    path = tmp_path / "config.yaml"
    cfg = build_config(provider_key="ollama", preset="standard", target_url="https://t")
    write_config(str(path), cfg)
    assert path.is_file()
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["scanner"]["ai_provider"] == "ollama"
    assert loaded["scanner"]["target_url"] == "https://t"
    assert "enabled_checks" in loaded["vulnerability_scanner"]


def test_run_onboard_force_with_mocked_prompts(tmp_path, monkeypatch):
    from utils import onboard

    path = tmp_path / "cfg.yaml"
    answers = iter(
        [
            "4",  # ollama (provider keys: 1 openai, 2 claude, 3 openai_compatible, 4 ollama)
            "http://localhost:11434",  # base url
            "llama2",  # model
            "n",  # no extra providers
            "https://target.test",  # target
            "3",  # threads
            "1",  # depth
            "50",  # max urls
            "1",  # quick mode
            "n",  # recon skipped path uses mode==1 so recon not asked... wait mode 1
            "",  # oast
            "",  # proxy
            "y",  # verify ssl
            "1",  # core checks
            "1",  # html
            "n",  # cve
            "n",  # mobile
        ]
    )

    def fake_ask(prompt, **kwargs):
        try:
            return next(answers)
        except StopIteration:
            return kwargs.get("default", "")

    def fake_confirm(prompt, default=False):
        v = fake_ask(prompt, default="y" if default else "n")
        return str(v).lower() in ("y", "yes", "true", "1")

    def fake_int(prompt, default=0):
        v = fake_ask(prompt, default=str(default))
        try:
            return int(v)
        except Exception:
            return default

    monkeypatch.setattr(onboard.Prompt, "ask", staticmethod(fake_ask))
    monkeypatch.setattr(onboard.Confirm, "ask", staticmethod(fake_confirm))
    monkeypatch.setattr(onboard.IntPrompt, "ask", staticmethod(fake_int))

    cfg = onboard.run_onboard(str(path), force=True)
    assert path.is_file()
    assert cfg["scanner"]["ai_provider"] == "ollama"
    assert cfg["scanner"]["target_url"] == "https://target.test"
    assert "sql_injection" in cfg["vulnerability_scanner"]["enabled_checks"]


def test_cli_has_setup_flag():
    from deep_eye import parse_arguments
    import sys

    old = sys.argv
    try:
        sys.argv = ["deep_eye.py", "--setup", "--no-banner"]
        args = parse_arguments()
        assert args.setup is True
    finally:
        sys.argv = old
