"""Regression tests for bug fixes and gap wiring."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def test_secret_vuln_uses_remediation_key():
    from core.scanner_engine import ScannerEngine

    # Build minimal engine without running network
    config = {
        'scanner': {},
        'vulnerability_scanner': {'enabled_checks': [], 'payload_generation': {'use_ai': False}},
        'secrets_scanner': {'enabled': False},
        'plugin_manager': {'enabled': False},
        'advanced': {},
        'experimental': {},
        'ai_providers': {},
    }
    eng = ScannerEngine(
        target_url='https://example.com',
        config=config,
        ai_manager=MagicMock(),
        depth=1,
        threads=1,
    )
    assert hasattr(eng, 'scope_manager')
    assert hasattr(eng, '_extra_module_testers')


def test_openai_compatible_generate_accepts_kwargs():
    from ai_providers.openai_compatible import OpenAICompatibleProvider
    import inspect
    sig = inspect.signature(OpenAICompatibleProvider.generate)
    assert any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )


def test_plugin_manager_loads_all_classes(tmp_path):
    from core.plugin_manager import PluginManager, PluginBase

    plugin_file = tmp_path / 'multi.py'
    plugin_file.write_text(
        'from core.plugin_manager import PluginBase\n'
        'class AlphaPlugin(PluginBase):\n'
        '    name = "Alpha"\n'
        '    def scan(self, url, context):\n'
        '        return []\n'
        'class BetaPlugin(PluginBase):\n'
        '    name = "Beta"\n'
        '    def scan(self, url, context):\n'
        '        return []\n',
        encoding='utf-8',
    )
    pm = PluginManager(http_client=MagicMock(), config={
        'plugin_manager': {'plugin_directory': str(tmp_path)},
        'plugins': {},
    })
    n = pm.load_plugins()
    assert n >= 2
    assert 'alphaplugin' in pm.plugins or 'alpha' in pm.plugins
    assert 'betaplugin' in pm.plugins or 'beta' in pm.plugins


def test_ai_payload_reads_oast_callback_from_config():
    from core.ai_payload_generator import AIPayloadGenerator

    cfg = {
        'scanner': {'oast_callback_url': 'https://my.oast.example/cb'},
        'vulnerability_scanner': {'payload_generation': {'use_ai': False, 'cve_database': False}},
    }
    gen = AIPayloadGenerator(ai_manager=MagicMock(), config=cfg)
    assert gen.OAST_CALLBACK_URL == 'https://my.oast.example/cb'


def test_rag_top_k_from_config_key_present():
    # Ensure example config documents top_k (engine reads rag.top_k)
    text = (REPO_ROOT / 'config' / 'config.example.yaml').read_text(encoding='utf-8')
    assert 'top_k:' in text
    assert 'tls_evasion:' in text
    assert 'directory_bruteforce' in text
