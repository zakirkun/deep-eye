"""Tests for intercepting proxy runner (Group H)."""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.intercepting_proxy import ProxyRunner


class TestProxyRunner:
    def test_disabled(self):
        runner = ProxyRunner({"intercepting_proxy": {"enabled": False}})
        assert not runner.is_enabled()
        assert runner.start() is False

    def test_proxy_url(self):
        runner = ProxyRunner({"intercepting_proxy": {
            "enabled": True, "bind_host": "127.0.0.1", "proxy_port": 9999
        }})
        assert runner.proxy_url() == "http://127.0.0.1:9999"

    def test_proxies_dict(self):
        runner = ProxyRunner({"intercepting_proxy": {
            "enabled": True, "proxy_port": 8080
        }})
        d = runner.proxies_dict()
        assert d["http"] == d["https"] == "http://127.0.0.1:8080"

    def test_build_command(self):
        runner = ProxyRunner({"intercepting_proxy": {
            "enabled": True, "bind_host": "0.0.0.0",
            "proxy_port": 8080, "mitmweb_port": 8081,
        }})
        cmd = runner.build_command()
        assert cmd[0] == "mitmweb"
        assert "--listen-host" in cmd
        assert "0.0.0.0" in cmd
        assert "8080" in cmd
        assert "8081" in cmd

    def test_handles_missing_mitmweb(self):
        runner = ProxyRunner({"intercepting_proxy": {"enabled": True}})
        with patch("modules.intercepting_proxy.proxy_runner.shutil.which", return_value=None):
            assert runner.start() is False

    def test_required_missing_raises(self):
        runner = ProxyRunner({"intercepting_proxy": {"enabled": True, "required": True}})
        with patch("modules.intercepting_proxy.proxy_runner.shutil.which", return_value=None):
            with pytest.raises(RuntimeError):
                runner.start()

    def test_starts_subprocess(self):
        runner = ProxyRunner({"intercepting_proxy": {"enabled": True}})
        fake_process = MagicMock()
        with patch("modules.intercepting_proxy.proxy_runner.shutil.which", return_value="/usr/bin/mitmweb"), \
             patch("modules.intercepting_proxy.proxy_runner.subprocess.Popen", return_value=fake_process) as popen_mock:
            assert runner.start() is True
            popen_mock.assert_called_once()
            runner.stop()
            fake_process.terminate.assert_called_once()
