"""Tests for login macro replay (Group D)."""
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.login_replay import (
    load_macro,
    validate_macro,
    MacroError,
    LoginPlayer,
    extract_csrf_value,
)
from modules.login_replay.player import _substitute, _substitute_recursive


class MockResponse:
    def __init__(self, status_code=200, text="", content=None):
        self.status_code = status_code
        self.text = text
        self.content = content if content is not None else text.encode("utf-8")


class MockCookieJar:
    def __init__(self):
        self.store = {}

    def set(self, name, value, domain=None):
        self.store[name] = (value, domain)


class MockSession:
    def __init__(self):
        self.cookies = MockCookieJar()


class MockHttpClient:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []
        self.session = MockSession()

    def get(self, url, headers=None, **kwargs):
        self.calls.append(("get", url, headers))
        return self._next_response("get", url)

    def post(self, url, data=None, headers=None, **kwargs):
        self.calls.append(("post", url, data, headers))
        return self._next_response("post", url)

    def _next_response(self, method, url):
        return self.responses.get((method, url), MockResponse())


class TestMacro:
    def test_validate_valid(self):
        validate_macro({
            "version": 1,
            "steps": [{"action": "get", "url": "https://example.com"}]
        })

    def test_validate_not_dict(self):
        with pytest.raises(MacroError):
            validate_macro([])

    def test_validate_no_steps(self):
        with pytest.raises(MacroError):
            validate_macro({"version": 1})

    def test_validate_invalid_action(self):
        with pytest.raises(MacroError):
            validate_macro({"steps": [{"action": "bogus"}]})

    def test_load_from_file(self, tmp_path):
        macro_data = {
            "version": 1,
            "name": "test",
            "steps": [
                {"action": "get", "url": "https://example.com"},
                {"action": "post", "url": "https://example.com/login", "data": {}}
            ]
        }
        path = tmp_path / "macro.json"
        path.write_text(json.dumps(macro_data), encoding="utf-8")
        loaded = load_macro(str(path))
        assert loaded["name"] == "test"
        assert len(loaded["steps"]) == 2


class TestSubstitution:
    def test_simple_var(self):
        assert _substitute("hello ${name}", {"name": "world"}) == "hello world"

    def test_missing_var(self):
        assert _substitute("hello ${missing}", {}) == "hello "

    def test_recursive_dict(self):
        result = _substitute_recursive(
            {"url": "https://${host}/login", "data": {"token": "${csrf}"}},
            {"host": "example.com", "csrf": "abc123"},
        )
        assert result["url"] == "https://example.com/login"
        assert result["data"]["token"] == "abc123"


class TestExtractCSRF:
    def test_input_with_value(self):
        html = '<form><input name="_token" value="xyz789" type="hidden"></form>'
        assert extract_csrf_value(html, "input[name=_token]") == "xyz789"

    def test_input_value_first(self):
        html = '<form><input value="abc" name="csrf"></form>'
        assert extract_csrf_value(html, "input[name=csrf]") == "abc"

    def test_no_match(self):
        html = "<form></form>"
        assert extract_csrf_value(html, "input[name=missing]") is None

    def test_empty_html(self):
        assert extract_csrf_value("", "input[name=x]") is None


class TestPlayer:
    def test_get_post_sequence(self):
        client = MockHttpClient(
            responses={
                ("get", "https://example.com/login"): MockResponse(200, "<form><input name='_token' value='abc' type='hidden'></form>"),
                ("post", "https://example.com/login"): MockResponse(302, "redirected"),
                ("get", "https://example.com/account"): MockResponse(200, "Welcome user"),
            }
        )
        player = LoginPlayer(client)
        macro = {
            "auth_check": {"url": "https://example.com/account", "must_contain": "Welcome"},
            "steps": [
                {"action": "get", "url": "https://example.com/login"},
                {"action": "extract_csrf", "from": "input[name=_token]", "save_as": "csrf"},
                {"action": "post", "url": "https://example.com/login",
                 "data": {"u": "x", "_token": "${csrf}"},
                 "expect_status": [200, 302]},
            ],
        }
        ok = player.play(macro)
        assert ok
        assert player.is_authenticated()

        post_call = next(c for c in client.calls if c[0] == "post")
        assert post_call[2]["_token"] == "abc"

    def test_auth_check_passes(self):
        client = MockHttpClient(
            responses={("get", "https://example.com"): MockResponse(200, "Welcome user")}
        )
        player = LoginPlayer(client)
        ok = player.play({
            "auth_check": {"url": "https://example.com", "must_contain": "Welcome"},
            "steps": [],
        })
        assert ok

    def test_auth_check_must_not_contain_fails(self):
        client = MockHttpClient(
            responses={("get", "https://example.com"): MockResponse(200, "Sign in to continue")}
        )
        player = LoginPlayer(client)
        ok = player.play({
            "auth_check": {"url": "https://example.com", "must_not_contain": "Sign in"},
            "steps": [],
        })
        assert not ok

    def test_step_failure_aborts(self):
        client = MockHttpClient(
            responses={("get", "https://example.com"): MockResponse(500, "")}
        )
        player = LoginPlayer(client)
        ok = player.play({
            "steps": [
                {"action": "get", "url": "https://example.com", "expect_status": [200]},
            ],
        })
        assert not ok
        assert not player.is_authenticated()

    def test_set_cookie(self):
        client = MockHttpClient()
        player = LoginPlayer(client)
        player.play({
            "steps": [
                {"action": "set_cookie", "name": "session", "value": "abc"},
            ],
        })
        assert client.session.cookies.store["session"] == ("abc", None)
