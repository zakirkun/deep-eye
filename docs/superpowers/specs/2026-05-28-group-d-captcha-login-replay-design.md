# Group D — CAPTCHA Detection + Login Macro Replay

**Date:** 2026-05-28
**Status:** Design — pending approval
**Scope:** (1) Detect CAPTCHA on target pages and skip/flag them. (2) Record a login sequence as a macro and replay before each scan to ensure authenticated context.

---

## Goals

- Avoid flooding pages protected by hCaptcha, reCAPTCHA, Cloudflare Turnstile, or generic CAPTCHA.
- Authenticate before scan: support flows that require form submission, multi-step login, or token refresh.
- Both features opt-in via config, off by default.

## Non-Goals

- Solving CAPTCHAs.
- Recording macros via browser UI.
- 2FA bypass (use authenticator app, paste TOTP into macro).

---

## Architecture

### CAPTCHA detection

```
modules/captcha_detection/
  __init__.py
  detector.py
```

`CaptchaDetector.detect(html: str, url: str) -> Optional[Dict]`:
returns `{"vendor": ..., "matched": ...}` or `None`.

Detection signals:
- reCAPTCHA: `<script src="*google.com/recaptcha*">`, `class="g-recaptcha"`
- hCaptcha: `<script src="*hcaptcha.com*">`, `class="h-captcha"`
- Turnstile: `<script src="*challenges.cloudflare.com/turnstile*">`, `class="cf-turnstile"`
- Generic: `<input type="hidden" name="captcha*">`, `<img src="*captcha*">`

Integration: when crawler fetches a page, run detector. If found:
- Add info-level vuln "CAPTCHA Protected Page"
- Skip vuln scan if `captcha.skip_protected: true`
- Track in `results['captcha_pages']`

### Login macro replay

```
modules/login_replay/
  __init__.py
  macro.py
  player.py
```

#### Macro format

```json
{
  "version": 1,
  "name": "demo-login",
  "auth_check": {
    "url": "https://example.com/account",
    "must_contain": "Welcome",
    "must_not_contain": "Sign in"
  },
  "steps": [
    {"action": "get",  "url": "https://example.com/login"},
    {"action": "extract_csrf", "from": "input[name=_token]", "save_as": "csrf"},
    {"action": "post", "url": "https://example.com/login",
     "data": {"username": "user", "password": "pw", "_token": "${csrf}"},
     "expect_status": [200, 302]},
    {"action": "get",  "url": "https://example.com/account",
     "expect_contains": "Welcome"}
  ]
}
```

Action types: `get`, `post`, `extract_csrf`, `extract_header`, `set_cookie`, `wait`, `playwright`.

Variables substituted via `${name}` in `data`, `url`, `headers`.

#### Player

```python
class LoginPlayer:
    def __init__(self, http_client, config: Dict)
    def play(self, macro: Dict) -> bool
    def is_authenticated(self) -> bool
```

Cookies persist across steps via shared `http_client.session`.

### Integration

`ScannerEngine.scan()`:
```
if config['login_replay']['enabled']:
    macro = load_macro(config['login_replay']['macro_path'])
    player = LoginPlayer(self.http_client, config)
    if not player.play(macro):
        if config['login_replay']['abort_on_fail']:
            return
```

Macro replay runs **before** crawling.

### Config

```yaml
captcha:
  enabled: false
  skip_protected: true
  vendors: [recaptcha, hcaptcha, turnstile, generic]

login_replay:
  enabled: false
  macro_path: "config/login_macro.json"
  abort_on_fail: true
  recheck_interval_seconds: 600
```

---

## Components

```
modules/captcha_detection/__init__.py
modules/captcha_detection/detector.py
modules/login_replay/__init__.py
modules/login_replay/macro.py
modules/login_replay/player.py

core/scanner_engine.py
  + invoke LoginPlayer before crawl
  + invoke CaptchaDetector during URL fetch hook

config/config.example.yaml
  + captcha: {...}
  + login_replay: {...}
```

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| CAPTCHA detected, skip_protected=true | Skip vuln scan, log finding |
| Login macro file missing | Log error, abort if `abort_on_fail` else continue unauthenticated |
| Login step fails | Log error with step index, abort if `abort_on_fail` |
| auth_check fails | Treat as login failure |
| CSRF extraction fails | Log warning, continue with empty var |

---

## Testing

`tests/test_captcha_detection.py`:
- `test_detect_recaptcha`
- `test_detect_hcaptcha`
- `test_detect_turnstile`
- `test_detect_generic`
- `test_no_captcha`

`tests/test_login_replay.py`:
- `test_macro_parse_valid`
- `test_macro_parse_invalid_action`
- `test_var_substitution`
- `test_extract_csrf`
- `test_play_get_post_sequence`
- `test_auth_check_passes`
- `test_auth_check_fails`
- `test_step_failure_aborts`

---

## Migration / Compat

- All new modules opt-in.
- No vuln dict shape change.
- CAPTCHA-protected pages produce info-level findings.

---

## Open Questions

None. Locked.

---

## Out of Scope

- CAPTCHA solving services
- Browser-recorded macros
- 2FA bypass
- OAuth flow auto-detection
