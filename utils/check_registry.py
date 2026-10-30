"""Single source of truth for vulnerability check names.

Check names currently live in three places, each loaded independently:

1. Built-in ``_check_*`` gates inside ``core/vulnerability_scanner.py`` ``scan()``
2. The 16 "classic" module imports in ``VulnerabilityScanner.__init__``
3. The ``_specs`` tuple (27 lazy feature testers)
4. ``ScannerEngine._init_extra_module_testers`` (5 engine-owned extras)

A typo in ``vulnerability_scanner.enabled_checks`` silently disables a check:
nothing validates the list against what actually exists. This module is the
authority the rest of the code can be validated against.

Importing this module must stay free of side effects -- no imports of
``modules.*``, no filesystem reads, no network. It is a table, nothing else.
"""
from __future__ import annotations

from typing import Dict, List, NamedTuple, Set

# Registration path for a check.
BUILTIN = "builtin"        # _check_* method gated inline in scan()
MODULE = "module"          # eagerly imported tester attribute on VulnerabilityScanner
FEATURE = "feature"        # lazy-imported via the _specs tuple
EXTRA = "extra"            # engine-owned, ScannerEngine._init_extra_module_testers
LIFECYCLE = "lifecycle"    # engine-orchestrated phase, not a per-URL check


class CheckSpec(NamedTuple):
    """One dispatchable check.

    Attributes:
        name: The value users put in ``vulnerability_scanner.enabled_checks``.
        kind: Registration path, one of the module-level constants above.
        target: For MODULE/FEATURE/EXTRA -- ``module.path:ClassName``. For
            BUILTIN -- the ``_check_*`` method name. For LIFECYCLE -- the
            config block that gates it.
        per_url: True when the check runs once per discovered URL.
        description: Short human label used by ``--check-config``.
    """

    name: str
    kind: str
    target: str
    per_url: bool
    description: str


def _c(name: str, method: str, description: str) -> CheckSpec:
    return CheckSpec(name, BUILTIN, method, True, description)


def _m(name: str, target: str, description: str) -> CheckSpec:
    return CheckSpec(name, MODULE, target, True, description)


def _f(name: str, target: str, description: str) -> CheckSpec:
    return CheckSpec(name, FEATURE, target, True, description)


def _e(name: str, target: str, description: str) -> CheckSpec:
    return CheckSpec(name, EXTRA, target, True, description)


CHECKS: tuple = (
    # --- Built-in _check_* gates (dispatched inline in VulnerabilityScanner.scan) ---
    _c("sql_injection", "_check_sql_injection", "SQL injection"),
    _c("xss", "_check_xss", "Cross-site scripting"),
    _c("command_injection", "_check_command_injection", "OS command injection"),
    _c("ssrf", "_check_ssrf", "Server-side request forgery"),
    _c("xxe", "_check_xxe", "XML external entity"),
    _c("path_traversal", "_check_path_traversal", "Path traversal"),
    _c("csrf", "_check_csrf", "Cross-site request forgery"),
    _c("open_redirect", "_check_open_redirect", "Open redirect"),
    _c("cors_misconfiguration", "_check_cors", "CORS misconfiguration"),
    _c("security_misconfiguration", "_check_security_headers", "Security header misconfiguration"),
    _c("lfi", "_check_lfi", "Local file inclusion"),
    _c("rfi", "_check_rfi", "Remote file inclusion"),
    _c("ssti", "_check_ssti", "Server-side template injection"),
    _c("crlf_injection", "_check_crlf_injection", "CRLF injection"),
    _c("host_header_injection", "_check_host_header_injection", "Host header injection"),
    _c("ldap_injection", "_check_ldap_injection", "LDAP injection"),
    _c("xml_injection", "_check_xml_injection", "XML injection"),
    _c("insecure_deserialization", "_check_insecure_deserialization", "Insecure deserialization"),
    _c("authentication_bypass", "_check_authentication_bypass", "Authentication bypass"),
    _c("information_disclosure", "_check_information_disclosure", "Information disclosure"),
    _c("sensitive_data_exposure", "_check_sensitive_data_exposure", "Sensitive data exposure"),
    _c("jwt_vulnerabilities", "_check_jwt_vulnerabilities", "JWT weaknesses"),
    _c("broken_authentication", "_check_broken_authentication", "Broken authentication"),
    # --- Eagerly imported module testers (attribute on VulnerabilityScanner) ---
    _m("api_security", "modules.api_security:APISecurityTester", "API security testing"),
    _m("graphql_security", "modules.api_security:GraphQLTester", "GraphQL endpoint testing"),
    _m("api_vulnerabilities", "modules.api_security:APISecurityTester", "Alias: api_security"),
    _m("graphql_vulnerabilities", "modules.api_security:GraphQLTester", "Alias: graphql_security"),
    _m("business_logic", "modules.business_logic:BusinessLogicTester", "Business logic flaws"),
    _m("authentication", "modules.authentication:AuthenticationTester", "Authentication testing"),
    _m("file_upload", "modules.file_upload:FileUploadTester", "File upload abuse"),
    _m("websocket", "modules.websocket:WebSocketTester", "WebSocket testing"),
    _m("anomaly_detector", "modules.ml_detection:AnomalyDetector", "ML anomaly detection"),
    _m("secret_scanning", "modules.secret_scanning:SecretScanner", "Response-body secret scan"),
    _m("nosql_injection", "modules.nosql_injection:NoSQLInjectionTester", "NoSQL injection"),
    _m("http_smuggling", "modules.http_smuggling:SmugglingTester", "HTTP request smuggling"),
    _m("race_condition", "modules.race_condition:RaceConditionTester", "Race condition"),
    _m("log4shell", "modules.log4shell:Log4ShellTester", "Log4Shell"),
    _m("oauth_testing", "modules.oauth_testing:OAuthTester", "OAuth flaws"),
    _m("mass_assignment", "modules.mass_assignment:MassAssignmentTester", "Mass assignment"),
    _m("prototype_pollution", "modules.prototype_pollution:PrototypePollutionTester", "Prototype pollution"),
    # --- Lazy feature testers (the _specs tuple) ---
    _f("cors_csp", "modules.cors_csp:CorsCspTester", "CORS + CSP deep"),
    _f("jwt_deep", "modules.jwt_deep:JWTDeepTester", "JWT deep analysis"),
    _f("graphql_deep", "modules.graphql_deep:GraphQLDeepTester", "GraphQL deep"),
    _f("idor", "modules.idor:IDORTester", "IDOR"),
    _f("stored_xss", "modules.stored_xss:StoredXSSTester", "Stored XSS"),
    _f("email_injection", "modules.email_injection:EmailHeaderInjectionTester", "Email header injection"),
    _f("cache_deception", "modules.cache_deception:CacheDeceptionTester", "Web cache deception"),
    _f("h2_smuggle", "modules.h2_smuggle:H2SmuggleTester", "HTTP/2 smuggling"),
    _f("supply_chain_js", "modules.supply_chain_js:SupplyChainJSTester", "Supply chain (JS)"),
    _f("waf_fingerprint", "modules.waf_fingerprint:WAFFingerprint", "WAF fingerprint"),
    _f("ssrf_cloud", "modules.ssrf_cloud:SSRFCloudTester", "SSRF cloud metadata"),
    _f("open_redirect_deep", "modules.open_redirect_deep:OpenRedirectDeepTester", "Open redirect deep"),
    _f("hpp_pollution", "modules.hpp_pollution:HPPTester", "HTTP parameter pollution"),
    _f("http_method_override", "modules.http_method_override:HTTPMethodOverrideTester", "HTTP method override"),
    _f("host_header_deep", "modules.host_header_deep:HostHeaderDeepTester", "Host header deep"),
    _f("crlf_header_inject_deep", "modules.crlf_header_inject_deep:CRLFHeaderInjectDeepTester", "CRLF header injection deep"),
    _f("ssti_engines", "modules.ssti_engines:SSTIEnginesTester", "SSTI per engine"),
    _f("api_bola_deep", "modules.api_bola_deep:APIBolaDeepTester", "API BOLA deep"),
    _f("websocket_deep", "modules.websocket_deep:WebSocketDeepTester", "WebSocket deep"),
    _f("sse_injection", "modules.sse_injection:SSEInjectionTester", "SSE injection"),
    _f("cloud_misconfig", "modules.cloud_misconfig:CloudMisconfigTester", "Cloud misconfiguration"),
    _f("php_webshell", "modules.php_webshell:PHPWebshellLFITester", "PHP webshell / LFI"),
    _f("frida_mobile", "modules.frida_mobile:FridaMobileTester", "Frida mobile hooks"),
    _f("android_static", "modules.android_static:AndroidStaticTester", "Android static APK"),
    _f("ios_plist", "modules.ios_plist:IOSPlistTester", "iOS Info.plist"),
    _f("mobile_ssl_pinning", "modules.mobile_ssl_pinning:MobileSSLPinningTester", "Mobile SSL pinning"),
    _f("mobile_ai_chain", "modules.mobile_ai_chain:MobileAIAttackChain", "Mobile AI attack chain"),
    # --- Engine-owned extras (_init_extra_module_testers) ---
    _e("directory_bruteforce", "modules.directory_bruteforce.dirb_scanner:DirectoryBruteforcer", "Directory bruteforce"),
    _e("port_scanner", "modules.port_scanner.scanner:PortScanner", "Port scan"),
    _e("saml_attacks", "modules.saml_attacks.saml_tester:SAMLTester", "SAML attacks"),
    _e("subdomain_takeover", "modules.subdomain_takeover.takeover_tester:SubdomainTakeoverTester", "Subdomain takeover"),
    _e("cache_poisoning", "modules.cache_poisoning.cache_tester:CachePoisoningTester", "Cache poisoning"),
)

#: name -> CheckSpec
REGISTRY: Dict[str, CheckSpec] = {spec.name: spec for spec in CHECKS}

#: Every dispatchable check name.
ALL_NAMES: Set[str] = set(REGISTRY)

#: Names grouped by registration path.
BY_KIND: Dict[str, Set[str]] = {}
for _spec in CHECKS:
    BY_KIND.setdefault(_spec.kind, set()).add(_spec.name)
del _spec

#: Checks that only run when the engine's ``mobile.enabled`` block is on.
#: These are FEATURE specs but are never dispatched from the per-URL loop.
MOBILE_NAMES: Set[str] = {
    "frida_mobile",
    "android_static",
    "ios_plist",
    "mobile_ssl_pinning",
    "mobile_ai_chain",
}

#: Checks that send state-changing requests; passive_mode must not run these.
STATE_CHANGING_NAMES: Set[str] = {
    "file_upload",
    "mass_assignment",
    "prototype_pollution",
    "race_condition",
    "http_smuggling",
    "h2_smuggle",
    "frida_mobile",
    "mobile_ai_chain",
}


def passive_allowed(names) -> List[str]:
    """Drop state-changing checks from ``names`` for passive_mode runs."""
    return [name for name in names if name not in STATE_CHANGING_NAMES]


def split_target(target: str):
    """Split a ``module.path:ClassName`` target into ``(module_path, class_name)``.

    Raises ValueError when the target is not in that form.
    """
    if ":" not in target:
        raise ValueError(f"check target is not 'module:Class': {target!r}")
    module_path, class_name = target.split(":", 1)
    return module_path, class_name


def get(name: str) -> CheckSpec:
    """Return the spec for ``name``, raising KeyError if unknown."""
    return REGISTRY[name]


def is_known(name: str) -> bool:
    """True when ``name`` is a registered check."""
    return name in REGISTRY


def names_for(kind: str) -> List[str]:
    """Sorted check names registered under ``kind``."""
    return sorted(BY_KIND.get(kind, set()))


def feature_specs() -> List[CheckSpec]:
    """Feature testers in declaration order (drives the ``_specs`` tuple)."""
    return [spec for spec in CHECKS if spec.kind == FEATURE]


def module_specs() -> List[CheckSpec]:
    """Eagerly imported module testers in declaration order."""
    return [spec for spec in CHECKS if spec.kind == MODULE]


def extra_specs() -> List[CheckSpec]:
    """Engine-owned extras in declaration order."""
    return [spec for spec in CHECKS if spec.kind == EXTRA]


def builtin_methods() -> List[str]:
    """``_check_*`` method names gated inline in ``VulnerabilityScanner.scan``."""
    return [spec.target for spec in CHECKS if spec.kind == BUILTIN]


def unknown(names) -> List[str]:
    """Return the subset of ``names`` that are not registered, preserving order."""
    seen: Set[str] = set()
    out: List[str] = []
    for name in names or []:
        if name in seen:
            continue
        seen.add(name)
        if name not in REGISTRY:
            out.append(name)
    return out


def summary() -> Dict[str, int]:
    """Count of registered checks per kind."""
    return {kind: len(names) for kind, names in sorted(BY_KIND.items())}
