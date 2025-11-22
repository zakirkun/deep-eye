"""
Secret Scanning Module
Scans response content for leaked secrets, API keys, tokens, and credentials.
"""

import re
from typing import List, Dict, Pattern

class SecretScanner:
    """Scans content for sensitive information and secrets."""
    
    def __init__(self, config: Dict):
        """Initialize the secret scanner."""
        self.config = config
        self.patterns = self._load_patterns()
        
    def _load_patterns(self) -> Dict[str, Pattern]:
        """Load regex patterns for secret detection."""
        return {
            'AWS Access Key': re.compile(r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])'),
            'AWS Secret Key': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
            'Google API Key': re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
            'Slack Token': re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})?'),
            'GitHub Personal Access Token': re.compile(r'ghp_[0-9a-zA-Z]{36}'),
            'Generic API Key': re.compile(r'(?i)(api_key|apikey|access_token|auth_token|api_token|secret_key|client_secret)\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{16,})[\"\']'),
            'Private Key': re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
            'Database Connection String': re.compile(r'(?i)(mysql|postgres|postgresql|mongodb|redis)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+:[0-9]+'),
            'JWT Token': re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
            'Stripe API Key': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            'Twilio API Key': re.compile(r'SK[0-9a-fA-F]{32}'),
            'Mailgun API Key': re.compile(r'key-[0-9a-zA-Z]{32}'),
        }

    def scan(self, content: str, url: str) -> List[Dict]:
        """
        Scan content for secrets.
        
        Args:
            content: The text content to scan (HTML, JS, JSON, etc.)
            url: The URL where the content was found
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        if not content:
            return vulnerabilities
            
        for name, pattern in self.patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                # Get the matched string
                matched_text = match.group(0)
                
                # For generic API keys, the secret is in group 2
                if name == 'Generic API Key' and match.groups():
                    matched_text = match.group(2)
                
                # Redact the secret for the report
                redacted = matched_text[:4] + '*' * (len(matched_text) - 8) + matched_text[-4:] if len(matched_text) > 8 else '***'
                
                vulnerabilities.append({
                    'type': 'Secret Leak',
                    'severity': 'critical',
                    'url': url,
                    'evidence': f"Found {name}: {redacted}",
                    'description': f"Leaked {name} detected in response content.",
                    'remediation': 'Revoke the compromised secret immediately and remove it from the codebase. Use environment variables or a secrets manager.'
                })
                
        return vulnerabilities
