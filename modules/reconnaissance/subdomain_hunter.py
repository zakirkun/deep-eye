"""
Advanced Subdomain Hunter
Aggressive subdomain discovery and enumeration
"""

import asyncio
import dns.resolver
import requests
from typing import Set, List, Dict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger

logger = get_logger(__name__)


class SubdomainHunter:
    """Advanced subdomain discovery and enumeration."""
    
    def __init__(self, config: Dict):
        """Initialize subdomain hunter."""
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
    
    def discover_subdomains(self, domain: str, aggressive: bool = True) -> Set[str]:
        """
        Discover subdomains using multiple techniques.
        
        Args:
            domain: Target domain
            aggressive: Use aggressive enumeration
            
        Returns:
            Set of discovered subdomains
        """
        logger.info(f"Starting subdomain discovery for: {domain}")
        
        subdomains = set()
        
        # Method 1: Certificate Transparency
        subdomains.update(self._crt_sh(domain))
        
        # Method 2: DNS bruteforce (if aggressive)
        if aggressive:
            subdomains.update(self._dns_bruteforce(domain))
        
        # Method 3: Search engine enumeration
        subdomains.update(self._search_engines(domain))
        
        # Method 4: Common subdomains
        subdomains.update(self._common_subdomains(domain))
        
        # Verify subdomains are alive
        live_subdomains = self._verify_subdomains(subdomains)
        
        logger.info(f"Discovered {len(live_subdomains)} live subdomains for {domain}")
        return live_subdomains
    
    def _crt_sh(self, domain: str) -> Set[str]:
        """Query Certificate Transparency logs via crt.sh."""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle wildcard and multiple names
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*', '').lstrip('.')
                        if subdomain and subdomain.endswith(domain):
                            subdomains.add(subdomain)
                
                logger.info(f"crt.sh found {len(subdomains)} subdomains")
        
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        return subdomains
    
    def _dns_bruteforce(self, domain: str, wordlist_size: int = 100) -> Set[str]:
        """Bruteforce DNS with common subdomain names."""
        subdomains = set()
        
        # Common subdomain prefixes
        common_prefixes = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'store', 'portal', 'app', 'mobile', 'cdn', 'static',
            'media', 'images', 'vpn', 'remote', 'secure', 'login', 'auth',
            'dashboard', 'panel', 'cpanel', 'webmail', 'smtp', 'pop', 'imap',
            'ns1', 'ns2', 'mx', 'mx1', 'mx2', 'dns', 'gateway', 'firewall',
            'proxy', 'lb', 'backup', 'db', 'database', 'sql', 'oracle',
            'docs', 'wiki', 'support', 'help', 'ticket', 'chat', 'forum',
            'beta', 'alpha', 'demo', 'sandbox', 'uat', 'qa', 'prod', 'production',
            'm', 'mobile', 'wap', 'old', 'new', 'v1', 'v2', 'api-v1', 'api-v2'
        ]
        
        logger.info(f"DNS bruteforce: testing {len(common_prefixes)} prefixes")
        
        def check_subdomain(prefix):
            subdomain = f"{prefix}.{domain}"
            try:
                self.resolver.resolve(subdomain, 'A')
                return subdomain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, prefix) for prefix in common_prefixes[:wordlist_size]]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        logger.info(f"DNS bruteforce found {len(subdomains)} subdomains")
        return subdomains
    
    def _search_engines(self, domain: str) -> Set[str]:
        """Enumerate subdomains via search engines."""
        subdomains = set()
        
        # Google dork
        try:
            query = f"site:*.{domain}"
            # Note: In production, use proper Google Search API
            # This is a placeholder
            logger.debug(f"Search engine query: {query}")
        except Exception as e:
            logger.debug(f"Search engine error: {e}")
        
        return subdomains
    
    def _common_subdomains(self, domain: str) -> Set[str]:
        """Return common subdomain patterns."""
        return {
            f"www.{domain}",
            f"api.{domain}",
            f"admin.{domain}",
            f"dev.{domain}",
            f"staging.{domain}",
            f"test.{domain}"
        }
    
    def _verify_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """Verify subdomains are alive via HTTP/HTTPS."""
        live = set()
        
        def check_alive(subdomain):
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.get(
                        url,
                        timeout=5,
                        allow_redirects=True,
                        verify=False
                    )
                    if response.status_code < 500:
                        return (subdomain, f"{protocol}://{subdomain}")
                except:
                    continue
            return None
        
        logger.info(f"Verifying {len(subdomains)} subdomains...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_alive, sub) for sub in subdomains]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, url = result
                    live.add(url)
        
        return live
    
    def get_subdomain_info(self, subdomain: str) -> Dict:
        """Get detailed information about a subdomain."""
        info = {
            'subdomain': subdomain,
            'ip_addresses': [],
            'nameservers': [],
            'mx_records': [],
            'txt_records': [],
            'alive': False,
            'http_status': None,
            'title': None,
            'server': None
        }
        
        # DNS records
        try:
            # A records
            answers = self.resolver.resolve(subdomain, 'A')
            info['ip_addresses'] = [str(rdata) for rdata in answers]
        except:
            pass
        
        try:
            # MX records
            answers = self.resolver.resolve(subdomain, 'MX')
            info['mx_records'] = [str(rdata.exchange) for rdata in answers]
        except:
            pass
        
        try:
            # TXT records
            answers = self.resolver.resolve(subdomain, 'TXT')
            info['txt_records'] = [str(rdata) for rdata in answers]
        except:
            pass
        
        # HTTP check
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = self.session.get(url, timeout=5, verify=False)
                info['alive'] = True
                info['http_status'] = response.status_code
                info['server'] = response.headers.get('Server', 'Unknown')
                
                # Extract title
                if '<title>' in response.text:
                    start = response.text.find('<title>') + 7
                    end = response.text.find('</title>', start)
                    if end > start:
                        info['title'] = response.text[start:end].strip()
                
                break
            except:
                continue
        
        return info

