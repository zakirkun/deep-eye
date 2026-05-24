"""
Deep Eye Scanner Engine
Orchestrates the entire scanning process
"""

import time
import threading
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console

from core.vulnerability_scanner import VulnerabilityScanner
from core.ai_payload_generator import AIPayloadGenerator
from core.plugin_manager import PluginManager
from core.pentest_state_manager import PentestStateManager, PentestPhase
from core.subdomain_scanner import SubdomainScanner
from modules.reconnaissance.recon_engine import ReconEngine
from modules.browser_automation.smart_tester import SmartBrowserTester
from utils.http_client import HTTPClient
from utils.parser import URLParser, ResponseParser
from utils.notification_manager import NotificationManager
from utils.logger import get_logger

console = Console()
logger = get_logger(__name__)


class ScannerEngine:
    """Main scanner engine that orchestrates the penetration testing process."""
    
    def __init__(
        self,
        target_url: str,
        config: Dict,
        ai_manager,
        depth: int = 2,
        threads: int = 5,
        proxy: Optional[str] = None,
        custom_headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        verbose: bool = False
    ):
        """Initialize the scanner engine."""
        self.target_url = target_url
        self.config = config
        self.ai_manager = ai_manager
        self.depth = depth
        self.threads = threads
        self.verbose = verbose
        
        # Initialize components
        self.http_client = HTTPClient(
            proxy=proxy,
            custom_headers=custom_headers,
            cookies=cookies,
            config=config
        )
        
        self.vulnerability_scanner = VulnerabilityScanner(
            config=config,
            http_client=self.http_client
        )
        
        self.ai_payload_generator = AIPayloadGenerator(
            ai_manager=ai_manager,
            config=config
        )
        
        self.recon_engine = ReconEngine(
            config=config,
            http_client=self.http_client
        )
        
        self.plugin_manager = PluginManager(
            http_client=self.http_client,
            config=config
        )
        
        # Load custom plugins
        if config.get('plugin_manager', {}).get('enabled', False):
            self.plugin_manager.load_plugins()
        
        self.notification_manager = NotificationManager(config)
        
        
        # Subdomain scanner
        self.subdomain_scanner = SubdomainScanner(self, config)
        
        # State tracking and management
        self.state_manager = PentestStateManager(target_url)
        self.visited_urls: Set[str] = set()
        self.urls_to_scan: List[str] = [target_url]
        self.vulnerabilities: List[Dict] = []
        self.scan_results: Dict = {}
        self.lock = threading.Lock()
        
        # Statistics
        self.start_time = None
        self.end_time = None
        
    def crawl(self, url: str, current_depth: int = 0) -> List[str]:
        """Crawl a URL and extract links."""
        if current_depth >= self.depth or url in self.visited_urls:
            return []
        
        with self.lock:
            self.visited_urls.add(url)
        
        try:
            response = self.http_client.get(url)
            if not response:
                return []
            
            parser = ResponseParser(response)
            links = parser.extract_links(base_url=url)
            
            # Filter links to same domain
            parsed_target = urlparse(self.target_url)
            same_domain_links = []
            
            for link in links:
                parsed_link = urlparse(link)
                if parsed_link.netloc == parsed_target.netloc:
                    if link not in self.visited_urls:
                        same_domain_links.append(link)
            
            return same_domain_links
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return []
    
    def crawl_recursive(self) -> Set[str]:
        """Recursively crawl the target website."""
        self.state_manager.set_phase(PentestPhase.CRAWLING)
        console.print("[bold blue]🕷️  Starting web crawler...[/bold blue]")
        
        all_urls = set([self.target_url])
        queue = [(self.target_url, 0)]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task(
                f"[cyan]Crawling (depth: {self.depth})...",
                total=None
            )
            
            while queue:
                url, depth = queue.pop(0)
                
                if depth >= self.depth:
                    continue
                
                new_links = self.crawl(url, depth)
                
                for link in new_links:
                    if link not in all_urls:
                        all_urls.add(link)
                        queue.append((link, depth + 1))
                        self.state_manager.update_urls(discovered=1)
                
                progress.update(
                    task,
                    description=f"[cyan]Crawling... Found {len(all_urls)} URLs"
                )
        
        console.print(f"[green]✓[/green] Crawling complete. Found {len(all_urls)} URLs\n")
        return all_urls
    
    def scan_url(self, url: str, recon_data: Optional[Dict] = None) -> List[Dict]:
        """Scan a single URL for vulnerabilities."""
        vulnerabilities = []
        
        try:
            self.state_manager.current_url_testing = url
            
            # Get AI-generated payloads for this URL
            response = self.http_client.get(url)
            if not response:
                self.state_manager.update_urls(tested=1)
                return vulnerabilities
            
            context = {
                'url': url,
                'response': response,
                'headers': dict(response.headers)
            }
            
            # Add OSINT data to context if available from reconnaissance
            if recon_data and 'osint' in recon_data:
                context['osint_data'] = recon_data['osint']
            
            # Generate intelligent payloads
            payloads = self.ai_payload_generator.generate_payloads(context)
            
            # Run vulnerability scans with state tracking
            scan_results = self.vulnerability_scanner.scan(
                url=url,
                payloads=payloads,
                context=context,
                state_manager=self.state_manager
            )
            
            vulnerabilities.extend(scan_results)
            
            # Run browser-based tests if enabled
            if self.config.get('advanced', {}).get('enable_javascript_rendering', False):
                try:
                    # Instantiate browser tester locally for thread safety
                    browser_tester = SmartBrowserTester(self.config)
                    browser_vulns = browser_tester.test_browser_sync(url, payloads)
                    vulnerabilities.extend(browser_vulns)
                except Exception as e:
                    logger.debug(f"Browser testing failed for {url}: {e}")
            
            # Run custom plugins
            if self.config.get('plugin_manager', {}).get('enabled', False):
                plugin_results = self.plugin_manager.scan_with_plugins(url, context)
                vulnerabilities.extend(plugin_results)
            
            # Update state with found vulnerabilities
            for vuln in vulnerabilities:
                self.state_manager.add_vulnerability(vuln.get('severity', 'info'))
                
                # Send critical vulnerability alerts
                if vuln.get('severity', '').lower() == 'critical':
                    try:
                        self.notification_manager.send_critical_vulnerability(vuln, self.target_url)
                    except Exception as e:
                        logger.debug(f"Error sending critical vulnerability alert: {e}")
            
            self.state_manager.update_urls(tested=1)
            
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
        
        return vulnerabilities
    
    def scan_all_urls(self, urls: Set[str], recon_data: Optional[Dict] = None):
        """Scan all discovered URLs for vulnerabilities."""
        self.state_manager.set_phase(PentestPhase.VULNERABILITY_SCANNING)
        console.print("[bold blue]🔍 Starting vulnerability scanning...[/bold blue]")
        console.print(f"[dim]Phase: {self.state_manager.current_phase.value}[/dim]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task(
                "[cyan]Scanning for vulnerabilities...",
                total=len(urls)
            )
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self.scan_url, url, recon_data): url
                    for url in urls
                }
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        vulns = future.result()
                        with self.lock:
                            self.vulnerabilities.extend(vulns)
                        
                        progress.advance(task)
                        
                        # Show detailed progress with state
                        critical = sum(1 for v in self.vulnerabilities if v.get('severity') == 'critical')
                        high = sum(1 for v in self.vulnerabilities if v.get('severity') == 'high')
                        
                        progress.update(
                            task,
                            description=f"[cyan]Scanning... {len(self.vulnerabilities)} vulns (🔴{critical} 🟠{high})"
                        )
                        
                    except Exception as e:
                        logger.error(f"Error processing {url}: {e}")
                        progress.advance(task)
        
        console.print(f"[green]✓[/green] Vulnerability scanning complete. Found {len(self.vulnerabilities)} issues\n")
    
    def run_reconnaissance(self) -> Dict:
        """Run reconnaissance modules."""
        self.state_manager.set_phase(PentestPhase.RECONNAISSANCE)
        console.print("[bold blue]🔎 Running reconnaissance...[/bold blue]")
        console.print(f"[dim]Phase: {self.state_manager.current_phase.value}[/dim]\n")
        recon_results = self.recon_engine.run(self.target_url)
        console.print("[green]✓[/green] Reconnaissance complete\n")
        return recon_results
    
    def scan(
        self,
        enable_recon: bool = False,
        full_scan: bool = False,
        quick_scan: bool = False,
        scan_subdomains: bool = False
    ) -> Dict:
        """
        Execute the complete scanning process.
        
        Args:
            enable_recon: Enable reconnaissance phase
            full_scan: Enable all vulnerability tests
            quick_scan: Run only basic tests
            scan_subdomains: Enable subdomain discovery and scanning (experimental)
            
        Returns:
            Dictionary containing scan results
        """
        self.start_time = datetime.now()
        self.state_manager.set_phase(PentestPhase.INITIALIZATION)
        
        results = {
            'target': self.target_url,
            'start_time': self.start_time.isoformat(),
            'config': {
                'depth': self.depth,
                'threads': self.threads,
                'recon_enabled': enable_recon,
                'scan_mode': 'full' if full_scan else 'quick' if quick_scan else 'standard',
                'browser_enabled': self.config.get('advanced', {}).get('enable_javascript_rendering', False),
                'screenshot_enabled': self.config.get('advanced', {}).get('screenshot_enabled', False),
                'subdomain_scanning': scan_subdomains
            }
        }
        
        # Phase 1: Reconnaissance (optional)
        recon_data = None
        if enable_recon:
            recon_data = self.run_reconnaissance()
            results['reconnaissance'] = recon_data
        
        # Phase 1.5: Subdomain Discovery & Scanning (experimental)
        if scan_subdomains:
            subdomain_results = self.subdomain_scanner.discover_and_scan(
                self.target_url,
                aggressive=self.config.get('experimental', {}).get('aggressive_subdomain_enum', True)
            )
            results['subdomain_scan'] = subdomain_results
            
            # Aggregate subdomain vulnerabilities into main results
            for subdomain, sub_result in subdomain_results.get('scan_results', {}).items():
                for vuln in sub_result.get('vulnerabilities', []):
                    # Mark as subdomain vulnerability
                    vuln['source'] = 'subdomain'
                    vuln['subdomain'] = subdomain
                    self.vulnerabilities.append(vuln)
        
        # Phase 2: Web Crawling
        discovered_urls = self.crawl_recursive()
        results['urls_crawled'] = len(discovered_urls)
        results['discovered_urls'] = list(discovered_urls)
        
        # Phase 3: Vulnerability Scanning
        if quick_scan:
            # Scan only main URL in quick mode
            self.scan_all_urls({self.target_url}, recon_data)
        else:
            self.scan_all_urls(discovered_urls, recon_data)
        
        # Compile results
        results['vulnerabilities'] = self.vulnerabilities
        results['severity_summary'] = self._calculate_severity_summary()
        
        # Add pentest state information
        results['pentest_state'] = self.state_manager.get_state_dict()
        
        self.end_time = datetime.now()
        self.state_manager.set_phase(PentestPhase.REPORTING)
        results['end_time'] = self.end_time.isoformat()
        results['duration'] = str(self.end_time - self.start_time)
        
        # Display state summary
        console.print("\n")
        self.state_manager.display_summary()
        
        # Send scan completion notification
        try:
            self.notification_manager.send_scan_complete(results)
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
        
        self.state_manager.set_phase(PentestPhase.COMPLETED)
        
        return results
    
    def _calculate_severity_summary(self) -> Dict[str, int]:
        """Calculate vulnerability severity summary."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
