"""
Subdomain Scanner
Orchestrates subdomain discovery and scanning
"""

from typing import Dict, List, Set, TYPE_CHECKING
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.reconnaissance.subdomain_hunter import SubdomainHunter
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.scanner_engine import ScannerEngine

console = Console()
logger = get_logger(__name__)


class SubdomainScanner:
    """Scan multiple subdomains for vulnerabilities."""
    
    def __init__(self, scanner_engine: 'ScannerEngine', config: Dict):
        """
        Initialize subdomain scanner.
        
        Args:
            scanner_engine: Main scanner engine instance
            config: Configuration dictionary
        """
        self.scanner_engine = scanner_engine
        self.config = config
        self.subdomain_hunter = SubdomainHunter(config)
        self.subdomain_results = {}
        self.max_subdomains = config.get('experimental', {}).get('max_subdomains_to_scan', 50)
    
    def discover_and_scan(self, target_url: str, aggressive: bool = True) -> Dict:
        """
        Discover subdomains and scan each one.
        
        Args:
            target_url: Main target URL
            aggressive: Use aggressive subdomain enumeration
            
        Returns:
            Dictionary containing all subdomain scan results
        """
        # Parse domain
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        console.print(f"\n[bold cyan]🔍 Discovering subdomains for: {domain}[/bold cyan]")
        
        # Discover subdomains
        subdomains = self.subdomain_hunter.discover_subdomains(domain, aggressive)
        
        if not subdomains:
            console.print("[yellow]No subdomains discovered[/yellow]")
            return {}
        
        # Limit number of subdomains to scan
        subdomains = set(list(subdomains)[:self.max_subdomains])
        
        # Display discovered subdomains
        self._display_subdomains(subdomains)
        
        # Scan each subdomain
        console.print(f"\n[bold cyan]🎯 Scanning {len(subdomains)} subdomains...[/bold cyan]\n")
        
        all_results = {
            'main_domain': domain,
            'subdomains_found': len(subdomains),
            'subdomain_urls': list(subdomains),
            'scan_results': {}
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task(
                "[cyan]Scanning subdomains...",
                total=len(subdomains)
            )
            
            # Scan subdomains with limited concurrency
            max_concurrent = min(self.config.get('scanner', {}).get('default_threads', 5), 3)
            
            with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                future_to_subdomain = {
                    executor.submit(self._scan_subdomain, subdomain): subdomain
                    for subdomain in subdomains
                }
                
                total_vulns = 0
                for future in as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        result = future.result()
                        all_results['scan_results'][subdomain] = result
                        
                        vuln_count = len(result.get('vulnerabilities', []))
                        total_vulns += vuln_count
                        
                        progress.advance(task)
                        progress.update(
                            task,
                            description=f"[cyan]Scanning... {total_vulns} total vulnerabilities found"
                        )
                        
                    except Exception as e:
                        logger.error(f"Error scanning subdomain {subdomain}: {e}")
                        progress.advance(task)
        
        # Summary
        all_results['total_vulnerabilities'] = total_vulns
        all_results['severity_summary'] = self._aggregate_severity(all_results['scan_results'])
        
        console.print(f"\n[green]✓[/green] Subdomain scanning complete")
        console.print(f"[green]✓[/green] Total vulnerabilities across all subdomains: {total_vulns}\n")
        
        return all_results
    
    def _scan_subdomain(self, subdomain_url: str) -> Dict:
        """Scan a single subdomain."""
        logger.info(f"Scanning subdomain: {subdomain_url}")
        
        try:
            # Create a lightweight scanner instance for this subdomain
            # Reuse HTTP client and AI manager from main scanner
            from core.vulnerability_scanner import VulnerabilityScanner
            from core.ai_payload_generator import AIPayloadGenerator
            from utils.http_client import HTTPClient
            
            # Create HTTP client for subdomain
            http_client = HTTPClient(config=self.config)
            
            # Get basic info
            response = http_client.get(subdomain_url)
            if not response:
                return {'vulnerabilities': [], 'error': 'Failed to connect'}
            
            context = {
                'url': subdomain_url,
                'response': response,
                'headers': dict(response.headers)
            }
            
            # Generate payloads
            ai_generator = AIPayloadGenerator(
                ai_manager=self.scanner_engine.ai_manager,
                config=self.config
            )
            payloads = ai_generator.generate_payloads(context)
            
            # Scan for vulnerabilities (quick scan - don't crawl subdomain deeply)
            vuln_scanner = VulnerabilityScanner(config=self.config, http_client=http_client)
            vulnerabilities = vuln_scanner.scan(
                url=subdomain_url,
                payloads=payloads,
                context=context
            )
            
            return {
                'url': subdomain_url,
                'vulnerabilities': vulnerabilities,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'technologies': self._detect_tech(context)
            }
            
        except Exception as e:
            logger.error(f"Error scanning subdomain {subdomain_url}: {e}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    def _detect_tech(self, context: Dict) -> List[str]:
        """Quick technology detection."""
        tech = []
        headers = context.get('headers', {})
        
        server = headers.get('server', '').lower()
        if 'apache' in server:
            tech.append('Apache')
        if 'nginx' in server:
            tech.append('Nginx')
        if 'iis' in server:
            tech.append('IIS')
        
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech.append('PHP')
        if 'asp.net' in powered_by:
            tech.append('ASP.NET')
        
        return tech
    
    def _display_subdomains(self, subdomains: Set[str]):
        """Display discovered subdomains in a table."""
        table = Table(title="Discovered Subdomains", show_header=True)
        table.add_column("No.", style="cyan", width=5)
        table.add_column("Subdomain URL", style="green")
        
        for idx, subdomain in enumerate(sorted(subdomains), 1):
            table.add_row(str(idx), subdomain)
        
        console.print(table)
    
    def _aggregate_severity(self, scan_results: Dict) -> Dict:
        """Aggregate severity counts from all subdomain scans."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for subdomain, result in scan_results.items():
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'info').lower()
                if severity in summary:
                    summary[severity] += 1
        
        return summary

