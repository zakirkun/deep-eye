#!/usr/bin/env python3
"""
CVE Database Update Script
Updates the CVE intelligence database from multiple sources:
- NIST NVD API v2.0 (with 7-day caching)
- NVD RSS Feed (fallback)
- CISA Known Exploited Vulnerabilities
- MITRE CVE API
- Exploit-DB
"""

import sys
import asyncio
import warnings
from pathlib import Path

# Suppress asyncio cleanup warnings
warnings.filterwarnings('ignore', category=RuntimeWarning, module='asyncio')

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.cve_intelligence.cve_scraper import CVEScraper
from utils.paths import cve_db_path, ensure_dirs
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel

console = Console()


async def scrape_latest_vulnerabilities(scraper, console):
    """Scrape latest vulnerabilities from RSS/JSON feeds."""
    console.print("[bold yellow]📡 Fetching latest vulnerabilities...[/bold yellow]")
    console.print("[dim]Sources: NVD RSS, CISA KEV[/dim]\n")
    
    try:
        latest_cves = await scraper.scrape_latest_vulnerabilities(max_items=100)
        
        if latest_cves:
            # Update database with latest CVEs
            updated = 0
            for cve_data in latest_cves:
                if scraper._update_cve_data_from_source(cve_data['cve_id'], cve_data):
                    updated += 1
            
            console.print(f"[green]✓[/green] Fetched {len(latest_cves)} latest CVEs")
            console.print(f"[green]✓[/green] Updated {updated} CVEs in database\n")
            return updated, latest_cves
        else:
            console.print("[yellow]⚠[/yellow] No latest vulnerabilities found\n")
            return 0, []
    except Exception as e:
        console.print(f"[red]✗[/red] Error fetching latest vulnerabilities: {e}\n")
        return 0, []


async def scrape_multi_source(scraper, cve_list, console):
    """Scrape CVE details from all sources (NVD Web, MITRE, Vulners)."""
    console.print("[bold yellow]🌐 Enriching CVEs from multiple sources...[/bold yellow]")
    console.print("[dim]Sources: NVD Web, MITRE, Vulners, GitHub[/dim]\n")
    
    try:
        updated = await scraper.scrape_from_all_sources(cve_list)
        console.print(f"[green]✓[/green] Enriched {updated} CVEs with additional data\n")
        return updated
    except Exception as e:
        console.print(f"[red]✗[/red] Error enriching CVEs: {e}\n")
        return 0


def main():
    """Main function to update CVE database from multiple sources."""
    console.print("\n")
    console.print(Panel.fit(
        "[bold cyan]🔄 Deep Eye - Multi-Source CVE Database Updater[/bold cyan]\n"
        "[dim]Fetching from NVD, CISA KEV, MITRE, and Exploit-DB[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    # Initialize scraper with browser support
    console.print("[cyan]Initializing CVE scraper...[/cyan]")
    ensure_dirs()
    scraper = CVEScraper(str(cve_db_path()), use_browser=True)
    console.print("[green]✓[/green] Scraper initialized with Playwright browser automation\n")
    
    # Get current stats
    stats = scraper.get_database_stats()
    
    # Display current stats
    table = Table(title="[bold]Current Database Statistics[/bold]", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Count", style="yellow", justify="right")
    
    table.add_row("Total CVEs", str(stats['total_cves']))
    table.add_row("Total Exploits", str(stats['total_exploits']))
    table.add_row("Technologies", str(stats['total_technologies']))
    
    console.print(table)
    console.print()
    
    # Track scraping results
    scraping_results = {}
    
    # 1. Scrape latest vulnerabilities (RSS/JSON feeds)
    console.print("[bold]Step 1/4: Latest Vulnerabilities[/bold]")
    latest_count, latest_cves = asyncio.run(scrape_latest_vulnerabilities(scraper, console))
    scraping_results['latest'] = latest_count
    
    # 2. Enrich CVEs from multiple sources (NVD Web, MITRE, Vulners)
    console.print("[bold]Step 2/4: Multi-Source Enrichment[/bold]")
    if latest_cves:
        cve_ids = [cve['cve_id'] for cve in latest_cves[:50]]  # Limit to 50 for performance
        enriched_count = asyncio.run(scrape_multi_source(scraper, cve_ids, console))
        scraping_results['enriched'] = enriched_count
    else:
        console.print("[dim]Skipping enrichment (no CVEs to enrich)[/dim]\n")
        scraping_results['enriched'] = 0
    
    # 3. NVD API (DISABLED)
    console.print("[bold]Step 3/4: NVD API[/bold]")
    console.print("[dim]NVD API disabled (using NVD Web in Step 2 instead)[/dim]\n")
    nvd_count = 0
    scraping_results['nvd'] = nvd_count
    
    # 4. Scrape Exploit-DB (if browser is available)
    console.print("[bold]Step 4/4: Exploit Database[/bold]")
    console.print("[bold yellow]🔧 Scraping exploit patterns from Exploit-DB...[/bold yellow]")
    console.print("[dim]Using Playwright browser automation...[/dim]\n")
    
    try:
        exploit_count = scraper.scrape_exploit_db(limit=500)
        console.print(f"[green]✓[/green] Scraped {exploit_count} exploit patterns\n")
        scraping_results['exploits'] = exploit_count
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Exploit-DB scraping failed: {e}\n")
        scraping_results['exploits'] = 0
    
    # Display updated stats
    stats = scraper.get_database_stats()
    
    console.print()
    console.print("[bold green]📊 Updated Database Statistics[/bold green]\n")
    
    # Create summary table
    summary_table = Table(show_header=True, header_style="bold green")
    summary_table.add_column("Metric", style="cyan", justify="left")
    summary_table.add_column("Count", style="yellow", justify="right")
    
    summary_table.add_row("Total CVEs", f"[bold]{stats['total_cves']}[/bold]")
    summary_table.add_row("Total Exploits", f"[bold]{stats['total_exploits']}[/bold]")
    summary_table.add_row("Technologies Tracked", f"[bold]{stats['total_technologies']}[/bold]")
    
    console.print(summary_table)
    console.print()
    
    # Severity breakdown
    if stats.get('by_severity'):
        severity_table = Table(title="[bold]CVEs by Severity[/bold]", show_header=True, header_style="bold magenta")
        severity_table.add_column("Severity", style="magenta", justify="left")
        severity_table.add_column("Count", style="yellow", justify="right")
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        for severity in severity_order:
            count = stats.get('by_severity', {}).get(severity, 0)
            if count > 0:
                severity_table.add_row(severity, str(count))
        
        console.print(severity_table)
        console.print()
    
    # Scraping summary
    scrape_summary = Table(title="[bold]Scraping Summary[/bold]", show_header=True, header_style="bold blue")
    scrape_summary.add_column("Source", style="blue", justify="left")
    scrape_summary.add_column("CVEs Added", style="yellow", justify="right")
    
    scrape_summary.add_row("Latest Vulnerabilities (RSS/JSON)", str(scraping_results.get('latest', 0)))
    scrape_summary.add_row("Multi-Source Enrichment", str(scraping_results.get('enriched', 0)))
    scrape_summary.add_row("NVD API (Disabled)", str(scraping_results.get('nvd', 0)))
    scrape_summary.add_row("Exploit-DB Patterns", str(scraping_results.get('exploits', 0)))
    scrape_summary.add_row("[bold]Total", f"[bold]{sum(scraping_results.values())}[/bold]")
    
    console.print(scrape_summary)
    console.print()
    
    console.print(f"[green]✓[/green] Database updated: [cyan]{stats['database_path']}[/cyan]\n")
    
    # Usage tip
    console.print(Panel.fit(
        "[bold cyan]💡 Next Steps:[/bold cyan]\n\n"
        "1. Enable CVE matching in [yellow]config.yaml[/yellow]:\n"
        "   [dim]experimental:\n"
        "     enable_cve_matching: true[/dim]\n\n"
        "2. Run a scan to see CVE intelligence in action:\n"
        "   [dim]python deep_eye.py -u https://target.com[/dim]",
        border_style="green"
    ))
    console.print()


if __name__ == "__main__":
    # Ensure UTF-8 encoding for Windows console
    if sys.platform == 'win32':
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Update cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]")
        sys.exit(1)

