#!/usr/bin/env python3
"""
CVE Database Update Script
Updates the CVE intelligence database from NVD and other sources
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.cve_intelligence.cve_scraper import CVEScraper
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def main():
    """Main function to update CVE database."""
    console.print("\n[bold cyan]🔄 Deep Eye - CVE Database Updater[/bold cyan]\n")
    
    # Initialize scraper
    scraper = CVEScraper("data/cve_intelligence.db")
    
    # Get current stats
    stats = scraper.get_database_stats()
    console.print(f"[cyan]Current database stats:[/cyan]")
    console.print(f"  Total CVEs: {stats['total_cves']}")
    console.print(f"  Total Exploits: {stats['total_exploits']}")
    console.print(f"  Technologies: {stats['total_technologies']}")
    console.print()
    
    # Scrape NVD
    console.print("[bold yellow]⬇️  Scraping CVEs from NVD...[/bold yellow]")
    console.print("[dim]This may take a few minutes...[/dim]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Downloading CVEs from NVD...", total=None)
        
        # Scrape last 365 days of CVEs
        count = scraper.scrape_nvd_cves(days_back=365, limit=2000)
        
        progress.update(task, description=f"[cyan]Downloaded {count} CVEs")
    
    console.print(f"[green]✓[/green] Scraped {count} CVEs from NVD\n")
    
    # Generate exploit patterns
    console.print("[bold yellow]🔧 Generating exploit patterns...[/bold yellow]")
    exploit_count = scraper.scrape_exploit_db(limit=500)
    console.print(f"[green]✓[/green] Generated {exploit_count} exploit patterns\n")
    
    # Display updated stats
    stats = scraper.get_database_stats()
    console.print("[bold green]📊 Updated Database Stats:[/bold green]")
    console.print(f"  Total CVEs: [cyan]{stats['total_cves']}[/cyan]")
    console.print(f"  Total Exploits: [cyan]{stats['total_exploits']}[/cyan]")
    console.print(f"  Technologies Tracked: [cyan]{stats['total_technologies']}[/cyan]")
    console.print(f"  By Severity:")
    for severity, count in stats.get('by_severity', {}).items():
        console.print(f"    {severity}: [yellow]{count}[/yellow]")
    console.print(f"\n[green]✓[/green] Database updated: {stats['database_path']}\n")
    
    console.print("\n[bold cyan]💡 Tip:[/bold cyan] Enable CVE matching in config.yaml:")
    console.print("[dim]experimental:\n  enable_cve_matching: true[/dim]\n")


if __name__ == "__main__":
    main()

