#!/usr/bin/env python3
"""
Deep Eye - Advanced AI-Driven Penetration Testing Tool
Main Entry Point
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional, Dict
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from core.scanner_engine import ScannerEngine
from core.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.config_loader import ConfigLoader
from ai_providers.provider_manager import AIProviderManager

console = Console()
logger = setup_logger()

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                          ║
║  ⠀⠀⠀⠀⡀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀              
║  ⠀⢸⠉⣹⠋⠉⢉⡟⢩⢋⠋⣽⡻⠭⢽⢉⠯⠭⠭⠭⢽⡍⢹⡍⠙⣯⠉⠉⠉⠉⠉⣿⢫⠉⠉⠉⢉⡟⠉⢿⢹⠉⢉⣉⢿⡝⡉⢩⢿⣻⢍⠉⠉⠩⢹⣟⡏⠉⠹⡉⢻⡍⡇  
║  ⠀⢸⢠⢹⠀⠀⢸⠁⣼⠀⣼⡝⠀⠀⢸⠘⠀⠀⠀⠀⠈⢿⠀⡟⡄⠹⣣⠀⠀⠐⠀⢸⡘⡄⣤⠀⡼⠁⠀⢺⡘⠉⠀⠀⠀⠫⣪⣌⡌⢳⡻⣦⠀⠀⢃⡽⡼⡀⠀⢣⢸⠸⡇      
║  ⠀⢸⡸⢸⠀⠀⣿⠀⣇⢠⡿⠀⠀⠀⠸⡇⠀⠀⠀⠀⠀⠘⢇⠸⠘⡀⠻⣇⠀⠀⠄⠀⡇⢣⢛⠀⡇⠀⠀⣸⠇⠀⠀⠀⠀⠀⠘⠄⢻⡀⠻⣻⣧⠀⠀⠃⢧⡇⠀⢸⢸⡇⡇  
║  ⠀⢸⡇⢸⣠⠀⣿⢠⣿⡾⠁⠀⢀⡀⠤⢇⣀⣐⣀⠀⠤⢀⠈⠢⡡⡈⢦⡙⣷⡀⠀⠀⢿⠈⢻⣡⠁⠀⢀⠏⠀⠀⠀⢀⠀⠄⣀⣐⣀⣙⠢⡌⣻⣷⡀⢹⢸⡅⠀⢸⠸⡇⡇  
║  ⠀⢸⡇⢸⣟⠀⢿⢸⡿⠀⣀⣶⣷⣾⡿⠿⣿⣿⣿⣿⣿⣶⣬⡀⠐⠰⣄⠙⠪⣻⣦⡀⠘⣧⠀⠙⠄⠀⠀⠀⠀⠀⣨⣴⣾⣿⠿⣿⣿⣿⣿⣿⣶⣯⣿⣼⢼⡇⠀⢸⡇⡇⡇  
║  ⠀⢸⢧⠀⣿⡅⢸⣼⡷⣾⣿⡟⠋⣿⠓⢲⣿⣿⣿⡟⠙⣿⠛⢯⡳⡀⠈⠓⠄⡈⠚⠿⣧⣌⢧⠀⠀⠀⠀⠀⣠⣺⠟⢫⡿⠓⢺⣿⣿⣿⠏⠙⣏⠛⣿⣿⣾⡇⢀⡿⢠⠀⡇  
║  ⠀⢸⢸⠀⢹⣷⡀⢿⡁⠀⠻⣇⠀⣇⠀⠘⣿⣿⡿⠁⠐⣉⡀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠳⠄⠀⠀⠀⠀⠋⠀⠘⡇⠀⠸⣿⣿⠟⠀⢈⣉⢠⡿⠁⣼⠁⣼⠃⣼⠀⡇  
║  ⠀⢸⠸⣀⠈⣯⢳⡘⣇⠀⠀⠈⡂⣜⣆⡀⠀⠀⢀⣀⡴⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢽⣆⣀⠀⠀⠀⣀⣜⠕⡊⠀⣸⠇⣼⡟⢠⠏⠀⡇  
║  ⠀⢸⠀⡟⠀⢸⡆⢹⡜⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠋⣾⡏⡇⡎⡇⠀⡇  
║  ⠀⢸⠀⢃⡆⠀⢿⡄⠑⢽⣄⠀⠀⠀⢀⠂⠠⢁⠈⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠄⡐⢀⠂⠀⠀⣠⣮⡟⢹⣯⣸⣱⠁⠀⡇  
║  ⠀⠈⠉⠉⠋⠉⠉⠋⠉⠉⠉⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠋⡟⠉⠉⡿⠋⠋⠋⠉⠉⠁  
║                                                                               
║                  Advanced AI-Driven Penetration Testing Tool                 
║                      Version 1.4.0 - Code Name (Hanzou)                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
"""


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Deep Eye - AI-Driven Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan with target from CLI:
    python deep_eye.py -u https://example.com
  
  Scan with target from config:
    python deep_eye.py --config myconfig.yaml
  
  Verbose mode:
    python deep_eye.py -u https://example.com -v
  
Note: All scan options are configured in config.yaml
      Use --config to specify a custom configuration file
        """
    )
    
    # Essential options only
    parser.add_argument(
        '-u', '--url',
        type=str,
        help='Target URL to scan (overrides config)'
    )
    
    parser.add_argument(
        '-c', '--config',
        type=str,
        default='config/config.yaml',
        help='Configuration file path (default: config/config.yaml)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Deep Eye v1.4.0 (Hanzou)',
        help='Show version and exit'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner display'
    )

    parser.add_argument(
        '--formats',
        type=str,
        default=None,
        help='Comma-separated report formats (e.g. junit,csv,xlsx). Overrides config.'
    )

    parser.add_argument(
        '--diff',
        nargs=2,
        metavar=('BASELINE', 'CURRENT'),
        help='Diff two scan JSON files instead of running a scan'
    )

    parser.add_argument(
        '--diff-output',
        type=str,
        default=None,
        help='Output path for diff report (default: reports/diff_<timestamp>.<ext>)'
    )

    parser.add_argument(
        '--diff-format',
        type=str,
        choices=['html', 'json', 'csv'],
        default='html',
        help='Diff report format (default: html)'
    )

    return parser.parse_args()


def display_banner():
    """Display the Deep Eye banner."""
    console.print(BANNER, style="bold cyan")
    console.print("⚠️  [bold yellow]Use only on authorized targets[/bold yellow] ⚠️\n")


def validate_config(config: Dict, target_url: str) -> bool:
    """Validate configuration and target URL."""
    # Validate URL
    if not target_url:
        console.print("[bold red]Error:[/bold red] Target URL is required. Specify in config or use -u option.")
        return False
    
    if not target_url.startswith(('http://', 'https://')):
        console.print("[bold red]Error:[/bold red] URL must start with http:// or https://")
        return False
    
    # Validate scanner settings
    scanner_config = config.get('scanner', {})
    depth = scanner_config.get('default_depth', 2)
    threads = scanner_config.get('default_threads', 5)
    
    if depth < 1 or depth > 10:
        console.print("[bold red]Error:[/bold red] Depth must be between 1 and 10 (check config)")
        return False
    
    if threads < 1 or threads > 50:
        console.print("[bold red]Error:[/bold red] Threads must be between 1 and 50 (check config)")
        return False
    
    return True


def _run_diff_mode(args) -> int:
    """Run scan diff between two JSON files. Returns exit code."""
    from core.scan_diff import diff_scans, load_scan_json
    from utils.exports.diff_renderer import render_html, render_json, render_csv
    from datetime import datetime

    baseline_path, current_path = args.diff
    try:
        baseline = load_scan_json(baseline_path)
        current = load_scan_json(current_path)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"[bold red]Error:[/bold red] Failed to load scan JSON: {e}")
        return 2

    diff = diff_scans(baseline, current)
    summary = diff.get("summary", {})

    # Resolve output path
    output_path = args.diff_output
    if not output_path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        Path("reports").mkdir(parents=True, exist_ok=True)
        ext = {"html": "html", "json": "json", "csv": "csv"}[args.diff_format]
        output_path = f"reports/diff_{timestamp}.{ext}"

    fmt = args.diff_format
    if fmt == "html":
        render_html(diff, output_path)
    elif fmt == "json":
        render_json(diff, output_path)
    elif fmt == "csv":
        render_csv(diff, output_path)

    console.print(f"\n[bold cyan]Scan Diff Summary[/bold cyan]")
    console.print(f"  Baseline: {baseline_path} ({diff['baseline']['vuln_count']} vulns)")
    console.print(f"  Current:  {current_path} ({diff['current']['vuln_count']} vulns)")
    console.print(f"  [bold red]New:[/bold red] {summary.get('new', 0)}")
    console.print(f"  [bold green]Fixed:[/bold green] {summary.get('fixed', 0)}")
    console.print(f"  [bold yellow]Severity Changed:[/bold yellow] {summary.get('severity_changed', 0)}")
    console.print(f"  Unchanged: {summary.get('unchanged', 0)}")
    console.print(f"  Net Delta: {summary.get('net_delta', 0)}")
    console.print(f"\n[bold green]✓[/bold green] Diff report saved to: {output_path}")
    return 0


def main():
    """Main execution function."""
    try:
        # Parse arguments
        args = parse_arguments()

        # Display banner
        if not args.no_banner:
            display_banner()

        # Diff mode: skip scan, run diff between two JSON files
        if args.diff:
            return _run_diff_mode(args)

        # Load configuration (run onboard wizard if config missing)
        config_path = Path(args.config)
        if not config_path.exists():
            from utils.onboard import run_onboard
            config = run_onboard(str(config_path))
        else:
            console.print("[bold blue]Loading configuration...[/bold blue]")
            config = ConfigLoader.load(args.config)
        
        # Get scanner config
        scanner_config = config.get('scanner', {})
        
        # Target URL: CLI overrides config
        target_url = args.url or scanner_config.get('target_url', '')
        
        # Validate configuration
        if not validate_config(config, target_url):
            sys.exit(1)
        
        # Get all settings from config
        depth = scanner_config.get('default_depth', 2)
        threads = scanner_config.get('default_threads', 5)
        ai_provider = scanner_config.get('ai_provider', 'openai')
        enable_recon = scanner_config.get('enable_recon', False)
        full_scan = scanner_config.get('full_scan', False)
        quick_scan = scanner_config.get('quick_scan', False)
        proxy = scanner_config.get('proxy') or None
        custom_headers = scanner_config.get('custom_headers', {})
        cookies = scanner_config.get('cookies', {})
        verbose = args.verbose
        
        # Experimental features
        experimental_config = config.get('experimental', {})
        scan_subdomains = experimental_config.get('enable_subdomain_scanning', False)
        
        # Initialize AI Provider
        console.print(f"[bold blue]Initializing AI Provider: {ai_provider}[/bold blue]")
        ai_manager = AIProviderManager(config)
        ai_manager.set_provider(ai_provider)
        
        # Initialize Scanner Engine
        console.print("[bold blue]Initializing Scanner Engine...[/bold blue]")
        scanner = ScannerEngine(
            target_url=target_url,
            config=config,
            ai_manager=ai_manager,
            depth=depth,
            threads=threads,
            proxy=proxy,
            custom_headers=custom_headers,
            cookies=cookies,
            verbose=verbose
        )
        
        # Display scan configuration
        scan_mode = 'Full Scan' if full_scan else 'Quick Scan' if quick_scan else 'Standard Scan'
        
        config_text = f"""[bold]Target:[/bold] {target_url}
[bold]Depth:[/bold] {depth}
[bold]Threads:[/bold] {threads}
[bold]AI Provider:[/bold] {ai_provider}
[bold]Scan Mode:[/bold] {scan_mode}
[bold]Reconnaissance:[/bold] {'Enabled' if enable_recon else 'Disabled'}"""
        
        if scan_subdomains:
            config_text += f"\n[bold]Subdomain Scanning:[/bold] [yellow]Enabled (Experimental)[/yellow]"
        
        if experimental_config.get('enable_cve_matching', False):
            config_text += f"\n[bold]CVE Matching:[/bold] [yellow]Enabled (Experimental)[/yellow]"
        
        scan_info = Panel(
            config_text,
            title="Scan Configuration",
            border_style="green"
        )
        console.print(scan_info)
        
        # Start scanning
        console.print("\n[bold green]Starting scan...[/bold green]\n")
        
        results = scanner.scan(
            enable_recon=enable_recon,
            full_scan=full_scan,
            quick_scan=quick_scan,
            scan_subdomains=scan_subdomains
        )
        
        # Generate report (from config)
        reporting_config = config.get('reporting', {})
        if reporting_config.get('enabled', True):
            console.print("\n[bold blue]Generating report...[/bold blue]")
            report_gen = ReportGenerator(config)

            # Get output settings from config
            output_dir = reporting_config.get('output_directory', 'reports')
            output_filename = reporting_config.get('output_filename', '')

            # Resolve formats: CLI --formats > config formats list > default_format
            if args.formats:
                formats = [f.strip() for f in args.formats.split(',') if f.strip()]
            elif reporting_config.get('formats'):
                formats = list(reporting_config['formats'])
            else:
                formats = [reporting_config.get('default_format', 'html')]

            # Create output directory if it doesn't exist
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            # Generate stem (without extension) once, reused across formats
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            domain = Path(target_url).stem.replace(':', '_')

            if output_filename:
                # User-specified filename: strip extension, use as stem
                stem = Path(output_filename).stem
            else:
                stem = f"deep_eye_{domain}_{timestamp}"

            # Format → file extension mapping
            ext_map = {
                'html': 'html',
                'pdf': 'pdf',
                'json': 'json',
                'sarif': 'sarif.json',
                'junit': 'junit.xml',
                'csv': 'csv',
                'xlsx': 'xlsx',
            }

            for fmt in formats:
                ext = ext_map.get(fmt, fmt)
                output_path = str(Path(output_dir) / f"{stem}.{ext}")
                try:
                    report_gen.generate(
                        results=results,
                        output_path=output_path,
                        format=fmt
                    )
                    console.print(f"[bold green]✓[/bold green] {fmt.upper()} report saved to: {output_path}")
                except ValueError as e:
                    console.print(f"[bold red]✗[/bold red] {fmt}: {e}")
                except Exception as e:
                    logger.error(f"Failed to generate {fmt} report: {e}", exc_info=True)
                    console.print(f"[bold red]✗[/bold red] {fmt}: {e}")
        
        # Display summary
        vuln_count = len(results.get('vulnerabilities', []))
        severity_counts = results.get('severity_summary', {})
        
        summary = Panel(
            f"""[bold]Total Vulnerabilities:[/bold] {vuln_count}
[bold red]Critical:[/bold red] {severity_counts.get('critical', 0)}
[bold yellow]High:[/bold yellow] {severity_counts.get('high', 0)}
[bold blue]Medium:[/bold blue] {severity_counts.get('medium', 0)}
[bold green]Low:[/bold green] {severity_counts.get('low', 0)}
[bold]URLs Crawled:[/bold] {results.get('urls_crawled', 0)}
[bold]Scan Duration:[/bold] {results.get('duration', 'N/A')}""",
            title="Scan Summary",
            border_style="cyan"
        )
        console.print("\n", summary)
        
        # Display experimental features info if enabled
        if scan_subdomains or experimental_config.get('enable_cve_matching', False):
            console.print("\n[bold yellow]ℹ️  Experimental Features Active:[/bold yellow]")
            if scan_subdomains:
                subdomain_count = results.get('subdomain_scan', {}).get('subdomains_found', 0)
                console.print(f"  • Subdomain Scanning: {subdomain_count} subdomains discovered and scanned")
            if experimental_config.get('enable_cve_matching', False):
                console.print(f"  • CVE Intelligence: Technology-CVE matching enabled")
        
        console.print("\n[bold green]Scan completed successfully![/bold green] 🎉\n")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
