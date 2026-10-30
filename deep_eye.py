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
        default=None,
        help='Configuration file path (default: user config dir, then repo config/config.yaml)'
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

    parser.add_argument(
        '--retest-new',
        type=str,
        default=None,
        metavar='BASELINE_JSON',
        help='After scan, only keep findings that are NEW vs baseline scan JSON'
    )

    parser.add_argument(
        '--scope-nl',
        type=str,
        default=None,
        help='Natural-language scope, e.g. "only /api/* no /logout host target.com"'
    )

    parser.add_argument(
        '--setup',
        action='store_true',
        help='Run interactive config setup wizard and exit'
    )

    parser.add_argument(
        '--setup-force',
        action='store_true',
        help='With --setup, overwrite existing config without extra prompt default'
    )

    parser.add_argument(
        '--check-config',
        action='store_true',
        help='Validate config (check names, ranges) and exit without scanning'
    )

    parser.add_argument(
        '--fail-on',
        type=str,
        default=None,
        choices=['critical', 'high', 'medium', 'low', 'info'],
        help='Exit non-zero when a finding at or above this severity exists'
    )

    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume a previous scan from its checkpoint (skips scanned URLs)'
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


def _fail_on_exit_code(severity_counts: Dict, threshold: str) -> int:
    """Return 1 when any finding meets or exceeds ``threshold``, else 0."""
    order = ['info', 'low', 'medium', 'high', 'critical']
    if threshold not in order:
        return 0
    floor = order.index(threshold)
    for severity in order[floor:]:
        if int(severity_counts.get(severity, 0) or 0) > 0:
            return 1
    return 0


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

        if getattr(args, "setup", False) or getattr(args, "setup_force", False):
            from utils.onboard import run_onboard
            from utils.paths import resolve_config
            setup_target = resolve_config(args.config, migrate=False)
            run_onboard(str(setup_target), force=bool(getattr(args, "setup_force", False)))
            return 0

        # Load configuration (run onboard wizard if config missing)
        from utils.paths import resolve_config
        config_path = resolve_config(args.config)
        if not config_path.exists():
            from utils.onboard import run_onboard
            config = run_onboard(str(config_path))
        else:
            console.print(f"[bold blue]Loading configuration from {config_path}...[/bold blue]")
            config = ConfigLoader.load(str(config_path))

        if getattr(args, 'scope_nl', None):
            from utils.nl_scope import apply_nl_scope_to_config
            config = apply_nl_scope_to_config(config, args.scope_nl)
            console.print(f"[dim]NL scope applied: {args.scope_nl}[/dim]")

        if getattr(args, 'check_config', False):
            from utils.config_validator import validate_config as validate_checks
            from utils.config_validator import format_report
            from utils.paths import describe
            report = validate_checks(config)
            console.print(format_report(report, str(config_path)))
            locations = describe()
            console.print(
                f"[dim]home: {locations['home']}\n"
                f"data: {locations['data_dir']}\n"
                f"logs: {locations['logs_dir']}[/dim]"
            )
            return 0 if not report.errors else 1

        if getattr(args, 'resume', False):
            config.setdefault('scanner', {})['resume'] = True
            console.print("[dim]Resume enabled: previously scanned URLs will be skipped[/dim]")
        
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

        if getattr(args, 'retest_new', None):
            try:
                from core.scan_diff import load_scan_json, _identity_no_sev
                baseline = load_scan_json(args.retest_new)
                base_keys = {
                    _identity_no_sev(v)
                    for v in baseline.get('vulnerabilities', [])
                    if v.get('type') and v.get('url')
                }
                before = len(results.get('vulnerabilities', []))
                results['vulnerabilities'] = [
                    v for v in results.get('vulnerabilities', [])
                    if _identity_no_sev(v) not in base_keys
                ]
                console.print(
                    f"[cyan]Retest-new:[/cyan] kept "
                    f"{len(results['vulnerabilities'])}/{before} new findings "
                    f"vs {args.retest_new}"
                )
            except Exception as e:
                console.print(f"[yellow]Retest-new skipped:[/yellow] {e}")
        
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

        exit_code = 0
        if getattr(args, 'fail_on', None):
            exit_code = _fail_on_exit_code(severity_counts, args.fail_on)
            if exit_code:
                console.print(
                    f"[bold red]Gate failed:[/bold red] findings at or above "
                    f"{args.fail_on} present"
                )
        return exit_code

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main() or 0)
