#!/usr/bin/env python3
"""
Example usage of Deep Eye
"""

from core.scanner_engine import ScannerEngine
from core.report_generator import ReportGenerator
from ai_providers.provider_manager import AIProviderManager
from utils.config_loader import ConfigLoader
from utils.logger import setup_logger

# Setup logging
logger = setup_logger(
    name="deep_eye_example",
    level="INFO",
    log_file="logs/example.log"
)

def main():
    """Example usage."""
    
    # Load configuration
    config = ConfigLoader.load("config/config.yaml")
    
    # Initialize AI Provider
    ai_manager = AIProviderManager(config)
    ai_manager.set_provider("openai")  # or "claude", "grok", "ollama"
    
    # Configure scan
    target_url = "https://example.com"
    
    # Initialize Scanner
    scanner = ScannerEngine(
        target_url=target_url,
        config=config,
        ai_manager=ai_manager,
        depth=2,
        threads=5,
        verbose=True
    )
    
    print(f"[*] Starting scan on {target_url}")
    
    # Run scan
    results = scanner.scan(
        enable_recon=True,
        full_scan=True
    )
    
    print(f"[+] Scan complete!")
    print(f"[+] Found {len(results['vulnerabilities'])} vulnerabilities")
    
    # Generate report
    report_gen = ReportGenerator(config)
    
    # Generate HTML report
    report_gen.generate(
        results=results,
        output_path="reports/scan_report.html",
        format="html"
    )
    
    print(f"[+] Report saved to: reports/scan_report.html")
    
    # Print summary
    severity_counts = results['severity_summary']
    print("\n=== Vulnerability Summary ===")
    print(f"Critical: {severity_counts.get('critical', 0)}")
    print(f"High: {severity_counts.get('high', 0)}")
    print(f"Medium: {severity_counts.get('medium', 0)}")
    print(f"Low: {severity_counts.get('low', 0)}")


if __name__ == "__main__":
    main()
