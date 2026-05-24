"""
Deep Eye v1.2.0 - Advanced Features Demo
Demonstrates WebSocket testing, ML detection, OSINT, and Interactive Reports
"""

import yaml
from utils.http_client import HTTPClient
from core.vulnerability_scanner import VulnerabilityScanner
from modules.reporting import InteractiveReportGenerator


def load_config():
    """Load configuration from config.yaml."""
    try:
        with open('config/config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("⚠️  Config file not found. Using example config...")
        with open('config/config.example.yaml', 'r') as f:
            return yaml.safe_load(f)


def demo_websocket_testing(scanner, target_url):
    """Demonstrate WebSocket security testing."""
    print("\n🔌 WebSocket Security Testing Demo")
    print("=" * 60)
    
    # Detect WebSocket endpoints
    ws_endpoints = scanner.websocket_tester.detect_websocket_endpoints(
        target_url, 
        "<script>var ws = new WebSocket('ws://example.com/chat');</script>"
    )
    
    if ws_endpoints:
        print(f"✅ Found {len(ws_endpoints)} WebSocket endpoint(s)")
        for endpoint in ws_endpoints:
            print(f"   • {endpoint}")
            
            # Test the endpoint
            print(f"\n   Testing {endpoint}...")
            vulnerabilities = scanner.websocket_tester.test(endpoint)
            
            if vulnerabilities:
                print(f"   ⚠️  Found {len(vulnerabilities)} issue(s)")
                for vuln in vulnerabilities:
                    print(f"      - {vuln['type']} ({vuln['severity']})")
            else:
                print("   ✅ No vulnerabilities found")
    else:
        print("ℹ️  No WebSocket endpoints detected")


def demo_ml_anomaly_detection(scanner):
    """Demonstrate ML-based anomaly detection."""
    print("\n🤖 Machine Learning Anomaly Detection Demo")
    print("=" * 60)
    
    # Sample scan results
    scan_results = [
        {'url': 'http://example.com/api/users', 'response_time': 0.15, 'status_code': 200, 'response_size': 1024},
        {'url': 'http://example.com/api/users', 'response_time': 0.18, 'status_code': 200, 'response_size': 1100},
        {'url': 'http://example.com/api/users', 'response_time': 5.2, 'status_code': 500, 'response_size': 50},  # Anomaly
        {'url': 'http://example.com/api/products', 'response_time': 0.12, 'status_code': 200, 'response_size': 2048},
    ]
    
    print(f"📊 Analyzing {len(scan_results)} scan results...")
    
    # Train baseline
    print("🔄 Training baseline model...")
    scanner.anomaly_detector.train(scan_results[:2])
    
    # Detect anomalies
    anomalies = scanner.anomaly_detector.analyze_scan_results(scan_results)
    
    if anomalies:
        print(f"\n⚠️  Detected {len(anomalies)} anomaly(ies)")
        for anomaly in anomalies:
            print(f"   • {anomaly.get('description', 'Unknown anomaly')}")
            print(f"     Score: {anomaly.get('anomaly_score', 0):.2f}")
    else:
        print("✅ No anomalies detected")


def demo_osint_reconnaissance(scanner, target_domain):
    """Demonstrate enhanced OSINT reconnaissance."""
    print("\n🔍 Enhanced OSINT Reconnaissance Demo")
    print("=" * 60)
    
    print(f"🌐 Gathering intelligence for: {target_domain}")
    
    # Gather OSINT
    osint_data = scanner.gather_osint(target_domain)
    
    # Display results
    if osint_data.get('emails'):
        print(f"\n📧 Email Addresses Found: {len(osint_data['emails'])}")
        for email in osint_data['emails'][:5]:
            print(f"   • {email}")
    
    if osint_data.get('subdomains'):
        print(f"\n🌐 Subdomains Found: {len(osint_data['subdomains'])}")
        for subdomain in osint_data['subdomains'][:5]:
            print(f"   • {subdomain}")
    
    if osint_data.get('social_media'):
        print(f"\n👥 Social Media Profiles:")
        for platform, url in osint_data['social_media'].items():
            if url:
                print(f"   • {platform}: {url}")
    
    if osint_data.get('breaches'):
        print(f"\n⚠️  Data Breaches Found: {len(osint_data['breaches'])}")
        for breach in osint_data['breaches'][:3]:
            print(f"   • {breach}")
    
    print(f"\n✅ OSINT reconnaissance complete")


def demo_payload_obfuscation(scanner):
    """Demonstrate advanced payload obfuscation."""
    print("\n🎭 Advanced Payload Obfuscation Demo")
    print("=" * 60)
    
    # Original payloads
    payloads = {
        'xss': "<script>alert('XSS')</script>",
        'sql_injection': "' OR '1'='1",
        'command_injection': "; cat /etc/passwd"
    }
    
    print("📝 Original Payloads:")
    for attack_type, payload in payloads.items():
        print(f"   • {attack_type}: {payload}")
    
    print("\n🔄 Applying obfuscation techniques...")
    
    for attack_type, payload in payloads.items():
        obfuscated = scanner.payload_obfuscator.obfuscate_payload(
            payload, 
            attack_type,
            techniques=['base64_encoding', 'url_encoding', 'unicode_encoding']
        )
        print(f"\n🎭 {attack_type.upper()}:")
        print(f"   Original:   {payload}")
        print(f"   Obfuscated: {obfuscated[:100]}{'...' if len(obfuscated) > 100 else ''}")


def demo_interactive_report():
    """Demonstrate interactive HTML report generation."""
    print("\n📊 Interactive HTML Report Generation Demo")
    print("=" * 60)
    
    # Sample vulnerabilities
    sample_vulnerabilities = [
        {
            'type': 'SQL Injection',
            'severity': 'critical',
            'url': 'http://example.com/api/users?id=1',
            'description': 'SQL injection vulnerability allows database manipulation',
            'evidence': "Error: MySQL syntax error at line 1",
            'remediation': 'Use parameterized queries or prepared statements'
        },
        {
            'type': 'Cross-Site Scripting (XSS)',
            'severity': 'high',
            'url': 'http://example.com/search?q=test',
            'description': 'Reflected XSS allows arbitrary JavaScript execution',
            'evidence': "<script>alert('XSS')</script> reflected in response",
            'remediation': 'Implement proper input validation and output encoding'
        },
        {
            'type': 'Missing Security Headers',
            'severity': 'medium',
            'url': 'http://example.com/',
            'description': 'Critical security headers are missing',
            'evidence': 'X-Frame-Options, CSP, HSTS headers not found',
            'remediation': 'Add security headers to all HTTP responses'
        }
    ]
    
    # Generate report
    config = load_config()
    report_generator = InteractiveReportGenerator(config)
    
    scan_results = {
        'target': 'http://example.com',
        'scan_time': '2025-10-15T12:00:00',
        'vulnerabilities': sample_vulnerabilities
    }
    
    output_file = 'reports/demo_interactive_report.html'
    report_path = report_generator.generate_interactive_report(scan_results, output_file)
    
    print(f"✅ Interactive report generated: {report_path}")
    print("   Features:")
    print("   • Interactive severity filtering")
    print("   • Real-time search functionality")
    print("   • Chart.js visualizations")
    print("   • Responsive design")
    print("   • Detailed vulnerability cards")


def main():
    """Main demo function."""
    print("\n" + "=" * 60)
    print("🔍 Deep Eye v1.2.0 - Advanced Features Demo")
    print("=" * 60)
    
    # Load configuration
    config = load_config()
    
    # Initialize components
    http_client = HTTPClient(config)
    scanner = VulnerabilityScanner(config, http_client)
    
    # Demo target
    target_url = "http://example.com"
    target_domain = "example.com"
    
    # Run demos
    try:
        demo_websocket_testing(scanner, target_url)
        demo_ml_anomaly_detection(scanner)
        demo_osint_reconnaissance(scanner, target_domain)
        demo_payload_obfuscation(scanner)
        demo_interactive_report()
        
        print("\n" + "=" * 60)
        print("✅ Demo completed successfully!")
        print("=" * 60)
        print("\n📚 Next Steps:")
        print("   1. Configure AI providers in config/config.yaml")
        print("   2. Run: python deep_eye.py -u <target-url>")
        print("   3. Enable v1.2.0 modules in configuration")
        print("   4. View interactive reports in reports/ folder")
        print("\n⚠️  Warning: Only test on authorized targets!")
        
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        print("   Make sure all dependencies are installed:")
        print("   pip install -r requirements.txt")


if __name__ == "__main__":
    main()
