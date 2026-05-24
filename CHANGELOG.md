# Changelog

All notable changes to Deep Eye will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2025-12-30

#### Fixed
- **NIX Installer** - Fixed issue where *nix installer unable to run as expected.
## [1.4.0] - 2025-10-27

### Added

#### AI-Powered Browser Automation with Browser Use
- **Smart Browser Tester Module** - AI-driven browser-based vulnerability testing
  - **Browser Use Integration** - Uses Browser Use ([browser-use.com](https://browser-use.com)) - 71.8k+ GitHub stars
  - **AI-Powered XSS Testing** - GPT-4 intelligently navigates pages and tests for XSS
  - **AI SQLi Detection** - AI reads page content and identifies SQL error messages
  - **Intelligent Form Interaction** - AI automatically finds and fills form fields
  - **Hidden Element Discovery & Testing** - AI finds and evaluates hidden inputs, forms, and elements
    - Discovers hidden input fields (type="hidden")
    - Finds display:none and visibility:hidden elements
    - Detects opacity:0 and off-screen positioned elements
    - Tests for hidden element manipulation vulnerabilities
    - Identifies sensitive data exposure in hidden fields (API keys, tokens, credentials)
    - Evaluates hidden forms and iframes for security issues
  - **Context Understanding** - AI understands page structure and interactions
  - **Adaptive Testing** - AI adapts to different web application patterns
  - **Automatic Fallback** - Falls back to Playwright if Browser Use unavailable
  - **DOM XSS Testing** - Test for DOM-based XSS vulnerabilities
  - **Clickjacking Detection** - Verify X-Frame-Options protection
  - **Screenshot Capture** - Auto-capture proof-of-concept screenshots as base64
  - **Dialog Detection** - Detect and handle JavaScript alert/confirm/prompt dialogs
  - **Async Operations** - Asynchronous browser operations for better performance

#### Enhanced Reporting System
- **Interactive HTML Reports with Modern UI**
  - **Chart.js Integration** - Visual severity distribution and vulnerability type charts
  - **DataTables Integration** - Sortable, searchable, and paginated vulnerability tables
  - **Dynamic Filtering** - Filter vulnerabilities by severity and type in real-time
  - **Expandable Details** - View full vulnerability details without leaving the report
  - **Screenshot Evidence** - Embedded base64 screenshots directly in HTML reports
  - **Responsive Design** - Mobile-friendly report layout
  - **Export Options** - Export to CSV, Excel, and print-friendly formats
  - **Evidence Boxes** - Highlighted payload and evidence sections with syntax highlighting

#### Real-Time Pentest State Management
- **Pentest State Manager** - Track and display pentest progress in real-time
  - **Phase Tracking** - Monitor current phase (Initialization, Recon, Crawling, Scanning, Reporting)
  - **Live Statistics** - Real-time vulnerability counts by severity
  - **Attack Tracking** - Monitor individual attack attempts with success/failure rates
  - **Time Tracking** - Per-phase elapsed time and total scan duration
  - **Progress Display** - Rich CLI tables showing current state
  - **Attack Statistics** - Comprehensive attack type statistics with success rates
  - **State Persistence** - Export state for analysis and reporting

#### Optimized Attack Logic
- **Context-Aware Payload Generation**
  - **Technology Stack Detection** - Automatically detect web technologies (PHP, ASP.NET, WordPress, etc.)
  - **WAF Detection** - Identify Web Application Firewalls (Cloudflare, Sucuri, Akamai, etc.)
  - **Database-Specific Payloads** - Generate targeted SQLi payloads for MySQL, PostgreSQL, MSSQL, Oracle
  - **WAF Bypass Payloads** - Automatic WAF bypass techniques when WAF is detected
  - **Payload Caching** - Cache generated payloads for improved performance
  - **Smart Payload Selection** - Limit payloads to most effective ones based on context
  - **SSTI Detection** - Technology-specific SSTI payloads (Jinja, Flask, Django, PHP)
  - **LFI/RFI Optimization** - Enhanced file inclusion payloads

#### Enhanced Payload System
- **Improved Payload Diversity**
  - Database-specific SQL injection payloads
  - Context-aware XSS payloads (JSON, HTML, etc.)
  - Advanced XSS event handlers (animate, autofocus, marquee, etc.)
  - WAF bypass techniques (encoding, obfuscation, case manipulation)
  - Template injection payloads for various frameworks
  - Enhanced LFI/RFI payloads with null byte injection

#### Experimental Features (v1.4.0+)
- **CVE Intelligence System** - Real-world vulnerability intelligence
  - **CVE Scraper** - Scrapes CVEs from NVD (National Vulnerability Database)
  - **SQLite Storage** - Stores CVEs, exploits, and technology mappings
  - **CVE Matcher** - Matches detected technologies with relevant CVEs
  - **Exploit Extraction** - Extracts exploit payloads from CVE data
  - **CVE-Based Payloads** - Generates payloads based on real CVE exploits
  - **Technology Mapping** - Maps CVEs to affected technologies and versions
  - **Auto-Update Script** - `scripts/update_cve_database.py` for easy updates
  - **Severity Filtering** - Filter CVEs by severity (CRITICAL, HIGH, MEDIUM, LOW)
  
- **Advanced Subdomain Reconnaissance** - Comprehensive subdomain discovery and scanning
  - **Certificate Transparency** - Query crt.sh for subdomain certificates
  - **DNS Bruteforce** - Test 100+ common subdomain patterns
  - **Search Engine Enumeration** - Discover subdomains via search engines
  - **Subdomain Verification** - Verify subdomain liveness via HTTP/HTTPS
  - **Parallel Scanning** - Scan multiple subdomains concurrently
  - **Subdomain Intelligence** - Gather info (IP, server, title, technologies) per subdomain
  - **Aggregate Reporting** - Combine all subdomain vulnerabilities in main report
  - **Smart Filtering** - Limit number of subdomains to scan (configurable)

### Changed
- **AI Provider Support Expanded**
  - Added Google Gemini as AI provider option
  - Now supports 5 AI providers: OpenAI, Claude, Grok, OLLAMA, Gemini
  - Gemini offers fast and cost-effective AI-powered testing
  
- **Scanner Engine Updates**
  - Integrated browser automation for enhanced testing
  - Added state management for real-time progress tracking
  - Improved vulnerability detection with browser verification
  - Enhanced CLI output with phase indicators and real-time stats
  - Better error handling and logging
  - Added hidden element testing to all browser scans
  - Added subdomain discovery and scanning capability

- **Vulnerability Scanner Improvements**
  - Added state_manager parameter to scan() method for tracking
  - Individual attack tracking with start/end timestamps
  - Success/failure tracking per attack type
  - Improved evidence collection with more details

- **Configuration Enhancements**
  - Added `enable_javascript_rendering` option for browser testing
  - Added `screenshot_enabled` option for screenshot capture
  - Updated comments with installation requirements

- **Report Generation**
  - Complete HTML template overhaul with modern design
  - Added Chart.js and DataTables dependencies via CDN
  - Improved evidence presentation with highlighted boxes
  - Better mobile responsiveness
  - Screenshot support in HTML reports

- **Performance Optimizations**
  - Payload caching reduces redundant AI calls
  - Context hashing for efficient cache lookups
  - Reduced payload count with smart selection
  - Deduplication of generated payloads
  - CVE database indexing for fast lookups
  - Parallel subdomain verification

- **CVE Intelligence Integration**
  - AI payload generator now uses CVE database for targeted payloads
  - Automatic technology-to-CVE matching
  - Prioritizes CVE-based exploits over generic payloads
  - Real-world exploit patterns from CVE data

### Fixed
- Browser automation error handling
- Screenshot capture in different scenarios
- Payload generation for edge cases
- State tracking in concurrent scans
- CLI progress indicators showing correct phase

### Dependencies
- Added `playwright>=1.40.0` for browser automation
- Added `browser-use>=0.1.0` for AI-powered browser automation (71.8k+ stars)
- Added `langchain-openai>=0.1.0` for Browser Use AI integration
- Added `google-generativeai>=0.3.0` for Google Gemini AI provider
- Chart.js 4.4.0 (CDN) for interactive charts
- DataTables 1.13.7 (CDN) for enhanced tables
- jQuery 3.7.0 (CDN) for DataTables functionality
- Uses existing `dnspython` for DNS subdomain enumeration
- Uses existing `sqlite3` (built-in) for CVE database

### New Scripts
- Added `scripts/update_cve_database.py` - CVE database updater and builder
  - Scrapes CVEs from NVD API (with fallback to built-in patterns)
  - Creates SQLite database with CVE intelligence
  - Generates exploit patterns automatically
  - Display comprehensive database statistics

### Documentation
- Updated QUICKSTART.md with browser automation instructions
- Added advanced features section
- Added configuration examples for new features
- Added troubleshooting for browser automation
- Added performance tips
- Added experimental features documentation (CVE Intelligence, Subdomain Scanning)
- Added CVE database update instructions
- Added subdomain scanning examples
- Updated README.md with v1.4.0 features and experimental section

## [1.3.0] - 2025-10-20

### Added

#### New Features
- **Custom Plugin System** - Extensible architecture for custom vulnerability scanners
  - Plugin base class for easy development
  - Hot-reload plugin loading from `plugins/` directory
  - Example plugin included for demonstration
  - Plugin enable/disable via configuration
  - Automatic plugin discovery and initialization
  
- **Multi-Channel Notification System** - Real-time alerts for scan completion and critical findings
  - **Email Notifications** - SMTP-based email alerts with HTML formatting
  - **Slack Integration** - Webhook-based Slack notifications with rich formatting
  - **Discord Integration** - Discord webhook notifications with embed support
  - Immediate alerts for critical vulnerabilities
  - Configurable notification triggers
  - Detailed scan summary in notifications
  
- **Enhanced Reporting with OSINT Data** - Comprehensive reconnaissance data in reports
  - DNS records displayed in PDF and HTML reports
  - OSINT findings integration (emails, subdomains, technologies)
  - GitHub leak detection in reports
  - Breach database results
  - Social media footprint
  - Beautiful formatting with dedicated sections

#### New Vulnerability Scanners
- **15 New Vulnerability Scanners** - Expanded from 30+ to 45+ attack methods
  - **Local File Inclusion (LFI)** - Detects file inclusion vulnerabilities for reading local files
  - **Remote File Inclusion (RFI)** - Identifies remote file inclusion leading to potential RCE
  - **Server-Side Template Injection (SSTI)** - Tests for template injection vulnerabilities
  - **CRLF Injection** - Checks for header manipulation and response splitting
  - **Host Header Injection** - Detects cache poisoning and SSRF via Host header
  - **LDAP Injection** - Tests for LDAP query manipulation vulnerabilities
  - **XML Injection** - Identifies XML structure manipulation issues
  - **Insecure Deserialization** - Detects unsafe deserialization patterns (Java, Python, PHP)
  - **Authentication Bypass** - Tests various authentication bypass techniques
  - **Information Disclosure** - Scans for exposed sensitive information (passwords, API keys, secrets)
  - **Sensitive Data Exposure** - Detects PII exposure (SSN, credit cards, emails, phone numbers)
  - **JWT Vulnerabilities** - Checks for JWT "none" algorithm and weak signing algorithms
  - **Broken Authentication** - Tests session management security (Secure/HttpOnly flags, weak session IDs)
  - **API Vulnerabilities** (alias) - Backward compatibility for api_security
  - **GraphQL Vulnerabilities** (alias) - Backward compatibility for graphql_security

### Changed
- Updated vulnerability scanner from 30+ to 45+ attack methods
- Enhanced scanner engine with comprehensive coverage of OWASP Top 10 and beyond
- All new scanners include detailed evidence collection and remediation guidance
- Improved error handling and logging for all scanner modules
- **CLI simplified** - All scan options now configured via config.yaml (CLI only has -u, -c, -v, --version)
- **Report generation** - Now fully controlled by config (output directory, filename, format)
- **Config-driven architecture** - All modules read settings from centralized config

### Fixed
- **PDF Report Generation** - Fixed XML/HTML special character escaping for valid PDF output
- **OSINT Integration** - Enhanced OSINT data collection and proper integration into reconnaissance flow
- **Reconnaissance Data Flow** - OSINT results properly flattened and accessible in reports (emails, subdomains, technologies, breaches, GitHub leaks)

## [1.2.1] - 2025-10-15

### Fixed
- **PDF Report Generation on Windows**
  - Replaced WeasyPrint with ReportLab for Windows compatibility
  - WeasyPrint requires GTK libraries which are problematic on Windows
  - ReportLab provides native Windows support with no external dependencies
  - Added automatic fallback to HTML if PDF generation fails
  - Improved error handling and user feedback
  - Updated requirements.txt (WeasyPrint now optional/commented)

### Changed
- **Report Generator Improvements**
  - Enhanced PDF layout with professional styling
  - Added color-coded severity indicators in PDF reports
  - Improved table formatting for better readability
  - Added comprehensive metadata section
  - Better vulnerability detail presentation

- **OSINT Refactoring**
  - Moved OSINT gathering from vulnerability scanner to reconnaissance phase
  - OSINT intelligence is now collected during reconnaissance (--recon flag)
  - Integrated EnhancedOSINT module into ReconEngine
  - OSINT data is now available in scan context for all modules
  - Updated configuration: removed 'osint_gathering' from vulnerability_scanner checks
  - Added 'osint_gathering' to reconnaissance enabled_modules
  - Cleaner separation of concerns: recon gathers intelligence, scanner tests vulnerabilities

## [1.2.0] - 2025-10-15

### Added
- **WebSocket Security Testing Module**
  - Origin header validation testing
  - WebSocket authentication verification
  - Message injection attack detection (XSS, SQLi, Command injection)
  - DoS attack testing (large payloads, message flooding)
  - Rate limiting verification
  - TLS/SSL verification for WSS connections
  - Protocol downgrade attack detection
  - Information disclosure testing
  - Automatic WebSocket endpoint detection
- **Machine Learning Anomaly Detection Module**
  - Unsupervised anomaly detection using IsolationForest
  - Response time pattern analysis
  - Status code anomaly detection
  - Error message clustering
  - Response size analysis
  - Parameter behavior monitoring
  - Baseline training capability
  - Composite anomaly scoring
- **Interactive HTML Report Generator**
  - Dynamic JavaScript-based filtering by severity
  - Real-time vulnerability search
  - Interactive Chart.js visualizations (doughnut, bar charts)
  - Responsive modern design with gradient backgrounds
  - Severity statistics dashboard
  - Vulnerability type distribution charts
  - Color-coded severity badges
  - Detailed evidence and remediation sections
  - Print-friendly styling
  - Mobile-responsive layout
- **Enhanced OSINT Reconnaissance Module**
  - Automated Google dorking with common queries
  - Email address harvesting from public sources
  - Document and image metadata extraction
  - Social media footprint analysis
  - Breach database integration (HaveIBeenPwned)
  - Certificate Transparency log queries
  - GitHub code and secret search
  - Pastebin leak detection
- **Advanced Payload Obfuscation Module**
  - Base64 encoding variations
  - URL encoding (single, double, mixed)
  - Unicode character encoding
  - Hexadecimal encoding
  - Random case manipulation
  - SQL/JavaScript comment insertion
  - String concatenation techniques
  - Null byte injection
  - Multiple encoding layers
  - Character substitution (homoglyphs)
  - WAF-specific bypass patterns

### Changed
- Updated core vulnerability scanner to integrate v1.2.0 modules
- Enhanced configuration with WebSocket, ML, OSINT, and obfuscation settings
- Added new dependencies: websocket-client, scikit-learn, numpy, pandas
- Updated README.md with v1.2.0 feature descriptions
- Improved vulnerability scanner with obfuscated payload testing
- Added OSINT and anomaly detection helper methods to scanner

## [1.1.0] - 2025-10-15

### Added
- **API Security Testing Module** - OWASP API Top 10 2023 compliance
  - Broken authentication detection
  - Excessive data exposure testing
  - Rate limiting verification
  - Object-level authorization testing (IDOR)
  - Mass assignment vulnerability detection
  - Security misconfiguration checks
  - Injection testing (SQL, NoSQL, Command, XML)
  - Improper assets management detection
  - Insufficient logging verification
- **GraphQL Security Module**
  - Introspection query testing
  - Query depth limit testing
  - Batch query attack detection
  - Field suggestion information disclosure testing
- **Business Logic Testing Module**
  - Price manipulation detection
  - Quantity manipulation testing
  - Workflow bypass detection
  - Race condition testing
  - Coupon/promo code abuse detection
  - Referral program abuse testing
  - Action limit bypass detection
- **Authentication Testing Module**
  - Weak password acceptance testing
  - Brute force protection verification
  - Default credentials detection
  - Session fixation testing
  - Session timeout verification
  - JWT security testing (none algorithm, weak signatures)
  - Password reset token security
  - OAuth implementation testing
  - MFA bypass detection
- **File Upload Vulnerability Module**
  - Unrestricted file upload detection
  - Path traversal in uploads
  - File type bypass testing (MIME type manipulation)
  - Malicious content detection (polyglot files)
  - File size limit testing
  - Double extension vulnerability testing
  - SVG XSS detection
  - XXE via file upload testing
- **Collaborative Scanning Features**
  - Team-based scanning sessions
  - Work distribution among team members
  - Real-time progress tracking
  - Vulnerability discovery attribution
  - Session export (JSON/CSV formats)
  - Session finalization with statistics

### Changed
- Updated vulnerability scanner from 25+ to 30+ attack methods
- Enhanced configuration with new module settings
- Improved README with new feature descriptions
- Updated scanner engine to integrate new modules

## [1.0.0] - 2025-10-15

### Added
- Initial release of Deep Eye
- Multi-AI provider support (OpenAI, Claude, Grok, OLLAMA)
- Comprehensive vulnerability scanner with 25+ attack methods
- SQL Injection detection (Error-based, Blind, Time-based)
- Cross-Site Scripting (XSS) detection
- Command Injection testing
- SSRF vulnerability detection
- XXE vulnerability detection
- Path Traversal testing
- CSRF detection
- Open Redirect detection
- CORS misconfiguration detection
- Security headers analysis
- Web crawler with configurable depth
- Multi-threaded scanning engine
- AI-powered payload generation
- Context-aware testing
- Reconnaissance module with DNS enumeration
- Subdomain discovery
- Technology detection
- Professional report generation (HTML, PDF, JSON)
- Executive summary generation
- Severity-based vulnerability classification
- Rich CLI with progress indicators
- Comprehensive logging system
- Configuration management
- Proxy support
- Custom headers and cookies support
- Rate limiting
- SSL certificate verification
- Retry logic for failed requests
- Error handling and recovery

### Security
- Input validation for all user inputs
- Safe API key handling
- SSL/TLS verification
- Rate limiting to prevent abuse
- Secure report storage

### Documentation
- Comprehensive README with usage examples
- Quick start guide
- Configuration examples
- API documentation
- Contributing guidelines
- Legal disclaimer and licensing

## [Unreleased]

### Planned Features
- Authentication testing module
- Session management analysis
- API security testing
- GraphQL vulnerability scanning
- WebSocket testing
- File upload vulnerability detection
- Business logic testing
- Machine learning-based anomaly detection
- Interactive HTML reports
- Database integration for result storage
- RESTful API for programmatic access
- Web UI dashboard
- Scheduled scanning
- Notification system (email, Slack, Discord)
- Integration with CI/CD pipelines
- Docker containerization
- Kubernetes deployment support
- Cloud deployment options
- Enhanced reconnaissance with OSINT
- Advanced payload obfuscation
- Custom plugin system
- Collaborative scanning features

---

For older versions and detailed changes, see [GitHub Releases](https://github.com/zakirkun/deep-eye/releases)
