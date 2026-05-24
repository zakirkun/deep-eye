"""
CVE Intelligence Scraper
Scrapes CVE data from multiple sources and stores in SQLite database
"""

import sqlite3
import json
import time
import requests
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)


class CVEScraper:
    """Scrape and manage CVE intelligence database."""
    
    def __init__(self, db_path: str = "data/cve_intelligence.db"):
        """Initialize CVE scraper with database path."""
        self.db_path = db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Deep-Eye-Security-Scanner/1.4.0'
        })
        
        # Create database directory if not exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize CVE database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # CVE table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_entries (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                modified_date TEXT,
                affected_products TEXT,
                attack_vector TEXT,
                exploit_available BOOLEAN,
                reference_urls TEXT,
                cwe_id TEXT,
                raw_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # CVE exploits table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                exploit_type TEXT,
                exploit_payload TEXT,
                exploit_description TEXT,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id)
            )
        ''')
        
        # Technology mapping table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                technology TEXT,
                version_affected TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON cve_entries(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_published ON cve_entries(published_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_technology ON cve_technologies(technology)')
        
        conn.commit()
        conn.close()
        logger.info(f"CVE database initialized: {self.db_path}")
    
    def scrape_nvd_cves(self, days_back: int = 30, limit: int = 1000):
        """
        Scrape CVEs from NVD (National Vulnerability Database).
        
        Args:
            days_back: Number of days to look back
            limit: Maximum number of CVEs to fetch
        """
        logger.info(f"Scraping CVEs from NVD (last {days_back} days, limit: {limit})")
        
        # NVD API endpoint (v2.0)
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        # NVD API v2.0 requires specific date format
        # Using lastModStartDate instead of pubStartDate for better results
        params = {
            'lastModStartDate': start_date.isoformat() + 'Z',
            'lastModEndDate': end_date.isoformat() + 'Z',
            'resultsPerPage': min(limit, 2000)
        }
        
        try:
            # Add delay to respect NVD rate limits (no API key = 5 requests per 30 seconds)
            time.sleep(6)
            
            response = self.session.get(base_url, params=params, timeout=30)
            
            if response.status_code == 404:
                logger.warning("NVD API endpoint not accessible, using fallback method")
                return self._create_default_cve_database()
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            logger.info(f"Found {len(vulnerabilities)} CVEs from NVD")
            
            # Store in database
            stored = 0
            for vuln in vulnerabilities:
                if self._store_cve_nvd(vuln):
                    stored += 1
            
            logger.info(f"Stored {stored} CVEs in database")
            return stored
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to scrape NVD: {e}")
            logger.info("Using fallback: Creating default CVE database with common vulnerabilities")
            return self._create_default_cve_database()
        except Exception as e:
            logger.error(f"Error processing NVD data: {e}")
            return self._create_default_cve_database()
    
    def _create_default_cve_database(self) -> int:
        """Create default CVE database with common web vulnerabilities."""
        logger.info("Creating default CVE database with common web vulnerabilities")
        
        common_cves = [
            {
                'cve_id': 'CVE-WEB-SQLI-001',
                'description': 'SQL Injection vulnerability in web applications allowing database manipulation',
                'severity': 'CRITICAL',
                'cvss_score': 9.8,
                'cwe_id': 'CWE-89',
                'technologies': ['MySQL', 'PostgreSQL', 'MSSQL', 'Oracle', 'PHP', 'ASP.NET'],
                'exploits': [
                    "' OR '1'='1", "' UNION SELECT NULL--", "' AND SLEEP(5)--",
                    "admin' --", "' AND 1=1--", "' OR 1=1#"
                ]
            },
            {
                'cve_id': 'CVE-WEB-XSS-001',
                'description': 'Cross-Site Scripting (XSS) vulnerability allowing JavaScript injection',
                'severity': 'HIGH',
                'cvss_score': 7.5,
                'cwe_id': 'CWE-79',
                'technologies': ['JavaScript', 'HTML', 'All Web Applications'],
                'exploits': [
                    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>", "javascript:alert(1)"
                ]
            },
            {
                'cve_id': 'CVE-WEB-RCE-001',
                'description': 'Remote Code Execution via command injection in web applications',
                'severity': 'CRITICAL',
                'cvss_score': 10.0,
                'cwe_id': 'CWE-78',
                'technologies': ['Linux', 'Unix', 'PHP', 'Python', 'Node.js'],
                'exploits': [
                    "; ls -la", "| whoami", "`cat /etc/passwd`",
                    "$(cat /etc/passwd)", "; sleep 5"
                ]
            },
            {
                'cve_id': 'CVE-WEB-XXE-001',
                'description': 'XML External Entity (XXE) vulnerability allowing file disclosure',
                'severity': 'HIGH',
                'cvss_score': 8.5,
                'cwe_id': 'CWE-611',
                'technologies': ['XML', 'SOAP', 'REST API'],
                'exploits': [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
                ]
            },
            {
                'cve_id': 'CVE-WEB-LFI-001',
                'description': 'Local File Inclusion allowing reading arbitrary files',
                'severity': 'HIGH',
                'cvss_score': 7.8,
                'cwe_id': 'CWE-22',
                'technologies': ['PHP', 'ASP.NET', 'JSP'],
                'exploits': [
                    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/passwd", "/etc/passwd%00"
                ]
            },
            {
                'cve_id': 'CVE-WEB-SSTI-001',
                'description': 'Server-Side Template Injection leading to RCE',
                'severity': 'CRITICAL',
                'cvss_score': 9.5,
                'cwe_id': 'CWE-94',
                'technologies': ['Jinja2', 'Flask', 'Django', 'Twig'],
                'exploits': [
                    "{{7*7}}", "{{config}}", "${7*7}", "<%= 7*7 %>"
                ]
            },
            {
                'cve_id': 'CVE-WEB-SSRF-001',
                'description': 'Server-Side Request Forgery allowing internal network access',
                'severity': 'HIGH',
                'cvss_score': 8.0,
                'cwe_id': 'CWE-918',
                'technologies': ['All Web Applications'],
                'exploits': [
                    "http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/"
                ]
            },
            {
                'cve_id': 'CVE-WEB-CSRF-001',
                'description': 'Cross-Site Request Forgery allowing unauthorized actions',
                'severity': 'MEDIUM',
                'cvss_score': 6.5,
                'cwe_id': 'CWE-352',
                'technologies': ['All Web Applications'],
                'exploits': []
            }
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        stored = 0
        
        for cve in common_cves:
            try:
                # Store CVE
                cursor.execute('''
                    INSERT OR REPLACE INTO cve_entries 
                    (cve_id, description, severity, cvss_score, published_date, 
                     modified_date, affected_products, reference_urls, cwe_id, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve['cve_id'],
                    cve['description'],
                    cve['severity'],
                    cve['cvss_score'],
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    json.dumps(cve['technologies']),
                    json.dumps([]),
                    cve['cwe_id'],
                    json.dumps(cve)
                ))
                
                # Store technology mappings
                for tech in cve['technologies']:
                    cursor.execute('''
                        INSERT OR IGNORE INTO cve_technologies (cve_id, technology, version_affected)
                        VALUES (?, ?, ?)
                    ''', (cve['cve_id'], tech, '*'))
                
                # Store exploits
                for payload in cve.get('exploits', []):
                    exploit_type = cve['description'].split()[0]  # First word of description
                    cursor.execute('''
                        INSERT INTO cve_exploits 
                        (cve_id, exploit_type, exploit_payload, exploit_description, source)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        cve['cve_id'],
                        exploit_type,
                        payload,
                        cve['description'],
                        'Deep Eye Built-in'
                    ))
                
                stored += 1
                
            except Exception as e:
                logger.debug(f"Error storing default CVE {cve['cve_id']}: {e}")
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created default CVE database with {stored} vulnerability patterns")
        return stored
    
    def _store_cve_nvd(self, vuln_data: Dict) -> bool:
        """Store NVD CVE data in database."""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            if not cve_id:
                return False
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Extract CVSS score and severity
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            severity = 'UNKNOWN'
            
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = self._cvss2_to_severity(cvss_score)
            
            # Extract dates
            published = cve.get('published', '')
            modified = cve.get('lastModified', '')
            
            # Extract affected products
            configurations = cve.get('configurations', [])
            affected = self._extract_affected_products(configurations)
            
            # Extract references
            references = cve.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references[:5]]
            
            # Extract CWE
            weaknesses = cve.get('weaknesses', [])
            cwe_id = ''
            if weaknesses:
                cwe_desc = weaknesses[0].get('description', [])
                if cwe_desc:
                    cwe_id = cwe_desc[0].get('value', '')
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_entries 
                (cve_id, description, severity, cvss_score, published_date, 
                 modified_date, affected_products, reference_urls, cwe_id, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                description,
                severity,
                cvss_score,
                published,
                modified,
                json.dumps(affected),
                json.dumps(ref_urls),
                cwe_id,
                json.dumps(vuln_data)
            ))
            
            # Store technology mappings
            for tech in affected:
                cursor.execute('''
                    INSERT INTO cve_technologies (cve_id, technology, version_affected)
                    VALUES (?, ?, ?)
                ''', (cve_id, tech.get('product', ''), tech.get('version', '')))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.debug(f"Error storing CVE {vuln_data.get('cve', {}).get('id', 'unknown')}: {e}")
            return False
    
    def _extract_affected_products(self, configurations: List) -> List[Dict]:
        """Extract affected products from CVE configurations."""
        products = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable', False):
                        cpe_uri = cpe.get('criteria', '')
                        # Parse CPE: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) >= 5:
                            products.append({
                                'vendor': parts[3],
                                'product': parts[4],
                                'version': parts[5] if len(parts) > 5 else '*'
                            })
        
        return products
    
    def _cvss2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity."""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def scrape_exploit_db(self, limit: int = 100):
        """Scrape exploit information from public sources."""
        logger.info(f"Scraping exploits (limit: {limit})")
        
        # This is a placeholder - in production, you'd integrate with Exploit-DB API
        # or other exploit databases
        
        # For now, we'll create some common exploit patterns based on CVE types
        common_exploits = [
            {
                'cve_pattern': 'SQL',
                'exploit_type': 'SQL Injection',
                'payloads': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "' AND SLEEP(5)--"
                ]
            },
            {
                'cve_pattern': 'XSS',
                'exploit_type': 'Cross-Site Scripting',
                'payloads': [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>"
                ]
            },
            {
                'cve_pattern': 'Command',
                'exploit_type': 'Command Injection',
                'payloads': [
                    "; ls -la",
                    "| whoami",
                    "`cat /etc/passwd`"
                ]
            }
        ]
        
        stored = 0
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all CVEs from database
        cursor.execute('SELECT cve_id, description FROM cve_entries LIMIT ?', (limit,))
        cves = cursor.fetchall()
        
        for cve_id, description in cves:
            for exploit in common_exploits:
                if exploit['cve_pattern'].lower() in description.lower():
                    for payload in exploit['payloads']:
                        cursor.execute('''
                            INSERT OR IGNORE INTO cve_exploits 
                            (cve_id, exploit_type, exploit_payload, exploit_description, source)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            cve_id,
                            exploit['exploit_type'],
                            payload,
                            f"Generic {exploit['exploit_type']} payload",
                            'Built-in patterns'
                        ))
                        stored += 1
        
        conn.commit()
        conn.close()
        
        logger.info(f"Stored {stored} exploit patterns")
        return stored
    
    def get_cves_for_technology(self, technology: str, limit: int = 50) -> List[Dict]:
        """Get CVEs matching a specific technology."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score, 
                   c.published_date, c.exploit_available
            FROM cve_entries c
            JOIN cve_technologies t ON c.cve_id = t.cve_id
            WHERE t.technology LIKE ? OR c.description LIKE ?
            ORDER BY c.cvss_score DESC
            LIMIT ?
        ''', (f'%{technology}%', f'%{technology}%', limit))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'cve_id': row[0],
                'description': row[1],
                'severity': row[2],
                'cvss_score': row[3],
                'published_date': row[4],
                'exploit_available': row[5]
            })
        
        conn.close()
        return results
    
    def get_exploits_for_cve(self, cve_id: str) -> List[Dict]:
        """Get exploit payloads for a specific CVE."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT exploit_type, exploit_payload, exploit_description, source
            FROM cve_exploits
            WHERE cve_id = ?
        ''', (cve_id,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'type': row[0],
                'payload': row[1],
                'description': row[2],
                'source': row[3]
            })
        
        conn.close()
        return results
    
    def get_database_stats(self) -> Dict:
        """Get CVE database statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total CVEs
        cursor.execute('SELECT COUNT(*) FROM cve_entries')
        total_cves = cursor.fetchone()[0]
        
        # By severity
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM cve_entries 
            GROUP BY severity
        ''')
        by_severity = dict(cursor.fetchall())
        
        # Total exploits
        cursor.execute('SELECT COUNT(*) FROM cve_exploits')
        total_exploits = cursor.fetchone()[0]
        
        # Total technologies
        cursor.execute('SELECT COUNT(DISTINCT technology) FROM cve_technologies')
        total_techs = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_cves': total_cves,
            'by_severity': by_severity,
            'total_exploits': total_exploits,
            'total_technologies': total_techs,
            'database_path': self.db_path
        }

