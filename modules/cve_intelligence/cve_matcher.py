"""
CVE Matcher
Matches detected technologies with CVE database for targeted testing
"""

import sqlite3
from typing import Dict, List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class CVEMatcher:
    """Match technologies with CVE database for intelligent payload generation."""
    
    def __init__(self, db_path: str = "data/cve_intelligence.db"):
        """Initialize CVE matcher."""
        self.db_path = db_path
    
    def match_technology_cves(self, technologies: List[str], severity_min: str = 'MEDIUM') -> Dict:
        """
        Match detected technologies with relevant CVEs.
        
        Args:
            technologies: List of detected technologies
            severity_min: Minimum severity to include
            
        Returns:
            Dictionary mapping technologies to their CVEs and exploits
        """
        matches = {}
        
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level = severity_order.get(severity_min, 2)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for tech in technologies:
                # Get CVEs for this technology
                cursor.execute('''
                    SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score,
                           c.cwe_id, c.attack_vector
                    FROM cve_entries c
                    LEFT JOIN cve_technologies t ON c.cve_id = t.cve_id
                    WHERE (t.technology LIKE ? OR c.description LIKE ? OR c.affected_products LIKE ?)
                    ORDER BY c.cvss_score DESC
                    LIMIT 20
                ''', (f'%{tech}%', f'%{tech}%', f'%{tech}%'))
                
                cves = []
                for row in cursor.fetchall():
                    severity = row[2] or 'UNKNOWN'
                    if severity_order.get(severity, 0) >= min_level:
                        cve_data = {
                            'cve_id': row[0],
                            'description': row[1],
                            'severity': severity,
                            'cvss_score': row[3],
                            'cwe_id': row[4],
                            'attack_vector': row[5]
                        }
                        
                        # Get exploits for this CVE
                        cursor.execute('''
                            SELECT exploit_type, exploit_payload, exploit_description
                            FROM cve_exploits
                            WHERE cve_id = ?
                            LIMIT 5
                        ''', (row[0],))
                        
                        exploits = []
                        for exploit_row in cursor.fetchall():
                            exploits.append({
                                'type': exploit_row[0],
                                'payload': exploit_row[1],
                                'description': exploit_row[2]
                            })
                        
                        cve_data['exploits'] = exploits
                        cves.append(cve_data)
                
                if cves:
                    matches[tech] = cves
                    logger.info(f"Found {len(cves)} CVEs for {tech}")
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Error matching CVEs: {e}")
        
        return matches
    
    def get_payloads_from_cves(self, cve_matches: Dict) -> Dict[str, List[str]]:
        """
        Extract exploit payloads from CVE matches.
        
        Args:
            cve_matches: CVE matches from match_technology_cves()
            
        Returns:
            Dictionary mapping attack types to payloads
        """
        payloads = {
            'sql_injection': [],
            'xss': [],
            'command_injection': [],
            'xxe': [],
            'ssrf': [],
            'path_traversal': [],
            'ssti': []
        }
        
        for tech, cves in cve_matches.items():
            for cve in cves:
                for exploit in cve.get('exploits', []):
                    exploit_type = exploit.get('type', '').lower()
                    payload = exploit.get('payload', '')
                    
                    if not payload:
                        continue
                    
                    # Map exploit type to attack category
                    if 'sql' in exploit_type:
                        payloads['sql_injection'].append(payload)
                    elif 'xss' in exploit_type or 'script' in exploit_type:
                        payloads['xss'].append(payload)
                    elif 'command' in exploit_type or 'rce' in exploit_type:
                        payloads['command_injection'].append(payload)
                    elif 'xxe' in exploit_type or 'xml' in exploit_type:
                        payloads['xxe'].append(payload)
                    elif 'ssrf' in exploit_type:
                        payloads['ssrf'].append(payload)
                    elif 'path' in exploit_type or 'traversal' in exploit_type:
                        payloads['path_traversal'].append(payload)
                    elif 'template' in exploit_type or 'ssti' in exploit_type:
                        payloads['ssti'].append(payload)
        
        # Remove duplicates
        for key in payloads:
            payloads[key] = list(set(payloads[key]))
        
        return payloads
    
    def enrich_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Enrich vulnerability with CVE information.
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            Enriched vulnerability with CVE data
        """
        vuln_type = vulnerability.get('type', '').lower()
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Find related CVEs based on vulnerability type
            search_terms = []
            if 'sql' in vuln_type:
                search_terms = ['%SQL injection%', '%SQLi%']
            elif 'xss' in vuln_type:
                search_terms = ['%XSS%', '%cross-site scripting%']
            elif 'command' in vuln_type:
                search_terms = ['%command injection%', '%RCE%']
            elif 'xxe' in vuln_type:
                search_terms = ['%XXE%', '%XML external%']
            
            if search_terms:
                query = ' OR '.join(['description LIKE ?' for _ in search_terms])
                cursor.execute(f'''
                    SELECT cve_id, description, severity, cvss_score
                    FROM cve_entries
                    WHERE {query}
                    ORDER BY cvss_score DESC
                    LIMIT 3
                ''', search_terms)
                
                related_cves = []
                for row in cursor.fetchall():
                    related_cves.append({
                        'cve_id': row[0],
                        'description': row[1][:150],
                        'severity': row[2],
                        'cvss_score': row[3]
                    })
                
                if related_cves:
                    vulnerability['related_cves'] = related_cves
                    logger.debug(f"Enriched {vuln_type} with {len(related_cves)} related CVEs")
            
            conn.close()
            
        except Exception as e:
            logger.debug(f"Error enriching vulnerability: {e}")
        
        return vulnerability

