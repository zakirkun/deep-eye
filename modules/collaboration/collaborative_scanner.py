"""
Collaborative Scanning Module
Enables team collaboration and distributed scanning
"""

import json
import re
import time
import hashlib
from typing import Dict, List, Optional
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)


class CollaborativeScanner:
    """Manage collaborative scanning sessions."""
    
    def __init__(self, config: Dict):
        """Initialize collaborative scanner."""
        self.config = config
        self.session_file = Path(config.get('session_file', 'data/scan_session.json'))
        self.session_file.parent.mkdir(parents=True, exist_ok=True)
        self.current_session = None
    
    def create_session(self, target: str, scan_type: str, team: List[str]) -> Dict:
        """
        Create a new collaborative scanning session.
        
        Args:
            target: Target URL or domain
            scan_type: Type of scan (full, quick, custom)
            team: List of team member identifiers
            
        Returns:
            Session information
        """
        session_id = self._generate_session_id(target)
        
        session = {
            'session_id': session_id,
            'target': target,
            'scan_type': scan_type,
            'team': team,
            'created_at': time.time(),
            'status': 'active',
            'scanned_urls': [],
            'vulnerabilities': [],
            'assigned_tasks': {},
            'progress': {
                'total_urls': 0,
                'scanned_urls': 0,
                'vulnerabilities_found': 0
            }
        }
        
        self.current_session = session
        self._save_session(session)
        
        logger.info(f"Created collaborative session: {session_id}")
        return session
    
    def join_session(self, session_id: str, member_id: str) -> Optional[Dict]:
        """
        Join an existing scanning session.
        
        Args:
            session_id: Session identifier
            member_id: Team member identifier
            
        Returns:
            Session information or None
        """
        session = self._load_session(session_id)
        
        if session:
            if member_id not in session['team']:
                session['team'].append(member_id)
                self._save_session(session)
            
            self.current_session = session
            logger.info(f"Member {member_id} joined session {session_id}")
            return session
        
        logger.warning(f"Session {session_id} not found")
        return None
    
    def get_assigned_work(self, session_id: str, member_id: str) -> List[str]:
        """
        Get URLs assigned to a team member.
        
        Args:
            session_id: Session identifier
            member_id: Team member identifier
            
        Returns:
            List of URLs to scan
        """
        session = self._load_session(session_id)
        
        if not session:
            return []
        
        # Get or create assignment for this member
        if member_id not in session['assigned_tasks']:
            # Auto-assign work
            self._distribute_work(session)
        
        return session['assigned_tasks'].get(member_id, [])
    
    def report_progress(self, session_id: str, member_id: str, 
                       scanned_url: str, vulnerabilities: List[Dict]) -> None:
        """
        Report scanning progress to the session.
        
        Args:
            session_id: Session identifier
            member_id: Team member identifier
            scanned_url: URL that was scanned
            vulnerabilities: Vulnerabilities found
        """
        session = self._load_session(session_id)
        
        if not session:
            logger.warning(f"Session {session_id} not found")
            return
        
        # Update scanned URLs
        if scanned_url not in session['scanned_urls']:
            session['scanned_urls'].append(scanned_url)
        
        # Add vulnerabilities
        for vuln in vulnerabilities:
            vuln['discovered_by'] = member_id
            vuln['discovered_at'] = time.time()
            session['vulnerabilities'].append(vuln)
        
        # Update progress
        session['progress']['scanned_urls'] = len(session['scanned_urls'])
        session['progress']['vulnerabilities_found'] = len(session['vulnerabilities'])
        
        # Remove from assigned tasks
        if member_id in session['assigned_tasks']:
            if scanned_url in session['assigned_tasks'][member_id]:
                session['assigned_tasks'][member_id].remove(scanned_url)
        
        self._save_session(session)
        logger.info(f"Progress reported for {scanned_url} by {member_id}")
    
    def get_session_status(self, session_id: str) -> Optional[Dict]:
        """
        Get current session status.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session status information
        """
        session = self._load_session(session_id)
        
        if not session:
            return None
        
        total_assigned = sum(len(urls) for urls in session['assigned_tasks'].values())
        
        return {
            'session_id': session_id,
            'target': session['target'],
            'status': session['status'],
            'team_size': len(session['team']),
            'progress': session['progress'],
            'pending_tasks': total_assigned,
            'completion_percentage': self._calculate_completion(session)
        }
    
    def add_urls_to_scan(self, session_id: str, urls: List[str]) -> None:
        """
        Add new URLs to the scanning queue.
        
        Args:
            session_id: Session identifier
            urls: List of URLs to add
        """
        session = self._load_session(session_id)
        
        if not session:
            logger.warning(f"Session {session_id} not found")
            return
        
        session['progress']['total_urls'] += len(urls)
        
        # Distribute new work
        self._distribute_urls(session, urls)
        self._save_session(session)
        
        logger.info(f"Added {len(urls)} URLs to session {session_id}")
    
    def get_vulnerabilities(self, session_id: str, 
                           severity: Optional[str] = None) -> List[Dict]:
        """
        Get vulnerabilities found in session.
        
        Args:
            session_id: Session identifier
            severity: Filter by severity (optional)
            
        Returns:
            List of vulnerabilities
        """
        session = self._load_session(session_id)
        
        if not session:
            return []
        
        vulnerabilities = session['vulnerabilities']
        
        if severity:
            vulnerabilities = [v for v in vulnerabilities if v.get('severity') == severity]
        
        return vulnerabilities
    
    def finalize_session(self, session_id: str) -> Dict:
        """
        Finalize and close a scanning session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Final session report
        """
        session = self._load_session(session_id)
        
        if not session:
            return {}
        
        session['status'] = 'completed'
        session['completed_at'] = time.time()
        
        # Calculate statistics
        severity_counts = self._count_by_severity(session['vulnerabilities'])
        contributor_stats = self._calculate_contributor_stats(session)
        
        report = {
            'session_id': session_id,
            'target': session['target'],
            'duration': session.get('completed_at', time.time()) - session['created_at'],
            'team_size': len(session['team']),
            'total_urls_scanned': len(session['scanned_urls']),
            'total_vulnerabilities': len(session['vulnerabilities']),
            'severity_breakdown': severity_counts,
            'contributor_stats': contributor_stats,
            'completion_time': time.strftime('%Y-%m-%d %H:%M:%S', 
                                            time.localtime(session.get('completed_at', time.time())))
        }
        
        self._save_session(session)
        logger.info(f"Session {session_id} finalized")
        
        return report
    
    def export_session(self, session_id: str, format: str = 'json') -> str:
        """
        Export session data.
        
        Args:
            session_id: Session identifier
            format: Export format (json, csv)
            
        Returns:
            Path to exported file
        """
        session = self._load_session(session_id)
        
        if not session:
            return ""
        
        export_dir = Path('data/exports')
        export_dir.mkdir(parents=True, exist_ok=True)
        
        if format == 'json':
            export_file = export_dir / f"{session_id}_export.json"
            with open(export_file, 'w') as f:
                json.dump(session, f, indent=2)
        elif format == 'csv':
            import csv
            export_file = export_dir / f"{session_id}_export.csv"
            with open(export_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['url', 'type', 'severity', 'discovered_by'])
                writer.writeheader()
                for vuln in session['vulnerabilities']:
                    writer.writerow({
                        'url': vuln.get('url', ''),
                        'type': vuln.get('type', ''),
                        'severity': vuln.get('severity', ''),
                        'discovered_by': vuln.get('discovered_by', '')
                    })
        
        logger.info(f"Session exported to {export_file}")
        return str(export_file)
    
    def _generate_session_id(self, target: str) -> str:
        """Generate unique session ID."""
        timestamp = str(time.time())
        return hashlib.sha256(f"{target}{timestamp}".encode()).hexdigest()[:16]
    
    def _save_session(self, session: Dict) -> None:
        """Save session to file."""
        session_file = Path('data/sessions') / f"{session['session_id']}.json"
        session_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(session_file, 'w') as f:
            json.dump(session, f, indent=2)
    
    @staticmethod
    def _validate_session_id(session_id: str) -> bool:
        """Validate session ID format to prevent path traversal."""
        # Session IDs are 16-char hex strings generated by _generate_session_id
        return bool(re.match(r'^[a-f0-9]{16}$', session_id))

    def _load_session(self, session_id: str) -> Optional[Dict]:
        """Load session from file."""
        if not self._validate_session_id(session_id):
            logger.warning(f"Invalid session_id format rejected: {session_id!r}")
            return None

        session_file = Path('data/sessions') / f"{session_id}.json"

        if not session_file.exists():
            return None

        with open(session_file, 'r') as f:
            return json.load(f)
    
    def _distribute_work(self, session: Dict) -> None:
        """Distribute work among team members."""
        # Get unassigned URLs
        all_assigned = set()
        for urls in session['assigned_tasks'].values():
            all_assigned.update(urls)
        
        # This is a placeholder - in real implementation,
        # you would get URLs from the scanning queue
        # For now, we just ensure each member has an assignment dict
        for member in session['team']:
            if member not in session['assigned_tasks']:
                session['assigned_tasks'][member] = []
    
    def _distribute_urls(self, session: Dict, urls: List[str]) -> None:
        """Distribute URLs to team members."""
        team_size = len(session['team'])
        
        if team_size == 0:
            return
        
        # Round-robin distribution
        for i, url in enumerate(urls):
            member = session['team'][i % team_size]
            if member not in session['assigned_tasks']:
                session['assigned_tasks'][member] = []
            session['assigned_tasks'][member].append(url)
    
    def _calculate_completion(self, session: Dict) -> float:
        """Calculate session completion percentage."""
        total = session['progress']['total_urls']
        if total == 0:
            return 0.0
        
        scanned = session['progress']['scanned_urls']
        return (scanned / total) * 100
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _calculate_contributor_stats(self, session: Dict) -> Dict[str, Dict]:
        """Calculate statistics per contributor."""
        stats = {}
        
        for vuln in session['vulnerabilities']:
            member = vuln.get('discovered_by', 'unknown')
            if member not in stats:
                stats[member] = {
                    'vulnerabilities_found': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            
            stats[member]['vulnerabilities_found'] += 1
            severity = vuln.get('severity', 'low')
            if severity in stats[member]:
                stats[member][severity] += 1
        
        return stats
