"""
Notification Manager
Sends notifications via Email, Slack, and Discord
"""

import json
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from datetime import datetime
import requests

from utils.logger import get_logger

logger = get_logger(__name__)


class NotificationManager:
    """Manages sending notifications to various platforms."""
    
    def __init__(self, config: Dict):
        """
        Initialize notification manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.notification_config = config.get('notifications', {})
        self.enabled = self.notification_config.get('enabled', False)
    
    def send_scan_complete(self, scan_results: Dict) -> bool:
        """
        Send scan completion notification.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            True if any notification was sent successfully
        """
        if not self.enabled:
            return False
        
        success = False
        
        # Prepare notification data
        notification_data = self._prepare_notification_data(scan_results)
        
        # Send to enabled channels
        if self.notification_config.get('email', {}).get('enabled', False):
            if self._send_email(notification_data):
                success = True
        
        if self.notification_config.get('slack', {}).get('enabled', False):
            if self._send_slack(notification_data):
                success = True
        
        if self.notification_config.get('discord', {}).get('enabled', False):
            if self._send_discord(notification_data):
                success = True
        
        return success
    
    @staticmethod
    def _sanitize_evidence(evidence: str, max_length: int = 500) -> str:
        """
        Sanitize vulnerability evidence before sending to external webhooks.

        Redacts patterns that commonly contain secrets (tokens, session IDs,
        passwords, API keys, cookies) to prevent accidental data leakage
        through Slack/Discord/Email notifications.
        """
        if not evidence:
            return ""

        # Redact common secret patterns
        patterns = [
            (r'(?i)(bearer\s+)\S+', r'\1**REDACTED**'),
            (r'(?i)(token|session[_-]?id|api[_-]?key|password|passwd|secret|authorization)[=:]\s*\S+',
             r'\1=**REDACTED**'),
            (r'(?i)(set-cookie:\s*)\S+', r'\1**REDACTED**'),
            (r'(?i)(cookie:\s*)\S+', r'\1**REDACTED**'),
            # Redact long base64-like strings (potential tokens)
            (r'[A-Za-z0-9+/=]{40,}', '**REDACTED_TOKEN**'),
        ]

        sanitized = evidence
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized)

        return sanitized[:max_length]

    def send_critical_vulnerability(self, vulnerability: Dict, target_url: str) -> bool:
        """
        Send immediate notification for critical vulnerability.
        
        Args:
            vulnerability: Vulnerability details
            target_url: Target URL
            
        Returns:
            True if notification sent successfully
        """
        if not self.enabled:
            return False
        
        if not self.notification_config.get('notify_on_critical', True):
            return False
        
        notification_data = {
            'title': '🚨 Critical Vulnerability Detected',
            'target': target_url,
            'vulnerability_type': vulnerability.get('type', 'Unknown'),
            'severity': vulnerability.get('severity', 'Unknown'),
            'url': vulnerability.get('url', ''),
            'evidence': self._sanitize_evidence(vulnerability.get('evidence', '')),
            'timestamp': datetime.now().isoformat()
        }
        
        success = False
        
        if self.notification_config.get('slack', {}).get('enabled', False):
            if self._send_slack_critical(notification_data):
                success = True
        
        if self.notification_config.get('discord', {}).get('enabled', False):
            if self._send_discord_critical(notification_data):
                success = True
        
        return success
    
    def _prepare_notification_data(self, scan_results: Dict) -> Dict:
        """Prepare notification data from scan results."""
        vuln_count = len(scan_results.get('vulnerabilities', []))
        severity_summary = scan_results.get('severity_summary', {})
        
        return {
            'title': '✅ Scan Completed',
            'target': scan_results.get('target', 'Unknown'),
            'start_time': scan_results.get('start_time', ''),
            'end_time': scan_results.get('end_time', ''),
            'duration': scan_results.get('duration', 'N/A'),
            'urls_crawled': scan_results.get('urls_crawled', 0),
            'total_vulnerabilities': vuln_count,
            'critical': severity_summary.get('critical', 0),
            'high': severity_summary.get('high', 0),
            'medium': severity_summary.get('medium', 0),
            'low': severity_summary.get('low', 0),
            'info': severity_summary.get('info', 0),
        }
    
    def _send_email(self, data: Dict) -> bool:
        """Send email notification."""
        try:
            email_config = self.notification_config.get('email', {})
            
            smtp_server = email_config.get('smtp_server')
            smtp_port = email_config.get('smtp_port', 587)
            username = email_config.get('username')
            password = email_config.get('password')
            from_addr = email_config.get('from_address')
            to_addrs = email_config.get('to_addresses', [])
            
            if not all([smtp_server, username, password, from_addr, to_addrs]):
                logger.warning("Email configuration incomplete")
                return False
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Deep Eye: {data['title']} - {data['target']}"
            msg['From'] = from_addr
            msg['To'] = ', '.join(to_addrs)
            
            # Create HTML body
            html_body = self._create_email_html(data)
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent to {len(to_addrs)} recipient(s)")
            return True
        
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            return False
    
    def _send_slack(self, data: Dict) -> bool:
        """Send Slack notification."""
        try:
            slack_config = self.notification_config.get('slack', {})
            webhook_url = slack_config.get('webhook_url')
            
            if not webhook_url:
                logger.warning("Slack webhook URL not configured")
                return False
            
            # Create Slack message
            message = {
                "text": f"{data['title']}: {data['target']}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{data['title']}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Target:*\n{data['target']}"},
                            {"type": "mrkdwn", "text": f"*Duration:*\n{data['duration']}"},
                            {"type": "mrkdwn", "text": f"*URLs Crawled:*\n{data['urls_crawled']}"},
                            {"type": "mrkdwn", "text": f"*Total Vulnerabilities:*\n{data['total_vulnerabilities']}"}
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"🔴 *Critical:* {data['critical']}"},
                            {"type": "mrkdwn", "text": f"🟠 *High:* {data['high']}"},
                            {"type": "mrkdwn", "text": f"🟡 *Medium:* {data['medium']}"},
                            {"type": "mrkdwn", "text": f"🔵 *Low:* {data['low']}"}
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=message, timeout=10)
            response.raise_for_status()
            
            logger.info("Slack notification sent successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
    
    def _send_slack_critical(self, data: Dict) -> bool:
        """Send critical vulnerability alert to Slack."""
        try:
            slack_config = self.notification_config.get('slack', {})
            webhook_url = slack_config.get('webhook_url')
            
            if not webhook_url:
                return False
            
            message = {
                "text": f"🚨 CRITICAL: {data['vulnerability_type']} detected at {data['target']}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 Critical Vulnerability Detected"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Type:*\n{data['vulnerability_type']}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{data['severity'].upper()}"},
                            {"type": "mrkdwn", "text": f"*Target:*\n{data['target']}"},
                            {"type": "mrkdwn", "text": f"*URL:*\n{data['url']}"}
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Evidence:*\n```{data['evidence']}```"
                        }
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=message, timeout=10)
            response.raise_for_status()
            
            logger.info("Critical vulnerability alert sent to Slack")
            return True
        
        except Exception as e:
            logger.error(f"Error sending Slack critical alert: {e}")
            return False
    
    def _send_discord(self, data: Dict) -> bool:
        """Send Discord notification."""
        try:
            discord_config = self.notification_config.get('discord', {})
            webhook_url = discord_config.get('webhook_url')
            
            if not webhook_url:
                logger.warning("Discord webhook URL not configured")
                return False
            
            # Create Discord embed
            embed = {
                "title": f"{data['title']}: {data['target']}",
                "color": 5814783,  # Blue color
                "fields": [
                    {"name": "Target", "value": data['target'], "inline": True},
                    {"name": "Duration", "value": data['duration'], "inline": True},
                    {"name": "URLs Crawled", "value": str(data['urls_crawled']), "inline": True},
                    {"name": "Total Vulnerabilities", "value": str(data['total_vulnerabilities']), "inline": True},
                    {"name": "🔴 Critical", "value": str(data['critical']), "inline": True},
                    {"name": "🟠 High", "value": str(data['high']), "inline": True},
                    {"name": "🟡 Medium", "value": str(data['medium']), "inline": True},
                    {"name": "🔵 Low", "value": str(data['low']), "inline": True}
                ],
                "timestamp": datetime.now().isoformat(),
                "footer": {"text": "Deep Eye Scanner"}
            }
            
            message = {"embeds": [embed]}
            
            response = requests.post(webhook_url, json=message, timeout=10)
            response.raise_for_status()
            
            logger.info("Discord notification sent successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error sending Discord notification: {e}")
            return False
    
    def _send_discord_critical(self, data: Dict) -> bool:
        """Send critical vulnerability alert to Discord."""
        try:
            discord_config = self.notification_config.get('discord', {})
            webhook_url = discord_config.get('webhook_url')
            
            if not webhook_url:
                return False
            
            embed = {
                "title": "🚨 Critical Vulnerability Detected",
                "color": 16711680,  # Red color
                "fields": [
                    {"name": "Type", "value": data['vulnerability_type'], "inline": True},
                    {"name": "Severity", "value": data['severity'].upper(), "inline": True},
                    {"name": "Target", "value": data['target'], "inline": False},
                    {"name": "URL", "value": data['url'], "inline": False},
                    {"name": "Evidence", "value": f"```{data['evidence'][:1000]}```", "inline": False}
                ],
                "timestamp": data['timestamp'],
                "footer": {"text": "Deep Eye Scanner - Immediate Alert"}
            }
            
            message = {"embeds": [embed]}
            
            response = requests.post(webhook_url, json=message, timeout=10)
            response.raise_for_status()
            
            logger.info("Critical vulnerability alert sent to Discord")
            return True
        
        except Exception as e:
            logger.error(f"Error sending Discord critical alert: {e}")
            return False
    
    def _create_email_html(self, data: Dict) -> str:
        """Create HTML email body."""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background: #f4f4f4; }}
                .stat {{ display: inline-block; margin: 10px; padding: 10px; background: white; border-radius: 5px; }}
                .critical {{ color: #e74c3c; font-weight: bold; }}
                .high {{ color: #e67e22; font-weight: bold; }}
                .medium {{ color: #f39c12; font-weight: bold; }}
                .low {{ color: #3498db; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Deep Eye Scan Report</h1>
                    <p>{data['title']}</p>
                </div>
                <div class="content">
                    <h2>Scan Summary</h2>
                    <p><strong>Target:</strong> {data['target']}</p>
                    <p><strong>Duration:</strong> {data['duration']}</p>
                    <p><strong>URLs Crawled:</strong> {data['urls_crawled']}</p>
                    <p><strong>Total Vulnerabilities:</strong> {data['total_vulnerabilities']}</p>
                    
                    <h3>Severity Breakdown</h3>
                    <div class="stat critical">Critical: {data['critical']}</div>
                    <div class="stat high">High: {data['high']}</div>
                    <div class="stat medium">Medium: {data['medium']}</div>
                    <div class="stat low">Low: {data['low']}</div>
                    
                    <p style="margin-top: 20px; font-size: 12px; color: #7f8c8d;">
                        This is an automated notification from Deep Eye Scanner.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

