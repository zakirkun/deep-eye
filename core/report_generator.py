"""
Report Generator
Creates professional security assessment reports
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Template
from utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generate professional security reports."""

    def __init__(self, config: Dict):
        """Initialize report generator."""
        self.config = config
        self.report_config = config.get("reporting", {})
        self.template_dir = Path(__file__).parent.parent.parent / "templates"

    def generate(self, results: Dict, output_path: str, format: str = "html"):
        """
        Generate security report.

        Args:
            results: Scan results
            output_path: Output file path
            format: Report format (html, pdf, json)
        """
        if format == "json":
            self._generate_json(results, output_path)
        elif format == "html":
            self._generate_html(results, output_path)
        elif format == "pdf":
            self._generate_pdf(results, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _safe_serialize(self, obj: any):
        """Recursively make data JSON-safe."""
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        elif isinstance(obj, dict):
            return {str(k): self._safe_serialize(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple, set)):
            return [self._safe_serialize(v) for v in obj]
        else:
            # Fallback: try to convert to string
            return str(obj)

    def _generate_json(self, results: Dict, output_path: str):
        """Generate JSON report safely with inconsistent data."""
        try:
            safe_results = self._safe_serialize(results)

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(safe_results, f, indent=2, ensure_ascii=False)

            logger.info(f"JSON report generated: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}", exc_info=True)

    def _generate_html(self, results: Dict, output_path: str):
        """Generate HTML report."""
        template_content = self._get_html_template()
        template = Template(template_content)

        # Prepare data for template
        report_data = {
            "title": "Deep Eye Security Assessment Report",
            "generated_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": results.get("target"),
            "scan_duration": results.get("duration"),
            "summary": self._generate_summary(results),
            "vulnerabilities": self._sort_vulnerabilities(
                results.get("vulnerabilities", [])
            ),
            "severity_counts": results.get("severity_summary", {}),
            "urls_scanned": results.get("urls_crawled", 0),
            "reconnaissance": results.get("reconnaissance", {}),
        }

        html_content = template.render(**report_data)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML report generated: {output_path}")

    def _generate_pdf(self, results: Dict, output_path: str):
        """Generate PDF report using ReportLab (Windows-friendly)."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                PageBreak,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            from xml.sax.saxutils import escape

            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Custom styles
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#667eea"),
                spaceAfter=30,
                alignment=TA_CENTER,
            )

            heading_style = ParagraphStyle(
                "CustomHeading",
                parent=styles["Heading2"],
                fontSize=16,
                textColor=colors.HexColor("#667eea"),
                spaceAfter=12,
                spaceBefore=12,
            )

            # Title
            story.append(Paragraph("Deep Eye Security Assessment Report", title_style))
            story.append(Spacer(1, 0.2 * inch))

            # Metadata table
            metadata = [
                ["Target:", results.get("target", "N/A")],
                ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ["Scan Duration:", str(results.get("duration", "N/A"))],
                ["URLs Scanned:", str(results.get("urls_crawled", 0))],
            ]

            metadata_table = Table(metadata, colWidths=[2 * inch, 4 * inch])
            metadata_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ]
                )
            )
            story.append(metadata_table)
            story.append(Spacer(1, 0.3 * inch))

            # Reconnaissance & OSINT Data
            recon_data = results.get("reconnaissance", {})
            if recon_data:
                story.append(
                    Paragraph("Reconnaissance & OSINT Intelligence", heading_style)
                )

                # DNS Information
                dns_info = recon_data.get("dns", {})
                if dns_info:
                    story.append(Paragraph("<b>DNS Records:</b>", styles["Heading4"]))
                    dns_records = []
                    for record_type, records in dns_info.items():
                        if records:
                            dns_records.append(
                                [
                                    record_type.upper(),
                                    ", ".join(str(r) for r in records[:3]),
                                ]
                            )
                    if dns_records:
                        dns_table = Table(
                            [[heading, data] for heading, data in dns_records],
                            colWidths=[1.5 * inch, 4.5 * inch],
                        )
                        dns_table.setStyle(
                            TableStyle(
                                [
                                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                                ]
                            )
                        )
                        story.append(dns_table)
                        story.append(Spacer(1, 0.15 * inch))

                # OSINT Data
                osint_data = recon_data.get("osint", {})
                if osint_data:
                    story.append(
                        Paragraph("<b>OSINT Findings:</b>", styles["Heading4"])
                    )

                    # Emails
                    emails = osint_data.get("emails", [])
                    if emails:
                        story.append(
                            Paragraph(
                                f"Emails found: {len(emails)}", styles["BodyText"]
                            )
                        )
                        safe_emails = [escape(str(e)) for e in emails[:5]]
                        story.append(
                            Paragraph(", ".join(safe_emails), styles["BodyText"])
                        )
                        story.append(Spacer(1, 0.1 * inch))

                    # Subdomains
                    subdomains = osint_data.get("subdomains", [])
                    if subdomains:
                        story.append(
                            Paragraph(
                                f"Subdomains discovered: {len(subdomains)}",
                                styles["BodyText"],
                            )
                        )
                        safe_subdomains = [escape(str(s)) for s in subdomains[:10]]
                        story.append(
                            Paragraph(", ".join(safe_subdomains), styles["BodyText"])
                        )
                        story.append(Spacer(1, 0.1 * inch))

                    # Technologies
                    technologies = recon_data.get("technologies", [])
                    if technologies:
                        safe_techs = [escape(str(t)) for t in technologies]
                        story.append(
                            Paragraph(
                                f"Technologies detected: {', '.join(safe_techs)}",
                                styles["BodyText"],
                            )
                        )
                        story.append(Spacer(1, 0.1 * inch))

                story.append(PageBreak())

            # Severity Summary
            severity_counts = results.get("severity_summary", {})
            severity_data = [
                ["Severity", "Count"],
                ["Critical", str(severity_counts.get("critical", 0))],
                ["High", str(severity_counts.get("high", 0))],
                ["Medium", str(severity_counts.get("medium", 0))],
                ["Low", str(severity_counts.get("low", 0))],
            ]

            severity_table = Table(severity_data, colWidths=[3 * inch, 3 * inch])
            severity_colors = {
                1: colors.HexColor("#8B0000"),  # Critical
                2: colors.HexColor("#FF4500"),  # High
                3: colors.HexColor("#FFA500"),  # Medium
                4: colors.HexColor("#FFD700"),  # Low
            }

            severity_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ]
                    + [
                        ("BACKGROUND", (0, i), (0, i), severity_colors[i])
                        for i in severity_colors.keys()
                    ]
                )
            )
            story.append(severity_table)
            story.append(Spacer(1, 0.3 * inch))

            # Executive Summary
            story.append(Paragraph("Executive Summary", heading_style))
            summary_text = self._generate_summary(results)
            story.append(
                Paragraph(summary_text.replace("\n", "<br/>"), styles["BodyText"])
            )
            story.append(Spacer(1, 0.3 * inch))

            # Vulnerabilities
            story.append(Paragraph("Vulnerabilities", heading_style))
            vulnerabilities = self._sort_vulnerabilities(
                results.get("vulnerabilities", [])
            )

            if vulnerabilities:
                for vuln in vulnerabilities:
                    # Vulnerability title (escape special characters)
                    vuln_type = escape(str(vuln.get("type", "Unknown")))
                    vuln_severity = escape(str(vuln.get("severity", "info").upper()))
                    vuln_title = f"<b>{vuln_type}</b> - {vuln_severity}"
                    story.append(Paragraph(vuln_title, styles["Heading3"]))

                    # Vulnerability details (escape special characters)
                    vuln_url = escape(str(vuln.get("url", "N/A")))
                    vuln_param = escape(str(vuln.get("parameter", "N/A")))
                    vuln_desc = escape(str(vuln.get("description", "N/A")))
                    vuln_evidence = escape(
                        str(vuln.get("evidence", "N/A"))[:200]
                    )  # Limit evidence length
                    vuln_remediation = escape(str(vuln.get("remediation", "N/A")))

                    vuln_details = f"""
                    <b>URL:</b> {vuln_url}<br/>
                    <b>Parameter:</b> {vuln_param}<br/>
                    <b>Description:</b> {vuln_desc}<br/>
                    <b>Evidence:</b> {vuln_evidence}<br/>
                    <b>Remediation:</b> {vuln_remediation}
                    """
                    story.append(Paragraph(vuln_details, styles["BodyText"]))
                    story.append(Spacer(1, 0.2 * inch))
            else:
                story.append(
                    Paragraph("No vulnerabilities detected.", styles["BodyText"])
                )

            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")

        except ImportError as e:
            logger.error(f"ReportLab not available: {e}")
            logger.info("Falling back to HTML report...")
            html_path = output_path.replace(".pdf", ".html")
            self._generate_html(results, html_path)
            logger.info(f"HTML report available at: {html_path}")
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            logger.info("Falling back to HTML report...")
            html_path = output_path.replace(".pdf", ".html")
            self._generate_html(results, html_path)
            logger.info(f"HTML report available at: {html_path}")

    def _generate_summary(self, results: Dict) -> str:
        """Generate executive summary."""
        total_vulns = len(results.get("vulnerabilities", []))
        severity_counts = results.get("severity_summary", {})

        summary = f"""
        This security assessment identified {total_vulns} potential security issues on the target system.

        Critical vulnerabilities require immediate attention as they pose significant risk to the organization.
        High and medium severity issues should be addressed in order of priority.

        Risk Distribution:
        - Critical: {severity_counts.get("critical", 0)} issues
        - High: {severity_counts.get("high", 0)} issues
        - Medium: {severity_counts.get("medium", 0)} issues
        - Low: {severity_counts.get("low", 0)} issues
        """

        return summary.strip()

    def _sort_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Sort vulnerabilities by severity."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        return sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5),
        )

    def _get_html_template(self) -> str:
        """Get HTML report template with enhanced features."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>

    <!-- DataTables CSS -->
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/responsive/2.5.0/css/responsive.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.dataTables.min.css">

    <!-- jQuery and DataTables JS -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>

    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .metadata-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .metadata-card h3 {
            color: #667eea;
            margin-bottom: 10px;
        }

        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .chart-container h3 {
            color: #667eea;
            margin-bottom: 15px;
            text-align: center;
        }

        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .severity-card {
            padding: 20px;
            border-radius: 8px;
            color: white;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            cursor: pointer;
            transition: transform 0.2s;
        }

        .severity-card:hover {
            transform: translateY(-5px);
        }

        .severity-critical { background-color: #8B0000; }
        .severity-high { background-color: #FF4500; }
        .severity-medium { background-color: #FFA500; }
        .severity-low { background-color: #FFD700; color: #333; }
        .severity-info { background-color: #87CEEB; color: #333; }

        .severity-card h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }

        .section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }

        .filter-controls {
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filter-controls label {
            font-weight: bold;
            color: #667eea;
        }

        .filter-controls select {
            padding: 8px 12px;
            border: 2px solid #667eea;
            border-radius: 5px;
            font-size: 14px;
            cursor: pointer;
        }

        .vulnerability {
            border-left: 4px solid #ddd;
            padding: 20px;
            margin-bottom: 20px;
            background: #f9f9f9;
            border-radius: 4px;
        }

        .vulnerability.critical { border-left-color: #8B0000; }
        .vulnerability.high { border-left-color: #FF4500; }
        .vulnerability.medium { border-left-color: #FFA500; }
        .vulnerability.low { border-left-color: #FFD700; }

        .vulnerability h3 {
            color: #333;
            margin-bottom: 10px;
        }

        .vulnerability-meta {
            display: flex;
            gap: 20px;
            margin: 10px 0;
            flex-wrap: wrap;
        }

        .vulnerability-meta span {
            background: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.9em;
        }

        .code {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            max-height: 300px;
            overflow-y: auto;
        }

        .evidence-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }

        .evidence-box h4 {
            color: #856404;
            margin-bottom: 10px;
        }

        .screenshot-container {
            margin: 15px 0;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }

        .screenshot-container img {
            max-width: 100%;
            height: auto;
            display: block;
        }

        .recon-subsection {
            margin: 20px 0;
            padding: 20px;
            background: #f9f9f9;
            border-left: 4px solid #667eea;
            border-radius: 5px;
        }

        .recon-subsection h3 {
            color: #667eea;
            margin-bottom: 15px;
        }

        .recon-data {
            margin-top: 10px;
        }

        .recon-data p {
            margin: 8px 0;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 30px;
        }

        .dataTables_wrapper {
            padding: 20px 0;
        }

        table.dataTable {
            width: 100% !important;
        }

        .severity-badge {
            padding: 5px 10px;
            border-radius: 15px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }

        .badge-critical { background-color: #8B0000; }
        .badge-high { background-color: #FF4500; }
        .badge-medium { background-color: #FFA500; }
        .badge-low { background-color: #FFD700; color: #333; }
        .badge-info { background-color: #87CEEB; color: #333; }

        .expandable-content {
            display: none;
            margin-top: 10px;
            padding: 15px;
            background: white;
            border-radius: 5px;
        }

        .expand-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin-top: 10px;
        }

        .expand-btn:hover {
            background: #5568d3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 {{ title }}</h1>
            <p>Generated: {{ generated_date }}</p>
        </div>

        <div class="metadata">
            <div class="metadata-card">
                <h3>🎯 Target</h3>
                <p>{{ target }}</p>
            </div>
            <div class="metadata-card">
                <h3>⏱️ Scan Duration</h3>
                <p>{{ scan_duration }}</p>
            </div>
            <div class="metadata-card">
                <h3>🔗 URLs Scanned</h3>
                <p>{{ urls_scanned }}</p>
            </div>
            <div class="metadata-card">
                <h3>🐛 Total Vulnerabilities</h3>
                <p style="font-size: 2em; font-weight: bold; color: #667eea;">{{ vulnerabilities|length }}</p>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="charts-grid">
            <div class="chart-container">
                <h3>📊 Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>📈 Vulnerability Types</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>

        <div class="severity-grid">
            <div class="severity-card severity-critical" onclick="filterBySeverity('critical')">
                <h3>{{ severity_counts.critical }}</h3>
                <p>Critical</p>
            </div>
            <div class="severity-card severity-high" onclick="filterBySeverity('high')">
                <h3>{{ severity_counts.high }}</h3>
                <p>High</p>
            </div>
            <div class="severity-card severity-medium" onclick="filterBySeverity('medium')">
                <h3>{{ severity_counts.medium }}</h3>
                <p>Medium</p>
            </div>
            <div class="severity-card severity-low" onclick="filterBySeverity('low')">
                <h3>{{ severity_counts.low }}</h3>
                <p>Low</p>
            </div>
        </div>

        {% if reconnaissance %}
        <div class="section">
            <h2>🔎 Reconnaissance & OSINT Intelligence</h2>

            {% if reconnaissance.dns %}
            <div class="recon-subsection">
                <h3>DNS Records</h3>
                <div class="recon-data">
                    {% for record_type, records in reconnaissance.dns.items() %}
                        {% if records %}
                        <p><strong>{{ record_type|upper }}:</strong> {{ records|join(', ') }}</p>
                        {% endif %}
                    {% endfor %}
                </div>
            </div>
            {% endif %}

            {% if reconnaissance.osint %}
            <div class="recon-subsection">
                <h3>OSINT Findings</h3>
                <div class="recon-data">
                    {% if reconnaissance.osint.emails %}
                    <p><strong>Emails Found:</strong> {{ reconnaissance.osint.emails|length }}</p>
                    <pre class="code">{{ reconnaissance.osint.emails|join(', ') }}</pre>
                    {% endif %}

                    {% if reconnaissance.osint.subdomains %}
                    <p><strong>Subdomains Discovered:</strong> {{ reconnaissance.osint.subdomains|length }}</p>
                    <pre class="code">{{ reconnaissance.osint.subdomains[:10]|join(', ') }}</pre>
                    {% endif %}

                    {% if reconnaissance.osint.github_leaks %}
                    <p><strong>GitHub Potential Leaks:</strong> {{ reconnaissance.osint.github_leaks|length }}</p>
                    {% endif %}

                    {% if reconnaissance.osint.breaches %}
                    <p><strong>Breach Database Results:</strong></p>
                    <pre class="code">{{ reconnaissance.osint.breaches|join(', ') }}</pre>
                    {% endif %}
                </div>
            </div>
            {% endif %}

            {% if reconnaissance.technologies %}
            <div class="recon-subsection">
                <h3>Technologies Detected</h3>
                <div class="recon-data">
                    <p>{{ reconnaissance.technologies|join(', ') }}</p>
                </div>
            </div>
            {% endif %}
        </div>
        {% endif %}

        <div class="section">
            <h2>📋 Executive Summary</h2>
            <p style="white-space: pre-line;">{{ summary }}</p>
        </div>

        <div class="section">
            <h2>🐛 Vulnerabilities</h2>

            <div class="filter-controls">
                <label for="severityFilter">Filter by Severity:</label>
                <select id="severityFilter">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>

                <label for="typeFilter">Filter by Type:</label>
                <select id="typeFilter">
                    <option value="">All Types</option>
                </select>
            </div>

            {% if vulnerabilities %}
                <table id="vulnTable" class="display responsive nowrap" style="width:100%">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>URL</th>
                            <th>Parameter</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vuln in vulnerabilities %}
                        <tr>
                            <td>{{ vuln.type }}</td>
                            <td><span class="severity-badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span></td>
                            <td style="word-break: break-all;">{{ vuln.url[:50] }}...</td>
                            <td>{{ vuln.parameter or 'N/A' }}</td>
                            <td>
                                <button class="expand-btn" onclick="toggleDetails('vuln-{{ loop.index }}')">View Details</button>
                                <div id="vuln-{{ loop.index }}" class="expandable-content">
                                    <div class="vulnerability {{ vuln.severity }}">
                                        <h3>{{ vuln.type }}</h3>
                                        <div class="vulnerability-meta">
                                            <span><strong>Severity:</strong> {{ vuln.severity|upper }}</span>
                                            <span><strong>URL:</strong> {{ vuln.url }}</span>
                                            {% if vuln.parameter %}
                                            <span><strong>Parameter:</strong> {{ vuln.parameter }}</span>
                                            {% endif %}
                                        </div>
                                        <p><strong>Description:</strong> {{ vuln.description }}</p>
                                        {% if vuln.payload %}
                                        <div class="evidence-box">
                                            <h4>💉 Payload Used:</h4>
                                            <pre class="code">{{ vuln.payload }}</pre>
                                        </div>
                                        {% endif %}
                                        <div class="evidence-box">
                                            <h4>🔍 Evidence:</h4>
                                            <p>{{ vuln.evidence }}</p>
                                        </div>
                                        {% if vuln.screenshot %}
                                        <div class="screenshot-container">
                                            <img src="{{ vuln.screenshot }}" alt="Vulnerability Screenshot">
                                        </div>
                                        {% endif %}
                                        <p><strong>🛡️ Remediation:</strong> {{ vuln.remediation }}</p>
                                    </div>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p>No vulnerabilities detected.</p>
            {% endif %}
        </div>

        <div class="footer">
            <p>This report was generated by <strong>Deep Eye v1.3.0</strong> - Advanced AI-Driven Penetration Testing Tool</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>

    <script>
        // Initialize DataTable
        $(document).ready(function() {
            var table = $('#vulnTable').DataTable({
                responsive: true,
                pageLength: 25,
                order: [[1, 'asc']], // Sort by severity
                buttons: ['copy', 'csv', 'excel', 'pdf', 'print']
            });

            // Populate type filter
            var types = new Set();
            {% for vuln in vulnerabilities %}
            types.add('{{ vuln.type }}');
            {% endfor %}
            types.forEach(function(type) {
                $('#typeFilter').append('<option value="' + type + '">' + type + '</option>');
            });

            // Filter functionality
            $('#severityFilter').on('change', function() {
                table.column(1).search(this.value).draw();
            });

            $('#typeFilter').on('change', function() {
                table.column(0).search(this.value).draw();
            });
        });

        // Toggle details
        function toggleDetails(id) {
            var element = document.getElementById(id);
            if (element.style.display === 'none' || element.style.display === '') {
                element.style.display = 'block';
            } else {
                element.style.display = 'none';
            }
        }

        // Filter by severity (from cards)
        function filterBySeverity(severity) {
            $('#severityFilter').val(severity).trigger('change');
        }

        // Severity Chart
        var ctxSeverity = document.getElementById('severityChart').getContext('2d');
        var severityChart = new Chart(ctxSeverity, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        {{ severity_counts.critical }},
                        {{ severity_counts.high }},
                        {{ severity_counts.medium }},
                        {{ severity_counts.low }}
                    ],
                    backgroundColor: ['#8B0000', '#FF4500', '#FFA500', '#FFD700']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Vulnerability Types Chart
        var vulnTypes = {};
        {% for vuln in vulnerabilities %}
        var type = '{{ vuln.type }}';
        vulnTypes[type] = (vulnTypes[type] || 0) + 1;
        {% endfor %}

        var ctxType = document.getElementById('typeChart').getContext('2d');
        var typeChart = new Chart(ctxType, {
            type: 'bar',
            data: {
                labels: Object.keys(vulnTypes),
                datasets: [{
                    label: 'Count',
                    data: Object.values(vulnTypes),
                    backgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"""
