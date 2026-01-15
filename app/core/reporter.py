import os
import json
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Table, TableStyle


class PDFGenerator:
    """
    Generate a concise, corporate-style PDF for a scan result.
    """

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_report(self, scan_data: Dict[str, Any]) -> str:
        """
        Create a PDF report from the given scan data.
        Returns the path to the generated file.
        """
        target_ip = scan_data.get("ip", "unknown")
        hostname = scan_data.get("hostname") or "N/A"
        timestamp = scan_data.get("timestamp") or datetime.utcnow().isoformat()
        risk = scan_data.get("risk") or {}
        intel = scan_data.get("intelligence") or {}
        services: List[Dict[str, Any]] = scan_data.get("services") or []

        safe_ts = timestamp.replace(":", "-")
        filename = os.path.join(self.reports_dir, f"scan-{target_ip}-{safe_ts}.pdf")

        styles = getSampleStyleSheet()
        title_style = styles["Title"]
        normal_style = styles["Normal"]
        header_style = styles["Heading2"]

        c = canvas.Canvas(filename, pagesize=LETTER)
        width, height = LETTER

        # Header
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(width / 2, height - 50, "CONFIDENTIAL - SECURITY RISK ASSESSMENT")
        c.setLineWidth(1)
        c.setStrokeColor(colors.darkgray)
        c.line(50, height - 60, width - 50, height - 60)

        y = height - 90
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Target IP: {target_ip}")
        y -= 16
        c.drawString(50, y, f"Hostname: {hostname}")
        y -= 16
        c.drawString(50, y, f"Scan Date: {timestamp}")

        # Executive Summary
        y -= 30
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Executive Summary")
        y -= 18
        score = risk.get("score", 0)
        level = (risk.get("label") or "UNKNOWN").upper()
        c.setFont("Helvetica-Bold", 22)
        c.setFillColor(self._risk_color(level))
        c.drawString(50, y, f"RISK LEVEL: {level}   SCORE: {score}")
        c.setFillColor(colors.white)

        # Ports table
        y -= 40
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Open Ports & Services")
        y -= 16
        table_data = [["Port", "Proto", "Service", "Version"]]
        if services:
            for svc in services:
                table_data.append([
                    str(svc.get("port", "")),
                    svc.get("protocol", ""),
                    svc.get("service_name", ""),
                    svc.get("version", "") or "",
                ])
        else:
            table_data.append(["-", "-", "No open ports", "-"])

        table = Table(table_data, colWidths=[60, 60, 180, 180])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2730")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1f2730")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0f141a")),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ]))
        table.wrapOn(c, width - 100, 200)
        table.drawOn(c, 50, y - table._height)
        y = y - table._height - 20

        # Intelligence section
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Intelligence (Public Exposure)")
        y -= 16
        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"ISP: {intel.get('isp', 'Unknown')}")
        y -= 14
        c.drawString(50, y, f"Country: {intel.get('country', 'Unknown')}")
        y -= 14
        vulns = intel.get("vulns") or []
        c.drawString(50, y, f"CVEs: {', '.join(vulns) if vulns else 'None reported'}")
        y -= 14

        # Findings
        findings = (risk.get("findings") or [])
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Findings")
        y -= 16
        c.setFont("Helvetica", 10)
        if findings:
            for f in findings:
                c.drawString(60, y, f"- {f}")
                y -= 12
                if y < 80:
                    c.showPage()
                    y = height - 50
        else:
            c.drawString(60, y, "No significant findings.")
            y -= 12

        # Footer
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColor(colors.HexColor("#6b7683"))
        c.drawCentredString(
            width / 2,
            40,
            "Generated by Intelligent Network Analyzer - B.Tech Final Year Project",
        )

        c.save()
        return filename

    def _risk_color(self, level: str):
        level = level.upper()
        if level == "CRITICAL":
            return colors.HexColor("#ff4040")
        if level == "HIGH":
            return colors.HexColor("#ff6b6b")
        if level == "MEDIUM":
            return colors.HexColor("#ffbd2e")
        return colors.HexColor("#3cffc7")
