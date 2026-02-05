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
        os_detected = scan_data.get("os_detected") or "Unknown"
        open_ports_count = scan_data.get("open_ports_count") or 0

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
        c.drawString(50, y, f"OS Detected: {os_detected}")
        y -= 16
        c.drawString(50, y, f"Scan Date: {timestamp}")
        y -= 16
        c.drawString(50, y, f"Open Ports Count: {open_ports_count}")

        # Executive Summary
        y -= 30
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Executive Summary")
        y -= 18
        score = risk.get("score", 0)
        level = (risk.get("label") or "UNKNOWN").upper()
        kev_flag = bool(risk.get("has_active_exploit"))
        c.setFont("Helvetica-Bold", 22)
        c.setFillColor(self._risk_color(level))
        c.drawString(50, y, f"RISK LEVEL: {level}   SCORE: {score}")
        c.setFillColor(colors.white)

        if kev_flag:
            y -= 28
            c.setFillColor(colors.HexColor("#2a0f0f"))
            c.roundRect(48, y, width - 96, 40, 6, stroke=0, fill=1)
            c.setFillColor(colors.HexColor("#ff4040"))
            c.setFont("Helvetica-Bold", 12)
            c.drawString(60, y + 24, "Action Required: Vulnerabilities with known active exploits detected (CISA KEV).")
            c.setFillColor(colors.white)
            c.setFont("Helvetica", 10)

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
        c.drawString(50, y, f"Status: {intel.get('status', 'Unknown')}")
        y -= 14
        c.drawString(50, y, f"Resolved IP: {intel.get('resolved_ip', 'Unknown')}")
        y -= 14
        c.drawString(50, y, f"ISP: {intel.get('isp', 'Unknown')}")
        y -= 14
        c.drawString(50, y, f"Organization: {intel.get('org', 'Unknown')}")
        y -= 14
        c.drawString(50, y, f"Country: {intel.get('country', 'Unknown')}")
        y -= 14
        c.drawString(50, y, f"Public Open Ports: {', '.join(map(str, intel.get('open_ports', []) or [])) or 'None'}")
        y -= 14
        vulns = intel.get("vulns") or []
        c.drawString(50, y, f"CVEs: {', '.join(vulns) if vulns else 'None reported'}")
        y -= 14
        msg = intel.get("message")
        if msg:
            c.drawString(50, y, f"Intel Note: {msg}")
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

    def generate_internal_report(self, scan_data: Dict[str, Any]) -> str:
        subnet = scan_data.get("subnet", "unknown")
        devices = scan_data.get("devices") or []
        filename = os.path.join(self.reports_dir, f"internal-scan-{subnet.replace('/', '_')}.pdf")

        c = canvas.Canvas(filename, pagesize=LETTER)
        width, height = LETTER
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(width / 2, height - 50, "INTERNAL NETWORK SCAN REPORT")
        c.setLineWidth(1)
        c.setStrokeColor(colors.darkgray)
        c.line(50, height - 60, width - 50, height - 60)

        y = height - 90
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Subnet: {subnet}")
        y -= 16
        c.drawString(50, y, f"Devices Found: {len(devices)}")
        y -= 24

        table_data = [["IP", "MAC", "Vendor", "Device Type", "Risk"]]
        for d in devices:
            risk = d.get("risk") or {}
            table_data.append([
                d.get("ip", ""),
                d.get("mac", ""),
                d.get("vendor", ""),
                d.get("device_type", ""),
                f"{risk.get('label', 'UNKNOWN')} ({risk.get('score', 0)})",
            ])
        if len(table_data) == 1:
            table_data.append(["-", "-", "-", "-", "No devices found"])

        table = Table(table_data, colWidths=[90, 110, 120, 120, 90])
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
        table.wrapOn(c, width - 100, 300)
        table.drawOn(c, 50, y - table._height)

        c.setFont("Helvetica-Oblique", 9)
        c.setFillColor(colors.HexColor("#6b7683"))
        c.drawCentredString(
            width / 2,
            40,
            "Generated by Intelligent Network Analyzer - B.Tech Final Year Project",
        )
        c.save()
        return filename

    def generate_device_report(self, device_info: Dict[str, Any]) -> str:
        ip = device_info.get("ip", "unknown")
        filename = os.path.join(self.reports_dir, f"device-{ip}.pdf")

        c = canvas.Canvas(filename, pagesize=LETTER)
        width, height = LETTER
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(width / 2, height - 50, "DEVICE DETAIL REPORT")
        c.setLineWidth(1)
        c.setStrokeColor(colors.darkgray)
        c.line(50, height - 60, width - 50, height - 60)

        y = height - 90
        c.setFont("Helvetica", 10)
        for label, key in [
            ("IP Address", "ip"),
            ("IPv4", "ipv4"),
            ("IPv6", "ipv6"),
            ("Public IP", "public_ip"),
            ("ISP", "isp"),
            ("City", "city"),
            ("Region", "region"),
            ("Country", "country"),
            ("Hostname", "hostname"),
            ("Target Host", "target_host"),
            ("OS Detected", "os_detected"),
            ("MAC Address", "mac_address"),
            ("MAC Vendor", "mac_vendor"),
            ("Device Manufacturer", "device_manufacturer"),
            ("Manufacturer Address", "manufacturer_address"),
            ("Vendor Source", "vendor_source"),
            ("Vendor Confidence", "vendor_confidence"),
            ("NetBIOS Name", "netbios_name"),
            ("NetBIOS Domain", "netbios_domain"),
            ("File Server", "fileserver"),
            ("First Seen", "first_seen"),
        ]:
            c.drawString(50, y, f"{label}: {device_info.get(key, 'Unknown')}")
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 10)

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
