from typing import List, Dict, Any
from app.models.schemas import RiskAssessment


class InternalRiskAnalyzer:
    """
    LAN-specific risk scoring. Does not use external intel (Shodan).
    """

    IOT_VENDORS = {"HIKVISION", "DAHUA", "ESPRESSIF"}
    CRITICAL_VENDORS = {"SIEMENS", "SCHNEIDER"}

    def assess(self, device: Dict[str, Any]) -> RiskAssessment:
        score = 0.0
        findings: List[str] = []

        vendor = (device.get("vendor") or "").upper()
        ports = device.get("ports") or []

        # Device type risk
        if any(tag in vendor for tag in self.IOT_VENDORS):
            score += 2.0
            findings.append("IoT/Camera vendor detected (+2.0)")
        if any(tag in vendor for tag in self.CRITICAL_VENDORS):
            score += 3.0
            findings.append("Critical infrastructure vendor detected (+3.0)")

        # Service risk
        port_set = set(p.get("port") for p in ports if isinstance(p, dict))
        if 445 in port_set:
            score += 3.0
            findings.append("SMB (445) exposed (+3.0)")
        if 23 in port_set:
            score += 2.5
            findings.append("Telnet (23) exposed (+2.5)")
        if 3389 in port_set:
            score += 2.0
            findings.append("RDP (3389) exposed (+2.0)")

        # Port count
        if len(port_set) > 5:
            score += 1.0
            findings.append("High port count (>5) (+1.0)")

        score = max(0.0, min(10.0, round(score, 2)))
        label = self._label(score)
        if not findings:
            findings.append("No significant LAN risks detected.")

        return RiskAssessment(score=score, label=label, findings=findings)

    def _label(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
