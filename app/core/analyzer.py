from typing import List, Iterable, Dict, Any
from app.models.schemas import ActiveScanResult, RiskAssessment, ServiceInfo
from app.core.exploit_checker import ExploitChecker


class RiskAnalyzer:
    """
    Correlates active scan (Nmap) and passive intel (Shodan) to produce a risk score.
    """

    # Ports considered "standard web" and not penalized by default
    STANDARD_PORTS = {80, 443}

    # High-risk ports with explicit penalties
    DANGEROUS_PORT_PENALTIES = {
        21: ("FTP exposed (port 21)", 1.5),
        23: ("Telnet exposed (port 23)", 2.5),
        3389: ("RDP exposed (port 3389)", 2.5),
        445: ("SMB exposed (port 445)", 3.0),
        22: ("SSH exposed (port 22)", 1.0),
    }

    def __init__(self):
        self.exploit_checker = ExploitChecker()

    def calculate_risk(self, nmap_data: ActiveScanResult, shodan_data: Dict[str, Any]) -> RiskAssessment:
        score = 0.0
        findings: List[str] = []
        has_active_exploit = False

        local_ports = [svc.port for svc in nmap_data.services] if nmap_data and nmap_data.services else []

        # 1) Base score for non-standard open ports
        for port in local_ports:
            if port in self.STANDARD_PORTS:
                continue
            score += 0.2
        if local_ports:
            findings.append(f"{len(local_ports)} open ports detected; +0.2 per non-standard port.")

        # 2) Dangerous port penalties
        for port in local_ports:
            if port in self.DANGEROUS_PORT_PENALTIES:
                msg, penalty = self.DANGEROUS_PORT_PENALTIES[port]
                score += penalty
                findings.append(f"{msg}: +{penalty}")

        # 3) Internet exposure multiplier via Shodan
        is_public = shodan_data.get("status") == "found"
        shodan_ports = shodan_data.get("open_ports") or []
        if is_public:
            score += 2.0
            findings.append("Host is publicly exposed (Shodan indexed): +2.0")
            if local_ports and shodan_ports:
                overlap = set(local_ports) & set(shodan_ports)
                if overlap:
                    score += 1.0
                    findings.append(
                        f"Public exposure matches local services (ports {sorted(overlap)}): +1.0"
                    )

        # 4) Vulnerability impact (CVE list)
        vulns = shodan_data.get("vulns") or []
        for cve in vulns:
            score += 1.5
            findings.append(f"CVE detected ({cve}): +1.5")
            if self.exploit_checker.check_cve(cve):
                score += 5.0
                has_active_exploit = True
                findings.append(f"ACTIVE RANSOMWARE THREAT: {cve} is in CISA KEV list (+5.0)")

        # 5) Clamp score and assign label
        score = max(0.0, min(10.0, round(score, 2)))
        label = self._label_for_score(score)

        if not findings:
            findings.append("No significant risks detected based on current data.")

        return RiskAssessment(score=score, label=label, findings=findings, has_active_exploit=has_active_exploit)

    def _label_for_score(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
