from pydantic import BaseModel
from typing import List, Optional

# --- Input Schema ---
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"

# --- Output Schemas ---

# 1. Nmap Service Info
class ServiceInfo(BaseModel):
    port: int
    protocol: str
    service_name: str
    state: str
    version: Optional[str] = None

# Active scan only (used internally before adding intelligence)
class ActiveScanResult(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    services: List[ServiceInfo]
    open_ports_count: int

# 2. Shodan Intelligence Info (NEW)
class IntelInfo(BaseModel):
    status: str
    resolved_ip: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    open_ports: Optional[List[int]] = []
    vulns: Optional[List[str]] = []
    message: Optional[str] = None

# 3. Risk Assessment (NEW)
class RiskAssessment(BaseModel):
    score: float
    label: str
    findings: List[str] = []
    has_active_exploit: bool = False

# 4. Combined Result
class ScanResult(BaseModel):
    id: Optional[int] = None
    ip: str
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    # Active Scan Data
    services: List[ServiceInfo]
    open_ports_count: int
    # Passive Intel Data (NEW)
    intelligence: IntelInfo
    # Risk Analysis (NEW)
    risk: Optional[RiskAssessment] = None

# 5. History item (DB summaries)
class ScanHistoryItem(BaseModel):
    id: int
    target_ip: str
    timestamp: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
