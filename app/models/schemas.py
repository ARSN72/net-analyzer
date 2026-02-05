from typing import List, Optional
from pydantic import BaseModel

# Requests
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    scan_speed: str = "standard"

class LocalScanRequest(BaseModel):
    target: Optional[str] = None  # CIDR, auto-detect if None
    scan_speed: str = "standard"

# Active scan models
class ServiceInfo(BaseModel):
    port: int
    protocol: str
    service_name: str
    state: str
    version: Optional[str] = None

class ActiveScanResult(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    services: List[ServiceInfo]
    open_ports_count: int

# Intel
class IntelInfo(BaseModel):
    status: str
    resolved_ip: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    open_ports: Optional[List[int]] = []
    vulns: Optional[List[str]] = []
    message: Optional[str] = None

# Risk
class RiskAssessment(BaseModel):
    score: float
    label: str
    findings: List[str] = []
    has_active_exploit: bool = False

# Combined external result
class ScanResult(BaseModel):
    id: Optional[int] = None
    ip: str
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    services: List[ServiceInfo]
    open_ports_count: int
    intelligence: IntelInfo
    risk: Optional[RiskAssessment] = None

# History
class ScanHistoryItem(BaseModel):
    id: int
    target_ip: str
    timestamp: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None

# Internal scan models
class LocalPort(BaseModel):
    port: int
    protocol: str
    service: Optional[str] = ""
    version: Optional[str] = ""

class LocalDevice(BaseModel):
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    hostname_source: Optional[str] = None
    ipv6: Optional[str] = None
    ports: List[LocalPort] = []
    device_type: str = "Unknown"
    risk: RiskAssessment
    risk_reasons: List[str] = []
    rogue: bool = False
    mac_vendor: Optional[str] = None
    manufacturer: Optional[str] = None
    manufacturer_address: Optional[str] = None
    vendor_source: Optional[str] = None
    vendor_confidence: Optional[float] = None
    os_guess: Optional[str] = None
    os_confidence: Optional[str] = None
    netbios_name: Optional[str] = None
    netbios_domain: Optional[str] = None
    fileserver: Optional[str] = None
    http_server: Optional[str] = None
    https_server: Optional[str] = None
    tls_subject: Optional[str] = None
    tls_issuer: Optional[str] = None
