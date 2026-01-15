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

# 2. Shodan Intelligence Info (NEW)
class IntelInfo(BaseModel):
    status: str
    isp: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    open_ports: Optional[List[int]] = []
    vulns: Optional[List[str]] = []
    message: Optional[str] = None

# 3. Combined Result
class ScanResult(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    # Active Scan Data
    services: List[ServiceInfo]
    open_ports_count: int
    # Passive Intel Data (NEW)
    intelligence: IntelInfo