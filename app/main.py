from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse
from app.core.scanner import NmapScanner
from app.core.intelligence import ShodanIntel
from app.core.analyzer import RiskAnalyzer
from app.core.local_scanner import LocalNetworkScanner
from app.models.schemas import (
    ScanRequest,
    LocalScanRequest,
    ScanResult,
    IntelInfo,
    ActiveScanResult,
    ScanHistoryItem,
    LocalDevice,
)
from app.db.database import SessionLocal, engine, Base
from app.db.models import ScanRecord
from app.core.reporter import PDFGenerator
import json
from typing import List
from datetime import datetime
import os
from app.utils.network import get_local_subnet
import ipaddress

app = FastAPI(title="Intelligent Network Scanner")

# Initialize engines
scanner_engine = NmapScanner()
intel_engine = ShodanIntel()
risk_engine = RiskAnalyzer()
local_scanner = LocalNetworkScanner()
report_engine = PDFGenerator()

# Create DB tables on startup
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/scan/external", response_model=ScanResult)
def perform_external_scan(request: ScanRequest, db=Depends(get_db)):
    try:
        # 1. Perform Active Scan (Nmap)
        nmap_data: ActiveScanResult = scanner_engine.scan(request.target, request.scan_type)
        
        # 2. Perform Passive Scan (Shodan)
        # Note: Shodan only has data for PUBLIC IPs. 
        # Local IPs (192.168.x.x, 127.0.0.1) will return "not found".
        shodan_data = intel_engine.get_ip_data(request.target)
        
        # 3. Combine Data
        # We take the Nmap result and inject the Shodan data into it
        final_result = ScanResult(
            ip=nmap_data.ip,
            hostname=nmap_data.hostname,
            os_detected=nmap_data.os_detected,
            services=nmap_data.services,
            open_ports_count=nmap_data.open_ports_count,
            intelligence=IntelInfo(**shodan_data),
            risk=risk_engine.calculate_risk(nmap_data, shodan_data)
        )
        
        # 4. Persist scan result
        record = ScanRecord(
            target_ip=final_result.ip,
            timestamp=datetime.utcnow(),
            risk_score=final_result.risk.score if final_result.risk else None,
            risk_level=final_result.risk.label if final_result.risk else None,
            scan_data=json.dumps(final_result.model_dump(), default=str)
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        # assign id back to response and update stored JSON with id included
        final_result.id = record.id
        record.scan_data = json.dumps(final_result.model_dump(), default=str)
        db.add(record)
        db.commit()
        return final_result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history", response_model=List[ScanHistoryItem])
def get_history(db=Depends(get_db)):
    records = (
        db.query(ScanRecord)
        .order_by(ScanRecord.timestamp.desc())
        .limit(10)
        .all()
    )
    return [
        ScanHistoryItem(
            id=rec.id,
            target_ip=rec.target_ip,
            timestamp=rec.timestamp.isoformat(),
            risk_score=rec.risk_score,
            risk_level=rec.risk_level,
        )
        for rec in records
    ]


@app.get("/report/{scan_id}")
def get_report(scan_id: int, db=Depends(get_db)):
    rec = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        scan_data = json.loads(rec.scan_data)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Stored scan data is corrupted")

    file_path = report_engine.generate_report(scan_data)
    return FileResponse(
        file_path,
        media_type="application/pdf",
        filename=file_path.split(os.sep)[-1]
    )


@app.post("/scan/internal", response_model=List[LocalDevice])
def scan_internal(request: LocalScanRequest):
    """
    Internal LAN survey. Uses local scanner and internal risk only.
    """
    try:
        cidr = request.target or get_local_subnet()
        net = ipaddress.ip_network(cidr, strict=False)
        if not net.is_private:
            raise HTTPException(status_code=400, detail="Offline scanner is restricted to local networks only")
        devices = local_scanner.scan_subnet(str(net))
        # map to LocalDevice (Pydantic will coerce)
        return [LocalDevice(**d) for d in devices]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/utils/my-subnet")
def get_my_subnet():
    return {"cidr": get_local_subnet()}


@app.get("/internal/scan")
async def internal_scan():
    """
    Internal LAN survey (auto-detected subnet).
    """
    cidr = get_local_subnet()
    print(f"Internal network scan endpoint hit for {cidr}")
    net = ipaddress.ip_network(cidr, strict=False)
    if not net.is_private:
        return {"error": "Offline scanner is restricted to local networks only"}
    print(f"Starting LAN scan for subnet {net}")
    devices = await local_scanner.scan_subnet_async(str(net))
    print(f"Discovered {len(devices)} devices; returning scan result")
    return {
        "subnet": str(net),
        "devices_found": len(devices),
        "devices": devices,
    }


@app.get("/", response_class=FileResponse)
def index():
    """Serve the C2 dashboard UI."""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    return FileResponse(template_path)
