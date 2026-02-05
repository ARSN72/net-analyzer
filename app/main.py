from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
import os
import json
from datetime import datetime
import ipaddress
import requests

from app.core.scanner import NmapScanner
from app.core.intelligence import ShodanIntel
from app.core.analyzer import RiskAnalyzer
from app.core.local_scanner import LocalNetworkScanner
from app.core.device_inspector import DeviceInspector
from app.core.reporter import PDFGenerator
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
from app.utils.network import get_local_subnet, normalize_target


app = FastAPI(title="Intelligent Network Scanner")

# Initialize engines
scanner_engine = NmapScanner()
intel_engine = ShodanIntel()
risk_engine = RiskAnalyzer()
local_scanner = LocalNetworkScanner()
device_inspector = DeviceInspector()
report_engine = PDFGenerator()
last_internal_scan: dict = {}

# Create DB tables on startup
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", response_class=FileResponse)
def index():
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    return FileResponse(template_path)


@app.post("/scan/external", response_model=ScanResult)
def perform_external_scan(request: ScanRequest, db=Depends(get_db)):
    try:
        target = normalize_target(request.target)
        if not target:
            raise HTTPException(status_code=400, detail="Invalid target")

        nmap_data: ActiveScanResult = scanner_engine.scan(target, request.scan_type)
        shodan_data = intel_engine.get_ip_data(target)

        final_result = ScanResult(
            ip=nmap_data.ip,
            hostname=nmap_data.hostname,
            os_detected=nmap_data.os_detected,
            services=nmap_data.services,
            open_ports_count=nmap_data.open_ports_count,
            intelligence=IntelInfo(**shodan_data),
            risk=risk_engine.calculate_risk(nmap_data, shodan_data),
        )

        record = ScanRecord(
            target_ip=final_result.ip,
            timestamp=datetime.utcnow(),
            risk_score=final_result.risk.score if final_result.risk else None,
            risk_level=final_result.risk.label if final_result.risk else None,
            scan_data=json.dumps(final_result.model_dump(), default=str),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        final_result.id = record.id
        record.scan_data = json.dumps(final_result.model_dump(), default=str)
        db.add(record)
        db.commit()
        return final_result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history", response_model=list[ScanHistoryItem])
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
        filename=file_path.split(os.sep)[-1],
    )


@app.post("/scan/internal", response_model=list[LocalDevice])
def scan_internal(request: LocalScanRequest):
    try:
        cidr = request.target or get_local_subnet()
        net = ipaddress.ip_network(cidr, strict=False)
        if not net.is_private:
            raise HTTPException(status_code=400, detail="Offline scanner is restricted to local networks only")
        devices = local_scanner.scan_subnet(str(net))
        return [LocalDevice(**d) for d in devices]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/internal/scan")
async def internal_scan():
    cidr = get_local_subnet()
    print(f"Internal network scan endpoint hit for {cidr}")
    net = ipaddress.ip_network(cidr, strict=False)
    if not net.is_private:
        return {"error": "Offline scanner is restricted to local networks only"}
    print(f"Starting LAN scan for subnet {net}")
    devices = await local_scanner.scan_subnet_async(str(net))
    print(f"Discovered {len(devices)} devices; returning scan result")
    global last_internal_scan
    last_internal_scan = {
        "subnet": str(net),
        "devices_found": len(devices),
        "devices": devices,
        "network_context": local_scanner.get_network_context(),
    }
    return last_internal_scan


@app.get("/internal/report")
def internal_report():
    if not last_internal_scan:
        raise HTTPException(status_code=404, detail="No internal scan data available")
    file_path = report_engine.generate_internal_report(last_internal_scan)
    return FileResponse(
        file_path,
        media_type="application/pdf",
        filename=file_path.split(os.sep)[-1],
    )


@app.get("/internal/device/{ip}")
def internal_device_info(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            raise HTTPException(status_code=400, detail="Offline scanner is restricted to local networks only")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    cached = None
    for dev in (last_internal_scan.get("devices") or []):
        if dev.get("ip") == ip:
            cached = dev
            break
    return device_inspector.get_device_info(ip, cached, last_internal_scan.get("network_context") or {})


@app.get("/internal/device/{ip}/ping")
def internal_device_ping(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            raise HTTPException(status_code=400, detail="Offline scanner is restricted to local networks only")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    return device_inspector.ping_test(ip)


@app.get("/internal/device/{ip}/ports")
def internal_device_ports(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            raise HTTPException(status_code=400, detail="Offline scanner is restricted to local networks only")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    return {"ports": device_inspector.scan_ports(ip)}


@app.get("/internal/device/{ip}/report")
def internal_device_report(ip: str):
    info = internal_device_info(ip)
    file_path = report_engine.generate_device_report(info)
    return FileResponse(
        file_path,
        media_type="application/pdf",
        filename=file_path.split(os.sep)[-1],
    )


@app.get("/utils/my-subnet")
def get_my_subnet():
    return {"cidr": get_local_subnet()}


@app.get("/utils/public-ip")
def get_public_ip():
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {"ip": "Unknown"}
