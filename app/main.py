from fastapi import FastAPI, HTTPException
from app.core.scanner import NmapScanner
from app.core.intelligence import ShodanIntel
from app.models.schemas import ScanRequest, ScanResult, IntelInfo

app = FastAPI(title="Intelligent Network Scanner")

# Initialize engines
scanner_engine = NmapScanner()
intel_engine = ShodanIntel()

@app.post("/scan", response_model=ScanResult)
def perform_scan(request: ScanRequest):
    try:
        # 1. Perform Active Scan (Nmap)
        nmap_data = scanner_engine.scan(request.target, request.scan_type)
        
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
            
            # Here is the new part:
            intelligence=IntelInfo(**shodan_data)
        )
        
        return final_result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))