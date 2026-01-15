from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse
from app.core.scanner import NmapScanner
from app.core.intelligence import ShodanIntel
from app.core.analyzer import RiskAnalyzer
from app.models.schemas import (
    ScanRequest,
    ScanResult,
    IntelInfo,
    ActiveScanResult,
    ScanHistoryItem,
)
from app.db.database import SessionLocal, engine, Base
from app.db.models import ScanRecord
from app.core.reporter import PDFGenerator
import json
from typing import List
from datetime import datetime
import os

app = FastAPI(title="Intelligent Network Scanner")

# Initialize engines
scanner_engine = NmapScanner()
intel_engine = ShodanIntel()
risk_engine = RiskAnalyzer()
report_engine = PDFGenerator()

# Create DB tables on startup
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/scan", response_model=ScanResult)
def perform_scan(request: ScanRequest, db=Depends(get_db)):
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


@app.get("/", response_class=HTMLResponse)
def terminal_ui():
    """
    Minimal terminal-style UI to trigger scans and view results.
    """
    html = """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Net Analyzer :: Terminal</title>
      <style>
        :root {
          --bg: #0b0e11;
          --panel: #0f141a;
          --accent: #3cffc7;
          --muted: #6b7683;
          --danger: #ff6b6b;
          --border: #1f2730;
          --text: #e8f0ff;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          min-height: 100vh;
          background: radial-gradient(circle at 20% 20%, #10151c 0, #0b0e11 40%),
                      radial-gradient(circle at 80% 0%, #0f1723 0, #0b0e11 35%),
                      #0b0e11;
          color: var(--text);
          font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 32px;
        }
        .terminal {
          width: min(1100px, 100%);
          background: var(--panel);
          border: 1px solid var(--border);
          border-radius: 12px;
          box-shadow: 0 15px 45px rgba(0, 0, 0, 0.45);
          overflow: hidden;
        }
        .title-bar {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 14px;
          background: #0c1117;
          border-bottom: 1px solid var(--border);
          font-size: 14px;
          color: var(--muted);
        }
        .dot {
          width: 12px;
          height: 12px;
          border-radius: 50%;
        }
        .dot.red { background: #ff5f56; }
        .dot.amber { background: #ffbd2e; }
        .dot.green { background: #27c93f; }
        .content { padding: 18px; display: grid; gap: 12px; }
        .prompt-line {
          display: grid;
          grid-template-columns: auto 1fr auto;
          gap: 10px;
          align-items: center;
          padding: 12px 14px;
          background: #0c1117;
          border: 1px solid var(--border);
          border-radius: 8px;
        }
        .toolbar {
          display: flex;
          gap: 10px;
          justify-content: flex-end;
          align-items: center;
        }
        label { color: var(--muted); font-size: 13px; }
        input, select {
          width: 100%;
          background: #0b0f14;
          color: var(--text);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 10px;
          font-family: inherit;
          font-size: 14px;
        }
        button {
          background: var(--accent);
          color: #04100c;
          border: none;
          padding: 10px 16px;
          border-radius: 6px;
          font-weight: 700;
          cursor: pointer;
          transition: transform 0.08s ease, box-shadow 0.08s ease;
        }
        button:hover { transform: translateY(-1px); box-shadow: 0 8px 16px rgba(60, 255, 199, 0.2); }
        button:active { transform: translateY(0); box-shadow: none; }
        .log {
          background: #05070b;
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 14px;
          min-height: 300px;
          white-space: pre-wrap;
          font-size: 13px;
          line-height: 1.45;
          overflow-y: auto;
        }
        .status { color: var(--muted); font-size: 12px; }
        .divider {
          height: 1px;
          background: var(--border);
          margin: 6px 0;
        }
        .muted { color: var(--muted); }
        .danger { color: var(--danger); }
        .btn-ghost {
          background: #0c1117;
          color: var(--text);
          border: 1px solid var(--border);
        }
        .btn-ghost:hover { box-shadow: 0 8px 16px rgba(255, 255, 255, 0.08); }
        .btn-ghost:disabled, button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
          box-shadow: none;
          transform: none;
        }
        .result-block {
          border-left: 2px solid var(--border);
          padding-left: 12px;
          margin-bottom: 12px;
        }
        .risk-chip {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 6px 10px;
          border-radius: 6px;
          font-weight: 700;
          letter-spacing: 0.3px;
        }
        .risk-low { background: rgba(60, 255, 199, 0.12); color: #3cffc7; }
        .risk-medium { background: rgba(255, 189, 46, 0.12); color: #ffbd2e; }
        .risk-high { background: rgba(255, 107, 107, 0.12); color: #ff6b6b; }
        .risk-critical { background: rgba(255, 64, 64, 0.18); color: #ff4040; }
        .table {
          display: grid;
          grid-template-columns: 80px 80px 1fr 1fr;
          border: 1px solid var(--border);
          border-radius: 6px;
          overflow: hidden;
          margin-top: 8px;
        }
        .table-header, .table-row {
          display: contents;
        }
        .table-cell {
          padding: 8px 10px;
          border-bottom: 1px solid var(--border);
          border-right: 1px solid var(--border);
          font-size: 13px;
        }
        .table-cell:last-child { border-right: none; }
        .table-header .table-cell {
          background: #0c1117;
          font-weight: 700;
          color: var(--muted);
        }
        .table-row:last-child .table-cell { border-bottom: none; }
        .pill {
          display: inline-block;
          padding: 4px 8px;
          border-radius: 12px;
          background: #0c1117;
          border: 1px solid var(--border);
          font-size: 12px;
          color: var(--text);
        }
        .list {
          margin: 6px 0 0 0;
          padding-left: 18px;
          color: var(--text);
        }
        .list li { margin: 4px 0; }
      </style>
    </head>
    <body>
      <div class="terminal">
        <div class="title-bar">
          <div class="dot red"></div><div class="dot amber"></div><div class="dot green"></div>
          <span>net-analyzer :: terminal</span>
        </div>
        <div class="content">
          <div class="prompt-line">
            <label for="target">target</label>
            <input id="target" type="text" placeholder="e.g. 8.8.8.8 or example.com" />
            <label for="scan_type">scan</label>
            <select id="scan_type">
              <option value="quick">quick</option>
              <option value="full">full</option>
            </select>
            <button id="run">run</button>
          </div>
          <div class="toolbar">
            <button id="clear" class="btn-ghost">clear logs</button>
            <button id="download" class="btn-ghost" disabled>download report</button>
          </div>
          <div class="status" id="status">ready. enter a target and press run.</div>
          <div class="divider"></div>
          <div class="log" id="log">awaiting command...</div>
        </div>
      </div>

      <script>
        const targetEl = document.getElementById('target');
        const scanEl = document.getElementById('scan_type');
        const statusEl = document.getElementById('status');
        const logEl = document.getElementById('log');
        const runBtn = document.getElementById('run');
        const clearBtn = document.getElementById('clear');
        const downloadBtn = document.getElementById('download');
        let lastResult = null;

        async function runScan() {
          const target = targetEl.value.trim();
          const scan_type = scanEl.value;
          if (!target) {
            statusEl.textContent = 'missing target.';
            statusEl.classList.add('danger');
            return;
          }
          statusEl.classList.remove('danger');
          statusEl.textContent = 'running scan...';
          runBtn.disabled = true;
          downloadBtn.disabled = true;
          appendLog(`$ net-analyzer --target ${target} --scan ${scan_type}`);
          try {
            const res = await fetch('/scan', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ target, scan_type })
            });
            const data = await res.json();
            if (!res.ok) {
              throw new Error(data.detail || 'Scan failed');
            }
            statusEl.textContent = 'scan complete.';
            lastResult = data;
            downloadBtn.disabled = false;
            appendLog(renderScanResult(data));
          } catch (err) {
            statusEl.textContent = 'error encountered.';
            statusEl.classList.add('danger');
            appendLog(`! error: ${err.message}`);
          } finally {
            runBtn.disabled = false;
          }
        }

        function appendLog(text) {
          const ts = new Date().toLocaleTimeString();
          const block = `<div class="result-block">[${ts}] ${text}</div>`;
          logEl.innerHTML = `${block}${logEl.innerHTML === 'awaiting command...' ? '' : '<br/>' + logEl.innerHTML}`;
        }

        function renderScanResult(data) {
          const risk = data.risk || {};
          const riskLabel = (risk.label || 'LOW').toUpperCase();
          const riskScore = risk.score != null ? Number(risk.score).toFixed(2) : '0.00';
          const riskClass = riskLabel === 'CRITICAL' ? 'risk-critical' :
                            riskLabel === 'HIGH' ? 'risk-high' :
                            riskLabel === 'MEDIUM' ? 'risk-medium' : 'risk-low';

          const services = Array.isArray(data.services) ? data.services : [];
          const intel = data.intelligence || {};
          const findings = Array.isArray(risk.findings) ? risk.findings : [];

          const portRows = services.map(s => `
            <div class="table-row">
              <div class="table-cell">${s.port}</div>
              <div class="table-cell">${s.protocol || ''}</div>
              <div class="table-cell">${s.service_name || ''}</div>
              <div class="table-cell">${s.version || ''}</div>
            </div>
          `).join('');

          const portTable = portRows || `
            <div class="table-row">
              <div class="table-cell" style="grid-column: 1 / span 4;">No open ports</div>
            </div>`;

          const vulnList = Array.isArray(intel.vulns) && intel.vulns.length
            ? intel.vulns.map(v => `<span class="pill danger">${v}</span>`).join(' ')
            : '<span class="muted">No CVEs reported</span>';

          const findingsList = findings.length
            ? `<ul class="list">${findings.map(f => `<li>${f}</li>`).join('')}</ul>`
            : '<span class="muted">No notable findings.</span>';

          return `
            <div>
              <div class="muted">target: ${data.ip || ''} ${data.hostname ? `(${data.hostname})` : ''}</div>
              <div class="muted">timestamp: ${new Date().toLocaleString()}</div>
              <div style="margin:8px 0;">
                <span class="risk-chip ${riskClass}">risk ${riskScore} :: ${riskLabel}</span>
              </div>
              <div>
                <div class="muted">ports/services</div>
                <div class="table">
                  <div class="table-header">
                    <div class="table-cell">Port</div>
                    <div class="table-cell">Proto</div>
                    <div class="table-cell">Service</div>
                    <div class="table-cell">Version</div>
                  </div>
                  ${portTable}
                </div>
              </div>
              <div style="margin-top:8px;">
                <div class="muted">intelligence</div>
                <div>ISP: ${intel.isp || 'Unknown'} | Country: ${intel.country || 'Unknown'}</div>
                <div>Vulns: ${vulnList}</div>
              </div>
              <div style="margin-top:8px;">
                <div class="muted">findings</div>
                ${findingsList}
              </div>
            </div>
          `;
        }

        runBtn.addEventListener('click', runScan);
        targetEl.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') runScan();
        });

        clearBtn.addEventListener('click', () => {
          logEl.innerHTML = 'awaiting command...';
          lastResult = null;
          downloadBtn.disabled = true;
        });

        downloadBtn.addEventListener('click', () => {
          if (!lastResult) return;
          const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `scan-report-${lastResult.ip || 'target'}.json`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        });
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
