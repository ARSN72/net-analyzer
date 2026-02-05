# Intelligent Network Analyzer

Hybrid cybersecurity assessment platform built with FastAPI. It supports split-brain operations: external public reconnaissance with Shodan + Nmap, and internal LAN surveying with device inventory, internal risk scoring, and rogue detection. It stores scan history in SQLite, provides a professional terminal/NOC dashboard, and generates PDF audit reports.

## What It Does
- **External scanning (Nmap):** Discovers open ports/services and OS hints on public targets (quick/full modes).
- **Passive intelligence (Shodan):** Validates public exposure and retrieves ISP, country, open ports, and CVEs.
- **Exploitability check (CISA KEV):** Flags active exploitation and boosts risk.
- **Internal LAN surveying:** Auto-detects the local subnet, discovers devices, enriches with service scans, and flags rogue or high-risk assets.
- **Separate risk engines:** External risk scoring is distinct from internal LAN risk scoring.
- **Persistence:** Saves external scans to SQLite (`scanner.db`) with full JSON payload and risk summary.
- **History API:** Fetch the 10 most recent scans via `/history`.
- **Unified dashboard:** Two workspaces—External Recon (terminal) and Internal Defense (NOC table).
- **PDF reports:** Generate corporate-style audit PDFs per external scan via `/report/{scan_id}`.

## Project Structure
```
app/
  core/
    scanner.py       # Nmap integration and parsing
    intelligence.py  # Shodan integration with resolution/public-IP guard
    analyzer.py      # Risk scoring engine
    internal_analyzer.py  # Internal LAN risk scoring (separate logic)
    local_scanner.py      # LAN discovery + enrichment
    exploit_checker.py    # CISA KEV exploitability check
    reporter.py      # PDF generation (ReportLab)
  utils/
    network.py       # Local subnet auto-detection
  db/
    database.py      # SQLAlchemy engine/session/Base
    models.py        # ScanRecord ORM model
  models/
    schemas.py       # Pydantic models (request/response/history/risk)
  main.py            # FastAPI app, routes, UI, orchestration
requirements.txt
```

## Setup
1. Clone the repo and create a virtual environment (Python 3.11+ recommended):
   ```bash
   python -m venv venv
   ```
2. Activate the virtual environment:
   - Windows (PowerShell):
     ```powershell
     .\venv\Scripts\Activate.ps1
     ```
   - Windows (cmd):
     ```cmd
     .\venv\Scripts\activate.bat
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
3. Install deps:
   ```bash
   pip install -r requirements.txt
   ```
4. Add `.env` with your Shodan API key:
   ```
   SHODAN_API_KEY=your_key_here
   ```
5. Run the server (port 5252):
   ```bash
   uvicorn app.main:app --reload --port 5252
   ```
6. Open the UI at `http://localhost:5252/`.

## Usage
- **External Recon (UI):** Enter target IP/hostname, choose quick/full, click `run`. Results render as a structured block (risk chip, ports table, intel, findings). Clear logs or download the PDF report via toolbar.
- **Internal Defense (UI):** Click `Scan Local Network` to auto-detect the subnet, discover devices, and populate the asset inventory table.
- **External scan (API):**
  ```bash
  curl -X POST http://localhost:8000/scan/external \
    -H "Content-Type: application/json" \
    -d '{"target":"8.8.8.8","scan_type":"quick"}'
  ```
- **Internal scan (API):**
  ```bash
  curl http://localhost:8000/internal/scan
  ```
- **View history:** `GET /history` returns the last 10 external records (id, target, timestamp, risk score/level).
- **Download PDF report:** `GET /report/{scan_id}` uses the stored external scan to emit a PDF saved under `reports/` and streamed to the client.

## Running on Another Computer
Virtual environments are not portable between machines. A new user should:
1. Clone the repo on their machine.
2. Create and activate their own virtual environment.
3. Install dependencies with `pip install -r requirements.txt`.
4. Add their own `.env` (Shodan API key).
5. Run the server with `uvicorn app.main:app --reload`.

## Risk Scoring (analyzer.py)
- Base: +0.2 per non-standard open port.
- Dangerous ports: 21 +1.5, 22 +1.0, 23 +2.5, 3389 +2.5, 445 +3.0.
- Public exposure: if Shodan finds the host, +2.0; if Shodan ports overlap local ports, +1.0.
- CVEs: each CVE +1.5.
- CISA KEV: if CVE is in KEV, +5.0 and flag `has_active_exploit`.
- Clamped 0–10 with labels LOW/MEDIUM/HIGH/CRITICAL. Findings list explains contributors.

## Internal Risk Scoring (internal_analyzer.py)
- Vendor heuristics: IoT/Camera vendors +2.0, critical infrastructure vendors +3.0.
- Service risk: SMB 445 (+3.0), Telnet 23 (+2.5), RDP 3389 (+2.0).
- Port count: >5 open ports +1.0.
- Clamped 0–10 with labels LOW/MEDIUM/HIGH/CRITICAL and clear findings.

## Data Model (SQLite via SQLAlchemy)
- `scans` table:
  - `id` (PK)
  - `target_ip`
  - `timestamp`
  - `risk_score`
  - `risk_level`
  - `scan_data` (full JSON payload as text)

## API Summary
- `POST /scan/external` → `ScanResult` (active services, intel, risk).
- `GET /internal/scan` → internal LAN survey results.
- `GET /history` → last 10 `ScanHistoryItem` (external scans).
- `GET /report/{scan_id}` → PDF download (ReportLab), saved to `reports/`.
- `GET /` → dashboard UI with External and Internal workspaces.

## Frontend Notes
- Dark monospace terminal aesthetic; no external CSS frameworks.
- Structured result rendering (no raw JSON): risk chip with color, grid table for ports, intel summary, bullet findings.
- Toolbar: clear logs, download PDF report for external scan.
- Internal workspace: auto-detect subnet, scan local network, display inventory table with risk and device type.

## Error Handling & Edge Cases
- Shodan lookups: resolve hostnames, reject private/reserved IPs gracefully with status/message.
- Scanner errors propagate as HTTP 500 with detail; UI shows error line.
- PDF generation validates stored JSON; returns 500 if corrupted scan data.
- Internal scans reject public IP ranges and return a clear error.

## Extensibility Ideas
- Add authentication/roles for multi-user deployments.
- Expand history filters/pagination; add delete/archive.
- Add CVSS-aware scoring and service-specific heuristics.
- Add scheduled scans and notifications.
- Enhance PDF with branding and charts.

## License / Attribution
Generated by Intelligent Network Analyzer - B.Tech Final Year Project. Customize licensing as needed for your deployment.
