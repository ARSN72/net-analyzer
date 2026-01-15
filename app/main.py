from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from app.core.scanner import NmapScanner
from app.core.intelligence import ShodanIntel
from app.models.schemas import ScanRequest, ScanResult, IntelInfo, ActiveScanResult

app = FastAPI(title="Intelligent Network Scanner")

# Initialize engines
scanner_engine = NmapScanner()
intel_engine = ShodanIntel()

@app.post("/scan", response_model=ScanResult)
def perform_scan(request: ScanRequest):
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
            intelligence=IntelInfo(**shodan_data)
        )
        
        return final_result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
            appendLog(formatResult(data));
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
          logEl.textContent = `[${ts}] ${
            text
          }\n\n${
            logEl.textContent
          }`.trim();
        }

        function formatResult(data) {
          return JSON.stringify(data, null, 2);
        }

        runBtn.addEventListener('click', runScan);
        targetEl.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') runScan();
        });
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
