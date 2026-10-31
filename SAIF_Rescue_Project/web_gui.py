import os
import sys
import json
import time
import shutil
import hashlib
import threading
import argparse
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse

from main import (
    load_malware_signatures,
    refresh_malware_signatures,
    prepare_live_target,
    scan_target_directory,
    run_full_system_scan,
    check_hardware_health,
    offline_registry_heal,
    LIVE_TARGET_DIR,
    QUARANTINE_DIR,
    DEFAULT_SIGNATURE_FEED_URL
)

PORT = 5000
HOST = os.environ.get("HIKMA_HOST", "127.0.0.1")

# Shared in-memory state
STATE = {
    "logs": [],
    "is_busy": False,
    "status": "SYSTEM READY",
    "stats": {"scanned": 0, "infected": 0, "clean": 0},
    "signatures_count": len(load_malware_signatures())
}
LOCK = threading.Lock()


def add_log(message: str, tag: str = "normal"):
    with LOCK:
        STATE["logs"].append({
            "text": message,
            "tag": tag,
            "time": time.strftime("%H:%M:%S")
        })
        if len(STATE["logs"]) > 300:
            STATE["logs"].pop(0)


def run_live_audit():
    with LOCK:
        if STATE["is_busy"]:
            return
        STATE["is_busy"] = True
        STATE["status"] = "AUDIT RUNNING"
        STATE["logs"].clear()

    try:
        signatures = load_malware_signatures()
        with LOCK:
            STATE["signatures_count"] = len(signatures)

        add_log("=" * 60, "cyan")
        add_log("      HIKMA RESCUE ENGINE -- FULL SYSTEM & COMPONENT SCAN", "cyan")
        add_log("=" * 60, "cyan")
        add_log("[INFO] Performing a live host-wide component scan instead of a single file check.\n", "yellow")

        add_log("--- [STAGE 1: HARDWARE HEALTH & SMART DIAGNOSTICS] ---", "cyan")
        check_hardware_health(log_callback=add_log)
        add_log("-" * 60 + "\n", "normal")
        time.sleep(0.2)

        add_log("--- [STAGE 2: OFFLINE WINDOWS REGISTRY CHECK] ---", "cyan")
        offline_registry_heal(log_callback=add_log)
        add_log("-" * 60 + "\n", "normal")
        time.sleep(0.2)

        stats = run_full_system_scan(signatures, log_callback=add_log)
        add_log("-" * 60, "normal")

        with LOCK:
            STATE["stats"] = {
                "scanned": stats["scanned"],
                "infected": stats["infected"],
                "clean": stats["clean"]
            }

        add_log("\n" + "=" * 60, "cyan")
        add_log("              HIKMA FULL HOST SCAN SUMMARY", "cyan")
        add_log("=" * 60, "cyan")
        add_log(f"  * Files Evaluated:           {stats['scanned']}", "normal")
        add_log(f"  * Malicious Binaries Found:  {stats['infected']}", "alert" if stats['infected'] else "green")
        add_log(f"  * Clean Files:               {stats['clean']}", "green")
        add_log("  * Scope: entire system and component roots", "yellow")
        add_log("=" * 60, "cyan")
        add_log("[SUCCESS] Full system and component scan completed.\n", "green")

    finally:
        with LOCK:
            STATE["is_busy"] = False
            STATE["status"] = "SYSTEM READY"


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIKMA Rescue Engine Console</title>
    <style>
        :root {
            --bg: #0f172a;
            --panel: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --cyan: #38bdf8;
            --green: #22c55e;
            --red: #ef4444;
            --yellow: #f59e0b;
            --blue-btn: #0284c7;
            --blue-btn-hover: #0369a1;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 20px; }
        .header {
            background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
            padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;
        }
        .header h1 { font-size: 1.4rem; color: var(--cyan); letter-spacing: 0.5px; }
        .header p { font-size: 0.85rem; color: var(--text-muted); margin-top: 4px; }
        .badge {
            background: #14532d; color: var(--green); padding: 8px 14px; border-radius: 6px;
            font-weight: 700; font-size: 0.85rem; letter-spacing: 0.5px;
        }
        .badge.busy { background: #713f12; color: var(--yellow); }
        .layout { display: grid; grid-template-columns: 310px 1fr; gap: 20px; }
        .panel {
            background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px;
        }
        .panel-title { font-size: 0.9rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 14px; letter-spacing: 0.5px; }
        .btn {
            display: block; width: 100%; border: none; border-radius: 6px; padding: 12px; margin-bottom: 10px;
            font-size: 0.9rem; font-weight: 600; cursor: pointer; transition: all 0.15s ease; text-align: left;
        }
        .btn-hero { background: var(--blue-btn); color: #fff; text-align: center; font-size: 0.95rem; font-weight: 700; padding: 14px; }
        .btn-hero:hover { background: var(--blue-btn-hover); }
        .btn-secondary { background: #334155; color: var(--text); }
        .btn-secondary:hover { background: #475569; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-top: 20px; }
        .stat-card { background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 12px; text-align: center; }
        .stat-val { font-size: 1.3rem; font-weight: 700; margin-top: 4px; }
        .stat-lbl { font-size: 0.75rem; color: var(--text-muted); }
        .stat-val.infected { color: var(--red); }
        .stat-val.clean { color: var(--green); }
        .terminal-container { display: flex; flex-direction: column; height: 580px; }
        .terminal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .terminal-box {
            background: #020617; border: 1px solid var(--border); border-radius: 8px; padding: 14px;
            flex-grow: 1; overflow-y: auto; font-family: "Consolas", "Courier New", monospace; font-size: 0.85rem; line-height: 1.45;
        }
        .log-cyan { color: var(--cyan); }
        .log-green { color: var(--green); }
        .log-alert { color: var(--red); font-weight: 700; }
        .log-yellow { color: var(--yellow); }
        .log-normal { color: #e2e8f0; }
        .btn-clear { background: transparent; border: 1px solid var(--border); color: var(--text-muted); padding: 4px 10px; border-radius: 4px; font-size: 0.8rem; cursor: pointer; }
        .btn-clear:hover { background: #334155; color: var(--text); }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ HIKMA RESCUE ENGINE DASHBOARD</h1>
            <p>Hardware SMART Diagnostics • Offline Registry Healing • SHA-256 Threat Vault</p>
        </div>
        <div id="statusBadge" class="badge">● SYSTEM READY</div>
    </div>

    <div class="layout">
        <div class="panel">
            <div class="panel-title">Engine Actions</div>
            <button id="btnDemo" class="btn btn-hero" onclick="triggerAction('audit')">Run Full System &amp; Component Scan</button>
            <button class="btn btn-secondary" onclick="triggerAction('smart')">💾 Check Hardware SMART</button>
            <button class="btn btn-secondary" onclick="triggerAction('heal')">Check Offline Windows Registry</button>
            <button class="btn btn-secondary" onclick="triggerAction('scan')">🛡️ Scan Live Target (SHA-256)</button>
            <button class="btn btn-secondary" onclick="triggerAction('signatures')">🔄 Update Online Signatures (<span id="sigCount">20</span>)</button>
            <button class="btn btn-secondary" onclick="triggerAction('clean')">🧹 Reset Quarantine Vault</button>

            <div class="panel-title" style="margin-top: 24px;">Telemetry</div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-lbl">Scanned</div>
                    <div id="statScanned" class="stat-val">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-lbl">Infected</div>
                    <div id="statInfected" class="stat-val infected">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-lbl">Clean</div>
                    <div id="statClean" class="stat-val clean">0</div>
                </div>
            </div>
        </div>

        <div class="panel terminal-container">
            <div class="terminal-header">
                <div class="panel-title" style="margin: 0;">Live Rescue Console</div>
                <button class="btn-clear" onclick="clearLogs()">Clear</button>
            </div>
            <div id="terminal" class="terminal-box"></div>
        </div>
    </div>

    <script>
        let lastLogCount = 0;

        async function fetchState() {
            try {
                const res = await fetch('/api/state');
                const data = await res.json();
                
                // Update badge
                const badge = document.getElementById('statusBadge');
                badge.innerText = '● ' + data.status;
                if (data.is_busy) {
                    badge.className = 'badge busy';
                    document.getElementById('btnDemo').disabled = true;
                } else {
                    badge.className = 'badge';
                    document.getElementById('btnDemo').disabled = false;
                }

                // Update stats
                document.getElementById('statScanned').innerText = data.stats.scanned;
                document.getElementById('statInfected').innerText = data.stats.infected;
                document.getElementById('statClean').innerText = data.stats.clean;
                document.getElementById('sigCount').innerText = data.signatures_count;

                // Update logs
                if (data.logs.length !== lastLogCount) {
                    const term = document.getElementById('terminal');
                    term.innerHTML = '';
                    data.logs.forEach(item => {
                        const line = document.createElement('div');
                        line.className = 'log-' + (item.tag || 'normal');
                        line.innerText = item.text;
                        term.appendChild(line);
                    });
                    term.scrollTop = term.scrollHeight;
                    lastLogCount = data.logs.length;
                }
            } catch (e) {
                console.error(e);
            }
        }

        async function triggerAction(action) {
            await fetch('/api/action/' + action, { method: 'POST' });
            fetchState();
        }

        async function clearLogs() {
            await fetch('/api/action/clear', { method: 'POST' });
            document.getElementById('terminal').innerHTML = '';
            lastLogCount = 0;
        }

        setInterval(fetchState, 600);
        fetchState();
    </script>
</body>
</html>
"""


class HikmaHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
        elif self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            with LOCK:
                data = json.dumps(STATE)
            self.wfile.write(data.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        action = self.path.replace("/api/action/", "").strip("/")
        if action == "audit":
            threading.Thread(target=run_live_audit, daemon=True).start()
        elif action == "smart":
            def do_smart():
                add_log("\n[ACTION] Running Hardware Health & SMART Diagnostic...", "cyan")
                check_hardware_health(log_callback=add_log)
            threading.Thread(target=do_smart, daemon=True).start()
        elif action == "heal":
            def do_heal():
                add_log("\n[ACTION] Running Offline Registry Persistence Audit...", "cyan")
                offline_registry_heal(log_callback=add_log)
            threading.Thread(target=do_heal, daemon=True).start()
        elif action == "scan":
            def do_scan():
                signatures = load_malware_signatures()
                target = prepare_live_target()
                stats = scan_target_directory(target, signatures, recursive=True, auto_quarantine=True, log_callback=add_log)
                with LOCK:
                    STATE["stats"] = {"scanned": stats["scanned"], "infected": stats["infected"], "clean": stats["clean"]}
            threading.Thread(target=do_scan, daemon=True).start()
        elif action == "signatures":
            def update_signatures():
                with LOCK:
                    STATE["status"] = "SIGNATURE UPDATE RUNNING"
                add_log("[DATABASE] Refreshing from MalwareBazaar. Local signatures remain available offline.", "cyan")
                signatures, added, error = refresh_malware_signatures(DEFAULT_SIGNATURE_FEED_URL)
                with LOCK:
                    STATE["signatures_count"] = len(signatures)
                    STATE["status"] = "OFFLINE DATABASE READY" if error else "ONLINE DATABASE READY"
                if error:
                    add_log(f"[DATABASE] Online refresh failed: {error}", "yellow")
                    add_log(f"[DATABASE] Continuing offline with {len(signatures)} local signatures.", "green")
                else:
                    add_log(f"[DATABASE] Online refresh complete. Added {added}; active count: {len(signatures)}.", "green")
            threading.Thread(target=update_signatures, daemon=True).start()
        elif action == "clean":
            if QUARANTINE_DIR.exists():
                shutil.rmtree(QUARANTINE_DIR)
            with LOCK:
                STATE["stats"] = {"scanned": 0, "infected": 0, "clean": 0}
            add_log("[CLEAN] Quarantine vault reset.", "yellow")
        elif action == "clear":
            with LOCK:
                STATE["logs"].clear()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        # Silence standard HTTP server access logs
        pass


def start_server():
    parser = argparse.ArgumentParser(description="HIKMA Rescue Engine web dashboard")
    parser.add_argument("--host", default=HOST, help="Bind address (default: 127.0.0.1; use 0.0.0.0 for a trusted LAN)")
    parser.add_argument("--port", type=int, default=PORT, help="Listening port")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), HikmaHTTPHandler)
    address = "127.0.0.1" if args.host == "0.0.0.0" else args.host
    print(f"[HIKMA WEB GUI] Server listening at http://{address}:{args.port}")
    add_log(f"[HIKMA WEB GUI] Console loaded at http://{address}:{args.port}", "green")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        warning = "[SECURITY] Network-bound dashboard has no authentication or TLS; use only on a trusted network."
        print(warning)
        add_log(warning, "yellow")
    add_log("[READY] Choose a full system scan, hardware check, or folder scan to begin.\n", "cyan")
    server.serve_forever()


if __name__ == "__main__":
    start_server()
