"""
HIDS - Flask Web API Server
Serves the dashboard and real-time monitoring API
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from hids_engine import HIDSEngine, Severity
import threading
import json
import time

app = Flask(__name__)
CORS(app)

# Global HIDS engine instance
engine = HIDSEngine()

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/status")
def api_status():
    return jsonify({
        "running":    engine.running,
        "scan_count": engine.scan_count,
        "uptime":     str(__import__("datetime").datetime.now() - engine.start_time).split(".")[0],
        "stats":      engine.stats,
        "alert_count": len(engine.alerts)
    })

@app.route("/api/system")
def api_system():
    return jsonify(engine.get_system_health())

@app.route("/api/alerts")
def api_alerts():
    limit     = int(request.args.get("limit", 50))
    severity  = request.args.get("severity", None)
    alerts    = [a.to_dict() for a in engine.alerts[-200:]]
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity.upper()]
    return jsonify(list(reversed(alerts))[:limit])

@app.route("/api/processes")
def api_processes():
    return jsonify(engine.get_processes())

@app.route("/api/connections")
def api_connections():
    return jsonify(engine.get_connections())

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    path = data.get("path", None)
    result = engine.run_scan(path)
    return jsonify({"success": True, "result": result})

@app.route("/api/start", methods=["POST"])
def api_start():
    if not engine.running:
        engine.start_monitoring(interval=30)
    return jsonify({"success": True, "message": "Monitoring started"})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    engine.stop_monitoring()
    return jsonify({"success": True, "message": "Monitoring stopped"})

@app.route("/api/clear_alerts", methods=["POST"])
def api_clear():
    engine.alerts.clear()
    engine.stats["total_alerts"]    = 0
    engine.stats["critical_alerts"] = 0
    engine.stats["high_alerts"]     = 0
    engine.stats["medium_alerts"]   = 0
    engine.stats["low_alerts"]      = 0
    return jsonify({"success": True})

@app.route("/api/signatures")
def api_signatures():
    from hids_engine import VIRUS_SIGNATURES
    return jsonify({
        "process_signatures": VIRUS_SIGNATURES["processes"],
        "suspicious_ports":   VIRUS_SIGNATURES["ports"],
        "known_hashes":       len(VIRUS_SIGNATURES["hashes"]),
        "keywords":           VIRUS_SIGNATURES["keywords"],
    })

# ─── Start Server ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  HIDS - Host-Based Intrusion Detection System")
    print("  College Project | Security Monitoring Dashboard")
    print("=" * 60)
    print("  Dashboard:  http://127.0.0.1:5000")
    print("  API Base:   http://127.0.0.1:5000/api/")
    print("=" * 60)

    # Auto-run initial scan in background
    threading.Thread(target=engine.run_scan, daemon=True).start()
    # Start continuous monitoring
    engine.start_monitoring(interval=60)

    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
