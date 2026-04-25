"""
HIDS - Host-Based Intrusion Detection System
Core Engine Module
Author: College Project
"""

import os
import sys
import time
import json
import hashlib
import logging
import platform
import threading
import subprocess
import psutil
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─── Logging Setup ───────────────────────────────────────────────────────────
LOG_FILE = Path(__file__).parent / "logs" / "hids.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("HIDS")

# ─── Threat Signatures Database ───────────────────────────────────────────────
VIRUS_SIGNATURES = {
    # MD5 hashes of known malware (demo values)
    "hashes": {
        "d41d8cd98f00b204e9800998ecf8427e": "Empty File Exploit",
        "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus",
        "69630e4574ec6798239b091cda43dca0": "CryptoLocker Sample",
    },
    # Suspicious process names
    "processes": [
        "mimikatz", "metasploit", "nmap", "netcat", "nc.exe",
        "meterpreter", "cobaltstrike", "empire", "havoc",
        "keylogger", "ransomware", "cryptominer", "xmrig",
        "torrent", "darkcomet", "njrat", "remcos"
    ],
    # Suspicious network ports
    "ports": {
        4444: "Metasploit Default Port",
        1337: "Common Backdoor Port",
        6667: "IRC Botnet C2",
        8080: "Common Proxy/Malware Port",
        9001: "Tor Relay Port",
        31337: "Elite Hacker Port",
        12345: "Common Backdoor",
        54321: "Reverse Shell Port"
    },
    # Suspicious file extensions
    "extensions": [
        ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".jar", ".py",
        ".sh", ".php", ".asp", ".aspx", ".dll", ".scr", ".pif"
    ],
    # Suspicious keywords in file names
    "keywords": [
        "keylog", "exploit", "payload", "backdoor", "rootkit",
        "ransomware", "trojan", "spyware", "adware", "malware",
        "virus", "worm", "botnet", "cryptominer", "stealer"
    ],
    # Suspicious registry keys (Windows)
    "registry_patterns": [
        r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
}

# ─── Alert Severity Levels ───────────────────────────────────────────────────
class Severity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

# ─── Alert Class ─────────────────────────────────────────────────────────────
class Alert:
    def __init__(self, severity, category, message, details=None):
        self.id        = int(time.time() * 1000)
        self.severity  = severity
        self.category  = category
        self.message   = message
        self.details   = details or {}
        self.timestamp = datetime.now().isoformat()
        self.resolved  = False

    def to_dict(self):
        return {
            "id":        self.id,
            "severity":  self.severity,
            "category":  self.category,
            "message":   self.message,
            "details":   self.details,
            "timestamp": self.timestamp,
            "resolved":  self.resolved
        }

# ─── HIDS Engine ─────────────────────────────────────────────────────────────
class HIDSEngine:
    def __init__(self):
        self.alerts           = []
        self.running          = False
        self.scan_count       = 0
        self.start_time       = datetime.now()
        self.baseline         = {}
        self.alert_callbacks  = []
        self.stats = {
            "total_alerts":    0,
            "critical_alerts": 0,
            "high_alerts":     0,
            "medium_alerts":   0,
            "low_alerts":      0,
            "processes_scanned": 0,
            "files_scanned":   0,
            "connections_scanned": 0,
        }

    def add_alert_callback(self, cb):
        self.alert_callbacks.append(cb)

    def _emit_alert(self, alert: Alert):
        self.alerts.append(alert)
        self.stats["total_alerts"] += 1
        sev = alert.severity
        if   sev == Severity.CRITICAL: self.stats["critical_alerts"] += 1
        elif sev == Severity.HIGH:     self.stats["high_alerts"]     += 1
        elif sev == Severity.MEDIUM:   self.stats["medium_alerts"]   += 1
        elif sev == Severity.LOW:      self.stats["low_alerts"]      += 1

        logger.warning(f"[{sev}] {alert.category}: {alert.message}")
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    # ── Process Monitor ───────────────────────────────────────────────────────
    def scan_processes(self):
        threats = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "cpu_percent", "memory_percent", "username"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                cmdline = " ".join(info.get("cmdline") or []).lower()
                self.stats["processes_scanned"] += 1

                for sig in VIRUS_SIGNATURES["processes"]:
                    if sig in name or sig in cmdline:
                        a = Alert(
                            Severity.CRITICAL,
                            "Process Threat",
                            f"Suspicious process detected: {info['name']} (PID {info['pid']})",
                            {
                                "pid":     info["pid"],
                                "name":    info["name"],
                                "exe":     info.get("exe"),
                                "cpu":     round(info.get("cpu_percent") or 0, 2),
                                "memory":  round(info.get("memory_percent") or 0, 2),
                                "user":    info.get("username"),
                                "matched": sig
                            }
                        )
                        self._emit_alert(a)
                        threats.append(a)
                        break

                # High CPU usage check (possible cryptominer)
                cpu = info.get("cpu_percent") or 0
                if cpu and cpu > 90:
                    a = Alert(
                        Severity.MEDIUM,
                        "Resource Abuse",
                        f"High CPU usage by {info['name']} ({cpu:.1f}%) — possible cryptominer",
                        {"pid": info["pid"], "name": info["name"], "cpu": cpu}
                    )
                    self._emit_alert(a)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return threats

    # ── Network Monitor ───────────────────────────────────────────────────────
    def scan_network(self):
        threats = []
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                self.stats["connections_scanned"] += 1
                if conn.raddr and conn.raddr.port in VIRUS_SIGNATURES["ports"]:
                    port    = conn.raddr.port
                    label   = VIRUS_SIGNATURES["ports"][port]
                    pid     = conn.pid
                    proc_name = "unknown"
                    try:
                        proc_name = psutil.Process(pid).name() if pid else "unknown"
                    except Exception:
                        pass
                    a = Alert(
                        Severity.HIGH,
                        "Network Threat",
                        f"Suspicious outbound connection to port {port} ({label})",
                        {
                            "local_addr":  f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                            "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status":      conn.status,
                            "pid":         pid,
                            "process":     proc_name,
                            "threat":      label
                        }
                    )
                    self._emit_alert(a)
                    threats.append(a)
        except psutil.AccessDenied:
            logger.warning("Access denied for network connections (try running as admin)")
        return threats

    # ── File System Monitor ───────────────────────────────────────────────────
    def scan_directory(self, path, max_files=200):
        threats = []
        try:
            root = Path(path)
            count = 0
            for f in root.rglob("*"):
                if count >= max_files:
                    break
                if not f.is_file():
                    continue
                count += 1
                self.stats["files_scanned"] += 1
                name_lower = f.name.lower()

                # Keyword check
                for kw in VIRUS_SIGNATURES["keywords"]:
                    if kw in name_lower:
                        a = Alert(
                            Severity.HIGH,
                            "File System Threat",
                            f"Suspicious filename detected: {f.name}",
                            {"path": str(f), "keyword": kw, "size": f.stat().st_size}
                        )
                        self._emit_alert(a)
                        threats.append(a)
                        break

                # Hash check (only small files for demo speed)
                if f.stat().st_size < 5_000_000:
                    try:
                        md5 = hashlib.md5(f.read_bytes()).hexdigest()
                        if md5 in VIRUS_SIGNATURES["hashes"]:
                            a = Alert(
                                Severity.CRITICAL,
                                "Known Malware",
                                f"Known malware hash matched: {f.name}",
                                {
                                    "path":   str(f),
                                    "md5":    md5,
                                    "threat": VIRUS_SIGNATURES["hashes"][md5]
                                }
                            )
                            self._emit_alert(a)
                            threats.append(a)
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"File scan error: {e}")
        return threats

    # ── System Health ─────────────────────────────────────────────────────────
    def get_system_health(self):
        cpu      = psutil.cpu_percent(interval=0.5)
        mem      = psutil.virtual_memory()
        disk     = psutil.disk_usage("/")
        net_io   = psutil.net_io_counters()
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime   = str(datetime.now() - boot_time).split(".")[0]

        return {
            "cpu_percent":    round(cpu, 1),
            "mem_percent":    round(mem.percent, 1),
            "mem_used_gb":    round(mem.used / 1e9, 2),
            "mem_total_gb":   round(mem.total / 1e9, 2),
            "disk_percent":   round(disk.percent, 1),
            "disk_used_gb":   round(disk.used / 1e9, 2),
            "disk_total_gb":  round(disk.total / 1e9, 2),
            "bytes_sent_mb":  round(net_io.bytes_sent / 1e6, 2),
            "bytes_recv_mb":  round(net_io.bytes_recv / 1e6, 2),
            "uptime":         uptime,
            "os":             platform.system(),
            "hostname":       platform.node(),
            "platform":       platform.platform(),
            "python_version": platform.python_version(),
        }

    # ── Running Processes Snapshot ────────────────────────────────────────────
    def get_processes(self, limit=30):
        procs = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status", "username"]):
            try:
                info = proc.info
                name_lower = (info.get("name") or "").lower()
                suspicious = any(sig in name_lower for sig in VIRUS_SIGNATURES["processes"])
                procs.append({
                    "pid":        info["pid"],
                    "name":       info["name"],
                    "cpu":        round(info.get("cpu_percent") or 0, 2),
                    "memory":     round(info.get("memory_percent") or 0, 2),
                    "status":     info.get("status"),
                    "user":       info.get("username"),
                    "suspicious": suspicious
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        procs.sort(key=lambda x: x["cpu"], reverse=True)
        return procs[:limit]

    # ── Network Connections Snapshot ──────────────────────────────────────────
    def get_connections(self, limit=20):
        conns = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr:
                    continue
                port = conn.raddr.port
                suspicious = port in VIRUS_SIGNATURES["ports"]
                threat_name = VIRUS_SIGNATURES["ports"].get(port, "")
                proc_name = "unknown"
                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                except Exception:
                    pass
                conns.append({
                    "local":      f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    "remote":     f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status":     conn.status,
                    "pid":        conn.pid,
                    "process":    proc_name,
                    "suspicious": suspicious,
                    "threat":     threat_name
                })
        except psutil.AccessDenied:
            pass
        return conns[:limit]

    # ── Full Scan ─────────────────────────────────────────────────────────────
    def run_scan(self, scan_path=None):
        self.scan_count += 1
        logger.info(f"Starting HIDS scan #{self.scan_count}")
        scan_path = scan_path or str(Path.home())
        start = time.time()

        self.scan_processes()
        self.scan_network()
        self.scan_directory(scan_path)

        duration = round(time.time() - start, 2)
        logger.info(f"Scan #{self.scan_count} completed in {duration}s")
        return {"scan_number": self.scan_count, "duration": duration}

    # ── Background Monitoring ─────────────────────────────────────────────────
    def start_monitoring(self, interval=30):
        self.running = True
        def monitor_loop():
            while self.running:
                try:
                    self.run_scan()
                except Exception as e:
                    logger.error(f"Monitor loop error: {e}")
                time.sleep(interval)
        t = threading.Thread(target=monitor_loop, daemon=True)
        t.start()
        logger.info(f"HIDS monitoring started (interval={interval}s)")

    def stop_monitoring(self):
        self.running = False
        logger.info("HIDS monitoring stopped")

    def get_status(self):
        return {
            "running":    self.running,
            "scan_count": self.scan_count,
            "uptime":     str(datetime.now() - self.start_time).split(".")[0],
            "alerts":     [a.to_dict() for a in self.alerts[-100:]],
            "stats":      self.stats,
        }
