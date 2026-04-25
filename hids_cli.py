"""
HIDS CLI Scanner — Run from terminal for quick scans
Usage: python hids_cli.py [--path /path/to/scan] [--watch] [--interval 30]
"""

import argparse
import time
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from hids_engine import HIDSEngine, Severity
from datetime import datetime

# Terminal colors
R  = "\033[91m"
Y  = "\033[93m"
G  = "\033[92m"
B  = "\033[94m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

BANNER = f"""
{C}{BOLD}
  ██╗  ██╗██╗██████╗ ███████╗
  ██║  ██║██║██╔══██╗██╔════╝
  ███████║██║██║  ██║███████╗
  ██╔══██║██║██║  ██║╚════██║
  ██║  ██║██║██████╔╝███████║
  ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝
{RST}{DIM}  Host-Based Intrusion Detection System{RST}
{DIM}  College Security Project — CLI Mode{RST}
"""

SEV_COLOR = {
    Severity.CRITICAL: R,
    Severity.HIGH:     Y,
    Severity.MEDIUM:   B,
    Severity.LOW:      G,
    Severity.INFO:     DIM,
}

def print_alert(alert):
    color = SEV_COLOR.get(alert.severity, W)
    ts = datetime.fromisoformat(alert.timestamp).strftime("%H:%M:%S")
    print(f"  {color}[{alert.severity:8s}]{RST} {W}{alert.message}{RST}")
    print(f"  {DIM}           {ts} | {alert.category}{RST}")
    if alert.details:
        for k, v in list(alert.details.items())[:3]:
            print(f"  {DIM}           {k}: {v}{RST}")
    print()

def run_scan_cli(engine, path):
    print(f"\n{C}{'─'*55}{RST}")
    print(f"  {BOLD}Scan #{engine.scan_count + 1}{RST}  {DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    print(f"{C}{'─'*55}{RST}\n")

    prev_count = len(engine.alerts)
    result = engine.run_scan(path)

    new_alerts = engine.alerts[prev_count:]
    if new_alerts:
        print(f"  {R}{BOLD}⚠  {len(new_alerts)} threat(s) detected!{RST}\n")
        for a in new_alerts:
            print_alert(a)
    else:
        print(f"  {G}✓  No threats detected — system clean{RST}\n")

    s = engine.stats
    print(f"  {DIM}Scanned: {s['processes_scanned']} processes | {s['files_scanned']} files | {s['connections_scanned']} connections{RST}")
    print(f"  {DIM}Duration: {result['duration']}s{RST}\n")

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="HIDS CLI Scanner")
    parser.add_argument("--path",     default=None, help="Directory to scan (default: home dir)")
    parser.add_argument("--watch",    action="store_true", help="Continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=30, help="Scan interval in seconds (watch mode)")
    args = parser.parse_args()

    engine = HIDSEngine()

    if args.watch:
        print(f"  {G}Starting continuous monitoring (interval={args.interval}s){RST}")
        print(f"  {DIM}Press Ctrl+C to stop{RST}\n")
        try:
            while True:
                run_scan_cli(engine, args.path)
                print(f"  {DIM}Next scan in {args.interval}s...{RST}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n\n  {Y}Monitoring stopped by user{RST}\n")
    else:
        run_scan_cli(engine, args.path)

    # Final summary
    s = engine.stats
    print(f"\n{C}{'═'*55}{RST}")
    print(f"  {BOLD}SCAN SUMMARY{RST}")
    print(f"  Total Alerts:    {R if s['total_alerts'] else G}{s['total_alerts']}{RST}")
    print(f"  Critical:        {R}{s['critical_alerts']}{RST}")
    print(f"  High:            {Y}{s['high_alerts']}{RST}")
    print(f"  Medium:          {B}{s['medium_alerts']}{RST}")
    print(f"  Low:             {G}{s['low_alerts']}{RST}")
    print(f"{C}{'═'*55}{RST}\n")

if __name__ == "__main__":
    main()
