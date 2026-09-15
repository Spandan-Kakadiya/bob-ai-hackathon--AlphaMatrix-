"""
BOB Defense Threat Intelligence Platform
One-Click Tactical Launcher Script with Auto-Port Resolution
"""

import sys
import os
import socket
import threading
import time
import webbrowser
from pathlib import Path
import uvicorn

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

def find_available_port(start_port: int = 8000, max_attempts: int = 20) -> int:
    """Find the first open available TCP port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port

def main():
    chosen_port = find_available_port(8000)

    print("=" * 68)
    print("  PROJECT BOB // MULTI-SOURCE DEFENSE THREAT INTEL PLATFORM")
    print("  Correlation Engine • MITRE ATT&CK Mapping • BLUF Briefings")
    print("=" * 68)
    print(f"\n[+] Starting Defense Intelligence Backend on http://127.0.0.1:{chosen_port} ...")
    print(f"[+] Tactical Command HUD available at http://127.0.0.1:{chosen_port}")
    print("[+] Press Ctrl+C to terminate tactical command session.\n")

    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(f"http://127.0.0.1:{chosen_port}")
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True).start()

    try:
        # Launch Uvicorn Server on available port
        uvicorn.run("backend.main:app", host="127.0.0.1", port=chosen_port, log_level="info")
    except KeyboardInterrupt:
        print("\n[!] Shutting down BOB Tactical Platform...")

if __name__ == "__main__":
    main()
