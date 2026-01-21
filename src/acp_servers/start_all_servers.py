#!/usr/bin/env python3
"""
Start all ACP MCP servers in separate processes.
This orchestrator launches each server on its designated port.
"""
import subprocess
import sys
import time
from pathlib import Path

# Server configurations
SERVERS = [
    {"name": "upload_incident", "port": 8001, "file": "upload_incident_server.py"},
    {"name": "notify_soc", "port": 8002, "file": "notify_soc_server.py"},
    {"name": "search_external_osint", "port": 8003, "file": "search_external_osint_server.py"},
    {"name": "search_internal_data", "port": 8004, "file": "search_internal_data_server.py"},
    {"name": "update_status", "port": 8005, "file": "update_status_server.py"},
]

def start_servers():
    """Start all ACP servers."""
    processes = []
    current_dir = Path(__file__).parent

    print("Starting ACP MCP Servers...")
    print("=" * 60)

    for server in SERVERS:
        server_path = current_dir / server["file"]
        print(f"Starting {server['name']} on port {server['port']}...")

        try:
            proc = subprocess.Popen(
                [sys.executable, str(server_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            processes.append({
                "name": server["name"],
                "port": server["port"],
                "process": proc
            })
            print(f"  ✓ {server['name']} started (PID: {proc.pid})")
        except Exception as e:
            print(f"  ✗ Failed to start {server['name']}: {e}")

    print("=" * 60)
    print(f"All servers started. Total: {len(processes)}")
    print("\nServer URLs:")
    for p in processes:
        print(f"  - {p['name']}: http://localhost:{p['port']}")

    print("\nPress Ctrl+C to stop all servers...")

    try:
        # Keep main process alive and monitor subprocesses
        while True:
            time.sleep(1)
            for p in processes:
                if p["process"].poll() is not None:
                    print(f"\n⚠ {p['name']} stopped unexpectedly (exit code: {p['process'].returncode})!")
                    # Print stderr if available
                    try:
                        stderr = p["process"].stderr.read()
                        if stderr:
                            print(f"   Error: {stderr[:500]}")
                    except Exception:
                        pass
    except KeyboardInterrupt:
        print("\n\nShutting down all servers...")
        for p in processes:
            print(f"  Stopping {p['name']}...")
            p["process"].terminate()
            p["process"].wait()
        print("All servers stopped.")

if __name__ == "__main__":
    start_servers()
