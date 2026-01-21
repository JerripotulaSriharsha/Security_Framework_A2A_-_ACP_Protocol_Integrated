#!/usr/bin/env python3
"""
Master startup script for ALL agents (A2A + ACP).

This script starts:
1. A2A Scoring Agents (ports 9101-9103) - Validity, Severity, Exploitability
2. ACP MCP Agents (ports 8001-8005) - External integrations
"""
import subprocess
import sys
import time
from pathlib import Path

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

# A2A Scoring Agents (for validity, severity, exploitability)
A2A_SERVERS = [
    {"name": "validity", "port": 9101, "file": "src/validity_server.py"},
    {"name": "severity", "port": 9102, "file": "src/severity_server.py"},
    {"name": "exploitability", "port": 9103, "file": "src/exploitability_server.py"},
]

# ACP MCP Agents (for external integrations)
ACP_SERVERS = [
    {"name": "upload_incident", "port": 8001, "file": "src/acp_servers/upload_incident_server.py"},
    {"name": "notify_soc", "port": 8002, "file": "src/acp_servers/notify_soc_server.py"},
    {"name": "search_external_osint", "port": 8003, "file": "src/acp_servers/search_external_osint_server.py"},
    {"name": "search_internal_data", "port": 8004, "file": "src/acp_servers/search_internal_data_server.py"},
    {"name": "update_status", "port": 8005, "file": "src/acp_servers/update_status_server.py"},
]

def start_servers():
    """Start all A2A and ACP servers."""
    processes = []
    current_dir = Path(__file__).parent

    print(f"{YELLOW}{'='*70}{RESET}")
    print(f"{YELLOW}Starting All Agents (A2A + ACP){RESET}")
    print(f"{YELLOW}{'='*70}{RESET}\n")

    # Start A2A Scoring Agents
    print(f"{BLUE}Starting A2A Scoring Agents...{RESET}")
    for server in A2A_SERVERS:
        server_path = current_dir / server["file"]
        print(f"  Starting {server['name']} on port {server['port']}...")

        try:
            proc = subprocess.Popen(
                [sys.executable, str(server_path)]
            )
            processes.append({
                "name": f"A2A:{server['name']}",
                "port": server["port"],
                "process": proc,
                "type": "a2a"
            })
            print(f"  {GREEN}✓ {server['name']} started (PID: {proc.pid}){RESET}")
        except Exception as e:
            print(f"  {RED}✗ Failed to start {server['name']}: {e}{RESET}")

    print()

    # Start ACP MCP Agents
    print(f"{BLUE}Starting ACP MCP Agents...{RESET}")
    for server in ACP_SERVERS:
        server_path = current_dir / server["file"]
        print(f"  Starting {server['name']} on port {server['port']}...")

        try:
            proc = subprocess.Popen(
                [sys.executable, str(server_path)]
            )
            processes.append({
                "name": f"ACP:{server['name']}",
                "port": server["port"],
                "process": proc,
                "type": "acp"
            })
            print(f"  {GREEN}✓ {server['name']} started (PID: {proc.pid}){RESET}")
        except Exception as e:
            print(f"  {RED}✗ Failed to start {server['name']}: {e}{RESET}")

    print(f"\n{YELLOW}{'='*70}{RESET}")
    print(f"{GREEN}All servers started. Total: {len(processes)}{RESET}")
    print(f"{YELLOW}{'='*70}{RESET}\n")

    # Display URLs by category
    print(f"{BLUE}A2A Scoring Agents (Validity/Severity/Exploitability):{RESET}")
    for p in [x for x in processes if x["type"] == "a2a"]:
        print(f"  - {p['name']:30} http://localhost:{p['port']}")

    print(f"\n{BLUE}ACP MCP Agents (External Integrations):{RESET}")
    for p in [x for x in processes if x["type"] == "acp"]:
        print(f"  - {p['name']:30} http://localhost:{p['port']}")

    print(f"\n{YELLOW}Press Ctrl+C to stop all servers...{RESET}\n")

    try:
        # Keep main process alive and monitor subprocesses
        while True:
            time.sleep(2)
            for p in processes:
                if p["process"].poll() is not None:
                    print(f"\n{RED}⚠ {p['name']} stopped unexpectedly (exit code: {p['process'].returncode})!{RESET}")
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Shutting down all servers...{RESET}")
        for p in processes:
            print(f"  Stopping {p['name']}...")
            p["process"].terminate()
            p["process"].wait()
        print(f"{GREEN}All servers stopped.{RESET}")

if __name__ == "__main__":
    start_servers()
