# ACP Servers Package
"""
Agent Communication Protocol (ACP) servers for the MCP layer.

This package contains independent microservices that handle external integrations:
- upload_incident_server: XSOAR incident uploads (port 8001)
- notify_soc_server: SOC notifications (port 8002)
- search_external_osint_server: OSINT searches (port 8003)
- search_internal_data_server: Internal data searches (port 8004)
- update_status_server: Status updates (port 8005)
"""

__version__ = "1.0.0"
