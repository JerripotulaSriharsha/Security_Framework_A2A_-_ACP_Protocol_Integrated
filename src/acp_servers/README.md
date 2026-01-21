# ACP MCP Servers

This directory contains ACP (Agent Communication Protocol) servers for the MCP (Model Context Protocol) layer.

## Architecture

The ACP integration implements the MCP layer as independent microservices:

```
┌─────────────────────────────────────────────────────────────┐
│                    LangGraph Orchestrator                    │
│  (Enrich → Validity/Severity/Exploitability → Playbooks →   │
│   Decision → Upload XSOAR / SOC Triage → Update Status)     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    ACP MCP Client Layer                      │
│              (acp_mcp_client.py - port manager)              │
└───┬──────┬──────┬──────┬──────┬──────────────────────────────┘
    │      │      │      │      │
    ▼      ▼      ▼      ▼      ▼
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
│ 8001 ││ 8002 ││ 8003 ││ 8004 ││ 8005 │  ACP Servers
└──────┘└──────┘└──────┘└──────┘└──────┘
Upload  Notify  OSINT  Internal Status
XSOAR   SOC    Search  Search  Update
```

## Servers

| Server | Port | Agent | Purpose |
|--------|------|-------|---------|
| upload_incident_server | 8001 | upload_incident_agent | Upload incidents to XSOAR |
| notify_soc_server | 8002 | notify_soc_agent | Notify SOC analysts (Slack/PagerDuty) |
| search_external_osint_server | 8003 | search_external_osint_agent | Search OSINT (VT, AbuseIPDB, etc.) |
| search_internal_data_server | 8004 | search_internal_data_agent | Search internal sources (SIEM, EDR, CMDB) |
| update_status_server | 8005 | update_status_agent | Update incident status |

## Usage

### Start All Servers

```bash
python start_all_servers.py
```

This will start all 5 ACP servers on ports 8001-8005.

### Start Individual Server

```bash
python upload_incident_server.py
```

### Enable/Disable ACP Mode

Set environment variable `USE_ACP`:

```bash
# Enable ACP (default)
export USE_ACP=true

# Disable ACP (use original tools)
export USE_ACP=false
```

## Testing

Test individual servers:

```python
import asyncio
from acp_sdk.client import Client

async def test_upload():
    async with Client(base_url="http://localhost:8001") as client:
        result = await client.run_sync(
            agent='upload_incident_agent',
            input='{"alert": {"id": "TEST-001"}}'
        )
        print(result.output[0].parts[0].content)

asyncio.run(test_upload())
```

## Configuration

Server ports can be customized in `acp_mcp_client.py`:

```python
client = ACPMCPClient(
    upload_incident_url="http://localhost:8001",
    notify_soc_url="http://localhost:8002",
    # ... etc
)
```

## Dependencies

```bash
pip install acp-sdk nest-asyncio
```

## Integration with LangGraph

The `graph.py` automatically detects ACP mode via `USE_ACP` environment variable and uses the ACP client instead of direct tool calls. **No changes to LangGraph orchestrator logic required.**
