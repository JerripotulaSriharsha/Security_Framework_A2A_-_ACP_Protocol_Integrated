# ACP Integration Guide

## Overview

This project now supports **ACP (Agent Communication Protocol)** for the MCP (Model Context Protocol) layer. The ACP integration allows external integrations (XSOAR, SOC notifications, OSINT, internal data sources) to run as independent microservices.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Input Layer (Streamlit UI)                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              LangGraph Orchestrator (UNTOUCHED)              │
│                                                               │
│  Enrich → Validity/Severity/Exploitability → Playbooks →    │
│  Decision → Upload XSOAR / SOC Triage → Update Status       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    ACP MCP Client Layer                      │
│              (acp_mcp_client.py - orchestrator)              │
└───┬──────┬──────┬──────┬──────┬──────────────────────────────┘
    │      │      │      │      │
    ▼      ▼      ▼      ▼      ▼
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
│ 8001 ││ 8002 ││ 8003 ││ 8004 ││ 8005 │  ACP Agent Servers
└──────┘└──────┘└──────┘└──────┘└──────┘
Upload  Notify  OSINT  Internal Status
XSOAR   SOC    Search  Search  Update
   │      │      │      │      │
   ▼      ▼      ▼      ▼      ▼
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
│XSOAR ││Slack ││ VT   ││SIEM  ││Case  │  External Systems
│      ││PgDuty││AbuseI││EDR   ││Mgmt  │
└──────┘└──────┘└──────┘└──────┘└──────┘
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- All existing dependencies
- `acp-sdk` for Agent Communication Protocol
- `nest-asyncio` for async compatibility

### 2. Start ACP Servers

```bash
cd src/acp_servers
python start_all_servers.py
```

This starts all 5 ACP servers on ports 8001-8005:

| Port | Server | Agent | Purpose |
|------|--------|-------|---------|
| 8001 | upload_incident_server | upload_incident_agent | XSOAR incident uploads |
| 8002 | notify_soc_server | notify_soc_agent | SOC notifications (Slack/PagerDuty) |
| 8003 | search_external_osint_server | search_external_osint_agent | OSINT searches (VT, AbuseIPDB, etc.) |
| 8004 | search_internal_data_server | search_internal_data_agent | Internal data (SIEM, EDR, CMDB) |
| 8005 | update_status_server | update_status_agent | Status updates |

### 3. Enable ACP Mode

Set environment variable (default is `true`):

```bash
# .env file
USE_ACP=true
```

Or disable ACP to use original tools:

```bash
USE_ACP=false
```

### 4. Run the Application

```bash
cd src
streamlit run streamlit_app.py
```

## How It Works

### Without ACP (Original)
```
graph.py → tools.py → Direct function calls
```

### With ACP (New)
```
graph.py → acp_mcp_client.py → HTTP/ACP → Agent Servers → External Systems
```

### Key Features

1. **Zero Changes to LangGraph**: The orchestrator logic remains untouched
2. **Drop-in Replacement**: ACP client matches the exact API of `tools.py`
3. **Environment Toggle**: Switch between ACP and direct mode via `USE_ACP`
4. **Microservices**: Each integration runs as an independent server
5. **Scalability**: Servers can be deployed separately and scaled independently

## Configuration

### Custom Ports

Edit `src/acp_mcp_client.py`:

```python
client = ACPMCPClient(
    upload_incident_url="http://localhost:8001",
    notify_soc_url="http://localhost:8002",
    search_osint_url="http://localhost:8003",
    search_internal_url="http://localhost:8004",
    update_status_url="http://localhost:8005"
)
```

### Remote Servers

Point to remote ACP servers:

```python
client = ACPMCPClient(
    upload_incident_url="http://xsoar-agent.example.com:8001",
    notify_soc_url="http://soc-notify.example.com:8002",
    # ... etc
)
```

## Testing Individual Servers

### Test Upload Incident Server

```python
import asyncio
from acp_sdk.client import Client

async def test():
    async with Client(base_url="http://localhost:8001") as client:
        result = await client.run_sync(
            agent='upload_incident_agent',
            input='{"alert": {"id": "TEST-001"}}'
        )
        print(result.output[0].parts[0].content)

asyncio.run(test())
```

### Test Notify SOC Server

```python
import asyncio
from acp_sdk.client import Client

async def test():
    async with Client(base_url="http://localhost:8002") as client:
        result = await client.run_sync(
            agent='notify_soc_agent',
            input='{"alert": {"id": "TEST-001"}, "note": "Critical alert"}'
        )
        print(result.output[0].parts[0].content)

asyncio.run(test())
```

## Implementing Real Integrations

Each server in `src/acp_servers/` contains a `# TODO` comment where you should add real integration code.

### Example: Real XSOAR Upload

Edit `src/acp_servers/upload_incident_server.py`:

```python
@server.agent()
async def upload_incident_agent(messages: list[Message]) -> AsyncGenerator[RunYield, RunYieldResume]:
    import json
    import httpx  # Add real HTTP client

    query = " ".join(part.content for m in messages for part in m.parts)
    payload = json.loads(query)

    # Real XSOAR integration
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://xsoar.example.com/api/v1/incidents",
            json=payload,
            headers={"Authorization": f"Bearer {XSOAR_API_KEY}"}
        )
        result = response.json()

    yield Message(parts=[MessagePart(content=json.dumps(result))])
```

## Deployment

### Development
```bash
python src/acp_servers/start_all_servers.py
```

### Production (Docker)

Create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  upload-incident:
    build: ./src/acp_servers
    command: python upload_incident_server.py
    ports:
      - "8001:8001"

  notify-soc:
    build: ./src/acp_servers
    command: python notify_soc_server.py
    ports:
      - "8002:8002"

  # ... etc for other servers
```

## Troubleshooting

### Servers Not Starting
- Check ports 8001-8005 are available
- Review server logs for errors

### Connection Refused
- Ensure all servers are running: `python start_all_servers.py`
- Check firewall rules

### Fallback to Original Tools
Set `USE_ACP=false` to bypass ACP and use direct tool calls.

## Benefits

1. **Separation of Concerns**: External integrations isolated from core logic
2. **Independent Scaling**: Scale each integration service separately
3. **Language Agnostic**: ACP servers can be written in any language
4. **Easy Testing**: Test integrations independently
5. **Fault Isolation**: If one server fails, others continue working

## Next Steps

1. Replace TODO comments with real API integrations
2. Add authentication/authorization to ACP servers
3. Implement health checks and monitoring
4. Deploy servers to production infrastructure
5. Add retry logic and circuit breakers
