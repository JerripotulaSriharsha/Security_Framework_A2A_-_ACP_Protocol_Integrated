# Quick Start Guide - ACP Integration

## Prerequisites

- Python 3.9+
- pip installed
- Ports 8001-8005 available

## 3-Step Setup

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all required packages including:
- `acp-sdk` - Agent Communication Protocol SDK
- `nest-asyncio` - Async compatibility
- All existing dependencies (langchain, langgraph, streamlit, etc.)

### Step 2: Start ALL Agents (A2A + ACP)

Open a terminal and run:

```bash
python start_all_agents.py
```

This will start **8 agent servers**:
- **A2A Agents** (ports 9101-9103): Validity, Severity, Exploitability scoring
- **ACP Agents** (ports 8001-8005): External integrations (XSOAR, SOC, OSINT, etc.)

You should see:

```
======================================================================
Starting All Agents (A2A + ACP)
======================================================================

Starting A2A Scoring Agents...
  Starting validity on port 9101...
  ✓ validity started (PID: 12345)
  Starting severity on port 9102...
  ✓ severity started (PID: 12346)
  Starting exploitability on port 9103...
  ✓ exploitability started (PID: 12347)

Starting ACP MCP Agents...
  Starting upload_incident on port 8001...
  ✓ upload_incident started (PID: 12348)
  Starting notify_soc on port 8002...
  ✓ notify_soc started (PID: 12349)
  Starting search_external_osint on port 8003...
  ✓ search_external_osint started (PID: 12350)
  Starting search_internal_data on port 8004...
  ✓ search_internal_data started (PID: 12351)
  Starting update_status on port 8005...
  ✓ update_status started (PID: 12352)
======================================================================
All servers started. Total: 8
======================================================================

A2A Scoring Agents (Validity/Severity/Exploitability):
  - A2A:validity                 http://localhost:9101
  - A2A:severity                 http://localhost:9102
  - A2A:exploitability           http://localhost:9103

ACP MCP Agents (External Integrations):
  - ACP:upload_incident          http://localhost:8001
  - ACP:notify_soc               http://localhost:8002
  - ACP:search_external_osint    http://localhost:8003
  - ACP:search_internal_data     http://localhost:8004
  - ACP:update_status            http://localhost:8005

Press Ctrl+C to stop all servers...
```

**Keep this terminal open!** All servers need to stay running.

### Step 3: Run the Application

Open a **new terminal** and run:

```bash
cd src
streamlit run streamlit_app.py
```

The Streamlit UI will open in your browser at `http://localhost:8501`.

## Verify Installation

### Option 1: Run Test Suite

In another terminal:

```bash
python src/test_acp_integration.py
```

You should see all tests pass:

```
============================================================
ACP Integration Test Suite
============================================================
...
Total: 5/5 tests passed
============================================================

All tests passed! ACP integration is working correctly.
```

### Option 2: Manual Test

In the Streamlit UI:
1. Use the default alert or enter your own
2. Click **"Run ▶️"**
3. Watch the flow execute through all nodes
4. Check that enrichment, scoring, and decision-making work correctly

## Environment Configuration

### Enable ACP Mode (Default)

Create/edit `.env` file in the project root:

```bash
USE_ACP=true
```

### Disable ACP Mode (Fallback)

To use the original direct tool calls instead of ACP:

```bash
USE_ACP=false
```

Then restart the Streamlit app.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit UI (Input)                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              LangGraph Orchestrator (UNCHANGED)              │
│                                                               │
│  Enrich → [Validity/Severity/Exploitability] → Playbooks    │
│             ↓         ↓           ↓                          │
│          A2A Agents (9101-9103)                              │
│                                                               │
│           Decision → Upload/Triage → Update Status           │
│                          ↓                                    │
│                     ACP MCP Layer                            │
│                          ↓                                    │
│             ACP Agents (8001-8005)                           │
└─────────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┴────────────────┐
        │                                 │
        ▼                                 ▼
  A2A Protocol                      ACP Protocol
  (Scoring Agents)                  (MCP Integrations)
        │                                 │
  9101: validity                   8001: upload_incident
  9102: severity                   8002: notify_soc
  9103: exploitability             8003: search_external_osint
                                   8004: search_internal_data
                                   8005: update_status
```

## Common Issues

### Port Already in Use

**Error:** `Address already in use: 8001`

**Solution:**
```bash
# Find and kill process using the port
# Windows:
netstat -ano | findstr :8001
taskkill /PID <PID> /F

# Linux/Mac:
lsof -ti:8001 | xargs kill -9
```

### Connection Refused

**Error:** `Connection refused to http://localhost:8001`

**Solution:** Make sure the ACP servers are running:
```bash
python src/acp_servers/start_all_servers.py
```

### Import Error: acp_sdk

**Error:** `ModuleNotFoundError: No module named 'acp_sdk'`

**Solution:** Install dependencies:
```bash
pip install -r requirements.txt
```

## What's Next?

1. **Explore the Code:** Check out the ACP servers in `src/acp_servers/`
2. **Customize Integrations:** Replace TODO comments with real API calls
3. **Read Full Guide:** See [ACP_INTEGRATION_GUIDE.md](ACP_INTEGRATION_GUIDE.md)
4. **Deploy to Production:** Follow deployment guide for Docker/K8s

## Need Help?

- 📖 Full documentation: [ACP_INTEGRATION_GUIDE.md](ACP_INTEGRATION_GUIDE.md)
- 📋 Implementation details: [ACP_IMPLEMENTATION_SUMMARY.md](ACP_IMPLEMENTATION_SUMMARY.md)
- 🔧 Server docs: [src/acp_servers/README.md](src/acp_servers/README.md)

## Summary

You now have:
- ✅ 5 independent ACP microservices running
- ✅ LangGraph orchestrator working with ACP backend
- ✅ Streamlit UI for testing the full flow
- ✅ Environment toggle between ACP and direct modes

**Enjoy your ACP-integrated A2A Security Framework!** 🎉
