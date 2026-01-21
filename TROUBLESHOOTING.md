# Troubleshooting Guide

## Common Issues and Solutions

### Issue: Servers Stop Unexpectedly

**Symptoms:**
```
⚠ upload_incident stopped unexpectedly!
⚠ notify_soc stopped unexpectedly!
```

**Solution:**
This is caused by a uvicorn version incompatibility with acp-sdk. The issue has been fixed in the requirements.txt.

**Steps to fix:**
```bash
pip install "uvicorn<0.32.0"
```

Or reinstall all dependencies:
```bash
pip install -r requirements.txt --force-reinstall
```

### Issue: AttributeError: module 'uvicorn.config' has no attribute 'LoopSetupType'

**Cause:** acp-sdk 1.0.3 is incompatible with uvicorn >= 0.32.0

**Solution:**
```bash
pip install "uvicorn<0.32.0"
```

### Issue: ModuleNotFoundError: No module named 'acp_sdk'

**Solution:**
```bash
pip install acp-sdk nest-asyncio
```

### Issue: Port Already in Use

**Error:**
```
OSError: [WinError 10048] Only one usage of each socket address
```

**Solution (Windows):**
```bash
# Find process using the port
netstat -ano | findstr :8001

# Kill the process
taskkill /PID <PID> /F
```

**Solution (Linux/Mac):**
```bash
# Find and kill process
lsof -ti:8001 | xargs kill -9
```

### Issue: Connection Refused

**Error:**
```
ConnectionRefusedError: [WinError 10061] No connection could be made
```

**Solution:**
1. Make sure servers are running:
   ```bash
   python src/acp_servers/start_all_servers.py
   ```

2. Check if ports are accessible:
   ```bash
   curl http://localhost:8001
   ```

3. Check firewall settings

### Issue: Test Suite Fails

**Solution:**
1. Ensure all servers are running first
2. Wait 2-3 seconds after starting servers before running tests
3. Check that no other services are using ports 8001-8005

### Verify Installation

Run this to verify everything is working:

```bash
# Test imports
python -c "from acp_sdk.server import Server; from acp_sdk.client import Client; print('ACP SDK imports OK')"

# Test server startup
cd src/acp_servers
timeout 3 python upload_incident_server.py 2>&1 | grep "Uvicorn running"
```

Expected output:
```
ACP SDK imports OK
INFO:     Uvicorn running on http://127.0.0.1:8001 (Press CTRL+C to quit)
```

## Version Requirements

```
Python: 3.9+
acp-sdk: >= 0.1.0
uvicorn: < 0.32.0  (IMPORTANT!)
nest-asyncio: >= 1.5.0
```

## Getting Help

If you continue to have issues:

1. Check the server logs for detailed error messages
2. Verify all dependencies are installed: `pip list | grep -E "acp-sdk|uvicorn|nest-asyncio"`
3. Try running servers individually to isolate the problem
4. Check the ACP_INTEGRATION_GUIDE.md for more details

## Quick Reset

If everything is broken, try this full reset:

```bash
# 1. Uninstall conflicting packages
pip uninstall acp-sdk uvicorn -y

# 2. Reinstall with correct versions
pip install acp-sdk "uvicorn<0.32.0" nest-asyncio

# 3. Restart servers
python src/acp_servers/start_all_servers.py
```
