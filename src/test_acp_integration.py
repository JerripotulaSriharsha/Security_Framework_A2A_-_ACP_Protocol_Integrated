#!/usr/bin/env python3
"""
Test script for ACP integration.
Tests each ACP server independently and then the full integration.
"""
import asyncio
import json
import sys
from acp_sdk.client import Client


# ANSI colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


async def test_upload_incident():
    """Test upload_incident_agent on port 8001."""
    print(f"\n{BLUE}Testing upload_incident_agent (port 8001)...{RESET}")
    try:
        async with Client(base_url="http://localhost:8001") as client:
            test_payload = {
                "alert": {"id": "TEST-001", "title": "Test Alert"},
                "scores": {"validity": 0.8, "severity": "High", "exploitability": 0.7}
            }
            result = await client.run_sync(
                agent='upload_incident_agent',
                input=json.dumps(test_payload)
            )
            response = result.output[0].parts[0].content
            print(f"{GREEN}✓ Response: {response}{RESET}")
            return True
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False


async def test_notify_soc():
    """Test notify_soc_agent on port 8002."""
    print(f"\n{BLUE}Testing notify_soc_agent (port 8002)...{RESET}")
    try:
        async with Client(base_url="http://localhost:8002") as client:
            test_payload = {
                "alert": {"id": "TEST-002", "title": "Critical Alert"},
                "note": "Requires immediate attention"
            }
            result = await client.run_sync(
                agent='notify_soc_agent',
                input=json.dumps(test_payload)
            )
            response = result.output[0].parts[0].content
            print(f"{GREEN}✓ Response: {response}{RESET}")
            return True
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False


async def test_search_external_osint():
    """Test search_external_osint_agent on port 8003."""
    print(f"\n{BLUE}Testing search_external_osint_agent (port 8003)...{RESET}")
    try:
        async with Client(base_url="http://localhost:8003") as client:
            result = await client.run_sync(
                agent='search_external_osint_agent',
                input="203.0.113.55"
            )
            response = result.output[0].parts[0].content
            print(f"{GREEN}✓ Response: {response}{RESET}")
            return True
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False


async def test_search_internal_data():
    """Test search_internal_data_agent on port 8004."""
    print(f"\n{BLUE}Testing search_internal_data_agent (port 8004)...{RESET}")
    try:
        async with Client(base_url="http://localhost:8004") as client:
            result = await client.run_sync(
                agent='search_internal_data_agent',
                input="srv-42"
            )
            response = result.output[0].parts[0].content
            print(f"{GREEN}✓ Response: {response}{RESET}")
            return True
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False


async def test_update_status():
    """Test update_status_agent on port 8005."""
    print(f"\n{BLUE}Testing update_status_agent (port 8005)...{RESET}")
    try:
        async with Client(base_url="http://localhost:8005") as client:
            test_payload = {"incident_id": "INC-123", "status": "Resolved"}
            result = await client.run_sync(
                agent='update_status_agent',
                input=json.dumps(test_payload)
            )
            response = result.output[0].parts[0].content
            print(f"{GREEN}✓ Response: {response}{RESET}")
            return True
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False


async def test_all():
    """Run all tests."""
    print(f"{YELLOW}{'='*60}{RESET}")
    print(f"{YELLOW}ACP Integration Test Suite{RESET}")
    print(f"{YELLOW}{'='*60}{RESET}")

    tests = [
        ("Upload Incident", test_upload_incident),
        ("Notify SOC", test_notify_soc),
        ("Search External OSINT", test_search_external_osint),
        ("Search Internal Data", test_search_internal_data),
        ("Update Status", test_update_status),
    ]

    results = []
    for name, test_func in tests:
        result = await test_func()
        results.append((name, result))

    print(f"\n{YELLOW}{'='*60}{RESET}")
    print(f"{YELLOW}Test Results Summary{RESET}")
    print(f"{YELLOW}{'='*60}{RESET}")

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = f"{GREEN}✓ PASS{RESET}" if result else f"{RED}✗ FAIL{RESET}"
        print(f"{name:.<40} {status}")

    print(f"{YELLOW}{'='*60}{RESET}")
    print(f"Total: {passed}/{total} tests passed")
    print(f"{YELLOW}{'='*60}{RESET}\n")

    if passed == total:
        print(f"{GREEN}All tests passed! ACP integration is working correctly.{RESET}")
        return 0
    else:
        print(f"{RED}Some tests failed. Check that all servers are running:{RESET}")
        print(f"{YELLOW}  python src/acp_servers/start_all_servers.py{RESET}")
        return 1


async def main():
    """Main entry point."""
    try:
        exit_code = await test_all()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Tests interrupted by user.{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}Unexpected error: {e}{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
