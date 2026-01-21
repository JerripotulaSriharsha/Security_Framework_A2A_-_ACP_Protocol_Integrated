# ACP Client for MCP Layer
"""
This module provides an ACP-based client wrapper for the MCP layer.
It communicates with ACP servers instead of calling tools directly.
"""
import asyncio
import json
from typing import Dict, List
from datetime import datetime
from acp_sdk.client import Client


def _default_serializer(obj):
    """JSON serializer for datetime and Pydantic models."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, 'model_dump'):
        return obj.model_dump(mode='json')
    if hasattr(obj, 'dict'):
        return obj.dict()
    raise TypeError(f"Type {type(obj)} not serializable")


class ACPMCPClient:
    """
    ACP Client wrapper for MCP (Model Context Protocol) layer.
    Orchestrates communication with ACP agent servers for external integrations.
    """

    def __init__(
        self,
        upload_incident_url: str = "http://localhost:8001",
        notify_soc_url: str = "http://localhost:8002",
        search_osint_url: str = "http://localhost:8003",
        search_internal_url: str = "http://localhost:8004",
        update_status_url: str = "http://localhost:8005"
    ):
        self.upload_incident_url = upload_incident_url
        self.notify_soc_url = notify_soc_url
        self.search_osint_url = search_osint_url
        self.search_internal_url = search_internal_url
        self.update_status_url = update_status_url

    async def upload_incident(self, payload: Dict) -> Dict:
        """Upload incident to XSOAR via ACP server."""
        async with Client(base_url=self.upload_incident_url) as client:
            result = await client.run_sync(
                agent='upload_incident_agent',
                input=json.dumps(payload, default=_default_serializer)
            )
            response_content = result.output[0].parts[0].content
            return json.loads(response_content)

    async def notify_soc(self, payload: Dict) -> Dict:
        """Notify SOC analysts via ACP server."""
        async with Client(base_url=self.notify_soc_url) as client:
            result = await client.run_sync(
                agent='notify_soc_agent',
                input=json.dumps(payload, default=_default_serializer)
            )
            response_content = result.output[0].parts[0].content
            return json.loads(response_content)

    async def search_external_osint(self, query: str) -> List[Dict]:
        """Search external OSINT sources via ACP server."""
        async with Client(base_url=self.search_osint_url) as client:
            result = await client.run_sync(
                agent='search_external_osint_agent',
                input=query
            )
            response_content = result.output[0].parts[0].content
            return json.loads(response_content)

    async def search_internal_data(self, query: str) -> List[Dict]:
        """Search internal data sources via ACP server."""
        async with Client(base_url=self.search_internal_url) as client:
            result = await client.run_sync(
                agent='search_internal_data_agent',
                input=query
            )
            response_content = result.output[0].parts[0].content
            return json.loads(response_content)

    async def update_status(self, incident_id: str, status: str) -> Dict:
        """Update incident status via ACP server."""
        async with Client(base_url=self.update_status_url) as client:
            payload = {"incident_id": incident_id, "status": status}
            result = await client.run_sync(
                agent='update_status_agent',
                input=json.dumps(payload, default=_default_serializer)
            )
            response_content = result.output[0].parts[0].content
            return json.loads(response_content)


# Synchronous wrappers for backwards compatibility with existing code
def _run_async(coro):
    """Helper to run async functions synchronously."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If already in async context, create new task
            import nest_asyncio
            nest_asyncio.apply()
    except RuntimeError:
        pass
    return asyncio.run(coro)


# Global ACP client instance
_acp_client = ACPMCPClient()


# Sync wrappers that match the original tools.py API
def search_internal_data(query: str) -> List[Dict]:
    """Sync wrapper for search_internal_data."""
    return _run_async(_acp_client.search_internal_data(query))


def search_external_osint(query: str) -> List[Dict]:
    """Sync wrapper for search_external_osint."""
    return _run_async(_acp_client.search_external_osint(query))


def notify_soc(payload: Dict) -> Dict:
    """Sync wrapper for notify_soc."""
    return _run_async(_acp_client.notify_soc(payload))


class XSOARClient:
    """ACP-based XSOAR client."""

    def __init__(self, base_url: str = "https://xsoar.example"):
        self.base_url = base_url
        self._acp = _acp_client

    def upload_incident(self, payload: Dict) -> Dict:
        """Upload incident to XSOAR."""
        return _run_async(self._acp.upload_incident(payload))

    def update_status(self, incident_id: str, status: str) -> Dict:
        """Update incident status."""
        return _run_async(self._acp.update_status(incident_id, status))
