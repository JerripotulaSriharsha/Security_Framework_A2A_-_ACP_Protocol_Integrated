# ACP Server for Internal Data Searches
from collections.abc import AsyncGenerator

from acp_sdk.models import Message, MessagePart
from acp_sdk.server import RunYield, RunYieldResume, Server

server = Server()

@server.agent()
async def search_internal_data_agent(messages: list[Message]) -> AsyncGenerator[RunYield, RunYieldResume]:
    """
    Searches internal data sources (SIEM, EDR, CMDB, etc.).
    Input: query string
    Output: JSON list of internal data hits
    """
    import json

    query = " ".join(
        part.content
        for m in messages
        for part in m.parts
    ).strip()

    # TODO: Replace with actual internal data source queries (SIEM, EDR, CMDB, etc.)
    # For now, return mock data
    results = [
        {"source": "EDR", "hit": True, "host": "srv-42", "note": "Process spawn chain"},
        {"source": "CMDB", "owner": "Payments", "criticality": "High"},
    ]

    yield Message(parts=[MessagePart(content=json.dumps(results))])

if __name__ == "__main__":
    server.run(port=8004)
