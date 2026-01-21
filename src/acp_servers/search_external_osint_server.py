# ACP Server for External OSINT Searches
from collections.abc import AsyncGenerator

from acp_sdk.models import Message, MessagePart
from acp_sdk.server import RunYield, RunYieldResume, Server

server = Server()

@server.agent()
async def search_external_osint_agent(messages: list[Message]) -> AsyncGenerator[RunYield, RunYieldResume]:
    """
    Searches external OSINT sources (VT, AbuseIPDB, GreyNoise, etc.).
    Input: query string (IP, domain, hash, etc.)
    Output: JSON list of OSINT hits
    """
    import json

    query = " ".join(
        part.content
        for m in messages
        for part in m.parts
    ).strip()

    # TODO: Replace with actual OSINT API calls (VT, AbuseIPDB, GreyNoise, etc.)
    # For now, return mock data
    results = [
        {"source": "AbuseIPDB", "score": 85, "ip": query, "tags": ["bruteforce"]},
        {"source": "GreyNoise", "classification": "malicious", "ip": query},
    ]

    yield Message(parts=[MessagePart(content=json.dumps(results))])

if __name__ == "__main__":
    server.run(port=8003)
