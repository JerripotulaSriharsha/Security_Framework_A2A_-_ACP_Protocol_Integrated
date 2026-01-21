# ACP Server for Status Updates
from collections.abc import AsyncGenerator

from acp_sdk.models import Message, MessagePart
from acp_sdk.server import RunYield, RunYieldResume, Server

server = Server()

@server.agent()
async def update_status_agent(messages: list[Message]) -> AsyncGenerator[RunYield, RunYieldResume]:
    """
    Updates incident status in XSOAR or case management system.
    Input: JSON with incident_id and status
    Output: Confirmation of status update
    """
    import json

    query = " ".join(
        part.content
        for m in messages
        for part in m.parts
    )

    try:
        payload = json.loads(query)
        incident_id = payload.get("incident_id", "INC-PLACEHOLDER")
        status = payload.get("status", "Open")
    except json.JSONDecodeError:
        incident_id = "INC-PLACEHOLDER"
        status = "Open"

    # TODO: Replace with actual XSOAR/case management API call
    result = {
        "result": "ok",
        "incident_id": incident_id,
        "status": status
    }

    yield Message(parts=[MessagePart(content=json.dumps(result))])

if __name__ == "__main__":
    server.run(port=8005)
