# ACP Server for XSOAR Upload Incident
from collections.abc import AsyncGenerator
from datetime import datetime

from acp_sdk.models import Message, MessagePart
from acp_sdk.server import RunYield, RunYieldResume, Server

server = Server()

@server.agent()
async def upload_incident_agent(messages: list[Message]) -> AsyncGenerator[RunYield, RunYieldResume]:
    """
    Receives incident payload and uploads to XSOAR.
    Input: JSON string with alert, scores, playbooks
    Output: Upload confirmation with incident_id
    """
    import json

    # Extract payload from messages
    query = " ".join(
        part.content
        for m in messages
        for part in m.parts
    )

    try:
        payload = json.loads(query)
    except json.JSONDecodeError:
        payload = {"raw": query}

    # TODO: Replace with actual XSOAR API call
    # For now, simulate the upload
    result = {
        "result": "ok",
        "incident_id": f"INC-{datetime.utcnow().timestamp()}",
        "uploaded_at": datetime.utcnow().isoformat(),
        "payload_size": len(str(payload))
    }

    yield Message(parts=[MessagePart(content=json.dumps(result))])

if __name__ == "__main__":
    server.run(port=8001)
