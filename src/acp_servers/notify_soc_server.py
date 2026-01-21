# ACP Server for SOC Notifications
from collections.abc import AsyncGenerator
from datetime import datetime

from acp_sdk.models import Message, MessagePart
from acp_sdk.server import RunYield, RunYieldResume, Server

server = Server()

@server.agent()
async def notify_soc_agent(messages: list[Message]) -> AsyncGenerator[RunYield, RunYieldResume]:
    """
    Sends notifications to SOC analysts (Slack/PagerDuty/Email).
    Input: JSON string with alert, note, scores
    Output: Notification confirmation
    """
    import json

    query = " ".join(
        part.content
        for m in messages
        for part in m.parts
    )

    try:
        payload = json.loads(query)
    except json.JSONDecodeError:
        payload = {"raw": query}

    # TODO: Replace with actual Slack/PagerDuty integration
    # For now, simulate notification
    result = {
        "queued": True,
        "channel": "soc-triage",
        "ref": f"T-{datetime.utcnow().timestamp()}",
        "notified_at": datetime.utcnow().isoformat()
    }

    yield Message(parts=[MessagePart(content=json.dumps(result))])

if __name__ == "__main__":
    server.run(port=8002)
