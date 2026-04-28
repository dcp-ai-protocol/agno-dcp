"""MCP (Model Context Protocol) signing layer (DCP-04).

The :class:`DCPMCPMiddleware` signs outbound MCP messages with the
agent's keypair and verifies inbound messages. If the peer does not
speak DCP-AI (no DCP envelope on the message), the middleware falls
back to the unmodified Agno flow so DCP-AI adoption is fully
voluntary on both sides of a conversation.
"""

from agno_dcp.mcp.middleware import (
    DCPMCPMiddleware,
    MCPEnvelope,
    sign_mcp_message,
    verify_mcp_message,
)

__all__ = [
    "DCPMCPMiddleware",
    "MCPEnvelope",
    "sign_mcp_message",
    "verify_mcp_message",
]
