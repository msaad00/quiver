"""Transport-agnostic JSON-RPC dispatch entry-points.

`server.py` is the canonical home of the JSON-RPC method router and
per-tool subprocess plumbing — it has been the case since the stdio
transport shipped, and the existing `test_server_unit.py` suite
monkeypatches names directly on that module. To avoid a churn-only
refactor, this module is a thin façade: it re-imports the public
dispatch surface from `server` and exposes it under stable names
(`handle_request`, `call_tool`) so the SSE transport
(`transports/sse.py`) and any future remote transport can call
`dispatch.handle_request(message, transport="sse")` without depending
on the legacy underscore-prefixed spellings.

The contract — every guard, every audit field, every chain-hash link —
is identical regardless of how the request arrived. The only
difference on the audit record is the `transport` field; see
`docs/MCP_TRANSPORT.md`.
"""

from __future__ import annotations

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import server  # noqa: E402

# Public, transport-agnostic spellings.
handle_request = server._handle_request
call_tool = server._call_tool

# Audit + sink helpers used by both transports.
emit_audit_event = server._emit_audit_event
audit_sink = server._audit_sink
reset_audit_sink_for_tests = server._reset_audit_sink_for_tests

# Constants the SSE transport surfaces back to operators.
DEFAULT_TRANSPORT = server.DEFAULT_TRANSPORT
PROTOCOL_VERSION = server.PROTOCOL_VERSION
SERVER_NAME = server.SERVER_NAME
SERVER_VERSION = server.SERVER_VERSION

# Back-compat aliases. The transport layer prefers the public spelling
# but tests that load this module directly may already reach for the
# leading-underscore name.
_handle_request = handle_request
_call_tool = call_tool
_emit_audit_event = emit_audit_event
_reset_audit_sink_for_tests = reset_audit_sink_for_tests
