"""Adapters that wire Nota into specific MCP clients.

Each adapter knows the host's tool-call protocol and translates it to a
gate decision + an audit log entry. Nota itself stays client-agnostic;
adapters live here so a future Cursor / Cline / Continue / OpenAI Agents
SDK adapter can land alongside without touching the core.
"""
