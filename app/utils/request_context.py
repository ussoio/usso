"""Request-scoped context (IP, user-agent) for authz outside Depends."""

from contextvars import ContextVar

client_ip_var: ContextVar[str | None] = ContextVar("client_ip", default=None)
user_agent_var: ContextVar[str | None] = ContextVar("user_agent", default=None)
