"""Generic tenant-wide role specifications."""

from typing import TypedDict


class RoleSpec(TypedDict):
    """Human description plus scopes for a tenant-wide role."""

    description: str
    scopes: list[str]
