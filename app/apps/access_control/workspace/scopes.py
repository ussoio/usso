"""Default workspace role scopes (SSO core)."""

_default_workspace_scopes: dict[str, list[str]] = {
    "workspace_ceo_scopes": [
        "read:sso/*/*?workspace_id={workspace_id}",
        "manage:sso/usso/workspace?workspace_id={workspace_id}",
        # Workspace manager: add/remove members of this workspace only.
        "manage:sso/usso/member?workspace_id={workspace_id}",
        "create:sso/legal-acceptance?workspace_id={workspace_id}",
        "read:finance/*/*?workspace_id={workspace_id}",
        "create:finance/ipg/*?workspace_id={workspace_id}",
        "update:finance/ipg/*?workspace_id={workspace_id}",
        "delete:finance/exchange/order?workspace_id={workspace_id}",
    ],
    "workspace_member_scopes": [
        "read:sso/*/*?workspace_id={workspace_id}",
        "create:sso/legal-acceptance?workspace_id={workspace_id}",
        "read:finance/*/*?workspace_id={workspace_id}",
        "create:finance/ipg/*?workspace_id={workspace_id}",
    ],
    "personal_workspace_owner_scopes": [
        "read:sso/*/*?workspace_id={workspace_id}",
        "create:sso/legal-acceptance?workspace_id={workspace_id}",
        "read:finance/*/*?workspace_id={workspace_id}",
        "create:finance/ipg/*?workspace_id={workspace_id}",
    ],
}


def get_default_workspace_scopes() -> dict[str, list[str]]:
    """Return a copy of the current default workspace scope lists."""
    return {key: list(value) for key, value in _default_workspace_scopes.items()}


def register_default_workspace_scopes(scopes: dict[str, list[str]]) -> None:
    """Replace or extend default workspace scope lists (for deployment overlays)."""
    for key, value in scopes.items():
        _default_workspace_scopes[key] = list(value)
