"""JWT/session claim helpers."""


def jwt_claims_for_user(user: object, extra: dict | None = None) -> dict:
    """Copy custom claims and snapshot the display name at token issue time."""
    claims = dict(getattr(user, "custom_claims", None) or {})
    if extra:
        claims.update(extra)
    name = getattr(user, "name", None)
    if isinstance(name, str) and name.strip():
        claims["name"] = name.strip()
        claims["user_name"] = name.strip()
    return claims
