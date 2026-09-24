"""OAuth2 Client Management for tenant integration."""

from apps.tenant.models import Tenant
from utils.hasher import PasswordHasherService

from .models import OAuthClient
from .schemas import GrantType, ResponseType


async def create_oauth_client(
    tenant: Tenant,
    client_name: str,
    redirect_uris: list[str],
    grant_types: list[GrantType] | None = None,
    response_types: list[ResponseType] | None = None,
    allowed_scopes: list[str] | None = None,
    client_type: str = "confidential",
    user_id: str | None = None,
) -> OAuthClient:
    """Create a new OAuth client for a tenant."""
    # Set defaults
    if grant_types is None:
        grant_types = [GrantType.AUTHORIZATION_CODE]
    if response_types is None:
        response_types = [ResponseType.CODE]
    if allowed_scopes is None:
        allowed_scopes = ["openid", "profile", "email"]
    if user_id is None:
        user_id = tenant.user_id

    # Generate client credentials
    client_id = OAuthClient.generate_client_id()
    client_secret = OAuthClient.generate_client_secret()

    # Create client
    client = OAuthClient(
        client_id=client_id,
        client_secret=PasswordHasherService().hash_password(client_secret),
        client_name=client_name,
        client_type=client_type,
        redirect_uris=redirect_uris,
        grant_types=grant_types,
        response_types=response_types,
        allowed_scopes=allowed_scopes,
        tenant_id=tenant.uid,
        user_id=user_id,
    )

    await client.save()
    return client


async def get_oauth_client(
    tenant: Tenant,
    client_id: str,
) -> OAuthClient | None:
    """Get OAuth client by ID for a tenant."""
    return await OAuthClient.get_by_client_id(client_id, tenant.uid)


async def list_oauth_clients(
    tenant: Tenant,
    user_id: str | None = None,
    is_active: bool | None = None,
) -> list[OAuthClient]:
    """List OAuth clients for a tenant."""
    query = OAuthClient.get_query(
        user_id=user_id,
        tenant_id=tenant.uid,
        is_active=is_active,
    )

    items = await query.to_list()
    return items


async def update_oauth_client(
    tenant: Tenant,
    client_id: str,
    **updates: object,
) -> OAuthClient | None:
    """Update OAuth client."""
    client = await get_oauth_client(tenant, client_id)
    if not client:
        return None

    client = await OAuthClient.update_item(client, updates)
    return client


async def deactivate_oauth_client(
    tenant: Tenant,
    client_id: str,
) -> bool:
    """Deactivate OAuth client."""
    client = await get_oauth_client(tenant, client_id)
    if not client:
        return False

    client.is_active = False
    await client.save()
    return True


async def regenerate_client_secret(
    tenant: Tenant,
    client_id: str,
) -> str | None:
    """Regenerate client secret."""
    client = await get_oauth_client(tenant, client_id)
    if not client:
        return None

    new_secret = OAuthClient.generate_client_secret()
    client.client_secret = PasswordHasherService().hash_password(new_secret)
    await client.save()

    return new_secret


async def create_default_oauth_client(tenant: Tenant) -> OAuthClient:
    """Create a default OAuth client for a tenant."""
    return await create_oauth_client(
        tenant=tenant,
        client_name=f"{tenant.name} Default Client",
        redirect_uris=[
            "http://localhost:3000/callback",
            "https://localhost:3000/callback",
        ],
        grant_types=[GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
        response_types=[ResponseType.CODE],
        allowed_scopes=["openid", "profile", "email", "read", "write"],
        client_type="confidential",
    )


async def validate_client_redirect_uri(
    tenant: Tenant,
    client_id: str,
    redirect_uri: str,
) -> bool:
    """Validate that redirect URI is allowed for the client."""
    client = await get_oauth_client(tenant, client_id)
    if not client:
        return False

    return redirect_uri in client.redirect_uris


async def get_client_scopes(
    tenant: Tenant,
    client_id: str,
) -> list[str]:
    """Get allowed scopes for a client."""
    client = await get_oauth_client(tenant, client_id)
    if not client:
        return []

    return [scope.value for scope in client.allowed_scopes]


async def is_client_active(
    tenant: Tenant,
    client_id: str,
) -> bool:
    """Check if client is active."""
    client = await get_oauth_client(tenant, client_id)
    if not client:
        return False

    return client.is_active


async def validate_client_scopes(
    tenant: Tenant,
    client_id: str,
    scopes: list[str],
) -> bool:
    """Validate that scopes are allowed for the client."""
    client = await get_oauth_client(tenant, client_id)
    if not client:
        return False

    return all(scope in client.allowed_scopes for scope in scopes)
