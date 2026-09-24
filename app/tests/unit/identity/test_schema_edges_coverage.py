"""Edge coverage for validation and serialization security boundaries."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError
from usso_jwt.enums import Algorithm

from apps.identity.agent.schemas import (
    AgentCreateResponse,
    AgentCreateSchema,
    AgentSchema,
)
from apps.identity.auth.enums import (
    AuthFlow,
    AuthIdentifier,
    AuthSecret,
    AuthStep,
    validate_email_identifier,
)
from apps.identity.kyc.schemas import KYCCreateSchema
from apps.identity.profile.schemas import (
    ProfileDataCreateSchema,
    ProfileDataUpdateSchema,
)
from apps.identity.session.schemas import AuthSessionSchema
from apps.identity.user.schemas import UserIdentifierSchema, UserSchema
from apps.tenant.config import TokenConfig
from apps.tenant.models import Tenant
from apps.tenant.schemas import (
    TenantRetrieveSchema,
    TenantUpdateSchema,
    normalize_tenant_domains,
)
from apps.tenant.secrets import TenantSecrets
from server.exceptions import NotFoundError


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com/path",
        "example.com:invalid",
        "*.example.com",
    ],
)
def test_tenant_domain_rejections(domain: str) -> None:
    with pytest.raises(ValueError):
        normalize_tenant_domains([domain])


def test_tenant_domain_and_url_edges() -> None:
    assert normalize_tenant_domains(["EXAMPLE.COM.", "example.com"]) == ["example.com"]
    assert normalize_tenant_domains(["https://[::1]:8443/"]) == ["[::1]:8443"]
    assert TenantUpdateSchema(domains=None).domains is None

    tenant = TenantRetrieveSchema.model_construct(
        domains=["example.com"],
        frontend_urls=SimpleNamespace(login_url="/login", callback_url="https://ui/x"),
    )
    TenantRetrieveSchema.primary_domain.fset(tenant, "localhost")
    assert TenantRetrieveSchema.primary_domain.fget(tenant) == "localhost"
    assert TenantRetrieveSchema.primary_url.fget(tenant) == "http://localhost:8000"
    assert TenantRetrieveSchema.get_frontend_url(tenant, "callback") == "https://ui/x"
    assert TenantRetrieveSchema.get_frontend_url(tenant, "login").endswith("/login")


@pytest.mark.asyncio
async def test_tenant_lookup_rejects_invalid_domain_before_database() -> None:
    assert await Tenant.get_from_domain("https://example.com/path") is None


def test_auth_enum_and_flow_validation_edges() -> None:
    assert validate_email_identifier("not-an-email") == (
        False,
        "Email is invalid",
        None,
    )
    assert validate_email_identifier("A.B+tag@gmail.com")[2] == "AB@gmail.com"
    assert AuthIdentifier.CLIENT_ID.get_identifier_validator()("client") == (
        True,
        None,
        "client",
    )
    assert AuthIdentifier.EMAIL.fa_name == "ایمیل"
    assert AuthIdentifier.BALE_ID.fa_name == "شناسه بله"
    assert AuthIdentifier.BALE_ID.value == "bale_id"
    assert AuthIdentifier.BALE_ID.get_identifier_validator()("712091689") == (
        True,
        None,
        "712091689",
    )
    assert AuthSecret.get_identifier_type(AuthSecret.PASSWORD) is None

    invalid_steps = [
        {"methods": []},
        {"methods": [AuthSecret.PASSWORD], "required_num": 2},
        {"methods": [AuthSecret.PASSWORD, AuthSecret.PASSWORD]},
    ]
    for data in invalid_steps:
        with pytest.raises(ValidationError):
            AuthStep(**data)
    with pytest.raises(ValidationError):
        AuthFlow(allowed_identifiers=[AuthIdentifier.EMAIL], steps=[])
    with pytest.raises(ValidationError):
        AuthFlow(
            allowed_identifiers=[],
            steps=[AuthStep(methods=[AuthSecret.PASSWORD])],
        )


def test_profile_session_and_token_config_edges() -> None:
    legacy = ProfileDataCreateSchema(
        first_name="Ada",
        father_name="ignored",
        bank_accounts=[],
    )
    assert legacy.first_name == "Ada"
    assert "father_name" not in legacy.model_dump()

    session = AuthSessionSchema.model_construct(
        max_age_minutes=None,
        created_at=datetime.now() - timedelta(days=1),
        scopes=[],
    )
    assert session.expire_at is None
    assert not session.is_expired
    assert session.update_scopes(["read"]) == ["read"]

    config = TokenConfig()
    token_types = (
        "access",
        "refresh",
        "temporary",
        "one_time",
        "secure",
        "session",
    )
    for token_type in token_types:
        assert config.get_timeout(token_type) > 0
    with pytest.raises(ValueError, match="Invalid token type"):
        config.get_timeout("unknown")

    assert ProfileDataCreateSchema(avatar_url=None).avatar_url is None
    assert ProfileDataUpdateSchema(avatar_url="https://cdn.example/a.png").avatar_url


def test_user_schema_properties_and_avatar_validation() -> None:
    identifier = UserIdentifierSchema.model_construct(
        tenant_id="tenant",
        type=AuthIdentifier.EMAIL,
        identifier="user@example.com",
    )
    assert identifier.redis_key == "user_identifier:tenant:email:user@example.com"
    user = UserSchema.model_construct(name="Display")
    assert user.user_name == "Display"


def test_kyc_invalid_national_code() -> None:
    with pytest.raises(ValidationError):
        KYCCreateSchema(national_code="bad", birth_date="2000-01-01")


def test_agent_schema_security_and_response_dump() -> None:
    with pytest.raises(ValidationError, match="asymmetric"):
        AgentCreateSchema(name="a", scopes=[], alg=Algorithm.HS256)
    with pytest.raises(ValidationError, match="At least one"):
        AgentSchema(name="a", scopes=[], tenant_id="tenant")

    response = AgentCreateResponse.model_construct(
        uid="agent",
        tenant_id="tenant",
        name="a",
        scopes=[],
        client_id="agent",
        private_key=None,
    )
    assert "private_key" not in response.model_dump()


@pytest.mark.asyncio
async def test_agent_config_missing_and_cached_tenant() -> None:
    agent = AgentSchema.model_construct(
        uid="agent",
        tenant_id="tenant",
        name="robot",
        scopes=[],
        user_id="user",
        workspace_id=None,
    )
    with (
        patch(
            "apps.tenant.models.Tenant.get_by_uid",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(NotFoundError),
    ):
        await agent.get_config_response()

    agent._tenant = SimpleNamespace(
        primary_url="https://login.example",
        primary_domain="login.example",
    )
    result = await agent.get_config_response()
    assert result["client_id"] == "agent"
    assert result["client_email"] == "robot@login.example"


def test_tenant_secret_migration_non_mapping_values() -> None:
    marker = object()
    assert TenantSecrets.migrate_legacy_key_salts(marker) is marker
    assert TenantSecrets.migrate_legacy_key_salts({"keys": "invalid"}) == {
        "keys": "invalid"
    }
    result = TenantSecrets.migrate_legacy_key_salts({
        "pass_salt": "legacy",
        "keys": [123],
    })
    assert result == {"keys": [123]}
