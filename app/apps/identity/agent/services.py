"""Agent services."""

import hashlib
import time
import uuid

import usso_jwt.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from pymongo.errors import DuplicateKeyError
from usso import UserData, authorization
from usso.user import TokenType
from usso_jwt import JWTConfig
from usso_jwt.algorithms import AbstractKey
from usso_jwt.schemas import JWT, UnverifiedJWT
from usso_jwt.utils import normalize_pem_key_material

from apps.identity.api_key.services import generate_client_secret
from apps.identity.service_account import (
    assert_scopes_subset,
    authorize_service_account_create,
    resolve_create_binding,
    resolve_scope_ceiling,
)
from apps.tenant.models import Tenant
from server import db
from server.exceptions import (
    AlreadyExistsError,
    BadRequestError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from utils.hasher import PasswordHasherService

from ..auth.enums import LoginStatus
from ..auth.schemas import LoginResponse, PayloadData
from ..auth.services.token import resolve_acr
from ..user.models import User
from . import models, schemas


def kid_from_verify_key(verify_key: str | bytes) -> str | None:
    """Return SHA-256 hex of the public key SPKI DER (same as AbstractKey.kid)."""
    try:
        public_key = load_pem_public_key(
            normalize_pem_key_material(verify_key),
            backend=default_backend(),
        )
        der = public_key.public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()
    except (ValueError, TypeError, AttributeError):
        return None


def _unverified_iss(jwt: UnverifiedJWT) -> str | None:
    """Return iss when present and non-blank so kid lookup can run otherwise."""
    iss = jwt.unverified_payload.get("iss")
    if isinstance(iss, str) and iss.strip():
        return iss.strip()
    return None


def _agent_kid(agent: models.Agent) -> str | None:
    """Prefer persisted kid; fall back to hashing verify_key for legacy rows."""
    kid = getattr(agent, "kid", None)
    if kid:
        return kid
    verify_key = getattr(agent, "verify_key", None)
    if verify_key:
        return kid_from_verify_key(verify_key)
    return None


def _invalid_token_error(*, detail: str) -> UnauthorizedError:
    return UnauthorizedError(
        error_code="invalid_token",
        detail=detail,
        message={
            "en": "Invalid token.",
            "fa": "توکن دسترسی نامعتبر است.",
        },
    )


def _agent_not_found_error() -> UnauthorizedError:
    return UnauthorizedError(
        error_code="agent_not_found",
        detail="Agent not found.",
        message={
            "en": "Agent not found.",
            "fa": "عامل پیدا نشد.",
        },
    )


async def ensure_agent_kid(agent: models.Agent) -> models.Agent:
    """Persist kid from verify_key when an older agent is missing it."""
    if agent.kid or not agent.verify_key:
        return agent
    kid = kid_from_verify_key(agent.verify_key)
    if not kid:
        return agent
    existing = await models.Agent.get_by_kid(kid=kid, tenant_id=agent.tenant_id)
    if existing and existing.uid != agent.uid:
        raise UnauthorizedError(
            error_code="agent_kid_ambiguous",
            detail="Multiple agents match this key id.",
            message={
                "en": "Multiple agents match this key id.",
                "fa": "چند عامل با این شناسه کلید مطابقت دارند.",
            },
        )
    agent.kid = kid
    try:
        await agent.save()
    except DuplicateKeyError as exc:
        raise UnauthorizedError(
            error_code="agent_kid_ambiguous",
            detail="Multiple agents match this key id.",
            message={
                "en": "Multiple agents match this key id.",
                "fa": "چند عامل با این شناسه کلید مطابقت دارند.",
            },
        ) from exc
    return agent


async def generate_agent(
    data: schemas.AgentCreateSchema,
    tenant: Tenant,
    caller: UserData,
    caller_user: User,
) -> schemas.AgentCreateResponse:
    """Generate a new agent service account."""
    if data.verify_key is None:
        key = AbstractKey.generate_algorithm(data.alg)
        private_key = key.private_pem().decode()
        data.verify_key = key.public_pem().decode()
        kid = key.kid
    else:
        private_key = None
        kid = kid_from_verify_key(data.verify_key)
        if not kid:
            raise BadRequestError(
                error_code="invalid_verify_key",
                detail="Invalid agent public key.",
                message={
                    "en": "The agent public key is not valid.",
                    "fa": "کلید عمومی عامل معتبر نیست.",
                },
            )

    user_id, workspace_id = resolve_create_binding(
        caller=caller,
        user_id=data.user_id,
        workspace_id=data.workspace_id,
    )
    authorize_service_account_create(
        caller=caller, user_id=user_id, workspace_id=workspace_id
    )

    ceiling = await resolve_scope_ceiling(
        caller_user=caller_user,
        user_id=user_id,
        workspace_id=workspace_id,
    )
    assert_scopes_subset(requested=data.scopes, ceiling=ceiling)

    client_secret = generate_client_secret()
    hashed_client_secret = PasswordHasherService().hash_password(client_secret)

    existing = await models.Agent.get_by_kid(kid=kid, tenant_id=tenant.uid)
    if existing:
        raise AlreadyExistsError(
            error_code="agent_key_exists",
            detail="An agent with this public key already exists.",
            message={
                "en": "An agent with this public key already exists.",
                "fa": "عاملی با این کلید عمومی قبلاً ثبت شده.",
            },
        )

    agent = models.Agent(
        name=data.name,
        description=data.description,
        user_id=user_id,
        workspace_id=workspace_id,
        scopes=data.scopes,
        alg=data.alg,
        verify_key=data.verify_key,
        kid=kid,
        created_by=caller.uid,
        hashed_client_secret=hashed_client_secret,
        tenant_id=tenant.uid,
    )
    try:
        await agent.save()
    except DuplicateKeyError as exc:
        raise AlreadyExistsError(
            error_code="agent_key_exists",
            detail="An agent with this public key already exists.",
            message={
                "en": "An agent with this public key already exists.",
                "fa": "عاملی با این کلید عمومی قبلاً ثبت شده.",
            },
        ) from exc
    return schemas.AgentCreateResponse(
        **agent.model_dump(exclude={"hashed_client_secret"}),
        **(await agent.get_config_response()),
        private_key=private_key,
        client_secret=client_secret,
    )


def verify_agent_client_secret(*, agent: models.Agent, client_secret: str) -> bool:
    """Verify OAuth client_secret for an agent."""
    if not agent.hashed_client_secret or not client_secret:
        return False
    return PasswordHasherService().verify_password(
        agent.hashed_client_secret, client_secret
    )


def _raise_agent_ttl_exceeded(max_ttl: int) -> None:
    raise UnauthorizedError(
        error_code="agent_token_ttl_exceeded",
        detail=(
            f"Agent JWT lifetime must be <= {max_ttl} seconds (tenant access_timeout)."
        ),
        message={
            "en": f"Agent JWT lifetime must be <= {max_ttl} seconds.",
            "fa": f"اعتبار توکن عامل نباید بیشتر از {max_ttl} ثانیه باشد.",
        },
    )


async def _enforce_agent_jwt_ttl(
    *,
    payload: dict,
    tenant_id: str,
) -> None:
    iat = int(payload.get("iat") or 0)
    exp = int(payload.get("exp") or 0)
    if not iat or not exp or exp <= iat:
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Agent JWT must contain a valid iat and exp.",
            message={
                "en": "Agent token timestamps are invalid.",
                "fa": "زمان‌بندی توکن عامل نامعتبر است.",
            },
        )
    tenant = await Tenant.get_by_uid(tenant_id)
    max_ttl = tenant.config.token.access_timeout if tenant else 600
    if exp - iat > max_ttl:
        _raise_agent_ttl_exceeded(max_ttl)


async def _consume_agent_assertion(
    *, assertion: schemas.AgentAuthPayload, agent_id: str
) -> None:
    """Consume a signed agent assertion once to prevent token-minting replay."""
    if db.redis is None:
        raise ServiceUnavailableError(
            error_code="agent_assertion_store_unavailable",
            detail="Agent assertion replay protection is unavailable",
        )
    digest = hashlib.sha256(assertion.jti.encode()).hexdigest()
    try:
        acquired = await db.redis.set(
            f"usso:agent-assertion:{assertion.tenant_id}:{agent_id}:{digest}",
            "1",
            nx=True,
            ex=max(1, assertion.exp - int(time.time())),
        )
    except Exception as exc:
        raise ServiceUnavailableError(
            error_code="agent_assertion_store_unavailable",
            detail="Agent assertion replay protection is unavailable",
        ) from exc
    if not acquired:
        raise UnauthorizedError(
            error_code="agent_assertion_already_used",
            detail="Agent assertion has already been used",
        )


def _enforce_agent_tenant(payload: dict, *, tenant_id: str) -> None:
    """Bind an agent assertion to the tenant selected by the request host."""
    if payload.get("tenant_id") != tenant_id:
        raise UnauthorizedError(
            error_code="tenant_mismatch",
            detail="Agent token does not belong to this tenant.",
            message={
                "en": "Agent token does not belong to this tenant.",
                "fa": "توکن عامل متعلق به این سامانه نیست.",
            },
        )


async def _resolve_agent_for_auth(
    *,
    jwt: UnverifiedJWT,
    tenant_id: str,
) -> models.Agent:
    """
    Resolve an agent by JWT ``iss`` (agent uid) or header ``kid``.

    When ``AGENT_ID`` / ``iss`` is omitted (e.g. gitops IPG), lookup is by the
    public-key thumbprint in the JWT header. Multiple matches are rejected.
    """
    iss = _unverified_iss(jwt)
    raw_kid = jwt.unverified_header.get("kid")
    header_kid = (
        raw_kid.strip() if isinstance(raw_kid, str) and raw_kid.strip() else None
    )

    if not iss and not header_kid:
        raise _invalid_token_error(detail="Invalid JWT.")

    if iss:
        agent = await models.Agent.get_query(
            uid=iss, tenant_id=tenant_id
        ).first_or_none()
        if not agent:
            raise _agent_not_found_error()
        expected_kid = _agent_kid(agent)
        if header_kid and expected_kid and header_kid != expected_kid:
            raise _invalid_token_error(detail="JWT issuer and kid do not match.")
        return agent

    agents = await models.Agent.get_query(tenant_id=tenant_id).to_list()
    matches = [agent for agent in agents if _agent_kid(agent) == header_kid]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise UnauthorizedError(
            error_code="agent_kid_ambiguous",
            detail="Multiple agents match this key id.",
            message={
                "en": "Multiple agents match this key id.",
                "fa": "چند عامل با این شناسه کلید مطابقت دارند.",
            },
        )
    raise _agent_not_found_error()


async def agent_auth(
    token: str,
    *,
    tenant_id: str,
) -> tuple[models.Agent, schemas.AgentAuthPayload]:
    """Authenticate an agent using JWT token."""
    try:
        jwt = UnverifiedJWT(token=token)
        agent = await _resolve_agent_for_auth(jwt=jwt, tenant_id=tenant_id)
        if agent.is_active is False:
            raise UnauthorizedError(  # ruff:ignore[raise-within-try]
                error_code="agent_not_active",
                detail="Agent is not active.",
                message={
                    "en": "Agent is not active.",
                    "fa": "این عامل غیرفعال است.",
                },
            )
        agent = await ensure_agent_kid(agent)

        jwt = JWT(
            token=token,
            config=JWTConfig(
                key=agent.verify_key,
                type=agent.alg.value,
            ),
        )

        if not jwt.verify(expected_acr=agent.scopes):
            raise UnauthorizedError(  # ruff:ignore[raise-within-try]
                error_code="jwt_verification_failed",
                detail="JWT verification failed.",
                message={
                    "en": "JWT verification failed.",
                    "fa": "تأیید توکن دسترسی عامل انجام نشد.",
                },
            )

        verified_payload = dict(jwt.unverified_payload)
        if not verified_payload.get("tenant_id"):
            verified_payload["tenant_id"] = agent.tenant_id
        _enforce_agent_tenant(verified_payload, tenant_id=tenant_id)

        for scope in verified_payload.get("scopes", []):
            if not authorization.has_subset_scope(
                subset_scope=scope, user_scopes=agent.scopes
            ):
                raise UnauthorizedError(  # ruff:ignore[raise-within-try]
                    error_code="invalid_scopes",
                    detail="JWT scope mismatch.",
                    message={
                        "en": (
                            "The requested agent scopes are "
                            "not a subset of the agent's scopes."
                        ),
                        "fa": (
                            "سطح دسترسی درخواستی عامل باید "
                            "زیر مجموعه سطح دسترسی عامل قبلی باشد."
                        ),
                    },
                )

        await _enforce_agent_jwt_ttl(
            payload=verified_payload,
            tenant_id=agent.tenant_id,
        )
    except (BadRequestError, ServiceUnavailableError, UnauthorizedError):
        raise
    except usso_jwt.exceptions.JWTError as e:
        raise UnauthorizedError(
            error_code="unauthorized",
            detail=e.message,
            message={
                "en": e.message,
                "fa": "توکن دسترسی نامعتبر است.",
            },
        ) from e
    except Exception as e:
        raise UnauthorizedError(
            error_code="agent_auth_failed",
            detail="Agent auth failed.",
            message={
                "en": "Agent auth failed.",
                "fa": "ورود عامل انجام نشد.",
            },
        ) from e
    else:
        assertion = schemas.AgentAuthPayload(**verified_payload)
        await _consume_agent_assertion(assertion=assertion, agent_id=agent.uid)
        return agent, assertion


def create_agent_response(
    *,
    agent: models.Agent,
    tenant: Tenant,
    scopes: list[str],
    aud: str | None = None,
) -> LoginResponse:
    """
    Create agent (Service Account) authentication response.

    Args:
        agent: The agent
        tenant: The tenant
        scopes: The scopes
        aud: The audience
    Returns:
        The login response.

    """
    if agent.tenant_id != tenant.uid:
        raise UnauthorizedError(
            error_code="tenant_mismatch",
            detail="Agent does not belong to this tenant.",
            message={
                "en": "Agent does not belong to this tenant.",
                "fa": "عامل متعلق به این سامانه نیست.",
            },
        )

    now = int(time.time())

    payload = PayloadData(
        jti=str(uuid.uuid4()),
        token_type=TokenType.ACCESS,
        iss=tenant.primary_url,
        aud=aud,
        iat=now,
        nbf=now,
        exp=now + tenant.config.token.access_timeout,
        sub=agent.uid,
        tenant_id=agent.tenant_id,
        workspace_id=agent.workspace_id,
        scopes=scopes,
        amr=["agent_jwt"],
        acr=resolve_acr(["agent_jwt"]),
        signing_level=None,
        claims={
            "sub_type": "agent",
            "user_id": agent.user_id,
            "created_by": agent.created_by,
        },
    )

    payload.token = tenant.sign_jwt(payload=payload.model_dump())
    response = LoginResponse(
        **payload.model_dump(exclude={"token"}),
        status=LoginStatus.COMPLETED,
        tokens={TokenType.ACCESS: payload.token},
    )
    return response
