"""Agent and tenant schemas accept JOSE mixed-case algorithm names."""

import pytest
from pydantic import ValidationError
from usso_jwt.enums import Algorithm

from apps.identity.agent.schemas import AgentCreateSchema
from apps.tenant.schemas import TenantCreateSchema


@pytest.mark.parametrize("raw", ["Ed25519", "ED25519", "ed25519"])
def test_agent_create_accepts_ed25519_aliases(raw: str) -> None:
    """POST /agents body may send Ed25519 or ED25519."""
    data = AgentCreateSchema(
        name="exchange",
        description="platform service account",
        workspace_id="workspace-1",
        scopes=["*:*"],
        alg=raw,
    )
    assert data.alg is Algorithm.Ed25519


@pytest.mark.parametrize("raw", ["EdDSA", "EDDSA"])
def test_agent_create_accepts_eddsa_aliases(raw: str) -> None:
    """EdDSA mixed-case aliases map to the same enum member."""
    data = AgentCreateSchema(
        name="exchange",
        workspace_id="workspace-1",
        scopes=["*:*"],
        alg=raw,
    )
    assert data.alg is Algorithm.EdDSA


def test_agent_create_rejects_unknown_alg() -> None:
    """Unknown alg still fails validation."""
    with pytest.raises(ValidationError):
        AgentCreateSchema(
            name="exchange",
            workspace_id="workspace-1",
            scopes=["*:*"],
            alg="Ed448",
        )


def test_tenant_create_accepts_ed25519_alias() -> None:
    """Tenant create algorithm field uses the same aliasing."""
    data = TenantCreateSchema(
        name="cash",
        domains=["cash.example"],
        algorithm="Ed25519",
    )
    assert data.algorithm is Algorithm.Ed25519
