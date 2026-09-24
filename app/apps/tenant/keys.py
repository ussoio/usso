"""
Tenant cryptographic key management.

This module provides schemas and utilities for managing tenant
cryptographic keys used for JWT signing and encryption.
"""

import hashlib
import secrets
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import BaseModel, Field
from usso_jwt.algorithms import AbstractKey
from usso_jwt.enums import Algorithm

from server.config import Settings


class TenantKey(BaseModel):
    """
    Tenant cryptographic key schema.

    Represents a cryptographic key pair used for JWT signing or encryption.
    Private keys are encrypted with a password derived from the system
    password and a salt unique to this key.

    Attributes:
        kid: Key ID for key rotation and identification.
        alg: Algorithm used with this key.
        use: Intended use - "sig" for signing or "enc" for encryption.
        private_key: Encrypted private key in DER format.
        pass_salt: Per-key salt used to derive the encryption password.
        public_jwk: Public key in JSON Web Key format.
        public_pem: Public key in PEM format.
        is_active: Whether this key is currently active.
        created_at: Timestamp when the key was created.

    """

    kid: str | None = Field(None, description="Key ID")
    alg: Algorithm | None = Field(
        None, description="Algorithm intended for use with the key"
    )
    use: Literal["sig", "enc"] = Field(
        default="sig", description="Intended use of the key"
    )
    private_key: bytes = Field(
        description="Private key in DER encrypted with the system password",
    )
    pass_salt: str = Field(
        default="",
        description="Per-key salt for encrypting the private key",
    )
    public_jwk: dict = Field(..., description="JSON Web Key")
    public_pem: str = Field(..., description="Public key in PEM format")

    is_active: bool = Field(default=True, description="Whether the key is active")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Creation timestamp",
    )

    @property
    def kty(self) -> str:
        """
        Key type from algorithm.

        Returns:
            Key type string (e.g., "OKP", "EC").

        """
        return self.alg.kty

    @classmethod
    def create_random_key(
        cls, alg: Algorithm = Algorithm.Ed25519, pass_salt: str | None = None
    ) -> Self:
        """
        Create a new random cryptographic key pair.

        Args:
            alg: Algorithm to use for key generation.
            pass_salt: Optional per-key salt. A fresh salt is generated when
                omitted.

        Returns:
            New TenantKey instance with generated key pair.

        """
        key: AbstractKey = AbstractKey.generate_algorithm(alg)
        key_pass_salt = pass_salt or secrets.token_urlsafe(16)
        password = hashlib.sha256(
            (key_pass_salt + Settings.system_password).encode()
        ).digest()

        return cls(
            private_key=key.private_der(password=password),
            public_jwk=key.jwk(),
            public_pem=key.public_pem(),
            alg=alg,
            kid=key.kid,
            pass_salt=key_pass_salt,
        )

    def get_key(self, pass_salt: str | None = None) -> AbstractKey:
        """
        Decrypt and retrieve the private key.

        Args:
            pass_salt: Legacy tenant salt for keys created before per-key
                salts were introduced.

        Returns:
            AbstractKey instance for signing/encryption operations.

        """
        # Older documents do not have ``pass_salt`` and must be opened with
        # the legacy tenant salt supplied by the caller. New keys always use
        # their own stored salt and ignore the legacy fallback.
        key_pass_salt = self.pass_salt or pass_salt or ""
        password = hashlib.sha256(
            (key_pass_salt + Settings.system_password).encode()
        ).digest()
        return AbstractKey.load_der(self.private_key, password=password)
