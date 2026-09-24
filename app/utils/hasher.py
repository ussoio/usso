"""
Password hashing and verification service.

This module hashes new secrets with Argon2id and accepts only password-hashing
formats with per-secret salts. Raw MD5/SHA digests are deliberately rejected.
"""

import re

from singleton import Singleton


class PasswordHasherService(metaclass=Singleton):
    """
    Singleton service for password hashing and verification.

    Uses Argon2id for new password hashes and supports verification of
    multiple legacy hash algorithms for backward compatibility.
    """

    def __init__(
        self, memory_cost: int = 12288, time_cost: int = 3, parallelism: int = 1
    ) -> None:
        """
        Initialize the password hasher with Argon2 configuration.

        Args:
            memory_cost: Memory cost in KiB (default: 12288).
            time_cost: Number of iterations (default: 3).
            parallelism: Number of parallel threads (default: 1).

        """
        from argon2 import PasswordHasher, Type

        self.hasher = PasswordHasher(
            time_cost=time_cost,  # iterations
            memory_cost=memory_cost,  # in KiB
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,  # Use Argon2id
        )

    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id.

        Args:
            password: Plain text password to hash.

        Returns:
            Argon2id hash string.

        """
        return self.hasher.hash(password)

    def verify_password(self, hashed: str, password: str, **kwargs: object) -> bool:
        """
        Verify a password against a hash using appropriate algorithm.

        Automatically detects the hash algorithm and uses the appropriate
        verification method.

        Args:
            hashed: The hash string to verify against.
            password: Plain text password to verify.
            **kwargs: Additional arguments for specific hash algorithms.

        Returns:
            True if password matches the hash, False otherwise.

        """
        alg = self._detect_hash_algorithm(hashed)
        if alg is None:
            return False
        elif alg == "argon2":
            return self.verify_password_argon(hashed, password, **kwargs)
        elif alg == "bcrypt":
            return self.verify_password_bcrypt(hashed, password, **kwargs)
        elif alg == "scrypt":
            return self.verify_password_scrypt(hashed, password, **kwargs)
        elif alg == "pbkdf2":
            return self.verify_password_pbkdf2(hashed, password, **kwargs)
        return False

    def verify_password_argon(
        self, hashed: str, password: str, **kwargs: object
    ) -> bool:
        """
        Verify password against Argon2 hash.

        Args:
            hashed: Argon2 hash string.
            password: Plain text password to verify.
            **kwargs: Unused, kept for interface compatibility.

        Returns:
            True if password matches, False otherwise.

        """
        from argon2.exceptions import VerificationError, VerifyMismatchError

        try:
            return self.hasher.verify(hashed, password)
        except (VerificationError, VerifyMismatchError):
            return False

    def _detect_hash_algorithm(self, hash_str: str) -> str | None:
        """
        Detect the hash algorithm based on length or pattern.

        Args:
            hash_str: The hash string to analyze.

        Returns:
            Algorithm name (e.g., 'argon2', 'bcrypt', 'sha256') or None if unknown.

        """
        checksum_patterns = {
            "bcrypt": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",
            "scrypt": r"^\$scrypt\$.*$",
            "argon2": r"^\$argon2(id|i|d)\$.*$",
            "pbkdf2": r"^\$pbkdf2(-sha\d+)?\$.*$",
        }
        for algo, pattern in checksum_patterns.items():
            if re.match(pattern, hash_str):
                return algo

        return None

    def verify_password_bcrypt(
        self, hashed: str, password: str, **kwargs: object
    ) -> bool:
        """
        Verify password against bcrypt hash.

        Args:
            hashed: Bcrypt hash string.
            password: Plain text password to verify.
            **kwargs: Unused, kept for interface compatibility.

        Returns:
            True if password matches, False otherwise.

        """
        from bcrypt import checkpw

        return checkpw(password.encode(), hashed.encode())

    def verify_password_scrypt(
        self, hashed: str, password: str, **kwargs: object
    ) -> bool:
        """
        Verify password against scrypt hash.

        Args:
            hashed: Scrypt hash string.
            password: Plain text password to verify.
            **kwargs: Unused, kept for interface compatibility.

        Returns:
            True if password matches, False otherwise.

        """
        from passlib.hash import scrypt

        return scrypt.verify(password, hashed)

    def verify_password_pbkdf2(
        self, hashed: str, password: str, **kwargs: object
    ) -> bool:
        """
        Verify password against PBKDF2 hash.

        Args:
            hashed: PBKDF2 hash string.
            password: Plain text password to verify.
            **kwargs: Additional parameters for PBKDF2 verification.

        Returns:
            True if password matches, False otherwise.

        """
        from passlib.hash import pbkdf2_sha256, pbkdf2_sha512

        try:
            verifier = (
                pbkdf2_sha512 if hashed.startswith("$pbkdf2-sha512$") else pbkdf2_sha256
            )
            return verifier.verify(password, hashed)
        except (TypeError, ValueError):
            return False
