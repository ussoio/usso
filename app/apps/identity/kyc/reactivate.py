"""
Reactivate inactive users whose only blocker is incomplete KYC.

Feedback round 2 («KYC ناقص»): phone-only users (e.g. exchange staff imported
without birth date) were left inactive. Reactivating them lets them sign in;
the dashboard then routes them to the KYC step (no approved KYC record).

Dry run by default; prints the users it would change:

    uv run python -m apps.identity.kyc.reactivate --tenant <tenant_id>
    uv run python -m apps.identity.kyc.reactivate --tenant <tenant_id> --apply

Caution: an inactive user cannot be told apart from one an admin deactivated
on purpose. Review the dry-run list and pass ``--exclude`` for those uids.
Idempotent: a second run finds nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Any

from apps.identity.kyc.models import KYC
from apps.identity.kyc.schemas import KYCStatus
from apps.identity.user.models import User

logger = logging.getLogger(__name__)


async def find_incomplete_kyc_inactive_users(
    *,
    tenant_id: str,
    exclude: set[str] | None = None,
) -> list[User]:
    """Return non-deleted inactive users of a tenant without approved KYC."""
    approved = await KYC.find({
        "tenant_id": tenant_id,
        "status": KYCStatus.APPROVED,
        "is_deleted": False,
    }).to_list()
    approved_ids = {kyc.user_id for kyc in approved}
    users = await User.find({
        "tenant_id": tenant_id,
        "is_active": False,
        "is_deleted": False,
    }).to_list()
    skip = exclude or set()
    return [
        user for user in users if user.uid not in approved_ids and user.uid not in skip
    ]


async def reactivate_incomplete_kyc_users(
    *,
    tenant_id: str,
    apply: bool = False,
    exclude: set[str] | None = None,
) -> dict[str, Any]:
    """Reactivate matching users when ``apply`` is true; always report them."""
    users = await find_incomplete_kyc_inactive_users(
        tenant_id=tenant_id,
        exclude=exclude,
    )
    if apply:
        for user in users:
            user.is_active = True
            await user.save()
    return {
        "tenant_id": tenant_id,
        "matched": len(users),
        "applied": apply,
        "users": [{"uid": user.uid, "name": user.name} for user in users],
    }


async def _main(args: argparse.Namespace) -> None:  # pragma: no cover - CLI
    from fastapi_mongo_base.db import init_mongo_db

    from server.config import Settings

    await init_mongo_db(Settings())
    report = await reactivate_incomplete_kyc_users(
        tenant_id=args.tenant,
        apply=args.apply,
        exclude=set(args.exclude or []),
    )
    logger.warning(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", required=True, help="tenant uid")
    parser.add_argument("--apply", action="store_true", help="write changes")
    parser.add_argument("--exclude", nargs="*", help="user uids to keep inactive")
    asyncio.run(_main(parser.parse_args()))
