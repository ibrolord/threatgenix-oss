"""Expire elapsed application risk acceptances.

Run with:
    python -m app.cli.expire_risk_acceptances

This is intentionally small so production schedulers can invoke it directly.
"""

from __future__ import annotations

import asyncio

from app.database import async_session
from app.services.application_risk_acceptance import expire_application_risk_acceptances


async def main() -> int:
    async with async_session() as db:
        expired = await expire_application_risk_acceptances(db)
        await db.commit()
    print(f"expired {len(expired)} risk acceptance(s)")
    return len(expired)


if __name__ == "__main__":
    asyncio.run(main())
