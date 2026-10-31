"""Read-only Stripe validator. GET /v1/balance — no charges, no writes."""
from __future__ import annotations
import httpx


async def validate(key: str) -> tuple[bool | str | None, str]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://api.stripe.com/v1/balance",
                auth=(key, ""),
            )
    except Exception as e:
        return None, f"network error: {e}"
    if r.status_code == 200:
        return True, "GET /v1/balance returned 200 — key active (read scope confirmed)"
    if r.status_code in (401, 403):
        return False, f"Rejected ({r.status_code})"
    return None, f"Ambiguous response {r.status_code}"
