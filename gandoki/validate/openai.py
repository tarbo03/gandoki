"""Read-only OpenAI validator. GET /v1/models — no billable usage, no writes."""
from __future__ import annotations
import httpx


async def validate(key: str) -> tuple[bool | str | None, str]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
    except Exception as e:
        return None, f"network error: {e}"
    if r.status_code == 200:
        return True, "GET /v1/models returned 200 — key active (scope unknown)"
    if r.status_code in (401, 403):
        return False, f"Rejected ({r.status_code})"
    return None, f"Ambiguous response {r.status_code}"
