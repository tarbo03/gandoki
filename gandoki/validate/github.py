"""GitHub PAT validator via GET /user (read-only)."""
from __future__ import annotations
import httpx


async def validate(token: str) -> tuple[bool | str | None, str]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "Gandoki/1.0",
                },
            )
    except Exception as e:
        return None, f"network error: {e}"

    if r.status_code == 200:
        try:
            login = r.json().get("login", "?")
        except Exception:
            login = "?"
        return True, f"GET /user returned 200 (login={login})"
    if r.status_code == 401:
        return False, "Rejected (401) — invalid or expired token"
    if r.status_code == 403:
        return "partial", "403 — rate-limited or insufficient scope"
    return None, f"Ambiguous response {r.status_code}"
