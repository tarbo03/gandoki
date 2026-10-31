"""AWS access key ID validator via STS GetCallerIdentity.

Only the key ID (AKIA.../ASIA...) is validated, not the paired secret.
We sign with a placeholder secret; AWS parses AccessKeyId first.

  SignatureDoesNotMatch -> key ID exists (real AWS access key ID)
  InvalidClientTokenId  -> key ID does not exist
  ExpiredToken          -> key expired

CONFIRMED_PARTIAL is the best we can do without the paired secret.
"""
from __future__ import annotations
import hashlib
import hmac
import re
from datetime import datetime, timezone

import httpx


async def validate(key: str) -> tuple[bool | str | None, str]:
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    region, service = "us-east-1", "sts"

    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_headers = (
        "content-type:application/x-www-form-urlencoded\n"
        "host:sts.amazonaws.com\n"
        f"x-amz-date:{amzdate}\n"
    )
    signed_headers = "content-type;host;x-amz-date"
    canonical_request = (
        f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n"
        + hashlib.sha256(canonical_request.encode()).hexdigest()
    )

    def _sign(k, m):
        return hmac.new(k, m.encode(), hashlib.sha256).digest()

    k = _sign(b"AWS4FAKE", datestamp)
    k = _sign(k, region)
    k = _sign(k, service)
    k = _sign(k, "aws4_request")
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (
        f"AWS4-HMAC-SHA256 Credential={key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                "https://sts.amazonaws.com/",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Amz-Date": amzdate,
                    "Authorization": auth,
                },
                content=body,
            )
    except Exception as e:
        return None, f"network error: {e}"

    code_m = re.search(r"<Code>([^<]+)</Code>", r.text)
    code = code_m.group(1) if code_m else ""
    if code == "SignatureDoesNotMatch":
        return "partial", f"Key ID exists (STS: {code}); secret unavailable so full validation impossible"
    if code == "InvalidClientTokenId":
        return False, "STS rejected key ID (InvalidClientTokenId)"
    if code == "ExpiredToken":
        return False, "Key expired (ExpiredToken)"
    return None, f"Ambiguous STS response: {code or r.status_code}"
