"""Small, dependency-free OAuth 2.0 refresh-token client."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class OAuthTokenError(RuntimeError):
    """Safe-to-display token acquisition failure; never includes credentials."""


def refresh_access_token(
    token_url: str,
    client_id: str,
    refresh_token: str,
    client_secret: str | None = None,
    scope: str | None = None,
    timeout: float = 15.0,
) -> str:
    """Exchange a refresh token for a short-lived access token.

    OAuth authorization/consent is deliberately out of scope: obtain the
    refresh token using the provider's approved flow and keep it in a secret
    store or environment variable.
    """
    if not token_url.startswith("https://"):
        raise OAuthTokenError("OAuth token endpoint must use HTTPS")
    if not client_id or not refresh_token:
        raise OAuthTokenError("OAuth client ID and refresh token are required")

    fields = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    if client_secret:
        fields["client_secret"] = client_secret
    if scope:
        fields["scope"] = scope

    request = Request(
        token_url,
        data=urlencode(fields).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        # Do not include provider response bodies: they may contain identifiers.
        raise OAuthTokenError(f"OAuth token endpoint returned HTTP {exc.code}") from None
    except (URLError, TimeoutError, OSError):
        raise OAuthTokenError("Could not reach OAuth token endpoint") from None
    except (ValueError, UnicodeDecodeError):
        raise OAuthTokenError("OAuth token endpoint returned invalid JSON") from None

    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        error = payload.get("error") if isinstance(payload, dict) else None
        safe_error = error if isinstance(error, str) and error.replace("_", "").isalnum() else "invalid_response"
        raise OAuthTokenError(f"OAuth token response did not contain an access token ({safe_error})")
    return token
