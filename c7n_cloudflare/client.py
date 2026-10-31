"""Read-only Cloudflare API client for the Custodian provider.

Authenticates with an API token (CLOUDFLARE_API_TOKEN). CLOUDFLARE_ACCOUNT_IDS
(comma-separated) limits listings to those accounts; without it, everything the
token can read is listed.
"""

import logging
import os
import time
from typing import Any, Dict, Iterator, List, Optional

import requests

API_BASE = "https://api.cloudflare.com/client/v4"
TIMEOUT_SECONDS = 30
RETRIES = 4
PER_PAGE = 50

log = logging.getLogger("custodian.cloudflare")


class CloudflareError(Exception):
    """A Cloudflare API call failed (after retries for 429/5xx)."""

    def __init__(self, path: str, status: int, errors: List[Dict[str, Any]]) -> None:
        self.path = path
        self.status = status
        self.errors = errors
        detail = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errors) or "no details"
        hint = " (the API token is probably missing a read permission)" if status == 403 else ""
        super().__init__(f"Cloudflare API GET {path} returned {status}: {detail}{hint}")


class Session:
    """Session object handed to resource managers by the provider's session factory."""

    def __init__(self, token: Optional[str] = None, account_ids: Optional[List[str]] = None,
                 http: Optional[requests.Session] = None) -> None:
        token = token or os.environ.get("CLOUDFLARE_API_TOKEN", "")
        if not token:
            raise ValueError("CLOUDFLARE_API_TOKEN is not set")
        if account_ids is None:
            account_ids = [a.strip() for a in os.environ.get("CLOUDFLARE_ACCOUNT_IDS", "").split(",") if a.strip()]
        self.account_ids = account_ids
        self.http = http or requests.Session()
        self.http.headers["Authorization"] = f"Bearer {token}"
        self.http.headers["User-Agent"] = "leftsize-c7n-cloudflare"

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        for attempt in range(RETRIES + 1):
            response = self.http.get(f"{API_BASE}{path}", params=params, timeout=TIMEOUT_SECONDS)
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < RETRIES:
                    wait = float(response.headers.get("Retry-After") or 2 ** attempt)
                    log.debug("Cloudflare %s on %s, retrying in %ss", response.status_code, path, wait)
                    time.sleep(min(wait, 60))
                    continue
            try:
                body = response.json()
            except ValueError:
                body = {}
            if response.status_code >= 400 or not body.get("success", False):
                raise CloudflareError(path, response.status_code, body.get("errors") or [])
            return body
        raise CloudflareError(path, 429, [])  # unreachable: the last attempt raises or returns

    def get(self, path: str, **params: Any) -> Any:
        """The `result` of one GET."""
        return self._request(path, params or None).get("result")

    def paginate(self, path: str, **params: Any) -> Iterator[Dict[str, Any]]:
        """All items of a page-numbered list endpoint."""
        page = 1
        while True:
            body = self._request(path, {**params, "page": page, "per_page": PER_PAGE})
            yield from body.get("result") or []
            total_pages = (body.get("result_info") or {}).get("total_pages") or 1
            if page >= total_pages:
                return
            page += 1
