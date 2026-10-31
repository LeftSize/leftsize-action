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
        self._accounts: Optional[List[str]] = None
        self.http = http or requests.Session()
        self.http.headers["Authorization"] = f"Bearer {token}"
        self.http.headers["User-Agent"] = "leftsize-c7n-cloudflare"

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        for attempt in range(RETRIES + 1):
            if json_body is None:
                response = self.http.get(f"{API_BASE}{path}", params=params, timeout=TIMEOUT_SECONDS)
            else:
                response = self.http.post(f"{API_BASE}{path}", json=json_body, timeout=TIMEOUT_SECONDS)
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
            if json_body is not None and response.status_code < 400 and "data" in body:
                if body.get("errors"):
                    raise CloudflareError(path, response.status_code, body["errors"])
                return body  # GraphQL: {"data": ..., "errors": null}
            if response.status_code >= 400 or not body.get("success", False):
                raise CloudflareError(path, response.status_code, body.get("errors") or [])
            return body
        raise CloudflareError(path, 429, [])  # unreachable: the last attempt raises or returns

    def get(self, path: str, **params: Any) -> Any:
        """The `result` of one GET."""
        return self._request(path, params or None).get("result")

    def get_optional(self, path: str, **params: Any) -> Any:
        """The `result` of one GET, or None when the object doesn't exist (404), such as
        an R2 bucket without a CORS policy."""
        try:
            return self.get(path, **params)
        except CloudflareError as e:
            if e.status == 404:
                return None
            raise

    def graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """`data` of a GraphQL Analytics query (needs Account Analytics Read)."""
        return self._request("/graphql", json_body={"query": query, "variables": variables}).get("data") or {}

    def accounts(self) -> List[str]:
        """Account IDs to scan: CLOUDFLARE_ACCOUNT_IDS, else the accounts the token can
        list (needs Account Settings Read), else the accounts of the zones it can read."""
        if self._accounts is None:
            ids = list(self.account_ids)
            if not ids:
                ids = [a["id"] for a in self.paginate("/accounts") if a.get("id")]
            if not ids:
                ids = sorted({(z.get("account") or {}).get("id") for z in self.paginate("/zones")} - {None})
            self._accounts = ids
        return self._accounts

    def paginate_cursor(self, path: str, items_key: str, **params: Any) -> Iterator[Dict[str, Any]]:
        """All items of a cursor-paginated endpoint whose `result` is an object, such as
        R2 buckets (`{"buckets": [...]}`, next page via `result_info.cursor`)."""
        cursor = None
        while True:
            body = self._request(path, {**params, **({"cursor": cursor} if cursor else {})})
            yield from (body.get("result") or {}).get(items_key) or []
            cursor = (body.get("result_info") or {}).get("cursor")
            if not cursor:
                return

    def paginate(self, path: str, **params: Any) -> Iterator[Dict[str, Any]]:
        """All items of a page-numbered list endpoint."""
        page = 1
        while True:
            body = self._request(path, {**params, "page": page, "per_page": PER_PAGE})
            items = body.get("result") or []
            yield from items
            info = body.get("result_info") or {}
            if "total_pages" in info:
                if page >= (info.get("total_pages") or 1):
                    return
            elif len(items) < int(info.get("per_page") or PER_PAGE) or not items:
                # Some lists (tunnels, members) report no total_pages: stop at a short page
                return
            page += 1
