"""Read-only Cloudflare API client for the Custodian provider.

Authenticates with an API token (CLOUDFLARE_API_TOKEN). CLOUDFLARE_ACCOUNT_IDS
(comma-separated) limits listings to those accounts; without it, everything the
token can read is listed.
"""

import copy
import logging
import os
import time
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterator, List, Optional

import requests

API_BASE = "https://api.cloudflare.com/client/v4"
TIMEOUT_SECONDS = 30
RETRIES = 4
MAX_RETRY_WAIT_SECONDS = 300
PER_PAGE = 50
MAX_PAGES = 1000

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


def _retry_wait(response: Any, attempt: int) -> float:
    """Seconds to wait before a retry: Retry-After as seconds or an HTTP date, else
    exponential backoff."""
    value = (getattr(response, "headers", None) or {}).get("Retry-After") if response is not None else None
    if value:
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
            except (TypeError, ValueError):
                pass
    return float(2 ** attempt)


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
        # GET results shared by the policies of one Custodian run (one policy file):
        # zone settings and listings several filters ask for
        self._memo: Dict[str, Any] = {}
        self.http = http or requests.Session()
        self.http.headers["Authorization"] = f"Bearer {token}"
        self.http.headers["User-Agent"] = "leftsize-c7n-cloudflare"

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        for attempt in range(RETRIES + 1):
            try:
                if json_body is None:
                    response = self.http.get(f"{API_BASE}{path}", params=params, timeout=TIMEOUT_SECONDS)
                else:
                    response = self.http.post(f"{API_BASE}{path}", json=json_body, timeout=TIMEOUT_SECONDS)
            except requests.RequestException as e:
                if attempt < RETRIES:
                    wait = _retry_wait(None, attempt)
                    log.debug("Cloudflare request to %s failed (%s), retrying in %ss", path, type(e).__name__, wait)
                    time.sleep(wait)
                    continue
                raise CloudflareError(path, 0, [{"code": type(e).__name__, "message": "request failed"}]) from e
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < RETRIES:
                    wait = _retry_wait(response, attempt)
                    log.debug("Cloudflare %s on %s, retrying in %ss", response.status_code, path, wait)
                    # Cloudflare's rate limit window is five minutes; the scan's own timeout bounds the total
                    time.sleep(min(wait, MAX_RETRY_WAIT_SECONDS))
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

    def get_cached(self, path: str, optional: bool = False) -> Any:
        """`get` (or `get_optional`) once per path for this session."""
        key = f"{'?' if optional else ''}{path}"
        if key not in self._memo:
            self._memo[key] = self.get_optional(path) if optional else self.get(path)
        return self._memo[key]

    def zones(self) -> List[Dict[str, Any]]:
        """Zones the token can read (limited to CLOUDFLARE_ACCOUNT_IDS), listed once."""
        if "zones" not in self._memo:
            if self.account_ids:
                zones: List[Dict[str, Any]] = []
                for account_id in self.account_ids:
                    try:
                        zones.extend(self.paginate("/zones", **{"account.id": account_id}))
                    except CloudflareError as e:
                        if len(self.account_ids) == 1:
                            raise
                        # One account without Zone Read shouldn't hide the others' zones
                        log.warning("Skipped the zones of account %s: %s", account_id, e)
            else:
                zones = list(self.paginate("/zones"))
            self._memo["zones"] = zones
        return self._memo["zones"]

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
                try:
                    ids = [a["id"] for a in self.paginate("/accounts") if a.get("id")]
                except CloudflareError as e:
                    if e.status != 403:
                        raise
                    log.info("Can't list accounts (%s); using the accounts of the zones the token can read", e)
            if not ids:
                ids = sorted({(z.get("account") or {}).get("id") for z in self.zones()} - {None})
            self._accounts = ids
        return self._accounts

    def paginate_cursor(self, path: str, items_key: Optional[str] = None, **params: Any) -> Iterator[Dict[str, Any]]:
        """All items of a cursor-paginated endpoint (next page via `result_info.cursor`).
        `items_key` names the list inside an object `result`, such as R2 buckets
        (`{"buckets": [...]}`); without it `result` is the list (Registrar)."""
        cursor = None
        for _ in range(MAX_PAGES):
            body = self._request(path, {**params, **({"cursor": cursor} if cursor else {})})
            result = body.get("result")
            yield from ((result or {}).get(items_key) if items_key else result) or []
            next_cursor = (body.get("result_info") or {}).get("cursor")
            if not next_cursor or next_cursor == cursor:
                return
            cursor = next_cursor
        log.warning("Stopped listing %s after %d pages", path, MAX_PAGES)

    def paginate(self, path: str, **params: Any) -> Iterator[Dict[str, Any]]:
        """All items of a page-numbered list endpoint."""
        page = 1
        previous_first = None
        while True:
            body = self._request(path, {**params, "page": page, "per_page": PER_PAGE})
            items = body.get("result") or []
            # An endpoint that ignores paging returns the same items for every page
            first = items[0] if items else None
            if page > 1 and first is not None and first == previous_first:
                return
            # A copy: callers annotate the yielded items (account, leftsize)
            previous_first = copy.deepcopy(first)
            yield from items
            info = body.get("result_info") or {}
            if "total_pages" in info:
                if page >= (info.get("total_pages") or 1):
                    return
            elif len(items) < int(info.get("per_page") or PER_PAGE) or not items:
                # Some lists (tunnels, members) report no total_pages: stop at a short page
                return
            page += 1
            if page > MAX_PAGES:
                log.warning("Stopped listing %s after %d pages", path, MAX_PAGES)
                return
