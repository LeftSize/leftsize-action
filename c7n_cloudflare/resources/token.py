"""cloudflare.api-token: account-owned API tokens.

Token permission (read): Account API Tokens. User-owned tokens (`/user/tokens`)
are not listed: an account token can't see them.
"""

from typing import Any, Dict, Iterable

from ..provider import resources
from ..query import AccountResourceManager, TypeInfo

# Permission group names that grant changes, e.g. "DNS Write", "Workers Scripts Edit"
WRITE_WORDS = ("write", "edit", "admin")


def _summarize(token: Dict[str, Any]) -> Dict[str, Any]:
    request_ip = (token.get("condition") or {}).get("request_ip") or {}
    groups = sorted({
        g.get("name") for p in token.get("policies") or [] if p.get("effect", "allow") == "allow"
        for g in p.get("permission_groups") or [] if g.get("name")
    })
    return {
        "ipRestricted": bool(request_ip.get("in") or request_ip.get("not_in")),
        "permissionGroups": groups,
        "writePermissions": [g for g in groups if any(w in g.lower() for w in WRITE_WORDS)],
    }


@resources.register("api-token")
class ApiToken(AccountResourceManager):
    """Account-owned API tokens (`GET /accounts/{id}/tokens`): status, issued_on,
    last_used_on, expires_on, condition, policies; a summary under `leftsize`."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/tokens"
        kind = "api-token"
        date = "issued_on"
        default_report_fields = ("id", "name", "status", "last_used_on", "expires_on")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        # Token names aren't unique; the ID is
        return str(resource["id"])

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        for token in session.paginate(self.resource_type.path.format(account_id=account_id)):
            token["leftsize"] = _summarize(token)
            yield token
