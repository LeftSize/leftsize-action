"""cloudflare.account: accounts with their settings and a summary of their members.

Token permission (read): Account Settings.
"""

from typing import Any, Dict, List

from ..provider import resources
from ..query import QueryResourceManager, TypeInfo


def _summarize_members(members: List[Dict[str, Any]]) -> Dict[str, Any]:
    accepted = [m for m in members if m.get("status") == "accepted"]
    without = [((m.get("user") or {}).get("email") or m.get("email") or "unknown") for m in accepted
               if not (m.get("user") or {}).get("two_factor_authentication_enabled")]
    return {"memberCount": len(accepted), "membersWithout2fa": sorted(without)}


@resources.register("account")
class Account(QueryResourceManager):
    """Accounts (`GET /accounts/{id}`) with `settings.enforce_twofactor`, plus
    `leftsize.memberCount` and `leftsize.membersWithout2fa` (accepted members whose
    user has no two-factor authentication) from `GET /accounts/{id}/members`."""

    class resource_type(TypeInfo):
        path = "/accounts"
        kind = "account"
        default_report_fields = ("id", "name", "settings.enforce_twofactor")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])

    def list_resources(self, session: Any) -> List[Dict[str, Any]]:
        accounts = []
        for account_id in session.accounts():
            account = session.get(f"/accounts/{account_id}") or {"id": account_id}
            account["account"] = {"id": account_id, "name": account.get("name")}
            account["leftsize"] = _summarize_members(list(session.paginate(f"/accounts/{account_id}/members")))
            accounts.append(account)
        return accounts
