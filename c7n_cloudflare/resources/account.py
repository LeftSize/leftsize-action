"""cloudflare.account: accounts with their settings and a summary of their members.

Token permission (read): Account Settings.
"""

import logging
from typing import Any, Dict, List

from ..client import CloudflareError
from ..provider import resources
from ..query import QueryResourceManager, TypeInfo

log = logging.getLogger("custodian.cloudflare")


def _summarize_members(members: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Only a count: a list of members without 2FA would be a target list in an issue
    accepted = [m for m in members if m.get("status") == "accepted"]
    without = [m for m in accepted if not (m.get("user") or {}).get("two_factor_authentication_enabled")]
    return {"memberCount": len(accepted), "membersWithout2faCount": len(without)}


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
        account_ids = session.accounts()
        for account_id in account_ids:
            try:
                account = session.get(f"/accounts/{account_id}") or {"id": account_id}
                members = list(session.paginate(f"/accounts/{account_id}/members"))
            except CloudflareError as e:
                if len(account_ids) == 1:
                    raise
                # One account without the permission shouldn't hide the others' findings
                log.warning("Skipped account %s: %s", account_id, e)
                continue
            account["account"] = {"id": account_id, "name": account.get("name")}
            account["leftsize"] = _summarize_members(members)
            accounts.append(account)
        return accounts
