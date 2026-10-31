"""cloudflare.domain: domains registered with Cloudflare Registrar.

Uses `GET /accounts/{id}/registrar/registrations` (the legacy /registrar/domains
endpoint reached end of life on 2026-09-27). Account-owned API tokens can't use
Registrar; scanning domains needs a user API token with Registrar read access.
"""

from typing import Any, Dict, Iterable

from ..provider import resources
from ..query import AccountResourceManager, TypeInfo


@resources.register("domain")
class Domain(AccountResourceManager):
    """Registrations: domain_name, status, expires_at, auto_renew, locked, privacy_mode."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/registrar/registrations"
        kind = "domain"
        name = "domain_name"
        id = "domain_name"
        date = "created_at"
        default_report_fields = ("domain_name", "status", "expires_at", "auto_renew", "locked")

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        return session.paginate_cursor(self.resource_type.path.format(account_id=account_id), per_page=50)
