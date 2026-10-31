"""Zero Trust (Cloudflare One / Access) resources.

- cloudflare.zero-trust-user: users with their seats and last login. Token
  permission: Access: Audit Logs Read (the only permission the users API accepts),
  plus Access: Organizations, Identity Providers, and Groups Read for the seat
  expiration setting.
- cloudflare.access-app: Access applications with their (inline) policies.
  Token permission: Access: Apps and Policies Read.
- cloudflare.access-service-token: service tokens. Token permission: Access:
  Service Tokens Read.
- cloudflare.tunnel: Cloudflare Tunnels (not deleted). Token permission:
  Cloudflare Tunnel Read.
"""

from typing import Any, Dict, Iterable, List

from ..client import CloudflareError
from ..provider import resources
from ..query import AccountResourceManager, TypeInfo


@resources.register("zero-trust-user")
class ZeroTrustUser(AccountResourceManager):
    """Zero Trust users (`GET /accounts/{id}/access/users`): email, access_seat,
    gateway_seat, last_successful_login, created_at. `leftsize.seatExpiration` is the
    organization's `user_seat_expiration_inactive_time` (None when off or unreadable)."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/access/users"
        kind = "zero-trust-user"
        name = "email"
        date = "created_at"
        default_report_fields = ("email", "access_seat", "gateway_seat", "last_successful_login")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        try:
            org = session.get(f"/accounts/{account_id}/access/organizations") or {}
        except CloudflareError:
            org = {}  # the seat expiration is context, not a reason to skip the users
        for user in session.paginate(self.resource_type.path.format(account_id=account_id)):
            user["leftsize"] = {
                "hasSeat": bool(user.get("access_seat") or user.get("gateway_seat")),
                "seatExpiration": org.get("user_seat_expiration_inactive_time") or None,
            }
            yield user


def _everyone_policies(app: Dict[str, Any]) -> List[str]:
    """Names of allow policies whose include matches everyone, without any require rule."""
    names = []
    for policy in app.get("policies") or []:
        if policy.get("decision") != "allow" or policy.get("require"):
            continue
        if any("everyone" in rule for rule in policy.get("include") or [] if isinstance(rule, dict)):
            names.append(policy.get("name") or policy.get("id") or "unnamed")
    return names


@resources.register("access-app")
class AccessApp(AccountResourceManager):
    """Access applications (`GET /accounts/{id}/access/apps`) with inline `policies`;
    `leftsize.everyonePolicies` names the allow policies that include everyone."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/access/apps"
        kind = "access-app"
        date = "created_at"
        default_report_fields = ("id", "name", "domain", "type")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        for app in session.paginate(self.resource_type.path.format(account_id=account_id)):
            app["leftsize"] = {"everyonePolicies": _everyone_policies(app)}
            yield app


@resources.register("access-service-token")
class AccessServiceToken(AccountResourceManager):
    """Access service tokens (`GET /accounts/{id}/access/service_tokens`): name,
    client_id, expires_at, last_seen_at, duration, created_at. Secrets aren't returned."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/access/service_tokens"
        kind = "access-service-token"
        date = "created_at"
        default_report_fields = ("id", "name", "last_seen_at", "expires_at")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])


@resources.register("tunnel")
class Tunnel(AccountResourceManager):
    """Cloudflare Tunnels (`GET /accounts/{id}/cfd_tunnel?is_deleted=false`): name,
    status (inactive, degraded, healthy, down), conns_active_at, conns_inactive_at."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/cfd_tunnel"
        kind = "tunnel"
        date = "created_at"
        default_report_fields = ("id", "name", "status", "conns_inactive_at")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        for tunnel in session.paginate(self.resource_type.path.format(account_id=account_id), is_deleted="false"):
            tunnel.pop("connections", None)  # deprecated, and not needed
            yield tunnel
