"""cloudflare.lb-pool: load balancer pools, with the load balancers that use them.

Token permissions (read): Load Balancing: Monitors and Pools (account) and Load
Balancers (zone, every zone of the account).
"""

from typing import Any, Dict, Iterable, List, Set

from ..provider import resources
from ..query import AccountResourceManager, TypeInfo


def _pool_ids(lb: Dict[str, Any]) -> Set[str]:
    ids: Set[str] = set(lb.get("default_pools") or [])
    if lb.get("fallback_pool"):
        ids.add(lb["fallback_pool"])
    for key in ("region_pools", "country_pools", "pop_pools"):
        for pools in (lb.get(key) or {}).values():
            ids.update(pools or [])
    return ids


@resources.register("lb-pool")
class LoadBalancerPool(AccountResourceManager):
    """Pools (`GET /accounts/{id}/load_balancers/pools`): name, enabled, origins,
    monitor. `leftsize.loadBalancers` lists the load balancers (in any zone of the
    account) that reference the pool; `leftsize.originCount` counts its origins."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/load_balancers/pools"
        kind = "lb-pool"
        date = "created_on"
        default_report_fields = ("id", "name", "enabled")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        pools: List[Dict[str, Any]] = session.get(self.resource_type.path.format(account_id=account_id)) or []
        if not pools:
            return []
        users: Dict[str, List[str]] = {}
        for zone in session.paginate("/zones", **{"account.id": account_id}):
            for lb in session.get(f"/zones/{zone['id']}/load_balancers") or []:
                for pool_id in _pool_ids(lb):
                    users.setdefault(pool_id, []).append(lb.get("name") or lb.get("id"))
        for pool in pools:
            pool["leftsize"] = {
                "loadBalancers": sorted(users.get(pool["id"], [])),
                "originCount": len(pool.get("origins") or []),
            }
        return pools
