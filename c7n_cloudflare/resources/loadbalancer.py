"""cloudflare.lb-pool: load balancer pools, with what uses them.

Token permission (read): Load Balancing: Monitors and Pools.
"""

from typing import Any, Dict, Iterable, List

from ..provider import resources
from ..query import AccountResourceManager, TypeInfo


@resources.register("lb-pool")
class LoadBalancerPool(AccountResourceManager):
    """Pools (`GET /accounts/{id}/load_balancers/pools`): name, enabled, origins, monitor.

    `leftsize.referrers` lists what uses the pool, from Cloudflare's own reference
    lookup (`GET .../pools/{id}/references`, entries with reference_type
    `referrer`): load balancers as default, fallback, region, country or PoP pool,
    in pool sets or rule overrides. `leftsize.originCount` counts its origins.
    """

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/load_balancers/pools"
        kind = "lb-pool"
        date = "created_on"
        default_report_fields = ("id", "name", "enabled")

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource["id"])

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        pools: List[Dict[str, Any]] = session.get(self.resource_type.path.format(account_id=account_id)) or []
        for pool in pools:
            refs = session.get(f"{self.resource_type.path.format(account_id=account_id)}/{pool['id']}/references") or []
            pool["leftsize"] = {
                "referrers": sorted(
                    f"{r.get('resource_type')}:{r.get('resource_name') or r.get('resource_id')}"
                    for r in refs if r.get("reference_type") in ("referrer", "*")
                ),
                "originCount": len(pool.get("origins") or []),
            }
        return pools
