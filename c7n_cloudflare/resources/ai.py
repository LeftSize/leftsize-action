"""cloudflare.ai-model: Workers AI models an account called recently, with request counts.

Token permission (read): Account Analytics. Workers AI has no list of what an
account uses, so this resource comes from GraphQL Analytics
(`aiInferenceAdaptiveGroups`, grouped by `modelId` and `requestSource`). The
dataset is per account: it doesn't say which Worker or Pages project made the calls.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List

from ..provider import resources
from ..query import AccountResourceManager, TypeInfo

# Days of usage to look back; long enough to include weekly jobs
USAGE_DAYS = 14

USAGE_QUERY = """
query ($accountTag: string!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      aiInferenceAdaptiveGroups(limit: 10000, filter: {date_geq: $start, date_leq: $end}) {
        count
        dimensions { modelId requestSource }
      }
    }
  }
}
"""


@resources.register("ai-model")
class AiModel(AccountResourceManager):
    """Workers AI models called in the last 14 days, one per account and model:
    `modelId`, `requests` (sampled estimate), `requestSources` (e.g. worker binding,
    pages binding, rest api) and `days`."""

    class resource_type(TypeInfo):
        kind = "ai-model"
        id = "modelId"
        name = "modelId"
        date = None
        default_report_fields = ("modelId", "requests", "account.id")

    # Most accounts don't use Workers AI; without Account Analytics Read the query fails
    quiet_when_empty = True

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        # Analytics dates are UTC. Both bounds are inclusive and today is still running, so
        # this is USAGE_DAYS full days plus today so far (like the Workers `invocations` filter).
        end = datetime.now(timezone.utc).date()
        data = session.graphql(USAGE_QUERY, {
            "accountTag": account_id, "start": (end - timedelta(days=USAGE_DAYS)).isoformat(),
            "end": end.isoformat()})
        models: Dict[str, Dict[str, Any]] = {}
        for account in (data.get("viewer") or {}).get("accounts") or []:
            for row in account.get("aiInferenceAdaptiveGroups") or []:
                dims = row.get("dimensions") or {}
                model_id = dims.get("modelId")
                if not model_id:
                    continue
                model = models.setdefault(model_id, {
                    "modelId": model_id, "requests": 0, "requestSources": [], "days": USAGE_DAYS})
                model["requests"] += int(row.get("count") or 0)
                source = dims.get("requestSource")
                if source and source not in model["requestSources"]:
                    model["requestSources"].append(source)
        result: List[Dict[str, Any]] = sorted(models.values(), key=lambda m: m["modelId"])
        for model in result:
            model["requestSources"].sort()
        return result
