"""cloudflare.worker-script: Workers scripts with their settings and request volume.

Token permissions (read): Workers Scripts; Account Analytics for the `invocations` filter.
Without Workers Scripts Read the listing is empty rather than an error (verified
October 2026), so an empty listing is logged as a warning.
Binding values are never stored: plain-text values are replaced by their length.
"""

import logging
import re
from datetime import date, timedelta
from typing import Any, Dict, Iterable, List

from c7n.filters import Filter
from c7n.filters.core import OPERATORS
from c7n.utils import local_session, type_schema

from ..client import CloudflareError
from ..provider import resources
from ..query import AccountResourceManager, TypeInfo

log = logging.getLogger("custodian.cloudflare")

INVOCATIONS_QUERY = """
query ($accountTag: string!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      workersInvocationsAdaptive(limit: 10000, filter: {date_geq: $start, date_leq: $end}) {
        sum { requests }
        dimensions { scriptName }
      }
    }
  }
}
"""


def _summarize(settings: Dict[str, Any]) -> Dict[str, Any]:
    """LeftSize's view of a script's settings, under `leftsize`."""
    observability = settings.get("observability") or {}
    logs = observability.get("logs") or {}
    logs_enabled = bool(logs.get("enabled", observability.get("enabled", False)))
    rate = logs.get("head_sampling_rate", observability.get("head_sampling_rate"))
    return {
        "logsEnabled": logs_enabled,
        # Cloudflare samples every invocation (1) unless head_sampling_rate is set
        "logSamplingRate": float(rate) if rate is not None else 1.0,
        "bindings": [
            {"name": b.get("name"), "type": b.get("type"),
             **({"length": len(b.get("text") or "")} if b.get("type") == "plain_text" else {})}
            for b in settings.get("bindings") or []
        ],
        "compatibilityDate": settings.get("compatibility_date"),
        "usageModel": settings.get("usage_model"),
        "cpuMs": (settings.get("limits") or {}).get("cpu_ms"),
    }


@resources.register("worker-script")
class WorkerScript(AccountResourceManager):
    """Workers scripts (`GET /accounts/{id}/workers/scripts`), each with a summary of
    its settings (`GET .../scripts/{name}/settings`) under `leftsize`."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/workers/scripts"
        kind = "worker"
        name = "id"
        date = "modified_on"
        default_report_fields = ("id", "modified_on", "account.id")

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        scripts = session.get(self.resource_type.path.format(account_id=account_id)) or []
        domains: Dict[str, List[str]] = {}
        if scripts:
            for d in session.get(f"/accounts/{account_id}/workers/domains") or []:
                domains.setdefault(d.get("service"), []).append(d.get("hostname"))
        if not scripts:
            # Without Workers Scripts Read the API returns an empty list, not a 403. An account
            # without Workers looks the same, so this is a note, not a scan problem.
            log.info("No Workers listed for account %s. If it has Workers, the API token is "
                        "missing the Workers Scripts Read permission.", account_id)
        for script in scripts:
            settings = session.get(f"/accounts/{account_id}/workers/scripts/{script['id']}/settings") or {}
            schedules = (session.get(f"/accounts/{account_id}/workers/scripts/{script['id']}/schedules") or {})
            script["leftsize"] = {
                **_summarize(settings),
                "hasAssets": bool(script.get("has_assets")),
                "routes": [r.get("pattern") for r in script.get("routes") or [] if r.get("pattern")],
                "customDomains": sorted(h for h in domains.get(script["id"], []) if h),
                "cronTriggers": [c.get("cron") for c in schedules.get("schedules") or [] if c.get("cron")],
            }
        return scripts


@WorkerScript.filter_registry.register("invocations")
class InvocationsFilter(Filter):
    """Scripts by number of requests over the last `days` (GraphQL Analytics,
    `workersInvocationsAdaptive`). Stores `leftsize.requests` and `leftsize.requestDays`.

    :example:

    .. code-block:: yaml

        filters:
          - type: invocations
            days: 7
            op: gte
            value: 10000000
    """

    schema = type_schema("invocations", days={"type": "integer", "minimum": 1, "maximum": 30},
                         op={"enum": ["eq", "ne", "gt", "gte", "lt", "lte"]},
                         value={"type": "integer", "minimum": 0}, required=["value"])
    permissions = ("Account Analytics Read",)

    def requests_by_script(self, session: Any, account_id: str, days: int) -> Dict[str, int]:
        end = date.today()
        data = session.graphql(INVOCATIONS_QUERY, {
            "accountTag": account_id, "start": (end - timedelta(days=days)).isoformat(), "end": end.isoformat()})
        totals: Dict[str, int] = {}
        for account in (data.get("viewer") or {}).get("accounts") or []:
            for row in account.get("workersInvocationsAdaptive") or []:
                name = (row.get("dimensions") or {}).get("scriptName")
                if name:
                    totals[name] = totals.get(name, 0) + int((row.get("sum") or {}).get("requests") or 0)
        return totals

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        session = local_session(self.manager.session_factory)
        days = self.data.get("days", 7)
        op = OPERATORS[self.data.get("op", "gte")]
        per_account: Dict[str, Any] = {}
        accounts = {r["account"]["id"] for r in resources}
        matched = []
        for r in resources:
            account_id = r["account"]["id"]
            if account_id not in per_account:
                try:
                    per_account[account_id] = self.requests_by_script(session, account_id, days)
                except CloudflareError as e:
                    if len(accounts) == 1:
                        raise
                    # Skip the account: unavailable analytics aren't zero requests
                    log.warning("Skipped Workers analytics of account %s: %s", account_id, e)
                    per_account[account_id] = None
            if per_account[account_id] is None:
                continue
            summary = r.setdefault("leftsize", {})
            summary["requests"] = per_account[account_id].get(r["id"], 0)
            summary["requestDays"] = days
            if op(summary["requests"], self.data["value"]):
                matched.append(r)
        return matched


@WorkerScript.filter_registry.register("plaintext-secrets")
class PlaintextSecretsFilter(Filter):
    """Scripts with plain-text variables whose name looks like a credential
    (`pattern`, case-insensitive). Stores the names in `leftsize.plaintextSecretNames`;
    values are never read into the resource.
    """

    DEFAULT_PATTERN = r"secret|passw|token|api_?key|private_?key|credential"
    schema = type_schema("plaintext-secrets", pattern={"type": "string"})

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        pattern = re.compile(self.data.get("pattern", self.DEFAULT_PATTERN), re.IGNORECASE)
        matched = []
        for r in resources:
            summary = r.setdefault("leftsize", {})
            names = [b["name"] for b in summary.get("bindings") or []
                     if b.get("type") == "plain_text" and b.get("name") and pattern.search(b["name"])]
            summary["plaintextSecretNames"] = names
            if names:
                matched.append(r)
        return matched
