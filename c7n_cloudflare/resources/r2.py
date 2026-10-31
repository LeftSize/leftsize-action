"""cloudflare.r2-bucket: R2 buckets, plus per-bucket detail and lifecycle filters.

Token permission (read): Workers R2 Storage. Lists buckets in the default
jurisdiction only (EU/FedRAMP buckets need a jurisdiction header).
"""

from typing import Any, Dict, Iterable, List

from c7n.filters import Filter
from c7n.utils import local_session, type_schema

from ..provider import resources
from ..query import AccountResourceManager, DetailFilter, TypeInfo


@resources.register("r2-bucket")
class R2Bucket(AccountResourceManager):
    """R2 buckets (`GET /accounts/{id}/r2/buckets`): name, creation_date, location, storage_class."""

    class resource_type(TypeInfo):
        path = "/accounts/{account_id}/r2/buckets"
        kind = "r2-bucket"
        date = "creation_date"
        default_report_fields = ("name", "location", "storage_class", "creation_date")

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        return session.paginate_cursor(self.resource_type.path.format(account_id=account_id), "buckets",
                                       per_page=1000)


def bucket_path(bucket: Dict[str, Any], path: str) -> str:
    return f"/accounts/{bucket['account']['id']}/r2/buckets/{bucket['name']}/{path}"


@R2Bucket.filter_registry.register("bucket-detail")
class BucketDetailFilter(DetailFilter):
    """Match on `GET /accounts/{id}/r2/buckets/{name}/{path}`, e.g. `path: domains/managed`
    (the public r2.dev URL) with `key: value.enabled`, or `path: cors`.

    :example:

    .. code-block:: yaml

        filters:
          - type: bucket-detail
            path: domains/managed
            key: value.enabled
            value: true
    """

    schema = type_schema("bucket-detail", rinherit=DetailFilter.schema, required=["path"],
                         path={"type": "string", "pattern": "^[a-z0-9_/]+$"})

    def detail_path(self, resource: Dict[str, Any]) -> str:
        return bucket_path(resource, self.data["path"])


@R2Bucket.filter_registry.register("multipart-abort-rule")
class MultipartAbortRuleFilter(Filter):
    """Buckets by whether an enabled lifecycle rule for the whole bucket (empty prefix)
    aborts incomplete multipart uploads. Stores `leftsize.multipartAbortDays` (None
    without such a rule) and `leftsize.lifecycleRuleCount`.

    :example:

    .. code-block:: yaml

        filters:
          - type: multipart-abort-rule
            present: false
    """

    schema = type_schema("multipart-abort-rule", present={"type": "boolean"})

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        session = local_session(self.manager.session_factory)
        want = self.data.get("present", True)
        matched = []
        for r in resources:
            summary = r.setdefault("leftsize", {})
            if "multipartAbortDays" not in summary:
                rules = (session.get_optional(bucket_path(r, "lifecycle")) or {}).get("rules") or []
                ages = [
                    ((rule.get("abortMultipartUploadsTransition") or {}).get("condition") or {}).get("maxAge")
                    for rule in rules
                    if rule.get("enabled") and not (rule.get("conditions") or {}).get("prefix")
                    and rule.get("abortMultipartUploadsTransition")
                ]
                ages = [a for a in ages if isinstance(a, (int, float))]
                # maxAge is in seconds
                summary["multipartAbortDays"] = round(min(ages) / 86400, 1) if ages else None
                summary["lifecycleRuleCount"] = len(rules)
            if (summary["multipartAbortDays"] is not None) == want:
                matched.append(r)
        return matched
