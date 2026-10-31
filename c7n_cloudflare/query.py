"""Base resource managers and filters: list a Cloudflare collection, cache it, run the filters."""

from typing import Any, Dict, Iterable, List

from c7n.actions import ActionRegistry
from c7n.filters import FilterRegistry, ValueFilter
from c7n.manager import ResourceManager
from c7n.utils import local_session, type_schema


class TypeInfo:
    """Resource type metadata, the subset of c7n's TypeInfo that Custodian reads."""

    service = "cloudflare"
    id = "id"
    name = "name"
    date = "created_on"
    # API path of the listing, e.g. "/zones"
    path: str = ""
    # Kind in the LeftSize resource ID: cloudflare:account/{account_id}/{kind}/{name}
    kind: str = ""
    default_report_fields = ("id", "name")
    cfn_type = None
    arn_type = None


class QueryResourceManager(ResourceManager):
    resource_type = TypeInfo

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Per-class registries; FilterRegistry brings value/and/or/not/reduce/list-item
        cls.filter_registry = FilterRegistry("%s.filters" % cls.__name__.lower())
        cls.action_registry = ActionRegistry("%s.actions" % cls.__name__.lower())

    def get_model(self) -> Any:
        return self.resource_type

    def get_client(self) -> Any:
        return local_session(self.session_factory)

    def list_resources(self, session: Any) -> List[Dict[str, Any]]:
        return list(session.paginate(self.resource_type.path))

    def resource_name(self, resource: Dict[str, Any]) -> str:
        return str(resource.get(self.resource_type.name) or resource.get(self.resource_type.id) or "unknown")

    def resources(self, query: Any = None) -> List[Dict[str, Any]]:
        session = self.get_client()
        # The scan shares one cache file across policy files, so the next file of the
        # same resource type reuses this listing instead of calling the API again.
        key = {"cloudflare": self.__class__.__name__, "accounts": tuple(session.account_ids)}
        with self._cache:
            resources = self._cache.get(key)
            if resources is None:
                resources = self.list_resources(session)
                for r in resources:
                    account_id = (r.get("account") or {}).get("id") or "unknown"
                    # LeftSize resource ID (without the cloudflare: prefix)
                    r["c7n:cloudflare-id"] = f"account/{account_id}/{self.resource_type.kind}/{self.resource_name(r)}"
                self._cache.save(key, resources)
        return self.filter_resources(resources)

    def get_resources(self, resource_ids: List[str]) -> List[Dict[str, Any]]:
        return [r for r in self.resources() if r.get(self.resource_type.id) in resource_ids]


class AccountResourceManager(QueryResourceManager):
    """A resource listed per account (`/accounts/{account_id}/...`)."""

    def list_account(self, session: Any, account_id: str) -> Iterable[Dict[str, Any]]:
        return session.paginate(self.resource_type.path.format(account_id=account_id))

    def list_resources(self, session: Any) -> List[Dict[str, Any]]:
        resources = []
        for account_id in session.accounts():
            for r in self.list_account(session, account_id):
                r.setdefault("account", {"id": account_id})
                resources.append(r)
        return resources


class DetailFilter(ValueFilter):
    """Match on one extra GET per resource, compared like a value filter.

    The API `result` is available as `value` (so `key: value.status`); a missing
    object (404) is `value: null`. Results are stored on the resource under
    `c7n:details`, keyed by `path`.
    """

    schema = type_schema("detail", rinherit=ValueFilter.schema, required=["path"],
                         path={"type": "string", "pattern": "^[a-z0-9_/]+$"})
    schema_alias = False
    required_keys = {"value"}
    annotation_key = "c7n:details"

    def __init__(self, data: Dict[str, Any], manager: Any = None) -> None:
        super().__init__({"key": "value", **data}, manager)

    def detail_path(self, resource: Dict[str, Any]) -> str:
        raise NotImplementedError

    def fetch(self, session: Any, resource: Dict[str, Any]) -> Any:
        return session.get_optional(self.detail_path(resource))

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        session = local_session(self.manager.session_factory)
        path = self.data["path"]
        matched = []
        for r in resources:
            details = r.setdefault(self.annotation_key, {})
            if path not in details:
                details[path] = self.fetch(session, r)
            if self.match({"value": details[path]}):
                matched.append(r)
        return matched
