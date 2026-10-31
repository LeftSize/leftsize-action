"""Base resource manager: list a Cloudflare collection, cache it, run the filters."""

from typing import Any, Dict, List

from c7n.actions import ActionRegistry
from c7n.filters import FilterRegistry
from c7n.manager import ResourceManager
from c7n.utils import local_session


class TypeInfo:
    """Resource type metadata, the subset of c7n's TypeInfo that Custodian reads."""

    service = "cloudflare"
    id = "id"
    name = "name"
    date = "created_on"
    # API path of the listing, e.g. "/zones"
    path: str = ""
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

    def resources(self, query: Any = None) -> List[Dict[str, Any]]:
        session = self.get_client()
        # The scan shares one cache file across policy files, so the next file of the
        # same resource type reuses this listing instead of calling the API again.
        key = {"cloudflare": self.resource_type.path, "accounts": tuple(session.account_ids)}
        with self._cache:
            resources = self._cache.get(key)
            if resources is None:
                resources = self.list_resources(session)
                self._cache.save(key, resources)
        return self.filter_resources(resources)

    def get_resources(self, resource_ids: List[str]) -> List[Dict[str, Any]]:
        return [r for r in self.resources() if r.get(self.resource_type.id) in resource_ids]
