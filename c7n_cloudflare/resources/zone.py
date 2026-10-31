"""cloudflare.zone: zones (domains) with their plan, plus per-zone setting and Page Rules filters.

Token permissions (read): Zone, Zone Settings, Page Rules.
"""

from typing import Any, Dict, List, Optional

from c7n.filters import Filter, ValueFilter
from c7n.filters.core import OPERATORS
from c7n.utils import local_session, type_schema

from ..provider import resources
from ..query import QueryResourceManager, TypeInfo

# Page Rules settings Cloudflare's migration does not carry over (no direct replacement).
# https://developers.cloudflare.com/rules/reference/page-rules-migration/
UNMIGRATED_PAGE_RULE_SETTINGS = (
    "disable_performance",
    "disable_railgun",
    "disable_security",
    "response_buffering",
    "waf",
)


@resources.register("zone")
class Zone(QueryResourceManager):
    """Zones (`GET /zones`). Each zone carries `account`, `plan`, `status` and `paused`."""

    class resource_type(TypeInfo):
        path = "/zones"
        default_report_fields = ("id", "name", "status", "plan.name", "account.name")

    def list_resources(self, session: Any) -> List[Dict[str, Any]]:
        if not session.account_ids:
            return list(session.paginate("/zones"))
        zones: List[Dict[str, Any]] = []
        for account_id in session.account_ids:
            zones.extend(session.paginate("/zones", **{"account.id": account_id}))
        return zones


@Zone.filter_registry.register("zone-setting")
class ZoneSettingFilter(ValueFilter):
    """Match on one zone setting (`GET /zones/{id}/settings/{setting}`).

    The setting's `value` is compared like a value filter; the value is stored on the
    resource under `c7n:zone-settings`.

    :example:

    .. code-block:: yaml

        filters:
          - type: zone-setting
            setting: ssl
            op: in
            value: [off, flexible]
    """

    schema = type_schema("zone-setting", rinherit=ValueFilter.schema, required=["setting"],
                         setting={"type": "string", "pattern": "^[a-z0-9_]+$"})
    schema_alias = False
    required_keys = {"value"}
    annotation_key = "c7n:zone-settings"
    permissions = ("Zone Settings Read",)

    def __init__(self, data: Dict[str, Any], manager: Any = None) -> None:
        super().__init__({**data, "key": "value"}, manager)

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        session = local_session(self.manager.session_factory)
        setting = self.data["setting"]
        matched = []
        for zone in resources:
            settings = zone.setdefault(self.annotation_key, {})
            if setting not in settings:
                result = session.get(f"/zones/{zone['id']}/settings/{setting}") or {}
                settings[setting] = result.get("value")
            if self.match({"value": settings[setting]}):
                matched.append(zone)
        return matched


@Zone.filter_registry.register("page-rules")
class PageRulesFilter(Filter):
    """Zones by their number of Page Rules (`GET /zones/{id}/pagerules`, active and disabled).

    Stores a summary on the resource under `c7n:page-rules`: total, active, the settings
    the rules use, and the ones Cloudflare's migration won't carry over.

    :example:

    .. code-block:: yaml

        filters:
          - type: page-rules
            count: 1
            op: gte
    """

    schema = type_schema("page-rules", count={"type": "integer", "minimum": 0},
                         op={"enum": ["eq", "ne", "gt", "gte", "lt", "lte"]})
    annotation_key = "c7n:page-rules"
    permissions = ("Page Rules Read",)

    def process(self, resources: List[Dict[str, Any]], event: Any = None) -> List[Dict[str, Any]]:
        session = local_session(self.manager.session_factory)
        count = self.data.get("count", 1)
        op = OPERATORS[self.data.get("op", "gte")]
        matched = []
        for zone in resources:
            summary = zone.get(self.annotation_key)
            if summary is None:
                summary = summarize_page_rules(session.get(f"/zones/{zone['id']}/pagerules") or [])
                zone[self.annotation_key] = summary
            if op(summary["count"], count):
                matched.append(zone)
        return matched


def summarize_page_rules(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    settings = sorted({a.get("id") for r in rules for a in (r.get("actions") or []) if a.get("id")})
    urls: List[Optional[str]] = [
        ((r.get("targets") or [{}])[0].get("constraint") or {}).get("value") for r in rules
    ]
    return {
        "count": len(rules),
        "active": sum(1 for r in rules if r.get("status") == "active"),
        "settings": settings,
        "unmigrated": [s for s in settings if s in UNMIGRATED_PAGE_RULE_SETTINGS],
        "urls": [u for u in urls if u][:10],
    }
