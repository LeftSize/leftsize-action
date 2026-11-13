"""`custodian` with LeftSize's own provider (Cloudflare) and Azure filters registered.

c7n 0.9.48 has no plugin entry points, so out-of-tree providers and filters must be
imported before the CLI runs. Usage is the same as `custodian`:

    python leftsize_custodian.py run --output-dir out --dry-run policies/cloudflare-security.yml

It also writes `leftsize-examined.json` next to each policy's `resources.json`: how many
resources the policy's query returned before its filters, and how many of them had reads
denied. "Looked at 40 disks, flagged
none" means the rule found nothing to report; "looked at none" may just as well mean the
credentials can't see that resource type, so LeftSize doesn't treat the problems it
reported earlier as gone.
"""

import json
import sys

import c7n.resources
from c7n.manager import ResourceManager

import c7n_cloudflare  # noqa: F401  registers the cloudflare provider
import leftsize_azure  # noqa: F401  registers LeftSize's Azure filters (query-api-keys)

# `custodian schema cloudflare...` only accepts names in this tuple
if "cloudflare" not in c7n.resources.PROVIDER_NAMES:
    c7n.resources.PROVIDER_NAMES += ("cloudflare",)

EXAMINED_FILE = "leftsize-examined.json"

_filter_resources = ResourceManager.filter_resources


def _record_examined(self, resources, event=None):
    """Filters as usual, then writes the policy's unfiltered resource count once.

    Filters of related resources (a VPC, a security group) get managers of their own
    that share the policy's context; only the policy's own manager counts.
    """
    ctx = getattr(self, "ctx", None)
    policy = getattr(ctx, "policy", None)
    own = policy is not None and getattr(policy, "resource_manager", None) is self \
        and not getattr(self, "_leftsize_examined", False)
    if not own:
        return _filter_resources(self, resources, event)
    self._leftsize_examined = True
    examined = list(resources or [])
    filtered = _filter_resources(self, resources, event)
    try:
        # Custodian records some read failures on the resource instead of logging them
        # (S3: c7n:DeniedMethods, also added by filters such as check-public-block), so
        # they're counted after the filters ran, on the same resource objects
        denied = sum(1 for r in examined if isinstance(r, dict) and r.get("c7n:DeniedMethods"))
        ctx.output.write_file(EXAMINED_FILE, json.dumps({"examined": len(examined), "denied": denied, **_scanned_where(self)}))
    except Exception:  # noqa: BLE001  a missing count only makes LeftSize more careful
        pass
    return filtered


def _scanned_where(manager) -> dict:
    """Where Custodian actually looked, so coverage never names a place that wasn't
    scanned: the AWS account and region of the run (boto's default region needn't be the
    one LeftSize assumes), or the Azure subscription of the session (AZURE_SUBSCRIPTION_ID
    or the Azure CLI default, which needn't be the first one configured). Empty when
    unknown."""
    module = type(manager).__module__
    if module.startswith("c7n.resources") or module.startswith("c7n.query"):
        config = getattr(manager, "config", None)
        region = getattr(config, "region", None)
        account_id = getattr(config, "account_id", None)
        return {"region": region, "account": account_id} if region and account_id else {}
    if not module.startswith("c7n_azure"):
        return {}
    try:
        from c7n.utils import local_session
        subscription_id = local_session(manager.session_factory).get_subscription_id()
    except Exception:  # noqa: BLE001
        return {}
    return {"subscription": subscription_id} if subscription_id else {}


ResourceManager.filter_resources = _record_examined


def main() -> int:
    from c7n.cli import main as custodian_main
    return custodian_main()


if __name__ == "__main__":
    sys.exit(main())
