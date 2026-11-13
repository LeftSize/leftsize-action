"""`custodian` with LeftSize's own provider (Cloudflare) and Azure filters registered.

c7n 0.9.48 has no plugin entry points, so out-of-tree providers and filters must be
imported before the CLI runs. Usage is the same as `custodian`:

    python leftsize_custodian.py run --output-dir out --dry-run policies/cloudflare-security.yml

It also writes `leftsize-examined.json` next to each policy's `resources.json`: how many
resources the policy's query returned before its filters. "Looked at 40 disks, flagged
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
    """Writes the policy's unfiltered resource count once, then filters as usual.

    Filters of related resources (a VPC, a security group) get managers of their own
    that share the policy's context; only the policy's own manager counts.
    """
    ctx = getattr(self, "ctx", None)
    policy = getattr(ctx, "policy", None)
    if policy is not None and getattr(policy, "resource_manager", None) is self \
            and not getattr(self, "_leftsize_examined", False):
        self._leftsize_examined = True
        try:
            ctx.output.write_file(EXAMINED_FILE, json.dumps({"examined": len(resources)}))
        except Exception:  # noqa: BLE001  a missing count only makes LeftSize more careful
            pass
    return _filter_resources(self, resources, event)


ResourceManager.filter_resources = _record_examined


def main() -> int:
    from c7n.cli import main as custodian_main
    return custodian_main()


if __name__ == "__main__":
    sys.exit(main())
