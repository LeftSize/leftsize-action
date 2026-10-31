"""`custodian` with LeftSize's own providers (Cloudflare) registered.

c7n 0.9.48 has no plugin entry points, so out-of-tree providers must be imported
before the CLI runs. Usage is the same as `custodian`:

    python leftsize_custodian.py run --output-dir out --dry-run policies/cloudflare-security.yml
"""

import sys

import c7n.resources

import c7n_cloudflare  # noqa: F401  registers the cloudflare provider

# `custodian schema cloudflare...` only accepts names in this tuple
if "cloudflare" not in c7n.resources.PROVIDER_NAMES:
    c7n.resources.PROVIDER_NAMES += ("cloudflare",)


def main() -> int:
    from c7n.cli import main as custodian_main
    return custodian_main()


if __name__ == "__main__":
    sys.exit(main())
