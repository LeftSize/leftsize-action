"""Cloudflare provider for Cloud Custodian (read-only), used by LeftSize.

Importing this package registers the `cloudflare` provider and its resources.
"""

from . import provider  # noqa: F401  registers the provider
from .resources import r2, token, worker, zone  # noqa: F401  registers the resources
